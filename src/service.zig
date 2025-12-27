// Service Management Integration for Axiom
// Phase 38: FreeBSD rc.d service integration
//
// This module provides integration with FreeBSD's rc.d service management system,
// allowing packages to declare and manage services through Axiom.

const std = @import("std");
const types = @import("types.zig");
const errors = @import("errors.zig");

// ============================================================================
// Memory Safety Helpers
// ============================================================================

/// Safely convert ArrayList to owned slice, cleaning up on failure.
/// For ArrayLists containing allocated strings, this frees all items on failure.
fn toOwnedSliceOrCleanupStrings(
    allocator: std.mem.Allocator,
    list: *std.ArrayList([]const u8),
) ![]const []const u8 {
    return list.toOwnedSlice(allocator) catch |err| {
        // Free all duped strings in the list
        for (list.items) |item| {
            allocator.free(item);
        }
        list.deinit(allocator);
        return err;
    };
}

/// Safely convert ArrayList(u16) to owned slice, cleaning up on failure.
fn toOwnedSliceOrCleanupU16(allocator: std.mem.Allocator, list: *std.ArrayList(u16)) ![]const u16 {
    return list.toOwnedSlice(allocator) catch |err| {
        list.deinit(allocator);
        return err;
    };
}

/// Service-related errors
pub const ServiceError = error{
    ServiceNotFound,
    ServiceAlreadyEnabled,
    ServiceAlreadyDisabled,
    ServiceStartFailed,
    ServiceStopFailed,
    RcScriptNotFound,
    PermissionDenied,
    InvalidServiceConfig,
    ConflictingService,
    DependencyNotMet,
};

/// Type of service
pub const ServiceType = enum {
    /// Long-running daemon (e.g., nginx, postgresql)
    daemon,
    /// One-shot service that runs and exits (e.g., cleanvar)
    oneshot,
    /// Periodic service triggered by cron or timer
    periodic,
    /// Network service that listens on ports
    network,

    pub fn toString(self: ServiceType) []const u8 {
        return switch (self) {
            .daemon => "daemon",
            .oneshot => "oneshot",
            .periodic => "periodic",
            .network => "network",
        };
    }

    pub fn fromString(s: []const u8) ?ServiceType {
        if (std.mem.eql(u8, s, "daemon")) return .daemon;
        if (std.mem.eql(u8, s, "oneshot")) return .oneshot;
        if (std.mem.eql(u8, s, "periodic")) return .periodic;
        if (std.mem.eql(u8, s, "network")) return .network;
        return null;
    }
};

/// Service declaration in package manifest
pub const ServiceDeclaration = struct {
    /// Service name (used for rc.d script and enable variable)
    name: []const u8,
    /// Type of service
    service_type: ServiceType = .daemon,
    /// Path to rc.d script relative to package root (e.g., "etc/rc.d/nginx")
    rc_script: []const u8,
    /// Service dependencies (other service names that must be running)
    dependencies: []const []const u8 = &[_][]const u8{},
    /// Services that conflict with this one
    conflicts: []const []const u8 = &[_][]const u8{},
    /// Human-readable description
    description: ?[]const u8 = null,
    /// Default enabled state when package is installed
    default_enabled: bool = false,
    /// Ports this service listens on (for network services)
    ports: []const u16 = &[_]u16{},
    /// User to run service as (null = root)
    user: ?[]const u8 = null,
    /// Group to run service as
    group: ?[]const u8 = null,
    /// Environment variables to set
    environment: []const EnvironmentVar = &[_]EnvironmentVar{},

    pub const EnvironmentVar = struct {
        name: []const u8,
        value: []const u8,
    };

    pub fn deinit(self: *ServiceDeclaration, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.rc_script);
        for (self.dependencies) |dep| {
            allocator.free(dep);
        }
        allocator.free(self.dependencies);
        for (self.conflicts) |c| {
            allocator.free(c);
        }
        allocator.free(self.conflicts);
        if (self.description) |d| {
            allocator.free(d);
        }
        allocator.free(self.ports);
        if (self.user) |u| {
            allocator.free(u);
        }
        if (self.group) |g| {
            allocator.free(g);
        }
        for (self.environment) |env| {
            allocator.free(env.name);
            allocator.free(env.value);
        }
        allocator.free(self.environment);
    }
};

/// Current status of a service
pub const ServiceStatus = enum {
    running,
    stopped,
    starting,
    stopping,
    failed,
    unknown,

    pub fn toString(self: ServiceStatus) []const u8 {
        return switch (self) {
            .running => "running",
            .stopped => "stopped",
            .starting => "starting",
            .stopping => "stopping",
            .failed => "failed",
            .unknown => "unknown",
        };
    }
};

/// Information about a service instance
pub const ServiceInfo = struct {
    name: []const u8,
    package_name: []const u8,
    package_version: []const u8,
    service_type: ServiceType,
    status: ServiceStatus,
    enabled: bool,
    pid: ?u32,
    rc_script_path: []const u8,
    description: ?[]const u8,

    pub fn deinit(self: *ServiceInfo, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.package_name);
        allocator.free(self.package_version);
        allocator.free(self.rc_script_path);
        if (self.description) |d| {
            allocator.free(d);
        }
    }
};

/// Service configuration for rc.conf.d
pub const ServiceConfig = struct {
    /// Service name
    name: []const u8,
    /// Enable variable (e.g., nginx_enable="YES")
    enable: bool,
    /// Additional rc.conf variables
    variables: std.StringHashMap([]const u8),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, name: []const u8) ServiceConfig {
        return ServiceConfig{
            .name = name,
            .enable = false,
            .variables = std.StringHashMap([]const u8).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *ServiceConfig) void {
        var iter = self.variables.iterator();
        while (iter.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.variables.deinit();
    }

    /// Set a configuration variable
    pub fn setVar(self: *ServiceConfig, key: []const u8, value: []const u8) !void {
        const key_dup = try self.allocator.dupe(u8, key);
        errdefer self.allocator.free(key_dup);
        const value_dup = try self.allocator.dupe(u8, value);
        try self.variables.put(key_dup, value_dup);
    }

    /// Generate rc.conf.d file content
    pub fn toRcConf(self: ServiceConfig, allocator: std.mem.Allocator) ![]u8 {
        var result: std.ArrayList(u8) = .empty;
        errdefer result.deinit(allocator);
        const writer = result.writer(allocator);

        try std.fmt.format(writer,"# Axiom-managed service configuration for {s}\n", .{self.name});
        try std.fmt.format(writer,"# Do not edit manually - use 'axiom service' commands\n\n", .{});

        // Enable variable
        const enable_value = if (self.enable) "YES" else "NO";
        try std.fmt.format(writer,"{s}_enable=\"{s}\"\n", .{ self.name, enable_value });

        // Additional variables
        var iter = self.variables.iterator();
        while (iter.next()) |entry| {
            try std.fmt.format(writer,"{s}_{s}=\"{s}\"\n", .{ self.name, entry.key_ptr.*, entry.value_ptr.* });
        }

        return result.toOwnedSlice(allocator);
    }
};

/// Service manager for FreeBSD rc.d integration
pub const ServiceManager = struct {
    allocator: std.mem.Allocator,
    /// Base path for rc.conf.d files
    rc_conf_d_path: []const u8,
    /// Base path for rc.d scripts
    rc_d_path: []const u8,
    /// Axiom store path
    store_path: []const u8,

    pub fn init(allocator: std.mem.Allocator) ServiceManager {
        return ServiceManager{
            .allocator = allocator,
            .rc_conf_d_path = "/etc/rc.conf.d",
            .rc_d_path = "/usr/local/etc/rc.d",
            .store_path = "/axiom/store",
        };
    }

    pub fn initWithPaths(
        allocator: std.mem.Allocator,
        rc_conf_d_path: []const u8,
        rc_d_path: []const u8,
        store_path: []const u8,
    ) ServiceManager {
        return ServiceManager{
            .allocator = allocator,
            .rc_conf_d_path = rc_conf_d_path,
            .rc_d_path = rc_d_path,
            .store_path = store_path,
        };
    }

    /// List all services from packages in a profile
    pub fn listServicesFromProfile(
        self: *ServiceManager,
        profile_path: []const u8,
    ) ![]ServiceInfo {
        var services: std.ArrayList(ServiceInfo) = .empty;
        defer services.deinit(self.allocator);

        // Read profile packages and find services
        // For now, scan for rc.d scripts in linked packages
        const profile_etc_rc_d = try std.fs.path.join(self.allocator, &[_][]const u8{ profile_path, "etc", "rc.d" });
        defer self.allocator.free(profile_etc_rc_d);

        var dir = std.fs.cwd().openDir(profile_etc_rc_d, .{ .iterate = true }) catch {
            return services.toOwnedSlice(self.allocator);
        };
        defer dir.close();

        var iter = dir.iterate();
        while (try iter.next()) |entry| {
            if (entry.kind == .file or entry.kind == .sym_link) {
                const service_name = entry.name;
                const status = self.getServiceStatus(service_name) catch .unknown;
                const enabled = self.isServiceEnabled(service_name) catch false;

                try services.append(self.allocator, ServiceInfo{
                    .name = try self.allocator.dupe(u8, service_name),
                    .package_name = try self.allocator.dupe(u8, "unknown"),
                    .package_version = try self.allocator.dupe(u8, "0.0.0"),
                    .service_type = .daemon,
                    .status = status,
                    .enabled = enabled,
                    .pid = null,
                    .rc_script_path = try std.fs.path.join(self.allocator, &[_][]const u8{ profile_etc_rc_d, service_name }),
                    .description = null,
                });
            }
        }

        return services.toOwnedSlice(self.allocator);
    }

    /// Get status of a service
    pub fn getServiceStatus(self: *ServiceManager, service_name: []const u8) !ServiceStatus {
        // Run: service <name> status
        const result = try self.runServiceCommand(service_name, "status");
        defer self.allocator.free(result.stdout);
        defer self.allocator.free(result.stderr);

        if (result.exit_code == 0) {
            // Check output for running state
            if (std.mem.indexOf(u8, result.stdout, "is running") != null) {
                return .running;
            } else if (std.mem.indexOf(u8, result.stdout, "is not running") != null) {
                return .stopped;
            }
            return .running; // Exit 0 usually means running
        } else {
            return .stopped;
        }
    }

    /// Check if a service is enabled
    pub fn isServiceEnabled(self: *ServiceManager, service_name: []const u8) !bool {
        // Check rc.conf.d/<service_name> for enable="YES"
        const conf_path = try std.fs.path.join(self.allocator, &[_][]const u8{ self.rc_conf_d_path, service_name });
        defer self.allocator.free(conf_path);

        const content = std.fs.cwd().readFileAlloc(self.allocator, conf_path, 64 * 1024) catch {
            // No config file means not enabled by Axiom
            // Could still be enabled in main rc.conf
            return false;
        };
        defer self.allocator.free(content);

        // Look for <service_name>_enable="YES"
        var enable_var: std.ArrayList(u8) = .empty;
        defer enable_var.deinit(self.allocator);
        try enable_var.writer(self.allocator).print("{s}_enable", .{service_name});

        if (std.mem.indexOf(u8, content, enable_var.items)) |idx| {
            const rest = content[idx..];
            if (std.mem.indexOf(u8, rest, "YES") != null or std.mem.indexOf(u8, rest, "yes") != null) {
                return true;
            }
        }

        return false;
    }

    /// Enable a service
    pub fn enableService(self: *ServiceManager, service_name: []const u8) !void {
        std.debug.print("Enabling service: {s}\n", .{service_name});

        // Create rc.conf.d entry
        try self.writeServiceConfig(service_name, true);

        std.debug.print("Service {s} enabled\n", .{service_name});
    }

    /// Disable a service
    pub fn disableService(self: *ServiceManager, service_name: []const u8) !void {
        std.debug.print("Disabling service: {s}\n", .{service_name});

        // Update rc.conf.d entry
        try self.writeServiceConfig(service_name, false);

        std.debug.print("Service {s} disabled\n", .{service_name});
    }

    /// Start a service
    pub fn startService(self: *ServiceManager, service_name: []const u8) !void {
        std.debug.print("Starting service: {s}\n", .{service_name});

        const result = try self.runServiceCommand(service_name, "start");
        defer self.allocator.free(result.stdout);
        defer self.allocator.free(result.stderr);

        if (result.exit_code != 0) {
            std.debug.print("Failed to start service: {s}\n", .{result.stderr});
            return ServiceError.ServiceStartFailed;
        }

        std.debug.print("Service {s} started\n", .{service_name});
    }

    /// Stop a service
    pub fn stopService(self: *ServiceManager, service_name: []const u8) !void {
        std.debug.print("Stopping service: {s}\n", .{service_name});

        const result = try self.runServiceCommand(service_name, "stop");
        defer self.allocator.free(result.stdout);
        defer self.allocator.free(result.stderr);

        if (result.exit_code != 0) {
            std.debug.print("Failed to stop service: {s}\n", .{result.stderr});
            return ServiceError.ServiceStopFailed;
        }

        std.debug.print("Service {s} stopped\n", .{service_name});
    }

    /// Restart a service
    pub fn restartService(self: *ServiceManager, service_name: []const u8) !void {
        std.debug.print("Restarting service: {s}\n", .{service_name});

        const result = try self.runServiceCommand(service_name, "restart");
        defer self.allocator.free(result.stdout);
        defer self.allocator.free(result.stderr);

        if (result.exit_code != 0) {
            std.debug.print("Failed to restart service: {s}\n", .{result.stderr});
            return ServiceError.ServiceStartFailed;
        }

        std.debug.print("Service {s} restarted\n", .{service_name});
    }

    /// Reload a service configuration
    pub fn reloadService(self: *ServiceManager, service_name: []const u8) !void {
        std.debug.print("Reloading service: {s}\n", .{service_name});

        const result = try self.runServiceCommand(service_name, "reload");
        defer self.allocator.free(result.stdout);
        defer self.allocator.free(result.stderr);

        if (result.exit_code != 0) {
            // Some services don't support reload, try restart
            try self.restartService(service_name);
            return;
        }

        std.debug.print("Service {s} reloaded\n", .{service_name});
    }

    /// Write service configuration to rc.conf.d
    fn writeServiceConfig(self: *ServiceManager, service_name: []const u8, enabled: bool) !void {
        // Ensure rc.conf.d directory exists
        std.fs.cwd().makePath(self.rc_conf_d_path) catch |err| {
            errors.logMkdirBestEffort(@src(), err, self.rc_conf_d_path);
        };

        const conf_path = try std.fs.path.join(self.allocator, &[_][]const u8{ self.rc_conf_d_path, service_name });
        defer self.allocator.free(conf_path);

        var config = ServiceConfig.init(self.allocator, service_name);
        defer config.deinit();
        config.enable = enabled;

        const content = try config.toRcConf(self.allocator);
        defer self.allocator.free(content);

        const file = try std.fs.cwd().createFile(conf_path, .{});
        defer file.close();
        try file.writeAll(content);
    }

    /// Run a service command
    fn runServiceCommand(self: *ServiceManager, service_name: []const u8, action: []const u8) !CommandResult {
        var child = std.process.Child.init(
            &[_][]const u8{ "service", service_name, action },
            self.allocator,
        );
        child.stderr_behavior = .Pipe;
        child.stdout_behavior = .Pipe;

        try child.spawn();

        var stdout: std.ArrayList(u8) = .empty;
        defer stdout.deinit(self.allocator);
        var stderr: std.ArrayList(u8) = .empty;
        defer stderr.deinit(self.allocator);

        // Read stdout and stderr
        if (child.stdout) |stdout_pipe| {
            if (stdout_pipe.readToEndAlloc(self.allocator, 64 * 1024)) |stdout_data| {
                stdout.appendSlice(self.allocator, stdout_data) catch {};
                self.allocator.free(stdout_data);
            } else |err| {
                errors.logCollectionError(@src(), err, "read service stdout");
            }
        }
        if (child.stderr) |stderr_pipe| {
            if (stderr_pipe.readToEndAlloc(self.allocator, 64 * 1024)) |stderr_data| {
                stderr.appendSlice(self.allocator, stderr_data) catch {};
                self.allocator.free(stderr_data);
            } else |err| {
                errors.logCollectionError(@src(), err, "read service stderr");
            }
        }

        const term = try child.wait();
        const exit_code: u8 = switch (term) {
            .Exited => |code| code,
            else => 1,
        };

        return CommandResult{
            .exit_code = exit_code,
            .stdout = try stdout.toOwnedSlice(self.allocator),
            .stderr = try stderr.toOwnedSlice(self.allocator),
        };
    }

    const CommandResult = struct {
        exit_code: u8,
        stdout: []u8,
        stderr: []u8,
    };

    /// Link a service's rc.d script from package to system location
    pub fn linkServiceScript(
        self: *ServiceManager,
        package_path: []const u8,
        service: ServiceDeclaration,
    ) !void {
        // Source: <package_path>/<rc_script>
        const source = try std.fs.path.join(self.allocator, &[_][]const u8{ package_path, service.rc_script });
        defer self.allocator.free(source);

        // Destination: <rc_d_path>/<service_name>
        const dest = try std.fs.path.join(self.allocator, &[_][]const u8{ self.rc_d_path, service.name });
        defer self.allocator.free(dest);

        // Check source exists
        std.fs.cwd().access(source, .{}) catch {
            std.debug.print("RC script not found: {s}\n", .{source});
            return ServiceError.RcScriptNotFound;
        };

        // Create symlink
        std.fs.cwd().deleteFile(dest) catch |err| {
            errors.logFileCleanup(@src(), err, dest);
        }; // Remove existing
        try std.posix.symlink(source, dest);

        std.debug.print("Linked service script: {s} -> {s}\n", .{ dest, source });

        // Set default enabled state if specified
        if (service.default_enabled) {
            try self.enableService(service.name);
        }
    }

    /// Unlink a service's rc.d script
    pub fn unlinkServiceScript(self: *ServiceManager, service_name: []const u8) !void {
        // Stop and disable the service first
        self.stopService(service_name) catch |err| {
            errors.logServiceOp(@src(), err, "stop service", service_name);
        };
        self.disableService(service_name) catch |err| {
            errors.logServiceOp(@src(), err, "disable service", service_name);
        };

        // Remove the symlink
        const script_path = try std.fs.path.join(self.allocator, &[_][]const u8{ self.rc_d_path, service_name });
        defer self.allocator.free(script_path);

        std.fs.cwd().deleteFile(script_path) catch |err| {
            errors.logFileCleanup(@src(), err, script_path);
        };

        // Remove rc.conf.d entry
        const conf_path = try std.fs.path.join(self.allocator, &[_][]const u8{ self.rc_conf_d_path, service_name });
        defer self.allocator.free(conf_path);

        std.fs.cwd().deleteFile(conf_path) catch |err| {
            errors.logFileCleanup(@src(), err, conf_path);
        };

        std.debug.print("Unlinked service: {s}\n", .{service_name});
    }
};

/// Parse service declarations from manifest YAML
pub fn parseServiceDeclarations(allocator: std.mem.Allocator, yaml_content: []const u8) ![]ServiceDeclaration {
    var services: std.ArrayList(ServiceDeclaration) = .empty;
    defer services.deinit(allocator);

    var current_service: ?ServiceDeclaration = null;
    var in_services_section = false;
    var in_dependencies = false;
    var in_conflicts = false;
    var in_ports = false;

    var deps_list: std.ArrayList([]const u8) = .empty;
    defer deps_list.deinit(allocator);
    var conflicts_list: std.ArrayList([]const u8) = .empty;
    defer conflicts_list.deinit(allocator);
    var ports_list: std.ArrayList(u16) = .empty;
    defer ports_list.deinit(allocator);

    var lines = std.mem.splitSequence(u8, yaml_content, "\n");
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len == 0 or trimmed[0] == '#') continue;

        const indent = getIndent(line);

        if (std.mem.eql(u8, trimmed, "services:")) {
            in_services_section = true;
            continue;
        }

        if (!in_services_section) continue;

        // New service entry
        if (std.mem.startsWith(u8, trimmed, "- name:")) {
            // Save previous service
            if (current_service) |*svc| {
                // Use safe conversion with proper cleanup on failure
                svc.dependencies = try toOwnedSliceOrCleanupStrings(allocator, &deps_list);
                svc.conflicts = try toOwnedSliceOrCleanupStrings(allocator, &conflicts_list);
                svc.ports = try toOwnedSliceOrCleanupU16(allocator, &ports_list);
                try services.append(allocator, svc.*);
                deps_list = .empty;
                conflicts_list = .empty;
                ports_list = .empty;
            }

            var value = std.mem.trim(u8, trimmed[7..], " \t");
            if (value.len >= 2 and value[0] == '"' and value[value.len - 1] == '"') {
                value = value[1 .. value.len - 1];
            }

            current_service = ServiceDeclaration{
                .name = try allocator.dupe(u8, value),
                .rc_script = undefined,
            };
            in_dependencies = false;
            in_conflicts = false;
            in_ports = false;
            continue;
        }

        if (current_service == null) continue;

        // Handle list items
        if (std.mem.startsWith(u8, trimmed, "- ") and indent > 2) {
            var item = std.mem.trim(u8, trimmed[2..], " \t");
            if (item.len >= 2 and item[0] == '"' and item[item.len - 1] == '"') {
                item = item[1 .. item.len - 1];
            }

            if (in_dependencies) {
                try deps_list.append(allocator, try allocator.dupe(u8, item));
            } else if (in_conflicts) {
                try conflicts_list.append(allocator, try allocator.dupe(u8, item));
            } else if (in_ports) {
                const port = std.fmt.parseInt(u16, item, 10) catch continue;
                try ports_list.append(allocator, port);
            }
            continue;
        }

        // Parse service fields
        if (std.mem.indexOf(u8, trimmed, ":")) |colon_idx| {
            const key = std.mem.trim(u8, trimmed[0..colon_idx], " \t");
            var value = std.mem.trim(u8, trimmed[colon_idx + 1 ..], " \t");

            if (value.len >= 2 and value[0] == '"' and value[value.len - 1] == '"') {
                value = value[1 .. value.len - 1];
            }

            if (std.mem.eql(u8, key, "type")) {
                current_service.?.service_type = ServiceType.fromString(value) orelse .daemon;
                in_dependencies = false;
                in_conflicts = false;
                in_ports = false;
            } else if (std.mem.eql(u8, key, "rc_script")) {
                current_service.?.rc_script = try allocator.dupe(u8, value);
                in_dependencies = false;
                in_conflicts = false;
                in_ports = false;
            } else if (std.mem.eql(u8, key, "description")) {
                current_service.?.description = try allocator.dupe(u8, value);
                in_dependencies = false;
                in_conflicts = false;
                in_ports = false;
            } else if (std.mem.eql(u8, key, "default_enabled")) {
                current_service.?.default_enabled = std.mem.eql(u8, value, "true");
                in_dependencies = false;
                in_conflicts = false;
                in_ports = false;
            } else if (std.mem.eql(u8, key, "user")) {
                current_service.?.user = try allocator.dupe(u8, value);
                in_dependencies = false;
                in_conflicts = false;
                in_ports = false;
            } else if (std.mem.eql(u8, key, "group")) {
                current_service.?.group = try allocator.dupe(u8, value);
                in_dependencies = false;
                in_conflicts = false;
                in_ports = false;
            } else if (std.mem.eql(u8, key, "dependencies")) {
                in_dependencies = true;
                in_conflicts = false;
                in_ports = false;
            } else if (std.mem.eql(u8, key, "conflicts")) {
                in_dependencies = false;
                in_conflicts = true;
                in_ports = false;
            } else if (std.mem.eql(u8, key, "ports")) {
                in_dependencies = false;
                in_conflicts = false;
                in_ports = true;
            }
        }
    }

    // Save last service
    if (current_service) |*svc| {
        // Use safe conversion with proper cleanup on failure
        svc.dependencies = try toOwnedSliceOrCleanupStrings(allocator, &deps_list);
        svc.conflicts = try toOwnedSliceOrCleanupStrings(allocator, &conflicts_list);
        svc.ports = try toOwnedSliceOrCleanupU16(allocator, &ports_list);
        try services.append(allocator, svc.*);
    }

    return services.toOwnedSlice(allocator);
}

fn getIndent(line: []const u8) usize {
    var indent: usize = 0;
    for (line) |c| {
        if (c == ' ') {
            indent += 1;
        } else if (c == '\t') {
            indent += 2;
        } else {
            break;
        }
    }
    return indent;
}

// ============================================================================
// Unit Tests
// ============================================================================

test "ServiceType fromString" {
    try std.testing.expect(ServiceType.fromString("daemon") == .daemon);
    try std.testing.expect(ServiceType.fromString("oneshot") == .oneshot);
    try std.testing.expect(ServiceType.fromString("periodic") == .periodic);
    try std.testing.expect(ServiceType.fromString("network") == .network);
    try std.testing.expect(ServiceType.fromString("invalid") == null);
}

test "ServiceConfig toRcConf" {
    var config = ServiceConfig.init(std.testing.allocator, "nginx");
    defer config.deinit();

    config.enable = true;
    try config.setVar("flags", "-g daemon off;");

    const content = try config.toRcConf(std.testing.allocator);
    defer std.testing.allocator.free(content);

    try std.testing.expect(std.mem.indexOf(u8, content, "nginx_enable=\"YES\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "nginx_flags=\"-g daemon off;\"") != null);
}

test "parseServiceDeclarations" {
    const yaml =
        \\services:
        \\  - name: nginx
        \\    type: daemon
        \\    rc_script: etc/rc.d/nginx
        \\    description: "Web server"
        \\    default_enabled: true
        \\    dependencies:
        \\      - networking
        \\      - syslogd
        \\    ports:
        \\      - 80
        \\      - 443
    ;

    const services = try parseServiceDeclarations(std.testing.allocator, yaml);
    defer {
        for (services) |*svc| {
            var s = svc.*;
            s.deinit(std.testing.allocator);
        }
        std.testing.allocator.free(services);
    }

    try std.testing.expectEqual(@as(usize, 1), services.len);
    try std.testing.expectEqualStrings("nginx", services[0].name);
    try std.testing.expect(services[0].service_type == .daemon);
    try std.testing.expectEqualStrings("etc/rc.d/nginx", services[0].rc_script);
    try std.testing.expect(services[0].default_enabled);
    try std.testing.expectEqual(@as(usize, 2), services[0].dependencies.len);
    try std.testing.expectEqual(@as(usize, 2), services[0].ports.len);
}
