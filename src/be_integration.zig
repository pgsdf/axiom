const std = @import("std");
const zfs = @import("zfs.zig");
const profile = @import("profile.zig");
const bootenv = @import("bootenv.zig");

const Allocator = std.mem.Allocator;
const ZfsHandle = zfs.ZfsHandle;
const ProfileManager = profile.ProfileManager;
const BootEnvManager = bootenv.BootEnvManager;

/// Bootloader types supported
pub const BootloaderType = enum {
    freebsd,
    grub,
    systemd_boot,

    pub fn toString(self: BootloaderType) []const u8 {
        return switch (self) {
            .freebsd => "freebsd",
            .grub => "grub",
            .systemd_boot => "systemd-boot",
        };
    }

    pub fn fromString(s: []const u8) ?BootloaderType {
        if (std.mem.eql(u8, s, "freebsd")) return .freebsd;
        if (std.mem.eql(u8, s, "grub")) return .grub;
        if (std.mem.eql(u8, s, "systemd-boot")) return .systemd_boot;
        return null;
    }
};

/// Health check definition
pub const HealthCheck = struct {
    name: []const u8,
    command: []const u8,
    required: bool = true,
    timeout_seconds: u32 = 30,

    pub fn deinit(self: *HealthCheck, allocator: Allocator) void {
        allocator.free(self.name);
        allocator.free(self.command);
    }
};

/// Health check result
pub const HealthCheckResult = struct {
    name: []const u8,
    passed: bool,
    output: ?[]const u8,
    duration_ms: u64,

    pub fn deinit(self: *HealthCheckResult, allocator: Allocator) void {
        allocator.free(self.name);
        if (self.output) |o| allocator.free(o);
    }
};

/// Overall health status
pub const HealthStatus = struct {
    allocator: Allocator,
    results: std.ArrayList(HealthCheckResult),
    all_passed: bool,
    required_passed: bool,

    pub fn init(allocator: Allocator) HealthStatus {
        return .{
            .allocator = allocator,
            .results = .empty,
            .all_passed = true,
            .required_passed = true,
        };
    }

    pub fn deinit(self: *HealthStatus) void {
        for (self.results.items) |*r| {
            r.deinit(self.allocator);
        }
        self.results.deinit(self.allocator);
    }
};

/// Rollback trigger types
pub const RollbackTrigger = enum {
    boot_failure,
    service_failure,
    health_check_failure,
    manual,

    pub fn toString(self: RollbackTrigger) []const u8 {
        return switch (self) {
            .boot_failure => "boot_failure",
            .service_failure => "service_failure",
            .health_check_failure => "health_check_failure",
            .manual => "manual",
        };
    }
};

/// Rollback policy configuration
pub const RollbackPolicy = struct {
    auto_rollback_enabled: bool = true,
    triggers: []const RollbackTrigger = &[_]RollbackTrigger{
        .boot_failure,
        .service_failure,
        .health_check_failure,
    },
    grace_period_seconds: u32 = 300,
    health_checks: std.ArrayList(HealthCheck),

    pub fn init(_allocator: Allocator) RollbackPolicy {
        return .{
            .health_checks = .empty,
        };
    }

    pub fn deinit(self: *RollbackPolicy, allocator: Allocator) void {
        for (self.health_checks.items) |*hc| {
            hc.deinit(allocator);
        }
        self.health_checks.deinit(allocator);
    }

    /// Add a health check
    pub fn addHealthCheck(self: *RollbackPolicy, allocator: Allocator, check: HealthCheck) !void {
        try self.health_checks.append(allocator, check);
    }
};

/// Activation hook types
pub const HookType = enum {
    pre_activate,
    post_activate,
    on_rollback,
    pre_snapshot,
    post_snapshot,

    pub fn toString(self: HookType) []const u8 {
        return switch (self) {
            .pre_activate => "pre_activate",
            .post_activate => "post_activate",
            .on_rollback => "on_rollback",
            .pre_snapshot => "pre_snapshot",
            .post_snapshot => "post_snapshot",
        };
    }
};

/// Activation hook configuration
pub const ActivationHook = struct {
    hook_type: HookType,
    path: []const u8,
    timeout_seconds: u32 = 60,
    required: bool = false,

    pub fn deinit(self: *ActivationHook, allocator: Allocator) void {
        allocator.free(self.path);
    }
};

/// Hook execution result
pub const HookResult = struct {
    hook_type: HookType,
    path: []const u8,
    success: bool,
    exit_code: ?u8,
    output: ?[]const u8,

    pub fn deinit(self: *HookResult, allocator: Allocator) void {
        allocator.free(self.path);
        if (self.output) |o| allocator.free(o);
    }
};

/// Activation options
pub const ActivateOptions = struct {
    bootloader: BootloaderType = .freebsd,
    next_boot_only: bool = false,
    run_hooks: bool = true,
    skip_health_checks: bool = false,
};

/// Profile difference entry
pub const ProfileDiffEntry = struct {
    package_name: []const u8,
    diff_type: DiffType,
    version_a: ?[]const u8,
    version_b: ?[]const u8,

    pub const DiffType = enum {
        added,
        removed,
        version_changed,
        unchanged,
    };

    pub fn deinit(self: *ProfileDiffEntry, allocator: Allocator) void {
        allocator.free(self.package_name);
        if (self.version_a) |v| allocator.free(v);
        if (self.version_b) |v| allocator.free(v);
    }
};

/// Profile difference result
pub const ProfileDiff = struct {
    allocator: Allocator,
    entries: std.ArrayList(ProfileDiffEntry),
    be_a: []const u8,
    be_b: []const u8,

    pub fn init(allocator: Allocator, be_a: []const u8, be_b: []const u8) !ProfileDiff {
        return .{
            .allocator = allocator,
            .entries = .empty,
            .be_a = try allocator.dupe(u8, be_a),
            .be_b = try allocator.dupe(u8, be_b),
        };
    }

    pub fn deinit(self: *ProfileDiff) void {
        for (self.entries.items) |*e| {
            e.deinit(self.allocator);
        }
        self.entries.deinit(self.allocator);
        self.allocator.free(self.be_a);
        self.allocator.free(self.be_b);
    }

    pub fn addedCount(self: *const ProfileDiff) usize {
        var count: usize = 0;
        for (self.entries.items) |e| {
            if (e.diff_type == .added) count += 1;
        }
        return count;
    }

    pub fn removedCount(self: *const ProfileDiff) usize {
        var count: usize = 0;
        for (self.entries.items) |e| {
            if (e.diff_type == .removed) count += 1;
        }
        return count;
    }

    pub fn changedCount(self: *const ProfileDiff) usize {
        var count: usize = 0;
        for (self.entries.items) |e| {
            if (e.diff_type == .version_changed) count += 1;
        }
        return count;
    }
};

/// BE Profile Manager - manages profile snapshots in boot environments
pub const BeProfileManager = struct {
    allocator: Allocator,
    zfs_handle: *ZfsHandle,
    profile_mgr: *ProfileManager,
    be_mgr: *BootEnvManager,
    axiom_root: []const u8,

    const Self = @This();

    pub fn init(
        allocator: Allocator,
        zfs_handle: *ZfsHandle,
        profile_mgr: *ProfileManager,
        be_mgr: *BootEnvManager,
    ) Self {
        return .{
            .allocator = allocator,
            .zfs_handle = zfs_handle,
            .profile_mgr = profile_mgr,
            .be_mgr = be_mgr,
            .axiom_root = "/axiom",
        };
    }

    /// Snapshot a profile to a boot environment
    pub fn snapshotProfile(self: *Self, profile_name: []const u8, be_name: []const u8) !void {
        // Verify profile exists
        _ = self.profile_mgr.getProfile(profile_name) catch {
            return error.ProfileNotFound;
        };

        // Create BE directory structure
        const be_profile_path = try std.fmt.allocPrint(
            self.allocator,
            "{s}/be/{s}/{s}",
            .{ self.axiom_root, be_name, profile_name },
        );
        defer self.allocator.free(be_profile_path);

        // Create directory
        std.fs.cwd().makePath(be_profile_path) catch |err| {
            if (err != error.PathAlreadyExists) return err;
        };

        // Copy profile.lock.yaml to BE
        const src_lock = try std.fmt.allocPrint(
            self.allocator,
            "{s}/profiles/{s}/profile.lock.yaml",
            .{ self.axiom_root, profile_name },
        );
        defer self.allocator.free(src_lock);

        const dst_lock = try std.fmt.allocPrint(
            self.allocator,
            "{s}/profile.lock.yaml",
            .{be_profile_path},
        );
        defer self.allocator.free(dst_lock);

        try std.fs.cwd().copyFile(src_lock, std.fs.cwd(), dst_lock, .{});
    }

    /// Restore a profile from a boot environment
    pub fn restoreProfile(self: *Self, be_name: []const u8, profile_name: []const u8) !void {
        const be_lock_path = try std.fmt.allocPrint(
            self.allocator,
            "{s}/be/{s}/{s}/profile.lock.yaml",
            .{ self.axiom_root, be_name, profile_name },
        );
        defer self.allocator.free(be_lock_path);

        const dst_lock = try std.fmt.allocPrint(
            self.allocator,
            "{s}/profiles/{s}/profile.lock.yaml",
            .{ self.axiom_root, profile_name },
        );
        defer self.allocator.free(dst_lock);

        // Backup current lock file
        const backup_path = try std.fmt.allocPrint(
            self.allocator,
            "{s}.bak",
            .{dst_lock},
        );
        defer self.allocator.free(backup_path);

        std.fs.cwd().copyFile(dst_lock, std.fs.cwd(), backup_path, .{}) catch {};

        // Restore from BE
        try std.fs.cwd().copyFile(be_lock_path, std.fs.cwd(), dst_lock, .{});
    }

    /// Compare profiles between two boot environments
    pub fn diffProfiles(
        self: *Self,
        be_a: []const u8,
        be_b: []const u8,
        profile_name: []const u8,
    ) !ProfileDiff {
        var diff = try ProfileDiff.init(self.allocator, be_a, be_b);
        errdefer diff.deinit();

        // Load packages from BE A
        var packages_a = std.StringHashMap([]const u8).init(self.allocator);
        defer {
            var iter = packages_a.iterator();
            while (iter.next()) |entry| {
                self.allocator.free(entry.key_ptr.*);
                self.allocator.free(entry.value_ptr.*);
            }
            packages_a.deinit();
        }

        try self.loadBePackages(&packages_a, be_a, profile_name);

        // Load packages from BE B
        var packages_b = std.StringHashMap([]const u8).init(self.allocator);
        defer {
            var iter = packages_b.iterator();
            while (iter.next()) |entry| {
                self.allocator.free(entry.key_ptr.*);
                self.allocator.free(entry.value_ptr.*);
            }
            packages_b.deinit();
        }

        try self.loadBePackages(&packages_b, be_b, profile_name);

        // Find differences
        var iter_a = packages_a.iterator();
        while (iter_a.next()) |entry| {
            const pkg_name = entry.key_ptr.*;
            const version_a = entry.value_ptr.*;

            if (packages_b.get(pkg_name)) |version_b| {
                if (!std.mem.eql(u8, version_a, version_b)) {
                    try diff.entries.append(self.allocator, .{
                        .package_name = try self.allocator.dupe(u8, pkg_name),
                        .diff_type = .version_changed,
                        .version_a = try self.allocator.dupe(u8, version_a),
                        .version_b = try self.allocator.dupe(u8, version_b),
                    });
                }
            } else {
                try diff.entries.append(self.allocator, .{
                    .package_name = try self.allocator.dupe(u8, pkg_name),
                    .diff_type = .removed,
                    .version_a = try self.allocator.dupe(u8, version_a),
                    .version_b = null,
                });
            }
        }

        // Find packages only in B
        var iter_b = packages_b.iterator();
        while (iter_b.next()) |entry| {
            const pkg_name = entry.key_ptr.*;
            const version_b = entry.value_ptr.*;

            if (packages_a.get(pkg_name) == null) {
                try diff.entries.append(self.allocator, .{
                    .package_name = try self.allocator.dupe(u8, pkg_name),
                    .diff_type = .added,
                    .version_a = null,
                    .version_b = try self.allocator.dupe(u8, version_b),
                });
            }
        }

        return diff;
    }

    fn loadBePackages(
        self: *Self,
        packages: *std.StringHashMap([]const u8),
        be_name: []const u8,
        profile_name: []const u8,
    ) !void {
        const lock_path = try std.fmt.allocPrint(
            self.allocator,
            "{s}/be/{s}/{s}/profile.lock.yaml",
            .{ self.axiom_root, be_name, profile_name },
        );
        defer self.allocator.free(lock_path);

        const file = std.fs.cwd().openFile(lock_path, .{}) catch {
            return; // Empty if not found
        };
        defer file.close();

        const content = try file.readToEndAlloc(self.allocator, 1024 * 1024);
        defer self.allocator.free(content);

        // Simple YAML parsing for packages
        var lines = std.mem.splitScalar(u8, content, '\n');
        var in_packages = false;
        var current_pkg: ?[]const u8 = null;

        while (lines.next()) |line| {
            const trimmed = std.mem.trim(u8, line, " \t\r");

            if (std.mem.eql(u8, trimmed, "packages:")) {
                in_packages = true;
                continue;
            }

            if (in_packages) {
                if (std.mem.startsWith(u8, trimmed, "- name:")) {
                    const name_start = std.mem.indexOf(u8, trimmed, ":") orelse continue;
                    const name = std.mem.trim(u8, trimmed[name_start + 1 ..], " \t\"");
                    if (current_pkg) |p| self.allocator.free(p);
                    current_pkg = try self.allocator.dupe(u8, name);
                } else if (std.mem.startsWith(u8, trimmed, "version:") and current_pkg != null) {
                    const ver_start = std.mem.indexOf(u8, trimmed, ":") orelse continue;
                    const version = std.mem.trim(u8, trimmed[ver_start + 1 ..], " \t\"");
                    try packages.put(current_pkg.?, try self.allocator.dupe(u8, version));
                    current_pkg = null;
                }
            }
        }

        if (current_pkg) |p| self.allocator.free(p);
    }
};

/// Bootloader Integration - manages bootloader configuration for BEs
pub const BootloaderIntegration = struct {
    allocator: Allocator,
    zfs_handle: *ZfsHandle,
    bootloader_type: BootloaderType,
    hooks: std.ArrayList(ActivationHook),
    rollback_policy: RollbackPolicy,

    const Self = @This();

    pub fn init(allocator: Allocator, zfs_handle: *ZfsHandle) Self {
        return .{
            .allocator = allocator,
            .zfs_handle = zfs_handle,
            .bootloader_type = .freebsd,
            .hooks = .empty,
            .rollback_policy = RollbackPolicy.empty,
        };
    }

    pub fn deinit(self: *Self) void {
        for (self.hooks.items) |*h| {
            h.deinit(self.allocator);
        }
        self.hooks.deinit(self.allocator);
        self.rollback_policy.deinit(self.allocator);
    }

    pub fn setBootloader(self: *Self, bootloader: BootloaderType) void {
        self.bootloader_type = bootloader;
    }

    /// Add an activation hook
    pub fn addHook(self: *Self, hook: ActivationHook) !void {
        try self.hooks.append(self.allocator, hook);
    }

    /// Configure auto-rollback policy
    pub fn configureAutoRollback(self: *Self, policy: RollbackPolicy) void {
        self.rollback_policy.deinit(self.allocator);
        self.rollback_policy = policy;
    }

    /// Activate a boot environment
    pub fn activateBe(self: *Self, be_name: []const u8, options: ActivateOptions) !void {
        // Run pre-activate hooks
        if (options.run_hooks) {
            try self.runHooks(.pre_activate);
        }

        // Update bootloader configuration based on type
        switch (options.bootloader) {
            .freebsd => try self.activateFreeBSD(be_name, options.next_boot_only),
            .grub => try self.activateGrub(be_name, options.next_boot_only),
            .systemd_boot => try self.activateSystemdBoot(be_name, options.next_boot_only),
        }

        // Run post-activate hooks
        if (options.run_hooks) {
            try self.runHooks(.post_activate);
        }
    }

    fn activateFreeBSD(self: *Self, be_name: []const u8, next_boot_only: bool) !void {
        const config_path = if (next_boot_only)
            "/boot/loader.conf.local"
        else
            "/boot/loader.conf";

        // Read existing config
        var config_content: std.ArrayList(u8) = .empty;
        defer config_content.deinit(self.allocator);

        const file = std.fs.cwd().openFile(config_path, .{}) catch null;
        if (file) |f| {
            defer f.close();
            const existing = try f.readToEndAlloc(self.allocator, 64 * 1024);
            defer self.allocator.free(existing);

            // Filter out existing vfs.root.mountfrom
            var lines = std.mem.splitScalar(u8, existing, '\n');
            while (lines.next()) |line| {
                if (!std.mem.startsWith(u8, line, "vfs.root.mountfrom=")) {
                    try config_content.appendSlice(self.allocator, line);
                    try config_content.append(self.allocator, '\n');
                }
            }
        }

        // Add new boot environment
        const be_line = try std.fmt.allocPrint(
            self.allocator,
            "vfs.root.mountfrom=\"zfs:zroot/ROOT/{s}\"\n",
            .{be_name},
        );
        defer self.allocator.free(be_line);

        try config_content.appendSlice(self.allocator, be_line);

        // Write config
        const out_file = try std.fs.cwd().createFile(config_path, .{});
        defer out_file.close();
        try out_file.writeAll(config_content.items);
    }

    fn activateGrub(self: *Self, be_name: []const u8, next_boot_only: bool) !void {
        _ = next_boot_only;

        // Update GRUB default entry
        const grub_default = try std.fmt.allocPrint(
            self.allocator,
            "GRUB_DEFAULT=\"gnulinux-{s}-advanced\"\n",
            .{be_name},
        );
        defer self.allocator.free(grub_default);

        // Write to /etc/default/grub.d/axiom-be.cfg
        std.fs.cwd().makePath("/etc/default/grub.d") catch {};

        const cfg_file = try std.fs.cwd().createFile("/etc/default/grub.d/axiom-be.cfg", .{});
        defer cfg_file.close();
        try cfg_file.writeAll(grub_default);

        // Note: In real implementation, would run update-grub
    }

    fn activateSystemdBoot(self: *Self, be_name: []const u8, next_boot_only: bool) !void {
        _ = next_boot_only;

        // Create loader entry
        const entry_path = try std.fmt.allocPrint(
            self.allocator,
            "/boot/loader/entries/axiom-{s}.conf",
            .{be_name},
        );
        defer self.allocator.free(entry_path);

        const entry_content = try std.fmt.allocPrint(
            self.allocator,
            \\title Axiom BE: {s}
            \\linux /vmlinuz
            \\initrd /initramfs.img
            \\options root=zfs:zroot/ROOT/{s} rw
            \\
        ,
            .{ be_name, be_name },
        );
        defer self.allocator.free(entry_content);

        const entry_file = try std.fs.cwd().createFile(entry_path, .{});
        defer entry_file.close();
        try entry_file.writeAll(entry_content);
    }

    /// Run health checks
    pub fn runHealthChecks(self: *Self) !HealthStatus {
        var status = HealthStatus.init(self.allocator);
        errdefer status.deinit();

        for (self.rollback_policy.health_checks.items) |check| {
            const start_time = std.time.milliTimestamp();

            var result = HealthCheckResult{
                .name = try self.allocator.dupe(u8, check.name),
                .passed = false,
                .output = null,
                .duration_ms = 0,
            };

            // Execute health check command
            var child = std.process.Child.init(
                &[_][]const u8{ "/bin/sh", "-c", check.command },
                self.allocator,
            );
            child.spawn() catch {
                result.passed = false;
                result.duration_ms = @intCast(std.time.milliTimestamp() - start_time);
                try status.results.append(status.allocator, result);

                if (check.required) {
                    status.required_passed = false;
                }
                status.all_passed = false;
                continue;
            };

            const term = child.wait() catch {
                result.passed = false;
                result.duration_ms = @intCast(std.time.milliTimestamp() - start_time);
                try status.results.append(status.allocator, result);

                if (check.required) {
                    status.required_passed = false;
                }
                status.all_passed = false;
                continue;
            };

            result.passed = term.Exited == 0;
            result.duration_ms = @intCast(std.time.milliTimestamp() - start_time);

            if (!result.passed) {
                status.all_passed = false;
                if (check.required) {
                    status.required_passed = false;
                }
            }

            try status.results.append(status.allocator, result);
        }

        return status;
    }

    /// Run hooks of a specific type
    pub fn runHooks(self: *Self, hook_type: HookType) !void {
        for (self.hooks.items) |hook| {
            if (hook.hook_type == hook_type) {
                try self.executeHook(hook);
            }
        }
    }

    fn executeHook(self: *Self, hook: ActivationHook) !void {
        var child = std.process.Child.init(
            &[_][]const u8{ "/bin/sh", "-c", hook.path },
            self.allocator,
        );

        child.spawn() catch |err| {
            if (hook.required) return err;
            return;
        };

        const term = child.wait() catch |err| {
            if (hook.required) return err;
            return;
        };

        if (term.Exited != 0 and hook.required) {
            return error.HookFailed;
        }
    }

    /// Perform rollback to previous BE
    pub fn rollback(self: *Self, reason: RollbackTrigger, previous_be: []const u8) !void {
        // Run on_rollback hooks
        try self.runHooks(.on_rollback);

        // Activate previous BE
        try self.activateBe(previous_be, .{
            .bootloader = self.bootloader_type,
            .next_boot_only = false,
            .run_hooks = false,
            .skip_health_checks = true,
        });

        // Log rollback reason
        const log_entry = try std.fmt.allocPrint(
            self.allocator,
            "Rollback to {s} triggered by: {s}\n",
            .{ previous_be, reason.toString() },
        );
        defer self.allocator.free(log_entry);

        // Append to rollback log
        const log_file = std.fs.cwd().createFile("/var/log/axiom-rollback.log", .{
            .truncate = false,
        }) catch return;
        defer log_file.close();

        log_file.seekFromEnd(0) catch {};
        log_file.writeAll(log_entry) catch {};
    }
};

/// System upgrade manager with BE support
pub const SystemUpgradeManager = struct {
    allocator: Allocator,
    be_profile_mgr: *BeProfileManager,
    bootloader: *BootloaderIntegration,

    const Self = @This();

    pub fn init(
        allocator: Allocator,
        be_profile_mgr: *BeProfileManager,
        bootloader: *BootloaderIntegration,
    ) Self {
        return .{
            .allocator = allocator,
            .be_profile_mgr = be_profile_mgr,
            .bootloader = bootloader,
        };
    }

    /// Perform system upgrade in a new boot environment
    pub fn upgradeInBe(self: *Self, be_name: []const u8, profile_name: []const u8) !void {
        // Snapshot current profile to pre-upgrade BE
        try self.be_profile_mgr.snapshotProfile(profile_name, "pre-upgrade");

        // Create new BE for upgrade
        // In real implementation, would use be_mgr.create()

        // Snapshot profile to new BE
        try self.be_profile_mgr.snapshotProfile(profile_name, be_name);

        // Activate new BE for next boot
        try self.bootloader.activateBe(be_name, .{
            .next_boot_only = true,
            .run_hooks = true,
        });
    }
};

// Tests
test "HealthStatus.init" {
    var status = HealthStatus.init(std.testing.allocator);
    defer status.deinit();

    try std.testing.expect(status.all_passed);
    try std.testing.expect(status.required_passed);
}

test "ProfileDiff.init" {
    const allocator = std.testing.allocator;
    var diff = try ProfileDiff.init(allocator, "be-a", "be-b");
    defer diff.deinit();

    try std.testing.expectEqual(@as(usize, 0), diff.addedCount());
    try std.testing.expectEqual(@as(usize, 0), diff.removedCount());
}

test "RollbackPolicy.init" {
    const allocator = std.testing.allocator;
    var policy = RollbackPolicy.empty;
    defer policy.deinit(allocator);

    try std.testing.expect(policy.auto_rollback_enabled);
}
