// Package Launcher
//
// Runtime shim for executing packages directly without environment activation.
// Similar to AppImage's launcher stub, this sets up the necessary environment
// variables and executes the package's main executable.

const std = @import("std");
const types = @import("types.zig");
const store = @import("store.zig");
const closure = @import("closure.zig");

const PackageId = types.PackageId;
const Version = types.Version;
const PackageStore = store.PackageStore;
const Closure = closure.Closure;
const ClosureComputer = closure.ClosureComputer;

/// Launch configuration
pub const LaunchConfig = struct {
    /// Package to launch
    package: PackageId,

    /// Executable within the package (default: auto-detect from manifest)
    executable: ?[]const u8 = null,

    /// Arguments to pass to the executable
    args: []const []const u8 = &[_][]const u8{},

    /// Working directory (default: current directory)
    working_dir: ?[]const u8 = null,

    /// Additional environment variables
    env_overrides: std.StringHashMap([]const u8) = undefined,

    /// Isolation mode
    isolation: IsolationMode = .normal,

    /// Include closure packages in library path
    include_closure: bool = true,
};

/// Isolation modes for package execution
pub const IsolationMode = enum {
    /// Normal execution - package libs override system libs
    normal,

    /// Isolated - only package and closure libs available
    isolated,

    /// System - package libs added after system libs
    system_first,
};

/// Execution result
pub const LaunchResult = union(enum) {
    /// Successfully launched and exited
    exited: struct {
        code: u8,
        stdout: ?[]const u8,
        stderr: ?[]const u8,
    },

    /// Process was signaled
    signaled: u32,

    /// Launch failed
    failed: LaunchError,
};

pub const LaunchError = error{
    PackageNotFound,
    ExecutableNotFound,
    PermissionDenied,
    ClosureComputationFailed,
    EnvironmentSetupFailed,
    SpawnFailed,
    OutOfMemory,
};

/// Package launcher
pub const Launcher = struct {
    allocator: std.mem.Allocator,
    pkg_store: *PackageStore,
    closure_computer: ClosureComputer,

    /// Base library paths (system paths)
    system_lib_paths: []const []const u8 = &[_][]const u8{
        "/lib",
        "/usr/lib",
        "/usr/local/lib",
    },

    /// Base binary paths (system paths)
    system_bin_paths: []const []const u8 = &[_][]const u8{
        "/bin",
        "/usr/bin",
        "/usr/local/bin",
    },

    pub fn init(allocator: std.mem.Allocator, pkg_store: *PackageStore) Launcher {
        return .{
            .allocator = allocator,
            .pkg_store = pkg_store,
            .closure_computer = ClosureComputer.init(allocator, pkg_store),
        };
    }

    pub fn deinit(self: *Launcher) void {
        self.closure_computer.deinit();
    }

    /// Launch a package directly
    pub fn launch(self: *Launcher, config: LaunchConfig) LaunchResult {
        return self.launchInternal(config) catch |err| {
            return .{ .failed = err };
        };
    }

    fn launchInternal(self: *Launcher, config: LaunchConfig) LaunchError!LaunchResult {
        // 1. Verify package exists
        const pkg_meta = self.pkg_store.getPackage(config.package) catch {
            return LaunchError.PackageNotFound;
        };
        defer {
            var m = pkg_meta;
            m.manifest.deinit(self.allocator);
            self.allocator.free(m.dataset_path);
            for (m.dependencies) |dep| {
                self.allocator.free(dep.name);
            }
            self.allocator.free(m.dependencies);
        }

        // 2. Determine executable path
        const exec_name = config.executable orelse
            self.detectMainExecutable(pkg_meta.dataset_path) catch {
            return LaunchError.ExecutableNotFound;
        };

        const exec_path = std.fs.path.join(self.allocator, &[_][]const u8{
            pkg_meta.dataset_path,
            "root",
            "bin",
            exec_name,
        }) catch return LaunchError.OutOfMemory;
        defer self.allocator.free(exec_path);

        // Verify executable exists
        std.fs.cwd().access(exec_path, .{}) catch {
            return LaunchError.ExecutableNotFound;
        };

        // 3. Compute closure if needed
        var pkg_closure: ?Closure = null;
        defer if (pkg_closure) |*c| c.deinit();

        if (config.include_closure) {
            pkg_closure = self.closure_computer.computeForPackage(config.package) catch {
                return LaunchError.ClosureComputationFailed;
            };
        }

        // 4. Build environment
        var env_map = std.process.EnvMap.init(self.allocator);
        defer env_map.deinit();

        // Copy current environment
        const current_env = std.process.getEnvMap(self.allocator) catch
            return LaunchError.EnvironmentSetupFailed;
        defer {
            var iter = current_env.iterator();
            while (iter.next()) |_| {}
        }

        // Build library path
        const lib_path = self.buildLibraryPath(
            pkg_meta.dataset_path,
            if (pkg_closure) |*c| c else null,
            config.isolation,
        ) catch return LaunchError.OutOfMemory;
        defer self.allocator.free(lib_path);

        env_map.put("LD_LIBRARY_PATH", lib_path) catch
            return LaunchError.EnvironmentSetupFailed;

        // Build PATH
        const bin_path = self.buildBinaryPath(
            pkg_meta.dataset_path,
            if (pkg_closure) |*c| c else null,
            config.isolation,
        ) catch return LaunchError.OutOfMemory;
        defer self.allocator.free(bin_path);

        env_map.put("PATH", bin_path) catch
            return LaunchError.EnvironmentSetupFailed;

        // Set package-specific variables
        env_map.put("AXIOM_PACKAGE", config.package.name) catch {};
        env_map.put("AXIOM_PACKAGE_ROOT", pkg_meta.dataset_path) catch {};

        // 5. Spawn process
        var argv = std.ArrayList([]const u8).init(self.allocator);
        defer argv.deinit();

        argv.append(exec_path) catch return LaunchError.OutOfMemory;
        for (config.args) |arg| {
            argv.append(arg) catch return LaunchError.OutOfMemory;
        }

        var child = std.process.Child.init(argv.items, self.allocator);
        child.cwd = config.working_dir;

        // Set environment
        child.env_map = &env_map;

        child.spawn() catch {
            return LaunchError.SpawnFailed;
        };

        const result = child.wait() catch {
            return LaunchError.SpawnFailed;
        };

        return switch (result.term) {
            .Exited => |code| .{
                .exited = .{
                    .code = code,
                    .stdout = null,
                    .stderr = null,
                },
            },
            .Signal => |sig| .{ .signaled = sig },
            else => .{
                .exited = .{
                    .code = 255,
                    .stdout = null,
                    .stderr = null,
                },
            },
        };
    }

    fn detectMainExecutable(self: *Launcher, dataset_path: []const u8) ![]const u8 {
        const bin_path = try std.fs.path.join(self.allocator, &[_][]const u8{
            dataset_path,
            "root",
            "bin",
        });
        defer self.allocator.free(bin_path);

        var dir = std.fs.cwd().openDir(bin_path, .{ .iterate = true }) catch {
            return error.ExecutableNotFound;
        };
        defer dir.close();

        // Return first executable found
        var iter = dir.iterate();
        while (iter.next() catch null) |entry| {
            if (entry.kind == .file) {
                return try self.allocator.dupe(u8, entry.name);
            }
        }

        return error.ExecutableNotFound;
    }

    fn buildLibraryPath(
        self: *Launcher,
        pkg_root: []const u8,
        pkg_closure: ?*const Closure,
        isolation: IsolationMode,
    ) ![]const u8 {
        var paths = std.ArrayList([]const u8).init(self.allocator);
        defer paths.deinit();

        // Add package's own lib directory first
        const pkg_lib = try std.fs.path.join(self.allocator, &[_][]const u8{
            pkg_root,
            "root",
            "lib",
        });
        try paths.append(pkg_lib);

        // Add closure package libraries
        if (pkg_closure) |c| {
            for (c.topo_order.items) |dep_id| {
                const dep_meta = self.pkg_store.getPackage(dep_id) catch continue;
                const dep_lib = try std.fs.path.join(self.allocator, &[_][]const u8{
                    dep_meta.dataset_path,
                    "root",
                    "lib",
                });
                try paths.append(dep_lib);
                self.allocator.free(dep_meta.dataset_path);
            }
        }

        // Add system paths based on isolation mode
        switch (isolation) {
            .normal, .system_first => {
                for (self.system_lib_paths) |sys_path| {
                    try paths.append(sys_path);
                }
            },
            .isolated => {
                // Don't add system paths in isolated mode
            },
        }

        // Join with colons
        return try std.mem.join(self.allocator, ":", paths.items);
    }

    fn buildBinaryPath(
        self: *Launcher,
        pkg_root: []const u8,
        pkg_closure: ?*const Closure,
        isolation: IsolationMode,
    ) ![]const u8 {
        var paths = std.ArrayList([]const u8).init(self.allocator);
        defer paths.deinit();

        // Add package's own bin directory first
        const pkg_bin = try std.fs.path.join(self.allocator, &[_][]const u8{
            pkg_root,
            "root",
            "bin",
        });
        try paths.append(pkg_bin);

        // Add closure package binaries
        if (pkg_closure) |c| {
            for (c.topo_order.items) |dep_id| {
                const dep_meta = self.pkg_store.getPackage(dep_id) catch continue;
                const dep_bin = try std.fs.path.join(self.allocator, &[_][]const u8{
                    dep_meta.dataset_path,
                    "root",
                    "bin",
                });
                try paths.append(dep_bin);
                self.allocator.free(dep_meta.dataset_path);
            }
        }

        // Add system paths based on isolation mode
        switch (isolation) {
            .normal, .system_first => {
                for (self.system_bin_paths) |sys_path| {
                    try paths.append(sys_path);
                }
            },
            .isolated => {
                // Don't add system paths in isolated mode
            },
        }

        // Join with colons
        return try std.mem.join(self.allocator, ":", paths.items);
    }

    /// Generate a launcher script for a package
    pub fn generateLauncherScript(
        self: *Launcher,
        pkg_id: PackageId,
        output_path: []const u8,
    ) !void {
        const pkg_meta = try self.pkg_store.getPackage(pkg_id);
        defer {
            var m = pkg_meta;
            m.manifest.deinit(self.allocator);
            self.allocator.free(m.dataset_path);
            for (m.dependencies) |dep| {
                self.allocator.free(dep.name);
            }
            self.allocator.free(m.dependencies);
        }

        // Compute closure
        var pkg_closure = try self.closure_computer.computeForPackage(pkg_id);
        defer pkg_closure.deinit();

        // Build library path
        const lib_path = try self.buildLibraryPath(
            pkg_meta.dataset_path,
            &pkg_closure,
            .normal,
        );
        defer self.allocator.free(lib_path);

        // Build binary path
        const bin_path = try self.buildBinaryPath(
            pkg_meta.dataset_path,
            &pkg_closure,
            .normal,
        );
        defer self.allocator.free(bin_path);

        // Detect main executable
        const exec_name = try self.detectMainExecutable(pkg_meta.dataset_path);
        defer self.allocator.free(exec_name);

        const exec_path = try std.fs.path.join(self.allocator, &[_][]const u8{
            pkg_meta.dataset_path,
            "root",
            "bin",
            exec_name,
        });
        defer self.allocator.free(exec_path);

        // Generate script
        const script = try std.fmt.allocPrint(self.allocator,
            \\#!/bin/sh
            \\# Axiom launcher script for {s}@{d}.{d}.{d}
            \\# Generated automatically - do not edit
            \\
            \\export LD_LIBRARY_PATH="{s}"
            \\export PATH="{s}"
            \\export AXIOM_PACKAGE="{s}"
            \\export AXIOM_PACKAGE_ROOT="{s}"
            \\
            \\exec "{s}" "$@"
            \\
        , .{
            pkg_id.name,
            pkg_id.version.major,
            pkg_id.version.minor,
            pkg_id.version.patch,
            lib_path,
            bin_path,
            pkg_id.name,
            pkg_meta.dataset_path,
            exec_path,
        });
        defer self.allocator.free(script);

        // Write script
        const file = try std.fs.cwd().createFile(output_path, .{});
        defer file.close();

        try file.writeAll(script);

        // Make executable
        try std.fs.cwd().chmod(output_path, 0o755);
    }
};

/// Parse a package reference string like "hello@1.0.0" or "hello"
pub fn parsePackageRef(allocator: std.mem.Allocator, ref: []const u8) !struct {
    name: []const u8,
    version: ?Version,
} {
    // Find @ separator
    if (std.mem.indexOf(u8, ref, "@")) |at_pos| {
        const name = ref[0..at_pos];
        const version_str = ref[at_pos + 1 ..];

        // Parse version
        const version = try parseVersion(version_str);

        return .{
            .name = try allocator.dupe(u8, name),
            .version = version,
        };
    } else {
        return .{
            .name = try allocator.dupe(u8, ref),
            .version = null,
        };
    }
}

fn parseVersion(str: []const u8) !Version {
    var parts: [3]u32 = .{ 0, 0, 0 };
    var part_idx: usize = 0;

    var iter = std.mem.splitScalar(u8, str, '.');
    while (iter.next()) |part| {
        if (part_idx >= 3) break;
        parts[part_idx] = std.fmt.parseInt(u32, part, 10) catch 0;
        part_idx += 1;
    }

    return .{
        .major = parts[0],
        .minor = parts[1],
        .patch = parts[2],
    };
}

// Tests
test "parse package reference" {
    const allocator = std.testing.allocator;

    {
        const result = try parsePackageRef(allocator, "hello@1.2.3");
        defer allocator.free(result.name);

        try std.testing.expectEqualStrings("hello", result.name);
        try std.testing.expect(result.version != null);
        try std.testing.expectEqual(@as(u32, 1), result.version.?.major);
        try std.testing.expectEqual(@as(u32, 2), result.version.?.minor);
        try std.testing.expectEqual(@as(u32, 3), result.version.?.patch);
    }

    {
        const result = try parsePackageRef(allocator, "world");
        defer allocator.free(result.name);

        try std.testing.expectEqualStrings("world", result.name);
        try std.testing.expect(result.version == null);
    }
}
