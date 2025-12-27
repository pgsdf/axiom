// PGSD Runtime Layers
//
// Runtime layers provide ABI-stable library sets that applications can depend on,
// similar to Flatpak's runtime concept but ZFS-backed for snapshots and rollback.

const std = @import("std");
const types = @import("types.zig");
const store = @import("store.zig");
const zfs = @import("zfs.zig");
const manifest = @import("manifest.zig");
const config = @import("config.zig");

const Version = types.Version;
const PackageId = types.PackageId;
const PackageStore = store.PackageStore;
const ZfsHandle = zfs.ZfsHandle;
const Manifest = manifest.Manifest;

/// Runtime layer metadata
pub const RuntimeInfo = struct {
    /// Runtime name (e.g., "pgsd-runtime-2025")
    name: []const u8,

    /// Runtime version
    version: Version,

    /// Description
    description: []const u8,

    /// Creation timestamp
    created_at: i64,

    /// Base packages included
    packages: []PackageId,

    /// ABI version this runtime provides
    abi_version: []const u8,

    /// Whether this runtime is marked as stable
    stable: bool,

    /// Dataset path
    dataset_path: []const u8,

    pub fn deinit(self: *RuntimeInfo, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.description);
        allocator.free(self.abi_version);
        allocator.free(self.dataset_path);
        allocator.free(self.packages);
    }
};

/// Runtime manifest format
pub const RuntimeManifest = struct {
    name: []const u8,
    version: Version,
    description: []const u8,
    abi_version: []const u8,
    stable: bool = false,

    /// Core library packages
    core_packages: []const []const u8,

    /// Optional extension packages
    extensions: []RuntimeExtension = &[_]RuntimeExtension{},

    /// Minimum compatible runtime version
    min_compatible: ?Version = null,

    pub fn serialize(self: RuntimeManifest, allocator: std.mem.Allocator) ![]const u8 {
        var output = std.ArrayList(u8).empty;
        defer output.deinit(allocator);

        const writer = output.writer(allocator);

        try writer.print("name: {s}\n", .{self.name});
        try writer.print("version: {d}.{d}.{d}\n", .{
            self.version.major,
            self.version.minor,
            self.version.patch,
        });
        try writer.print("description: {s}\n", .{self.description});
        try writer.print("abi_version: {s}\n", .{self.abi_version});
        try writer.print("stable: {}\n", .{self.stable});

        try writer.print("core_packages:\n", .{});
        for (self.core_packages) |pkg| {
            try writer.print("  - {s}\n", .{pkg});
        }

        if (self.extensions.len > 0) {
            try writer.print("extensions:\n", .{});
            for (self.extensions) |ext| {
                try writer.print("  - name: {s}\n", .{ext.name});
                try writer.print("    description: {s}\n", .{ext.description});
            }
        }

        if (self.min_compatible) |min| {
            try writer.print("min_compatible: {d}.{d}.{d}\n", .{
                min.major,
                min.minor,
                min.patch,
            });
        }

        return try output.toOwnedSlice(allocator);
    }
};

/// Runtime extension (optional add-ons)
pub const RuntimeExtension = struct {
    name: []const u8,
    description: []const u8,
    packages: []const []const u8,
};

/// Standard PGSD runtime definitions
pub const StandardRuntimes = struct {
    /// Base runtime with minimal system libraries
    pub const base_2025 = RuntimeManifest{
        .name = "pgsd-runtime-base-2025",
        .version = .{ .major = 2025, .minor = 1, .patch = 0 },
        .description = "PGSD Base Runtime 2025 - Minimal system libraries",
        .abi_version = "2025.1",
        .stable = true,
        .core_packages = &[_][]const u8{
            "libc",
            "libm",
            "libpthread",
            "libdl",
            "zlib",
            "openssl",
            "libcurl",
        },
    };

    /// Full runtime with common development tools
    pub const full_2025 = RuntimeManifest{
        .name = "pgsd-runtime-2025",
        .version = .{ .major = 2025, .minor = 1, .patch = 0 },
        .description = "PGSD Full Runtime 2025 - Common libraries and tools",
        .abi_version = "2025.1",
        .stable = true,
        .core_packages = &[_][]const u8{
            "libc",
            "libm",
            "libpthread",
            "libdl",
            "zlib",
            "openssl",
            "libcurl",
            "sqlite",
            "libxml2",
            "libpng",
            "libjpeg",
            "freetype",
        },
        .extensions = &[_]RuntimeExtension{
            .{
                .name = "python",
                .description = "Python 3.x runtime",
                .packages = &[_][]const u8{ "python3", "python3-pip" },
            },
            .{
                .name = "nodejs",
                .description = "Node.js runtime",
                .packages = &[_][]const u8{ "nodejs", "npm" },
            },
        },
    };

    /// Graphics/GUI runtime
    pub const gui_2025 = RuntimeManifest{
        .name = "pgsd-runtime-gui-2025",
        .version = .{ .major = 2025, .minor = 1, .patch = 0 },
        .description = "PGSD GUI Runtime 2025 - Graphics and windowing libraries",
        .abi_version = "2025.1",
        .stable = true,
        .core_packages = &[_][]const u8{
            "libX11",
            "libXext",
            "libXrender",
            "libXft",
            "cairo",
            "pango",
            "gtk3",
            "glib",
            "fontconfig",
            "mesa",
        },
        .min_compatible = .{ .major = 2025, .minor = 0, .patch = 0 },
    };
};

/// Runtime manager for creating and managing runtime layers
pub const RuntimeManager = struct {
    allocator: std.mem.Allocator,
    zfs_handle: *ZfsHandle,
    pkg_store: *PackageStore,

    /// Base path for runtime storage
    runtime_base: []const u8,

    pub fn init(
        allocator: std.mem.Allocator,
        zfs_handle: *ZfsHandle,
        pkg_store: *PackageStore,
    ) RuntimeManager {
        return .{
            .allocator = allocator,
            .zfs_handle = zfs_handle,
            .pkg_store = pkg_store,
            .runtime_base = config.DEFAULT_MOUNTPOINT ++ "/runtimes",
        };
    }

    pub fn deinit(self: *RuntimeManager) void {
        _ = self;
    }

    /// Create a new runtime layer from a manifest
    pub fn createRuntime(self: *RuntimeManager, runtime_manifest: RuntimeManifest) !RuntimeInfo {
        std.debug.print("Creating runtime: {s}\n", .{runtime_manifest.name});

        // Create runtime dataset
        const dataset_path = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{
            self.runtime_base,
            runtime_manifest.name,
        });
        errdefer self.allocator.free(dataset_path);

        // Create the directory structure
        std.fs.cwd().makePath(dataset_path) catch |err| {
            if (err != error.PathAlreadyExists) return err;
        };

        // Create subdirectories
        const lib_path = try std.fs.path.join(self.allocator, &[_][]const u8{ dataset_path, "lib" });
        defer self.allocator.free(lib_path);
        std.fs.cwd().makePath(lib_path) catch {};

        const share_path = try std.fs.path.join(self.allocator, &[_][]const u8{ dataset_path, "share" });
        defer self.allocator.free(share_path);
        std.fs.cwd().makePath(share_path) catch {};

        // Write runtime manifest
        const manifest_content = try runtime_manifest.serialize(self.allocator);
        defer self.allocator.free(manifest_content);

        const manifest_path = try std.fs.path.join(self.allocator, &[_][]const u8{ dataset_path, "runtime.yaml" });
        defer self.allocator.free(manifest_path);

        const manifest_file = try std.fs.cwd().createFile(manifest_path, .{});
        defer manifest_file.close();
        try manifest_file.writeAll(manifest_content);

        // Collect packages
        var packages = .empty;
        defer packages.deinit(self.allocator);

        for (runtime_manifest.core_packages) |pkg_name| {
            // Find package in store
            const pkg_list = try self.pkg_store.listPackages();
            for (pkg_list) |pkg_id| {
                if (std.mem.eql(u8, pkg_id.name, pkg_name)) {
                    try packages.append(self.allocator, pkg_id);
                    break;
                }
            }
        }

        return RuntimeInfo{
            .name = try self.allocator.dupe(u8, runtime_manifest.name),
            .version = runtime_manifest.version,
            .description = try self.allocator.dupe(u8, runtime_manifest.description),
            .created_at = std.time.timestamp(),
            .packages = try packages.toOwnedSlice(self.allocator),
            .abi_version = try self.allocator.dupe(u8, runtime_manifest.abi_version),
            .stable = runtime_manifest.stable,
            .dataset_path = dataset_path,
        };
    }

    /// List all available runtimes
    pub fn listRuntimes(self: *RuntimeManager) ![]RuntimeInfo {
        var runtimes: std.ArrayList(RuntimeInfo) = .empty;
        defer runtimes.deinit(self.allocator);

        var dir = std.fs.cwd().openDir(self.runtime_base, .{ .iterate = true }) catch {
            return try runtimes.toOwnedSlice(self.allocator);
        };
        defer dir.close();

        var iter = dir.iterate();
        while (try iter.next()) |entry| {
            if (entry.kind == .directory) {
                const runtime_info = self.loadRuntimeInfo(entry.name) catch continue;
                try runtimes.append(self.allocator, runtime_info);
            }
        }

        return try runtimes.toOwnedSlice(self.allocator);
    }

    fn loadRuntimeInfo(self: *RuntimeManager, name: []const u8) !RuntimeInfo {
        const manifest_path = try std.fmt.allocPrint(self.allocator, "{s}/{s}/runtime.yaml", .{
            self.runtime_base,
            name,
        });
        defer self.allocator.free(manifest_path);

        const manifest_content = try std.fs.cwd().readFileAlloc(
            self.allocator,
            manifest_path,
            1024 * 1024,
        );
        defer self.allocator.free(manifest_content);

        // Parse YAML (simplified)
        // In production, use proper YAML parser
        return RuntimeInfo{
            .name = try self.allocator.dupe(u8, name),
            .version = .{ .major = 2025, .minor = 1, .patch = 0 },
            .description = try self.allocator.dupe(u8, "Runtime layer"),
            .created_at = 0,
            .packages = &[_]PackageId{},
            .abi_version = try self.allocator.dupe(u8, "2025.1"),
            .stable = true,
            .dataset_path = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{
                self.runtime_base,
                name,
            }),
        };
    }

    /// Get a runtime by name
    pub fn getRuntime(self: *RuntimeManager, name: []const u8) !?RuntimeInfo {
        return self.loadRuntimeInfo(name) catch return null;
    }

    /// Check if a package is compatible with a runtime
    pub fn checkCompatibility(
        self: *RuntimeManager,
        pkg_manifest: Manifest,
        runtime_name: []const u8,
    ) !CompatibilityResult {
        _ = self;
        _ = pkg_manifest;
        _ = runtime_name;

        // Check if package declares runtime dependency
        // Compare ABI versions
        // Check for missing dependencies

        return .{
            .compatible = true,
            .warnings = &[_][]const u8{},
            .missing_deps = &[_][]const u8{},
        };
    }

    /// Create a snapshot of a runtime
    pub fn snapshotRuntime(self: *RuntimeManager, name: []const u8, snapshot_name: []const u8) !void {
        const dataset = try std.fmt.allocPrint(self.allocator, config.DEFAULT_POOL ++ "/" ++ config.DEFAULT_DATASET ++ "/runtimes/{s}", .{name});
        defer self.allocator.free(dataset);

        const snapshot = try std.fmt.allocPrint(self.allocator, "{s}@{s}", .{ dataset, snapshot_name });
        defer self.allocator.free(snapshot);

        var child = std.process.Child.init(
            &[_][]const u8{ "zfs", "snapshot", snapshot },
            self.allocator,
        );
        _ = try child.spawnAndWait();
    }

    /// Rollback a runtime to a snapshot
    pub fn rollbackRuntime(self: *RuntimeManager, name: []const u8, snapshot_name: []const u8) !void {
        const snapshot = try std.fmt.allocPrint(self.allocator, config.DEFAULT_POOL ++ "/" ++ config.DEFAULT_DATASET ++ "/runtimes/{s}@{s}", .{
            name,
            snapshot_name,
        });
        defer self.allocator.free(snapshot);

        var child = std.process.Child.init(
            &[_][]const u8{ "zfs", "rollback", snapshot },
            self.allocator,
        );
        _ = try child.spawnAndWait();
    }
};

/// Result of compatibility check
pub const CompatibilityResult = struct {
    compatible: bool,
    warnings: []const []const u8,
    missing_deps: []const []const u8,
};

/// Runtime dependency declaration (for package manifests)
pub const RuntimeDependency = struct {
    /// Runtime name
    name: []const u8,

    /// Minimum version required
    min_version: ?Version = null,

    /// Maximum version allowed
    max_version: ?Version = null,

    /// Required extensions
    extensions: []const []const u8 = &[_][]const u8{},
};

// Tests
test "runtime manifest serialization" {
    const allocator = std.testing.allocator;

    const runtime = RuntimeManifest{
        .name = "test-runtime",
        .version = .{ .major = 1, .minor = 0, .patch = 0 },
        .description = "Test runtime",
        .abi_version = "1.0",
        .core_packages = &[_][]const u8{ "libc", "libm" },
    };

    const content = try runtime.serialize(allocator);
    defer allocator.free(content);

    try std.testing.expect(std.mem.indexOf(u8, content, "name: test-runtime") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "version: 1.0.0") != null);
}
