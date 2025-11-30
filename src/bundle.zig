// Bundle Creation and Management
//
// Creates self-contained application bundles from packages and their closures.
// Supports multiple output formats including .pgsdimg (portable) and ZFS streams.

const std = @import("std");
const types = @import("types.zig");
const store = @import("store.zig");
const closure = @import("closure.zig");
const manifest = @import("manifest.zig");
const launcher = @import("launcher.zig");

const PackageId = types.PackageId;
const Version = types.Version;
const PackageStore = store.PackageStore;
const Closure = closure.Closure;
const ClosureComputer = closure.ClosureComputer;
const Manifest = manifest.Manifest;
const Launcher = launcher.Launcher;

/// Bundle output format
pub const BundleFormat = enum {
    /// PGSD portable image (self-extracting with launcher)
    pgsdimg,

    /// ZFS send stream (for efficient transfer)
    zfs_stream,

    /// Compressed tarball
    tarball,

    /// Directory (uncompressed, for testing)
    directory,
};

/// Bundle compression type
pub const CompressionType = enum {
    none,
    gzip,
    xz,
    zstd,
    lz4,
};

/// Bundle configuration
pub const BundleConfig = struct {
    /// Output format
    format: BundleFormat = .pgsdimg,

    /// Compression algorithm
    compression: CompressionType = .zstd,

    /// Include all closure packages
    include_closure: bool = true,

    /// Sign the bundle
    sign: bool = false,

    /// Signing key path
    signing_key: ?[]const u8 = null,

    /// Include provenance information
    include_provenance: bool = true,

    /// Bundle metadata
    metadata: BundleMetadata = .{},

    /// Executable to use as entry point (auto-detect if null)
    entry_point: ?[]const u8 = null,
};

/// Additional bundle metadata
pub const BundleMetadata = struct {
    /// Bundle name (defaults to package name)
    name: ?[]const u8 = null,

    /// Bundle description
    description: ?[]const u8 = null,

    /// Bundle icon path
    icon: ?[]const u8 = null,

    /// Desktop categories
    categories: []const []const u8 = &[_][]const u8{},

    /// MIME types handled
    mime_types: []const []const u8 = &[_][]const u8{},
};

/// Bundle manifest (bundled with the image)
pub const BundleManifest = struct {
    /// Format version
    format_version: u32 = 1,

    /// Bundle name
    name: []const u8,

    /// Package version
    version: Version,

    /// Creation timestamp
    created_at: i64,

    /// Entry point executable
    entry_point: []const u8,

    /// Included packages
    packages: []PackageId,

    /// Total uncompressed size
    uncompressed_size: u64,

    /// Compression type used
    compression: CompressionType,

    /// Signature (if signed)
    signature: ?[]const u8 = null,

    /// Provenance information
    provenance: ?Provenance = null,

    pub fn serialize(self: BundleManifest, allocator: std.mem.Allocator) ![]const u8 {
        var output = std.ArrayList(u8).init(allocator);
        defer output.deinit();

        const writer = output.writer();

        try writer.print("format_version: {d}\n", .{self.format_version});
        try writer.print("name: {s}\n", .{self.name});
        try writer.print("version: {d}.{d}.{d}\n", .{
            self.version.major,
            self.version.minor,
            self.version.patch,
        });
        try writer.print("created_at: {d}\n", .{self.created_at});
        try writer.print("entry_point: {s}\n", .{self.entry_point});
        try writer.print("uncompressed_size: {d}\n", .{self.uncompressed_size});
        try writer.print("compression: {s}\n", .{@tagName(self.compression)});

        try writer.print("packages:\n", .{});
        for (self.packages) |pkg| {
            try writer.print("  - {s}@{d}.{d}.{d}\n", .{
                pkg.name,
                pkg.version.major,
                pkg.version.minor,
                pkg.version.patch,
            });
        }

        if (self.signature) |sig| {
            try writer.print("signature: {s}\n", .{sig});
        }

        return try output.toOwnedSlice();
    }
};

/// Build provenance for bundles
pub const Provenance = struct {
    build_time: i64,
    builder: []const u8,
    host_os: []const u8,
    axiom_version: []const u8,
};

/// Bundle builder
pub const BundleBuilder = struct {
    allocator: std.mem.Allocator,
    pkg_store: *PackageStore,
    closure_computer: ClosureComputer,
    launcher_gen: Launcher,

    pub fn init(allocator: std.mem.Allocator, pkg_store: *PackageStore) BundleBuilder {
        return .{
            .allocator = allocator,
            .pkg_store = pkg_store,
            .closure_computer = ClosureComputer.init(allocator, pkg_store),
            .launcher_gen = Launcher.init(allocator, pkg_store),
        };
    }

    pub fn deinit(self: *BundleBuilder) void {
        self.closure_computer.deinit();
        self.launcher_gen.deinit();
    }

    /// Create a bundle from a package
    pub fn createBundle(
        self: *BundleBuilder,
        pkg_id: PackageId,
        output_path: []const u8,
        config: BundleConfig,
    ) !BundleResult {
        return switch (config.format) {
            .pgsdimg => try self.createPgsdImg(pkg_id, output_path, config),
            .zfs_stream => try self.createZfsStream(pkg_id, output_path, config),
            .tarball => try self.createTarball(pkg_id, output_path, config),
            .directory => try self.createDirectory(pkg_id, output_path, config),
        };
    }

    fn createPgsdImg(
        self: *BundleBuilder,
        pkg_id: PackageId,
        output_path: []const u8,
        config: BundleConfig,
    ) !BundleResult {
        // 1. Get package metadata
        var pkg_meta = try self.pkg_store.getPackage(pkg_id);
        defer {
            pkg_meta.manifest.deinit(self.allocator);
            self.allocator.free(pkg_meta.dataset_path);
            for (pkg_meta.dependencies) |dep| {
                self.allocator.free(dep.name);
            }
            self.allocator.free(pkg_meta.dependencies);
        }

        // 2. Compute closure
        var pkg_closure: ?Closure = null;
        defer if (pkg_closure) |*c| c.deinit();

        var included_packages = std.ArrayList(PackageId).init(self.allocator);
        defer included_packages.deinit();

        try included_packages.append(pkg_id);

        if (config.include_closure) {
            pkg_closure = try self.closure_computer.computeForPackage(pkg_id);
            for (pkg_closure.?.topo_order.items) |dep_id| {
                try included_packages.append(dep_id);
            }
        }

        // 3. Create temporary staging directory
        const staging_dir = try self.createStagingDir();
        defer self.cleanupStagingDir(staging_dir);

        // 4. Copy all package contents to staging
        var total_size: u64 = 0;
        for (included_packages.items) |incl_pkg| {
            const size = try self.stagePackage(staging_dir, incl_pkg);
            total_size += size;
        }

        // 5. Detect or use specified entry point
        const entry_point = config.entry_point orelse
            try self.launcher_gen.detectMainExecutable(pkg_meta.dataset_path);

        // 6. Generate launcher script
        const launcher_path = try std.fs.path.join(self.allocator, &[_][]const u8{
            staging_dir,
            "AppRun",
        });
        defer self.allocator.free(launcher_path);

        try self.generateAppRunScript(launcher_path, entry_point, included_packages.items);

        // 7. Create bundle manifest
        const bundle_manifest = BundleManifest{
            .name = config.metadata.name orelse pkg_id.name,
            .version = pkg_id.version,
            .created_at = std.time.timestamp(),
            .entry_point = entry_point,
            .packages = included_packages.items,
            .uncompressed_size = total_size,
            .compression = config.compression,
            .provenance = if (config.include_provenance) Provenance{
                .build_time = std.time.timestamp(),
                .builder = "axiom",
                .host_os = "FreeBSD",
                .axiom_version = "1.0.0",
            } else null,
        };

        // Write manifest
        const manifest_content = try bundle_manifest.serialize(self.allocator);
        defer self.allocator.free(manifest_content);

        const manifest_path = try std.fs.path.join(self.allocator, &[_][]const u8{
            staging_dir,
            "MANIFEST.yaml",
        });
        defer self.allocator.free(manifest_path);

        const manifest_file = try std.fs.cwd().createFile(manifest_path, .{});
        defer manifest_file.close();
        try manifest_file.writeAll(manifest_content);

        // 8. Create the final .pgsdimg file
        try self.createCompressedImage(staging_dir, output_path, config.compression);

        return .{
            .success = .{
                .output_path = try self.allocator.dupe(u8, output_path),
                .format = config.format,
                .size = try self.getFileSize(output_path),
                .packages_included = included_packages.items.len,
                .signed = config.sign,
            },
        };
    }

    fn createZfsStream(
        self: *BundleBuilder,
        pkg_id: PackageId,
        output_path: []const u8,
        config: BundleConfig,
    ) !BundleResult {
        // Get package dataset path
        var pkg_meta = try self.pkg_store.getPackage(pkg_id);
        defer {
            pkg_meta.manifest.deinit(self.allocator);
            self.allocator.free(pkg_meta.dataset_path);
            for (pkg_meta.dependencies) |dep| {
                self.allocator.free(dep.name);
            }
            self.allocator.free(pkg_meta.dependencies);
        }

        // Create ZFS send stream
        const dataset = try std.fmt.allocPrint(self.allocator, "{s}@export", .{
            pkg_meta.dataset_path,
        });
        defer self.allocator.free(dataset);

        // Create snapshot first
        var snapshot_child = std.process.Child.init(
            &[_][]const u8{ "zfs", "snapshot", dataset },
            self.allocator,
        );
        _ = try snapshot_child.spawnAndWait();

        // Run zfs send
        const output_file = try std.fs.cwd().createFile(output_path, .{});
        defer output_file.close();

        var send_args = std.ArrayList([]const u8).init(self.allocator);
        defer send_args.deinit();

        try send_args.append("zfs");
        try send_args.append("send");

        // Add compression flag based on config
        if (config.compression != .none) {
            try send_args.append("-c");
        }

        try send_args.append(dataset);

        var send_child = std.process.Child.init(send_args.items, self.allocator);
        send_child.stdout_behavior = .{ .pipe = output_file.handle };
        _ = try send_child.spawnAndWait();

        return .{
            .success = .{
                .output_path = try self.allocator.dupe(u8, output_path),
                .format = config.format,
                .size = try self.getFileSize(output_path),
                .packages_included = 1,
                .signed = config.sign,
            },
        };
    }

    fn createTarball(
        self: *BundleBuilder,
        pkg_id: PackageId,
        output_path: []const u8,
        config: BundleConfig,
    ) !BundleResult {
        // Similar to pgsdimg but outputs tar archive
        var pkg_meta = try self.pkg_store.getPackage(pkg_id);
        defer {
            pkg_meta.manifest.deinit(self.allocator);
            self.allocator.free(pkg_meta.dataset_path);
            for (pkg_meta.dependencies) |dep| {
                self.allocator.free(dep.name);
            }
            self.allocator.free(pkg_meta.dependencies);
        }

        // Compute closure
        var pkg_closure: ?Closure = null;
        defer if (pkg_closure) |*c| c.deinit();

        var included_packages = std.ArrayList(PackageId).init(self.allocator);
        defer included_packages.deinit();

        try included_packages.append(pkg_id);

        if (config.include_closure) {
            pkg_closure = try self.closure_computer.computeForPackage(pkg_id);
            for (pkg_closure.?.topo_order.items) |dep_id| {
                try included_packages.append(dep_id);
            }
        }

        // Create staging directory
        const staging_dir = try self.createStagingDir();
        defer self.cleanupStagingDir(staging_dir);

        // Stage packages
        for (included_packages.items) |incl_pkg| {
            _ = try self.stagePackage(staging_dir, incl_pkg);
        }

        // Create tarball with compression
        const tar_cmd = switch (config.compression) {
            .none => "tar",
            .gzip => "tar",
            .xz => "tar",
            .zstd => "tar",
            .lz4 => "tar",
        };

        const compress_flag = switch (config.compression) {
            .none => "",
            .gzip => "-z",
            .xz => "-J",
            .zstd => "--zstd",
            .lz4 => "--lz4",
        };

        var tar_args = std.ArrayList([]const u8).init(self.allocator);
        defer tar_args.deinit();

        try tar_args.append(tar_cmd);
        try tar_args.append("-cf");
        try tar_args.append(output_path);
        if (compress_flag.len > 0) {
            try tar_args.append(compress_flag);
        }
        try tar_args.append("-C");
        try tar_args.append(staging_dir);
        try tar_args.append(".");

        var tar_child = std.process.Child.init(tar_args.items, self.allocator);
        _ = try tar_child.spawnAndWait();

        return .{
            .success = .{
                .output_path = try self.allocator.dupe(u8, output_path),
                .format = config.format,
                .size = try self.getFileSize(output_path),
                .packages_included = included_packages.items.len,
                .signed = config.sign,
            },
        };
    }

    fn createDirectory(
        self: *BundleBuilder,
        pkg_id: PackageId,
        output_path: []const u8,
        config: BundleConfig,
    ) !BundleResult {
        // Create output directory
        std.fs.cwd().makeDir(output_path) catch |err| {
            if (err != error.PathAlreadyExists) return err;
        };

        // Compute closure
        var pkg_closure: ?Closure = null;
        defer if (pkg_closure) |*c| c.deinit();

        var included_packages = std.ArrayList(PackageId).init(self.allocator);
        defer included_packages.deinit();

        try included_packages.append(pkg_id);

        if (config.include_closure) {
            pkg_closure = try self.closure_computer.computeForPackage(pkg_id);
            for (pkg_closure.?.topo_order.items) |dep_id| {
                try included_packages.append(dep_id);
            }
        }

        // Stage packages directly to output
        var total_size: u64 = 0;
        for (included_packages.items) |incl_pkg| {
            const size = try self.stagePackage(output_path, incl_pkg);
            total_size += size;
        }

        return .{
            .success = .{
                .output_path = try self.allocator.dupe(u8, output_path),
                .format = config.format,
                .size = total_size,
                .packages_included = included_packages.items.len,
                .signed = config.sign,
            },
        };
    }

    fn createStagingDir(self: *BundleBuilder) ![]const u8 {
        const tmp_name = try std.fmt.allocPrint(self.allocator, "/tmp/axiom-bundle-{d}", .{
            std.time.timestamp(),
        });

        try std.fs.cwd().makeDir(tmp_name);

        return tmp_name;
    }

    fn cleanupStagingDir(self: *BundleBuilder, path: []const u8) void {
        std.fs.cwd().deleteTree(path) catch {};
        self.allocator.free(path);
    }

    fn stagePackage(self: *BundleBuilder, staging_dir: []const u8, pkg_id: PackageId) !u64 {
        var pkg_meta = self.pkg_store.getPackage(pkg_id) catch return 0;
        defer {
            pkg_meta.manifest.deinit(self.allocator);
            self.allocator.free(pkg_meta.dataset_path);
            for (pkg_meta.dependencies) |dep| {
                self.allocator.free(dep.name);
            }
            self.allocator.free(pkg_meta.dependencies);
        }

        // Create package directory in staging
        const pkg_dir = try std.fmt.allocPrint(self.allocator, "{s}/packages/{s}", .{
            staging_dir,
            pkg_id.name,
        });
        defer self.allocator.free(pkg_dir);

        std.fs.cwd().makePath(pkg_dir) catch {};

        // Copy package root
        const src_root = try std.fs.path.join(self.allocator, &[_][]const u8{
            pkg_meta.dataset_path,
            "root",
        });
        defer self.allocator.free(src_root);

        // Use cp -r to copy
        var cp_child = std.process.Child.init(
            &[_][]const u8{ "cp", "-r", src_root, pkg_dir },
            self.allocator,
        );
        _ = try cp_child.spawnAndWait();

        // Get size (approximation)
        return 0; // TODO: Calculate actual size
    }

    fn generateAppRunScript(
        self: *BundleBuilder,
        output_path: []const u8,
        entry_point: []const u8,
        packages: []const PackageId,
    ) !void {
        var script = std.ArrayList(u8).init(self.allocator);
        defer script.deinit();

        const writer = script.writer();

        try writer.print(
            \\#!/bin/sh
            \\# PGSD AppRun - Application launcher
            \\# Generated by Axiom Bundle Builder
            \\
            \\APPDIR="$(dirname "$(readlink -f "$0")")"
            \\
            \\# Build library path from all packages
            \\LD_LIBRARY_PATH=""
            \\
        , .{});

        for (packages) |pkg| {
            try writer.print(
                \\LD_LIBRARY_PATH="${{LD_LIBRARY_PATH}}:${{APPDIR}}/packages/{s}/root/lib"
                \\
            , .{pkg.name});
        }

        try writer.print(
            \\export LD_LIBRARY_PATH
            \\
            \\# Build PATH from all packages
            \\PATH=""
            \\
        , .{});

        for (packages) |pkg| {
            try writer.print(
                \\PATH="${{PATH}}:${{APPDIR}}/packages/{s}/root/bin"
                \\
            , .{pkg.name});
        }

        try writer.print(
            \\export PATH
            \\
            \\# Execute the application
            \\exec "${{APPDIR}}/packages/{s}/root/bin/{s}" "$@"
            \\
        , .{ packages[0].name, entry_point });

        const file = try std.fs.cwd().createFile(output_path, .{ .mode = 0o755 });
        defer file.close();

        try file.writeAll(script.items);
    }

    fn createCompressedImage(
        self: *BundleBuilder,
        staging_dir: []const u8,
        output_path: []const u8,
        compression: CompressionType,
    ) !void {
        // For now, create a self-extracting shell script with embedded tarball
        // In the future, this could use SquashFS or a custom format

        const header =
            \\#!/bin/sh
            \\# PGSD Portable Image
            \\# Self-extracting application bundle
            \\
            \\TMPDIR=$(mktemp -d)
            \\ARCHIVE_START=$(awk '/^__ARCHIVE_START__$/{print NR + 1; exit 0}' "$0")
            \\
            \\tail -n+$ARCHIVE_START "$0" | tar xz -C "$TMPDIR"
            \\
            \\"$TMPDIR/AppRun" "$@"
            \\EXIT_CODE=$?
            \\
            \\rm -rf "$TMPDIR"
            \\exit $EXIT_CODE
            \\
            \\__ARCHIVE_START__
            \\
        ;

        // Create output file
        const file = try std.fs.cwd().createFile(output_path, .{});
        defer file.close();

        // Write header
        try file.writeAll(header);

        // Append compressed tarball
        const compress_flag = switch (compression) {
            .none => "",
            .gzip, .zstd, .lz4, .xz => "-z",
        };

        var tar_args = std.ArrayList([]const u8).init(self.allocator);
        defer tar_args.deinit();

        try tar_args.append("tar");
        try tar_args.append("-c");
        if (compress_flag.len > 0) {
            try tar_args.append(compress_flag);
        }
        try tar_args.append("-C");
        try tar_args.append(staging_dir);
        try tar_args.append(".");

        var tar_child = std.process.Child.init(tar_args.items, self.allocator);
        tar_child.stdout_behavior = .{ .pipe = file.handle };
        _ = try tar_child.spawnAndWait();

        // Make executable
        try std.fs.cwd().chmod(output_path, 0o755);
    }

    fn getFileSize(self: *BundleBuilder, path: []const u8) !u64 {
        _ = self;
        const file = try std.fs.cwd().openFile(path, .{});
        defer file.close();

        const stat = try file.stat();
        return stat.size;
    }
};

/// Bundle creation result
pub const BundleResult = union(enum) {
    success: struct {
        output_path: []const u8,
        format: BundleFormat,
        size: u64,
        packages_included: usize,
        signed: bool,
    },

    failure: struct {
        message: []const u8,
        code: BundleError,
    },
};

pub const BundleError = error{
    PackageNotFound,
    ClosureComputationFailed,
    StagingFailed,
    CompressionFailed,
    SigningFailed,
    OutputWriteFailed,
};

// Tests
test "bundle creation" {
    // Unit tests would go here
}
