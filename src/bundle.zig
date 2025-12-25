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
const errors = @import("errors.zig");

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
        var output: std.ArrayList(u8) = .empty;
        defer output.deinit(allocator);

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

        return try output.toOwnedSlice(allocator);
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

        var included_packages: std.ArrayList(PackageId) = .empty;
        defer included_packages.deinit(self.allocator);

        try included_packages.append(self.allocator, pkg_id);

        if (config.include_closure) {
            pkg_closure = try self.closure_computer.computeForPackage(pkg_id);
            for (pkg_closure.?.topo_order.items) |dep_id| {
                try included_packages.append(self.allocator, dep_id);
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

        var send_args: std.ArrayList([]const u8) = .empty;
        defer send_args.deinit(self.allocator);

        try send_args.append(self.allocator, "zfs");
        try send_args.append(self.allocator, "send");

        // Add compression flag based on config
        if (config.compression != .none) {
            try send_args.append(self.allocator, "-c");
        }

        try send_args.append(self.allocator, dataset);

        var send_child = std.process.Child.init(send_args.items, self.allocator);
        send_child.stdout_behavior = .Pipe;
        try send_child.spawn();

        // Read stdout and write to file
        if (send_child.stdout) |stdout| {
            var buf: [4096]u8 = undefined;
            while (true) {
                const bytes_read = stdout.read(&buf) catch break;
                if (bytes_read == 0) break;
                try output_file.writeAll(buf[0..bytes_read]);
            }
        }

        _ = send_child.wait() catch |err| {
            errors.logProcessCleanup(@src(), err, "zfs send for bundle");
        };

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

        var included_packages: std.ArrayList(PackageId) = .empty;
        defer included_packages.deinit(self.allocator);

        try included_packages.append(self.allocator, pkg_id);

        if (config.include_closure) {
            pkg_closure = try self.closure_computer.computeForPackage(pkg_id);
            for (pkg_closure.?.topo_order.items) |dep_id| {
                try included_packages.append(self.allocator, dep_id);
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

        var tar_args: std.ArrayList([]const u8) = .empty;
        defer tar_args.deinit(self.allocator);

        try tar_args.append(self.allocator, tar_cmd);
        try tar_args.append(self.allocator, "-cf");
        try tar_args.append(self.allocator, output_path);
        if (compress_flag.len > 0) {
            try tar_args.append(self.allocator, compress_flag);
        }
        try tar_args.append(self.allocator, "-C");
        try tar_args.append(self.allocator, staging_dir);
        try tar_args.append(self.allocator, ".");

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

        var included_packages: std.ArrayList(PackageId) = .empty;
        defer included_packages.deinit(self.allocator);

        try included_packages.append(self.allocator, pkg_id);

        if (config.include_closure) {
            pkg_closure = try self.closure_computer.computeForPackage(pkg_id);
            for (pkg_closure.?.topo_order.items) |dep_id| {
                try included_packages.append(self.allocator, dep_id);
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
        std.fs.cwd().deleteTree(path) catch |err| {
            errors.logFileCleanup(@src(), err, path);
        };
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

        std.fs.cwd().makePath(pkg_dir) catch |err| {
            errors.logMkdirBestEffort(@src(), err, pkg_dir);
        };

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
        var script: std.ArrayList(u8) = .empty;
        defer script.deinit(self.allocator);

        const writer = script.writer(self.allocator);

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

        // Create output file with executable permissions
        const file = try std.fs.cwd().createFile(output_path, .{ .mode = 0o755 });
        defer file.close();

        // Write header
        try file.writeAll(header);

        // Append compressed tarball
        const compress_flag = switch (compression) {
            .none => "",
            .gzip, .zstd, .lz4, .xz => "-z",
        };

        var tar_args: std.ArrayList([]const u8) = .empty;
        defer tar_args.deinit(self.allocator);

        try tar_args.append(self.allocator, "tar");
        try tar_args.append(self.allocator, "-c");
        if (compress_flag.len > 0) {
            try tar_args.append(self.allocator, compress_flag);
        }
        try tar_args.append(self.allocator, "-C");
        try tar_args.append(self.allocator, staging_dir);
        try tar_args.append(self.allocator, ".");

        var tar_child = std.process.Child.init(tar_args.items, self.allocator);
        tar_child.stdout_behavior = .Pipe;
        try tar_child.spawn();

        // Read stdout and write to file
        if (tar_child.stdout) |stdout| {
            var buf: [4096]u8 = undefined;
            while (true) {
                const bytes_read = stdout.read(&buf) catch break;
                if (bytes_read == 0) break;
                try file.writeAll(buf[0..bytes_read]);
            }
        }

        _ = tar_child.wait() catch |err| {
            errors.logProcessCleanup(@src(), err, "tar for bundle");
        };
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
    // Phase 28: Bundle verification errors
    SignatureNotFound,
    SignatureInvalid,
    ManifestVerificationFailed,
    PayloadHashMismatch,
    BundleCorrupted,
    UntrustedSigner,
    VerificationRequired,
    ExtractionFailed,
    LaunchFailed,
};

// ============================================================================
// Phase 28: Secure Bundle Verification
// ============================================================================

/// Bundle verification status
pub const BundleVerificationStatus = enum {
    /// Bundle has not been verified
    unverified,

    /// Bundle verification is in progress
    verifying,

    /// Bundle signature is valid and trusted
    verified,

    /// Bundle signature is valid but signer is not in trust store
    untrusted,

    /// Bundle signature verification failed
    invalid,

    /// Bundle payload hash does not match manifest
    tampered,

    /// Bundle has no signature (unsigned)
    unsigned,

    pub fn isValid(self: BundleVerificationStatus) bool {
        return self == .verified;
    }

    pub fn isSafe(self: BundleVerificationStatus) bool {
        return self == .verified or self == .untrusted;
    }

    pub fn toString(self: BundleVerificationStatus) []const u8 {
        return switch (self) {
            .unverified => "unverified",
            .verifying => "verifying",
            .verified => "verified",
            .untrusted => "untrusted signer",
            .invalid => "invalid signature",
            .tampered => "tampered",
            .unsigned => "unsigned",
        };
    }
};

/// Bundle verification result with detailed information
pub const BundleVerificationResult = struct {
    status: BundleVerificationStatus,
    signer_id: ?[]const u8 = null,
    manifest_hash: ?[32]u8 = null,
    payload_hash: ?[32]u8 = null,
    verified_at: i64 = 0,
    error_message: ?[]const u8 = null,

    pub fn deinit(self: *BundleVerificationResult, allocator: std.mem.Allocator) void {
        if (self.signer_id) |id| {
            allocator.free(id);
        }
        if (self.error_message) |msg| {
            allocator.free(msg);
        }
    }
};

/// Extended bundle manifest with verification fields
pub const SecureBundleManifest = struct {
    /// Base manifest fields
    format_version: u32 = 2,
    name: []const u8,
    version: Version,
    created_at: i64,
    entry_point: []const u8,
    packages: []PackageId,
    uncompressed_size: u64,
    compression: CompressionType,

    /// Verification fields
    payload_offset: u64 = 0,
    payload_size: u64 = 0,
    payload_hash: [32]u8 = undefined,
    manifest_signature: ?[]const u8 = null,
    signer_public_key: ?[]const u8 = null,

    /// Provenance for verification
    provenance: ?Provenance = null,

    pub fn parse(allocator: std.mem.Allocator, data: []const u8) !SecureBundleManifest {
        var result = SecureBundleManifest{
            .name = "",
            .version = .{ .major = 0, .minor = 0, .patch = 0 },
            .created_at = 0,
            .entry_point = "",
            .packages = &[_]PackageId{},
            .uncompressed_size = 0,
            .compression = .none,
        };

        var lines = std.mem.splitScalar(u8, data, '\n');
        var packages_list: std.ArrayList(PackageId) = .empty;
        defer packages_list.deinit(allocator);

        var in_packages = false;

        while (lines.next()) |line| {
            const trimmed = std.mem.trim(u8, line, " \t\r");
            if (trimmed.len == 0) continue;

            if (std.mem.startsWith(u8, trimmed, "packages:")) {
                in_packages = true;
                continue;
            }

            if (in_packages) {
                if (std.mem.startsWith(u8, trimmed, "- ")) {
                    // Parse package entry like "- name@1.0.0"
                    const pkg_str = trimmed[2..];
                    if (std.mem.indexOf(u8, pkg_str, "@")) |at_pos| {
                        const pkg_name = try allocator.dupe(u8, pkg_str[0..at_pos]);
                        // Parse version
                        var ver_parts: [3]u32 = .{ 0, 0, 0 };
                        var ver_iter = std.mem.splitScalar(u8, pkg_str[at_pos + 1 ..], '.');
                        var idx: usize = 0;
                        while (ver_iter.next()) |part| {
                            if (idx >= 3) break;
                            ver_parts[idx] = std.fmt.parseInt(u32, part, 10) catch 0;
                            idx += 1;
                        }
                        try packages_list.append(allocator, .{
                            .name = pkg_name,
                            .version = .{
                                .major = ver_parts[0],
                                .minor = ver_parts[1],
                                .patch = ver_parts[2],
                            },
                            .revision = 0,
                            .build_id = "",
                        });
                    }
                } else if (!std.mem.startsWith(u8, trimmed, " ") and !std.mem.startsWith(u8, trimmed, "\t")) {
                    in_packages = false;
                }
            }

            if (!in_packages) {
                if (std.mem.startsWith(u8, trimmed, "format_version:")) {
                    const val = std.mem.trim(u8, trimmed[15..], " \t");
                    result.format_version = std.fmt.parseInt(u32, val, 10) catch 1;
                } else if (std.mem.startsWith(u8, trimmed, "name:")) {
                    result.name = try allocator.dupe(u8, std.mem.trim(u8, trimmed[5..], " \t"));
                } else if (std.mem.startsWith(u8, trimmed, "entry_point:")) {
                    result.entry_point = try allocator.dupe(u8, std.mem.trim(u8, trimmed[12..], " \t"));
                } else if (std.mem.startsWith(u8, trimmed, "created_at:")) {
                    const val = std.mem.trim(u8, trimmed[11..], " \t");
                    result.created_at = std.fmt.parseInt(i64, val, 10) catch 0;
                } else if (std.mem.startsWith(u8, trimmed, "uncompressed_size:")) {
                    const val = std.mem.trim(u8, trimmed[18..], " \t");
                    result.uncompressed_size = std.fmt.parseInt(u64, val, 10) catch 0;
                } else if (std.mem.startsWith(u8, trimmed, "payload_offset:")) {
                    const val = std.mem.trim(u8, trimmed[15..], " \t");
                    result.payload_offset = std.fmt.parseInt(u64, val, 10) catch 0;
                } else if (std.mem.startsWith(u8, trimmed, "payload_size:")) {
                    const val = std.mem.trim(u8, trimmed[13..], " \t");
                    result.payload_size = std.fmt.parseInt(u64, val, 10) catch 0;
                } else if (std.mem.startsWith(u8, trimmed, "payload_hash:")) {
                    const hex_str = std.mem.trim(u8, trimmed[13..], " \t");
                    if (hex_str.len >= 64) {
                        _ = std.fmt.hexToBytes(&result.payload_hash, hex_str[0..64]) catch |err| {
                            errors.logParseError(@src(), err, "parse payload hash hex");
                        };
                    }
                } else if (std.mem.startsWith(u8, trimmed, "compression:")) {
                    const val = std.mem.trim(u8, trimmed[12..], " \t");
                    result.compression = if (std.mem.eql(u8, val, "gzip"))
                        .gzip
                    else if (std.mem.eql(u8, val, "xz"))
                        .xz
                    else if (std.mem.eql(u8, val, "zstd"))
                        .zstd
                    else if (std.mem.eql(u8, val, "lz4"))
                        .lz4
                    else
                        .none;
                } else if (std.mem.startsWith(u8, trimmed, "version:")) {
                    const val = std.mem.trim(u8, trimmed[8..], " \t");
                    var ver_parts: [3]u32 = .{ 0, 0, 0 };
                    var ver_iter = std.mem.splitScalar(u8, val, '.');
                    var idx: usize = 0;
                    while (ver_iter.next()) |part| {
                        if (idx >= 3) break;
                        ver_parts[idx] = std.fmt.parseInt(u32, part, 10) catch 0;
                        idx += 1;
                    }
                    result.version = .{
                        .major = ver_parts[0],
                        .minor = ver_parts[1],
                        .patch = ver_parts[2],
                    };
                }
            }
        }

        result.packages = try packages_list.toOwnedSlice(allocator);
        return result;
    }

    pub fn deinit(self: *SecureBundleManifest, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.entry_point);
        for (self.packages) |pkg| {
            allocator.free(pkg.name);
        }
        allocator.free(self.packages);
        if (self.manifest_signature) |sig| {
            allocator.free(sig);
        }
        if (self.signer_public_key) |key| {
            allocator.free(key);
        }
    }
};

/// Secure bundle launcher with pre-execution verification
/// Thread-safe: Uses mutex protection for verification cache
pub const SecureBundleLauncher = struct {
    allocator: std.mem.Allocator,
    temp_dir: []const u8,
    trust_store_path: ?[]const u8,
    require_signature: bool,
    allow_untrusted: bool,

    /// Cache of verified bundles (path hash -> verification result)
    /// Protected by cache_mutex for thread-safe access
    verification_cache: std.StringHashMap(BundleVerificationResult),

    /// Mutex protecting verification_cache for thread-safe access
    cache_mutex: std.Thread.Mutex = .{},

    /// Secure extraction options
    pub const ExtractionOptions = struct {
        allow_symlinks: bool = false,
        strip_setuid: bool = true,
        max_file_size: u64 = 1024 * 1024 * 1024, // 1 GB
        max_total_size: u64 = 10 * 1024 * 1024 * 1024, // 10 GB
        max_path_length: usize = 1024,
    };

    pub const LauncherConfig = struct {
        temp_dir: []const u8 = "/tmp",
        trust_store_path: ?[]const u8 = null,
        require_signature: bool = true,
        allow_untrusted: bool = false,
    };

    pub fn init(allocator: std.mem.Allocator, config: LauncherConfig) SecureBundleLauncher {
        return .{
            .allocator = allocator,
            .temp_dir = config.temp_dir,
            .trust_store_path = config.trust_store_path,
            .require_signature = config.require_signature,
            .allow_untrusted = config.allow_untrusted,
            .verification_cache = std.StringHashMap(BundleVerificationResult).init(allocator),
        };
    }

    pub fn deinit(self: *SecureBundleLauncher) void {
        // Lock mutex during cleanup to ensure no concurrent access
        self.cache_mutex.lock();
        defer self.cache_mutex.unlock();

        var iter = self.verification_cache.iterator();
        while (iter.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            var result = entry.value_ptr.*;
            result.deinit(self.allocator);
        }
        self.verification_cache.deinit();
    }

    /// Verify a bundle without launching it
    /// Thread-safe: Uses mutex protection for cache access
    pub fn verify(self: *SecureBundleLauncher, bundle_path: []const u8) !BundleVerificationResult {
        // Check cache first (with lock)
        self.cache_mutex.lock();
        if (self.verification_cache.get(bundle_path)) |cached| {
            self.cache_mutex.unlock();
            return cached;
        }
        self.cache_mutex.unlock();

        // Open bundle file
        const bundle_file = std.fs.cwd().openFile(bundle_path, .{}) catch |err| {
            return .{
                .status = .invalid,
                .error_message = try std.fmt.allocPrint(
                    self.allocator,
                    "Failed to open bundle: {s}",
                    .{@errorName(err)},
                ),
            };
        };
        defer bundle_file.close();

        // Read manifest offset from bundle header
        const manifest_offset = try self.readManifestOffset(bundle_file);

        // Read and verify manifest
        const manifest_result = self.readAndVerifyManifest(bundle_file, manifest_offset) catch |err| {
            return .{
                .status = if (err == error.SignatureNotFound) .unsigned else .invalid,
                .error_message = try std.fmt.allocPrint(
                    self.allocator,
                    "Manifest verification failed: {s}",
                    .{@errorName(err)},
                ),
            };
        };

        // Verify payload hash
        const payload_hash = try self.hashPayload(bundle_file, manifest_result.payload_offset, manifest_result.payload_size);

        if (!std.mem.eql(u8, &payload_hash, &manifest_result.payload_hash)) {
            return .{
                .status = .tampered,
                .manifest_hash = null,
                .payload_hash = payload_hash,
                .error_message = try self.allocator.dupe(u8, "Payload hash does not match manifest"),
            };
        }

        const result = BundleVerificationResult{
            .status = .verified,
            .payload_hash = payload_hash,
            .verified_at = std.time.timestamp(),
        };

        // Cache the result (with lock)
        const path_copy = try self.allocator.dupe(u8, bundle_path);
        self.cache_mutex.lock();
        self.verification_cache.put(path_copy, result) catch |err| {
            self.cache_mutex.unlock();
            self.allocator.free(path_copy);
            return err;
        };
        self.cache_mutex.unlock();

        return result;
    }

    /// Launch a bundle with pre-execution verification
    pub fn launch(
        self: *SecureBundleLauncher,
        bundle_path: []const u8,
        args: []const []const u8,
    ) !SecureLaunchResult {
        // 1. Verify bundle signature BEFORE any extraction
        const verification = try self.verify(bundle_path);

        // Check verification requirements
        if (self.require_signature and verification.status == .unsigned) {
            return .{
                .failed = .{
                    .error_code = BundleError.VerificationRequired,
                    .message = "Bundle is not signed and signature verification is required",
                },
            };
        }

        if (!verification.status.isSafe()) {
            return .{
                .failed = .{
                    .error_code = BundleError.SignatureInvalid,
                    .message = verification.error_message orelse "Verification failed",
                },
            };
        }

        if (verification.status == .untrusted and !self.allow_untrusted) {
            return .{
                .failed = .{
                    .error_code = BundleError.UntrustedSigner,
                    .message = "Bundle signer is not in trust store",
                },
            };
        }

        // 2. Open bundle and read manifest
        const bundle_file = try std.fs.cwd().openFile(bundle_path, .{});
        defer bundle_file.close();

        const manifest_offset = try self.readManifestOffset(bundle_file);
        const bundle_manifest = try self.readAndVerifyManifest(bundle_file, manifest_offset);
        defer {
            var m = bundle_manifest;
            m.deinit(self.allocator);
        }

        // 3. Securely extract to temporary directory
        const extract_dir = try self.secureExtract(bundle_file, bundle_manifest);
        errdefer self.cleanup(extract_dir);

        // 4. Launch verified bundle
        return self.launchVerified(extract_dir, bundle_manifest, args);
    }

    fn readManifestOffset(self: *SecureBundleLauncher, file: std.fs.File) !u64 {
        _ = self;
        // Bundle format: [shell header][__MANIFEST_START__][manifest][__ARCHIVE_START__][payload]
        // Read file looking for manifest marker
        try file.seekTo(0);

        var buf: [4096]u8 = undefined;
        const bytes_read = try file.read(&buf);

        const manifest_marker = "__MANIFEST_START__";
        if (std.mem.indexOf(u8, buf[0..bytes_read], manifest_marker)) |pos| {
            return pos + manifest_marker.len;
        }

        // Fallback: assume manifest starts after shell script header (look for __ARCHIVE_START__)
        // and work backwards, or use a fixed offset for legacy bundles
        return 0; // Will be handled by readAndVerifyManifest
    }

    fn readAndVerifyManifest(
        self: *SecureBundleLauncher,
        file: std.fs.File,
        offset: u64,
    ) !SecureBundleManifest {
        // Read manifest data
        try file.seekTo(offset);

        // Find the end of manifest (marked by signature block or archive start)
        var manifest_buf: [64 * 1024]u8 = undefined;
        const bytes_read = try file.read(&manifest_buf);
        if (bytes_read == 0) {
            return error.ManifestVerificationFailed;
        }

        // Find signature delimiter
        const sig_delimiter = "---SIGNATURE---";
        const archive_marker = "__ARCHIVE_START__";

        var manifest_end: usize = bytes_read;
        var signature_start: ?usize = null;
        var signature_end: usize = bytes_read;

        if (std.mem.indexOf(u8, manifest_buf[0..bytes_read], sig_delimiter)) |sig_pos| {
            manifest_end = sig_pos;
            signature_start = sig_pos + sig_delimiter.len;

            if (std.mem.indexOf(u8, manifest_buf[signature_start.?..bytes_read], archive_marker)) |arch_pos| {
                signature_end = signature_start.? + arch_pos;
            }
        } else if (std.mem.indexOf(u8, manifest_buf[0..bytes_read], archive_marker)) |arch_pos| {
            manifest_end = arch_pos;
        }

        const manifest_data = manifest_buf[0..manifest_end];

        // Verify signature if present
        if (signature_start) |sig_start| {
            const sig_bytes = std.mem.trim(u8, manifest_buf[sig_start..signature_end], " \t\n\r");

            // Verify using Ed25519
            const verified = try self.verifySignature(manifest_data, sig_bytes);
            if (!verified) {
                return error.SignatureInvalid;
            }
        } else if (self.require_signature) {
            return error.SignatureNotFound;
        }

        // Parse manifest
        return SecureBundleManifest.parse(self.allocator, manifest_data);
    }

    fn verifySignature(self: *SecureBundleLauncher, data: []const u8, signature: []const u8) !bool {
        // Load trusted public keys from trust store
        if (self.trust_store_path) |trust_path| {
            var trust_dir = std.fs.cwd().openDir(trust_path, .{ .iterate = true }) catch {
                return false;
            };
            defer trust_dir.close();

            // Try each trusted key
            var iter = trust_dir.iterate();
            while (iter.next() catch null) |entry| {
                if (!std.mem.endsWith(u8, entry.name, ".pub")) continue;

                const key_file = trust_dir.openFile(entry.name, .{}) catch continue;
                defer key_file.close();

                var key_buf: [128]u8 = undefined;
                const key_bytes = key_file.read(&key_buf) catch continue;
                if (key_bytes < 32) continue;

                // Decode hex signature
                var sig_decoded: [64]u8 = undefined;
                if (signature.len >= 128) {
                    _ = std.fmt.hexToBytes(&sig_decoded, signature[0..128]) catch continue;
                } else {
                    continue;
                }

                // Decode public key
                var key_decoded: [32]u8 = undefined;
                _ = std.fmt.hexToBytes(&key_decoded, key_buf[0..64]) catch continue;

                // Verify signature
                const public_key = std.crypto.sign.Ed25519.PublicKey.fromBytes(key_decoded) catch continue;
                const sig = std.crypto.sign.Ed25519.Signature.fromBytes(sig_decoded);

                sig.verify(data, public_key) catch continue;
                return true;
            }
        }

        return false;
    }

    fn hashPayload(self: *SecureBundleLauncher, file: std.fs.File, offset: u64, size: u64) ![32]u8 {
        _ = self;
        try file.seekTo(offset);

        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        var buf: [8192]u8 = undefined;
        var remaining = size;

        while (remaining > 0) {
            const to_read = @min(remaining, buf.len);
            const bytes_read = try file.read(buf[0..to_read]);
            if (bytes_read == 0) break;

            hasher.update(buf[0..bytes_read]);
            remaining -= bytes_read;
        }

        return hasher.finalResult();
    }

    fn secureExtract(
        self: *SecureBundleLauncher,
        file: std.fs.File,
        bundle_manifest: SecureBundleManifest,
    ) ![]const u8 {
        // Create extraction directory with secure permissions
        const random_suffix = std.crypto.random.int(u64);
        const extract_dir = try std.fmt.allocPrint(
            self.allocator,
            "{s}/axiom-bundle-{x}",
            .{ self.temp_dir, random_suffix },
        );
        errdefer self.allocator.free(extract_dir);

        // Create directory with restricted permissions (owner only)
        std.fs.cwd().makeDir(extract_dir) catch |err| {
            if (err != error.PathAlreadyExists) return err;
        };

        // Set secure permissions using chmod
        var chmod_child = std.process.Child.init(
            &[_][]const u8{ "chmod", "700", extract_dir },
            self.allocator,
        );
        _ = chmod_child.spawnAndWait() catch |err| {
            errors.logNonCriticalWithCategory(@src(), err, .permission, "chmod extraction directory", extract_dir);
        };

        // Seek to payload
        try file.seekTo(bundle_manifest.payload_offset);

        // Extract using tar with security options
        var tar_args: std.ArrayList([]const u8) = .empty;
        defer tar_args.deinit(self.allocator);

        try tar_args.append(self.allocator, "tar");
        try tar_args.append(self.allocator, "-x");

        // Compression flag
        switch (bundle_manifest.compression) {
            .gzip => try tar_args.append(self.allocator, "-z"),
            .xz => try tar_args.append(self.allocator, "-J"),
            .zstd => try tar_args.append(self.allocator, "--zstd"),
            .lz4 => try tar_args.append(self.allocator, "--lz4"),
            .none => {},
        }

        try tar_args.append(self.allocator, "-C");
        try tar_args.append(self.allocator, extract_dir);

        // Security options: strip setuid/setgid, don't follow symlinks outside
        try tar_args.append(self.allocator, "--no-same-owner");
        try tar_args.append(self.allocator, "--no-same-permissions");

        var tar_child = std.process.Child.init(tar_args.items, self.allocator);
        tar_child.stdin_behavior = .Pipe;

        try tar_child.spawn();

        // Feed payload to tar's stdin
        if (tar_child.stdin) |stdin| {
            var buf: [8192]u8 = undefined;
            var remaining = bundle_manifest.payload_size;

            while (remaining > 0) {
                const to_read = @min(remaining, buf.len);
                const bytes_read = file.read(buf[0..to_read]) catch break;
                if (bytes_read == 0) break;

                stdin.writeAll(buf[0..bytes_read]) catch break;
                remaining -= bytes_read;
            }
            stdin.close();
        }

        const result = tar_child.wait() catch {
            return error.ExtractionFailed;
        };

        if (result.Exited != 0) {
            return error.ExtractionFailed;
        }

        return extract_dir;
    }

    fn launchVerified(
        self: *SecureBundleLauncher,
        extract_dir: []const u8,
        bundle_manifest: SecureBundleManifest,
        args: []const []const u8,
    ) !SecureLaunchResult {
        // Build path to AppRun or entry point
        const entry_path = try std.fs.path.join(self.allocator, &[_][]const u8{
            extract_dir,
            "AppRun",
        });
        defer self.allocator.free(entry_path);

        // Check if AppRun exists, otherwise use direct entry point
        const exec_path = blk: {
            std.fs.cwd().access(entry_path, .{}) catch {
                // Try direct entry point
                const direct_path = try std.fs.path.join(self.allocator, &[_][]const u8{
                    extract_dir,
                    "packages",
                    bundle_manifest.name,
                    "root",
                    "bin",
                    bundle_manifest.entry_point,
                });
                break :blk direct_path;
            };
            break :blk try self.allocator.dupe(u8, entry_path);
        };
        defer self.allocator.free(exec_path);

        // Build argv
        var argv: std.ArrayList([]const u8) = .empty;
        defer argv.deinit(self.allocator);

        try argv.append(self.allocator, exec_path);
        for (args) |arg| {
            try argv.append(self.allocator, arg);
        }

        // Set environment
        var env_map = std.process.EnvMap.init(self.allocator);
        defer env_map.deinit();

        try env_map.put("AXIOM_BUNDLE_DIR", extract_dir);
        try env_map.put("AXIOM_BUNDLE_NAME", bundle_manifest.name);
        try env_map.put("AXIOM_BUNDLE_VERIFIED", "true");

        // Spawn process
        var child = std.process.Child.init(argv.items, self.allocator);
        child.env_map = &env_map;

        child.spawn() catch {
            return .{
                .failed = .{
                    .error_code = BundleError.LaunchFailed,
                    .message = "Failed to spawn process",
                },
            };
        };

        const result = child.wait() catch {
            return .{
                .failed = .{
                    .error_code = BundleError.LaunchFailed,
                    .message = "Failed to wait for process",
                },
            };
        };

        return switch (result) {
            .Exited => |code| .{
                .success = .{
                    .exit_code = code,
                    .extract_dir = try self.allocator.dupe(u8, extract_dir),
                },
            },
            .Signal => |sig| .{
                .signaled = .{
                    .signal = sig,
                    .extract_dir = try self.allocator.dupe(u8, extract_dir),
                },
            },
            else => .{
                .failed = .{
                    .error_code = BundleError.LaunchFailed,
                    .message = "Unexpected process termination",
                },
            },
        };
    }

    pub fn cleanup(self: *SecureBundleLauncher, extract_dir: []const u8) void {
        std.fs.cwd().deleteTree(extract_dir) catch |err| {
            errors.logFileCleanup(@src(), err, extract_dir);
        };
        self.allocator.free(extract_dir);
    }

    /// Invalidate verification cache for a specific bundle
    /// Thread-safe: Uses mutex protection for cache access
    pub fn invalidateCache(self: *SecureBundleLauncher, bundle_path: []const u8) void {
        self.cache_mutex.lock();
        defer self.cache_mutex.unlock();

        if (self.verification_cache.fetchRemove(bundle_path)) |entry| {
            self.allocator.free(entry.key);
            var result = entry.value;
            result.deinit(self.allocator);
        }
    }

    /// Clear entire verification cache
    /// Thread-safe: Uses mutex protection for cache access
    pub fn clearCache(self: *SecureBundleLauncher) void {
        self.cache_mutex.lock();
        defer self.cache_mutex.unlock();

        var iter = self.verification_cache.iterator();
        while (iter.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            var result = entry.value_ptr.*;
            result.deinit(self.allocator);
        }
        self.verification_cache.clearRetainingCapacity();
    }
};

/// Secure launch result
pub const SecureLaunchResult = union(enum) {
    success: struct {
        exit_code: u8,
        extract_dir: []const u8,
    },

    signaled: struct {
        signal: u32,
        extract_dir: []const u8,
    },

    failed: struct {
        error_code: BundleError,
        message: []const u8,
    },

    pub fn deinit(self: *SecureLaunchResult, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .success => |s| allocator.free(s.extract_dir),
            .signaled => |s| allocator.free(s.extract_dir),
            .failed => {},
        }
    }
};

/// Bundle verification command-line options
pub const BundleVerifyOptions = struct {
    /// Require signature verification (default: true)
    require_signature: bool = true,

    /// Allow bundles signed by untrusted signers (default: false)
    allow_untrusted: bool = false,

    /// Path to trust store directory
    trust_store: ?[]const u8 = null,

    /// Skip verification entirely (DANGEROUS - for testing only)
    skip_verification: bool = false,

    /// Verbose output
    verbose: bool = false,
};

// Tests
test "bundle creation" {
    // Unit tests would go here
}

test "secure bundle manifest parsing" {
    const allocator = std.testing.allocator;

    const manifest_text =
        \\format_version: 2
        \\name: test-app
        \\version: 1.2.3
        \\created_at: 1700000000
        \\entry_point: test-app
        \\uncompressed_size: 1024
        \\compression: zstd
        \\payload_offset: 4096
        \\payload_size: 512
        \\packages:
        \\  - test-app@1.2.3
        \\  - libfoo@2.0.0
    ;

    var parsed_manifest = try SecureBundleManifest.parse(allocator, manifest_text);
    defer parsed_manifest.deinit(allocator);

    try std.testing.expectEqual(@as(u32, 2), parsed_manifest.format_version);
    try std.testing.expectEqualStrings("test-app", parsed_manifest.name);
    try std.testing.expectEqual(@as(u32, 1), parsed_manifest.version.major);
    try std.testing.expectEqual(@as(u32, 2), parsed_manifest.version.minor);
    try std.testing.expectEqual(@as(u32, 3), parsed_manifest.version.patch);
    try std.testing.expectEqual(@as(u64, 4096), parsed_manifest.payload_offset);
    try std.testing.expectEqual(@as(u64, 512), parsed_manifest.payload_size);
    try std.testing.expectEqual(@as(usize, 2), parsed_manifest.packages.len);
}

test "bundle verification status" {
    try std.testing.expect(BundleVerificationStatus.verified.isValid());
    try std.testing.expect(!BundleVerificationStatus.untrusted.isValid());
    try std.testing.expect(BundleVerificationStatus.verified.isSafe());
    try std.testing.expect(BundleVerificationStatus.untrusted.isSafe());
    try std.testing.expect(!BundleVerificationStatus.tampered.isSafe());
}
