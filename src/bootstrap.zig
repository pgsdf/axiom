const std = @import("std");
const zfs = @import("zfs.zig");
const types = @import("types.zig");
const store = @import("store.zig");
const manifest = @import("manifest.zig");
const import_pkg = @import("import.zig");
const secure_tar = @import("secure_tar.zig");
const config = @import("config.zig");
const errors = @import("errors.zig");

const ZfsHandle = zfs.ZfsHandle;
const PackageStore = store.PackageStore;
const Version = types.Version;
const Importer = import_pkg.Importer;

/// Bootstrap errors
pub const BootstrapError = error{
    InvalidBootstrapTarball,
    MissingBootstrapMetadata,
    IncompatibleArchitecture,
    IncompatibleOsVersion,
    PackageExtractionFailed,
    PackageImportFailed,
    NoPackagesToExport,
    ExportFailed,
    BootstrapAlreadyComplete,
    IoError,
    OutOfMemory,
};

/// Bootstrap package entry in metadata
pub const BootstrapPackage = struct {
    name: []const u8,
    version: []const u8,
    origin: ?[]const u8 = null,
    description: ?[]const u8 = null,
    provides: ?[]const []const u8 = null,
};

/// Bootstrap tarball metadata (bootstrap.yaml)
pub const BootstrapMetadata = struct {
    format_version: u32 = 1,
    created: []const u8,
    os_version: []const u8,
    arch: []const u8,
    description: []const u8,
    packages: []BootstrapPackage,

    pub fn deinit(self: *BootstrapMetadata, allocator: std.mem.Allocator) void {
        allocator.free(self.created);
        allocator.free(self.os_version);
        allocator.free(self.arch);
        allocator.free(self.description);
        for (self.packages) |pkg| {
            allocator.free(pkg.name);
            allocator.free(pkg.version);
            if (pkg.origin) |o| allocator.free(o);
            if (pkg.description) |d| allocator.free(d);
            if (pkg.provides) |provides| {
                for (provides) |p| allocator.free(p);
                allocator.free(provides);
            }
        }
        allocator.free(self.packages);
    }
};

/// Bootstrap status
pub const BootstrapStatus = struct {
    is_bootstrapped: bool,
    installed_packages: []const []const u8,
    missing_packages: []const []const u8,
    bootstrap_path: ?[]const u8,
};

/// Required bootstrap packages for building ports
/// Note: Package names here must match the names produced by mapPortName in ports.zig
/// e.g., lang/perl5.42 → "perl", devel/gmake → "make"
pub const REQUIRED_BOOTSTRAP_PACKAGES = [_][]const u8{
    "make", // from devel/gmake via mapPortName (gmake installs as 'make')
    "m4",
    "gettext-runtime",
    "gettext-tools",
    "libtextstyle",
    "perl", // from lang/perl5.42 via mapPortName
    "autoconf",
    "automake",
    "libtool",
    "pkgconf",
};

/// Minimal bootstrap packages (absolute minimum to get started)
pub const MINIMAL_BOOTSTRAP_PACKAGES = [_][]const u8{
    "make", // from devel/gmake
    "m4",
};

/// Bootstrap manager for creating and importing bootstrap tarballs
pub const BootstrapManager = struct {
    allocator: std.mem.Allocator,
    zfs_handle: *ZfsHandle,
    store: *PackageStore,
    importer: *Importer,

    const Self = @This();

    pub fn init(
        allocator: std.mem.Allocator,
        zfs_handle: *ZfsHandle,
        pkg_store: *PackageStore,
        importer: *Importer,
    ) Self {
        return Self{
            .allocator = allocator,
            .zfs_handle = zfs_handle,
            .store = pkg_store,
            .importer = importer,
        };
    }

    /// Check bootstrap status - which required packages are present
    pub fn checkStatus(self: *Self) !BootstrapStatus {
        var installed = std.ArrayList([]const u8).init(self.allocator);
        var missing = std.ArrayList([]const u8).init(self.allocator);

        for (REQUIRED_BOOTSTRAP_PACKAGES) |pkg_name| {
            if (try self.isPackageInstalled(pkg_name)) {
                try installed.append(pkg_name);
            } else {
                try missing.append(pkg_name);
            }
        }

        return BootstrapStatus{
            .is_bootstrapped = missing.items.len == 0,
            .installed_packages = try installed.toOwnedSlice(),
            .missing_packages = try missing.toOwnedSlice(),
            .bootstrap_path = config.DEFAULT_MOUNTPOINT ++ "/store/pkg",
        };
    }

    /// Check if a package is installed in the Axiom store
    fn isPackageInstalled(self: *Self, name: []const u8) !bool {
        // Check if package directory exists in store
        const pkg_path = try std.fmt.allocPrint(self.allocator, config.DEFAULT_MOUNTPOINT ++ "/store/pkg/{s}", .{name});
        defer self.allocator.free(pkg_path);

        var dir = std.fs.openDirAbsolute(pkg_path, .{}) catch {
            return false;
        };
        dir.close();
        return true;
    }

    /// Import a bootstrap tarball into the Axiom store
    pub fn importBootstrap(self: *Self, tarball_path: []const u8, options: ImportOptions) !ImportResult {
        std.debug.print("Importing bootstrap tarball: {s}\n", .{tarball_path});

        // Create temporary extraction directory
        const tmp_dir = "/tmp/axiom-bootstrap-import";
        std.fs.deleteTreeAbsolute(tmp_dir) catch |err| {
            errors.logFileCleanup(@src(), err, tmp_dir);
        };
        try std.fs.makeDirAbsolute(tmp_dir);
        defer std.fs.deleteTreeAbsolute(tmp_dir) catch |err| {
            errors.logFileCleanup(@src(), err, tmp_dir);
        };

        // Extract the tarball
        std.debug.print("  Extracting tarball...\n", .{});
        _ = try secure_tar.extractSecure(self.allocator, tarball_path, tmp_dir);

        // Read and parse bootstrap.yaml
        const metadata_path = try std.fs.path.join(self.allocator, &[_][]const u8{ tmp_dir, "bootstrap.yaml" });
        defer self.allocator.free(metadata_path);

        var metadata = try self.parseBootstrapMetadata(metadata_path);
        defer metadata.deinit(self.allocator);

        std.debug.print("  Bootstrap tarball info:\n", .{});
        std.debug.print("    OS Version: {s}\n", .{metadata.os_version});
        std.debug.print("    Architecture: {s}\n", .{metadata.arch});
        std.debug.print("    Packages: {d}\n", .{metadata.packages.len});
        std.debug.print("    Description: {s}\n", .{metadata.description});

        // Validate compatibility if not forced
        if (!options.force) {
            try self.validateCompatibility(&metadata);
        }

        // Import each package
        var imported: u32 = 0;
        var skipped: u32 = 0;
        var failed: u32 = 0;

        const packages_dir = try std.fs.path.join(self.allocator, &[_][]const u8{ tmp_dir, "packages" });
        defer self.allocator.free(packages_dir);

        for (metadata.packages) |pkg| {
            std.debug.print("\n  Importing: {s} {s}\n", .{ pkg.name, pkg.version });

            // Check if already installed
            if (!options.force and try self.isPackageInstalled(pkg.name)) {
                std.debug.print("    Skipped (already installed)\n", .{});
                skipped += 1;
                continue;
            }

            // Path to package directory in extracted tarball
            const pkg_dir = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ packages_dir, pkg.name });
            defer self.allocator.free(pkg_dir);

            // Import using existing importer
            _ = self.importer.import(
                import_pkg.ImportSource{ .directory = pkg_dir },
                .{
                    .name = pkg.name,
                    .version = Version.parse(pkg.version) catch null,
                    .description = pkg.description,
                    .dry_run = options.dry_run,
                },
            ) catch |err| {
                std.debug.print("    Failed: {}\n", .{err});
                failed += 1;
                continue;
            };

            std.debug.print("    Imported successfully\n", .{});
            imported += 1;
        }

        std.debug.print("\n============================================================\n", .{});
        std.debug.print("Bootstrap import complete:\n", .{});
        std.debug.print("  Imported: {d}\n", .{imported});
        std.debug.print("  Skipped:  {d}\n", .{skipped});
        std.debug.print("  Failed:   {d}\n", .{failed});
        std.debug.print("============================================================\n", .{});

        return ImportResult{
            .imported = imported,
            .skipped = skipped,
            .failed = failed,
            .total = @intCast(metadata.packages.len),
        };
    }

    /// Export installed packages to a bootstrap tarball
    pub fn exportBootstrap(self: *Self, output_path: []const u8, options: ExportOptions) !ExportResult {
        std.debug.print("Creating bootstrap tarball: {s}\n", .{output_path});

        // Determine which packages to export
        var packages_to_export = std.ArrayList([]const u8).init(self.allocator);
        defer packages_to_export.deinit();

        if (options.packages) |pkgs| {
            // Use specified packages
            for (pkgs) |pkg| {
                if (try self.isPackageInstalled(pkg)) {
                    try packages_to_export.append(pkg);
                } else {
                    std.debug.print("  Warning: Package '{s}' not found, skipping\n", .{pkg});
                }
            }
        } else if (options.minimal) {
            // Use minimal set
            for (MINIMAL_BOOTSTRAP_PACKAGES) |pkg| {
                if (try self.isPackageInstalled(pkg)) {
                    try packages_to_export.append(pkg);
                }
            }
        } else {
            // Use full required set
            for (REQUIRED_BOOTSTRAP_PACKAGES) |pkg| {
                if (try self.isPackageInstalled(pkg)) {
                    try packages_to_export.append(pkg);
                }
            }
        }

        if (packages_to_export.items.len == 0) {
            std.debug.print("Error: No packages available to export\n", .{});
            return BootstrapError.NoPackagesToExport;
        }

        std.debug.print("  Packages to export: {d}\n", .{packages_to_export.items.len});

        // Create staging directory
        const staging_dir = "/tmp/axiom-bootstrap-export";
        std.fs.deleteTreeAbsolute(staging_dir) catch |err| {
            errors.logFileCleanup(@src(), err, staging_dir);
        };
        try std.fs.makeDirAbsolute(staging_dir);
        defer if (!options.keep_staging) {
            std.fs.deleteTreeAbsolute(staging_dir) catch |err| {
                errors.logFileCleanup(@src(), err, staging_dir);
            };
        };

        // Create packages subdirectory
        const packages_staging = try std.fs.path.join(self.allocator, &[_][]const u8{ staging_dir, "packages" });
        defer self.allocator.free(packages_staging);
        try std.fs.makeDirAbsolute(packages_staging);

        // Copy each package to staging
        var package_entries = std.ArrayList(BootstrapPackage).init(self.allocator);
        defer package_entries.deinit();

        for (packages_to_export.items) |pkg_name| {
            std.debug.print("  Staging: {s}\n", .{pkg_name});

            const pkg_info = try self.stagePackage(pkg_name, packages_staging);
            try package_entries.append(pkg_info);
        }

        // Generate bootstrap.yaml
        try self.writeBootstrapMetadata(staging_dir, package_entries.items, options);

        // Create the tarball
        std.debug.print("  Creating tarball...\n", .{});
        try self.createTarball(staging_dir, output_path, options.compression);

        const result = ExportResult{
            .packages_exported = @intCast(packages_to_export.items.len),
            .output_path = output_path,
            .size_bytes = try self.getFileSize(output_path),
        };

        std.debug.print("\n============================================================\n", .{});
        std.debug.print("Bootstrap export complete:\n", .{});
        std.debug.print("  Packages: {d}\n", .{result.packages_exported});
        std.debug.print("  Output:   {s}\n", .{result.output_path});
        std.debug.print("  Size:     {d} bytes\n", .{result.size_bytes});
        std.debug.print("============================================================\n", .{});

        return result;
    }

    /// Stage a package from the Axiom store to the staging directory
    fn stagePackage(self: *Self, pkg_name: []const u8, staging_dir: []const u8) !BootstrapPackage {
        // Find the package in the store
        const pkg_base = try std.fmt.allocPrint(self.allocator, config.DEFAULT_MOUNTPOINT ++ "/store/pkg/{s}", .{pkg_name});
        defer self.allocator.free(pkg_base);

        // Find the latest version directory
        var version_str: []const u8 = "0.0.0";

        var base_dir = try std.fs.openDirAbsolute(pkg_base, .{ .iterate = true });
        defer base_dir.close();

        var iter = base_dir.iterate();
        while (try iter.next()) |entry| {
            if (entry.kind == .directory) {
                // This is a version directory
                version_str = try self.allocator.dupe(u8, entry.name);
                break;
            }
        }

        // Use the first version found
        const version_path = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ pkg_base, version_str });
        defer self.allocator.free(version_path);

        // Find revision directory
        var rev_dir = try std.fs.openDirAbsolute(version_path, .{ .iterate = true });
        defer rev_dir.close();

        var rev_iter = rev_dir.iterate();
        while (try rev_iter.next()) |rev_entry| {
            if (rev_entry.kind == .directory) {
                // Found revision, now find build-id
                const rev_path = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ version_path, rev_entry.name });
                defer self.allocator.free(rev_path);

                var build_dir = try std.fs.openDirAbsolute(rev_path, .{ .iterate = true });
                defer build_dir.close();

                var build_iter = build_dir.iterate();
                while (try build_iter.next()) |build_entry| {
                    if (build_entry.kind == .directory) {
                        // Found the package root
                        const full_pkg_path = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ rev_path, build_entry.name });
                        defer self.allocator.free(full_pkg_path);

                        // Create destination directory
                        const dest_dir = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ staging_dir, pkg_name });
                        defer self.allocator.free(dest_dir);

                        // Copy the package
                        try self.copyDirectory(full_pkg_path, dest_dir);

                        return BootstrapPackage{
                            .name = try self.allocator.dupe(u8, pkg_name),
                            .version = version_str,
                            .origin = null,
                            .description = null,
                            .provides = null,
                        };
                    }
                }
                break;
            }
        }

        return BootstrapPackage{
            .name = try self.allocator.dupe(u8, pkg_name),
            .version = version_str,
            .origin = null,
            .description = null,
            .provides = null,
        };
    }

    /// Copy a directory recursively
    fn copyDirectory(self: *Self, src: []const u8, dest: []const u8) !void {
        // Use system cp for now (more reliable for preserving permissions)
        var child = std.process.Child.init(&[_][]const u8{
            "cp",
            "-R",
            "-p",
            src,
            dest,
        }, self.allocator);

        _ = try child.spawnAndWait();
    }

    /// Write bootstrap.yaml metadata file
    fn writeBootstrapMetadata(self: *Self, staging_dir: []const u8, packages: []const BootstrapPackage, options: ExportOptions) !void {
        const metadata_path = try std.fs.path.join(self.allocator, &[_][]const u8{ staging_dir, "bootstrap.yaml" });
        defer self.allocator.free(metadata_path);

        var file = try std.fs.createFileAbsolute(metadata_path, .{});
        defer file.close();

        var writer = file.writer();

        // Get system info
        const os_version = options.os_version orelse "14.2";
        const arch = options.arch orelse "amd64";
        const description = options.description orelse "Axiom bootstrap packages for building ports";

        // Write YAML header
        try writer.print("# Axiom Bootstrap Tarball Metadata\n", .{});
        try writer.print("# Generated by: axiom bootstrap export\n", .{});
        try writer.print("---\n", .{});
        try writer.print("format_version: 1\n", .{});
        try writer.print("created: \"{s}\"\n", .{try self.getCurrentTimestamp()});
        try writer.print("os_version: \"{s}\"\n", .{os_version});
        try writer.print("arch: \"{s}\"\n", .{arch});
        try writer.print("description: \"{s}\"\n", .{description});
        try writer.print("\n", .{});
        try writer.print("packages:\n", .{});

        for (packages) |pkg| {
            try writer.print("  - name: \"{s}\"\n", .{pkg.name});
            try writer.print("    version: \"{s}\"\n", .{pkg.version});
            if (pkg.origin) |origin| {
                try writer.print("    origin: \"{s}\"\n", .{origin});
            }
            if (pkg.description) |desc| {
                try writer.print("    description: \"{s}\"\n", .{desc});
            }
        }
    }

    /// Get current timestamp in ISO format
    fn getCurrentTimestamp(self: *Self) ![]const u8 {
        _ = self;
        // Simple timestamp (would use std.time in real implementation)
        return "2024-01-01T00:00:00Z";
    }

    /// Create a tarball from a directory
    fn createTarball(self: *Self, source_dir: []const u8, output_path: []const u8, compression: CompressionType) !void {
        const compress_flag: []const u8 = switch (compression) {
            .none => "",
            .gzip => "z",
            .zstd => "--zstd",
            .xz => "J",
        };

        // Build tar command
        var args = std.ArrayList([]const u8).init(self.allocator);
        defer args.deinit();

        try args.append("tar");
        try args.append("-c");

        if (compression == .zstd) {
            try args.append("--zstd");
        } else if (compress_flag.len > 0) {
            const flag = try std.fmt.allocPrint(self.allocator, "-{s}", .{compress_flag});
            try args.append(flag);
        }

        try args.append("-f");
        try args.append(output_path);
        try args.append("-C");
        try args.append(source_dir);
        try args.append(".");

        var child = std.process.Child.init(args.items, self.allocator);
        _ = try child.spawnAndWait();
    }

    /// Get file size
    fn getFileSize(self: *Self, path: []const u8) !u64 {
        _ = self;
        const file = try std.fs.openFileAbsolute(path, .{});
        defer file.close();
        const stat = try file.stat();
        return stat.size;
    }

    /// Parse bootstrap.yaml metadata
    fn parseBootstrapMetadata(self: *Self, path: []const u8) !BootstrapMetadata {
        const file = std.fs.openFileAbsolute(path, .{}) catch {
            return BootstrapError.MissingBootstrapMetadata;
        };
        defer file.close();

        const content = try file.readToEndAlloc(self.allocator, 1024 * 1024);
        defer self.allocator.free(content);

        // Simple YAML parsing (for bootstrap.yaml format)
        return try self.parseYamlMetadata(content);
    }

    /// Simple YAML parser for bootstrap metadata
    fn parseYamlMetadata(self: *Self, content: []const u8) !BootstrapMetadata {
        var metadata = BootstrapMetadata{
            .format_version = 1,
            .created = try self.allocator.dupe(u8, "unknown"),
            .os_version = try self.allocator.dupe(u8, "unknown"),
            .arch = try self.allocator.dupe(u8, "unknown"),
            .description = try self.allocator.dupe(u8, ""),
            .packages = &[_]BootstrapPackage{},
        };

        var packages = std.ArrayList(BootstrapPackage).init(self.allocator);
        var current_pkg: ?BootstrapPackage = null;
        var in_packages_section = false;

        var lines = std.mem.splitScalar(u8, content, '\n');
        while (lines.next()) |line| {
            const trimmed = std.mem.trim(u8, line, " \t\r");

            // Skip comments and empty lines
            if (trimmed.len == 0 or trimmed[0] == '#') continue;

            // Check for packages section
            if (std.mem.eql(u8, trimmed, "packages:")) {
                in_packages_section = true;
                continue;
            }

            if (in_packages_section) {
                // Package entry starts with "- name:"
                if (std.mem.startsWith(u8, trimmed, "- name:")) {
                    // Save previous package if exists
                    if (current_pkg) |pkg| {
                        try packages.append(pkg);
                    }

                    const name_value = std.mem.trim(u8, trimmed[7..], " \t\"");
                    current_pkg = BootstrapPackage{
                        .name = try self.allocator.dupe(u8, name_value),
                        .version = try self.allocator.dupe(u8, "0.0.0"),
                        .origin = null,
                        .description = null,
                        .provides = null,
                    };
                } else if (current_pkg != null) {
                    // Parse package fields
                    if (std.mem.startsWith(u8, trimmed, "version:")) {
                        const value = std.mem.trim(u8, trimmed[8..], " \t\"");
                        self.allocator.free(current_pkg.?.version);
                        current_pkg.?.version = try self.allocator.dupe(u8, value);
                    } else if (std.mem.startsWith(u8, trimmed, "origin:")) {
                        const value = std.mem.trim(u8, trimmed[7..], " \t\"");
                        current_pkg.?.origin = try self.allocator.dupe(u8, value);
                    } else if (std.mem.startsWith(u8, trimmed, "description:")) {
                        const value = std.mem.trim(u8, trimmed[12..], " \t\"");
                        current_pkg.?.description = try self.allocator.dupe(u8, value);
                    }
                }
            } else {
                // Parse top-level fields
                if (std.mem.startsWith(u8, trimmed, "format_version:")) {
                    const value = std.mem.trim(u8, trimmed[15..], " \t");
                    metadata.format_version = std.fmt.parseInt(u32, value, 10) catch 1;
                } else if (std.mem.startsWith(u8, trimmed, "created:")) {
                    const value = std.mem.trim(u8, trimmed[8..], " \t\"");
                    self.allocator.free(metadata.created);
                    metadata.created = try self.allocator.dupe(u8, value);
                } else if (std.mem.startsWith(u8, trimmed, "os_version:")) {
                    const value = std.mem.trim(u8, trimmed[11..], " \t\"");
                    self.allocator.free(metadata.os_version);
                    metadata.os_version = try self.allocator.dupe(u8, value);
                } else if (std.mem.startsWith(u8, trimmed, "arch:")) {
                    const value = std.mem.trim(u8, trimmed[5..], " \t\"");
                    self.allocator.free(metadata.arch);
                    metadata.arch = try self.allocator.dupe(u8, value);
                } else if (std.mem.startsWith(u8, trimmed, "description:")) {
                    const value = std.mem.trim(u8, trimmed[12..], " \t\"");
                    self.allocator.free(metadata.description);
                    metadata.description = try self.allocator.dupe(u8, value);
                }
            }
        }

        // Don't forget the last package
        if (current_pkg) |pkg| {
            try packages.append(pkg);
        }

        metadata.packages = try packages.toOwnedSlice();
        return metadata;
    }

    /// Validate that bootstrap is compatible with current system
    fn validateCompatibility(self: *Self, metadata: *const BootstrapMetadata) !void {
        _ = self;
        // Get current system info
        const current_arch = "amd64"; // Would detect from system

        // Check architecture
        if (!std.mem.eql(u8, metadata.arch, current_arch)) {
            std.debug.print("Error: Bootstrap architecture mismatch\n", .{});
            std.debug.print("  Bootstrap: {s}\n", .{metadata.arch});
            std.debug.print("  System:    {s}\n", .{current_arch});
            return BootstrapError.IncompatibleArchitecture;
        }

        // OS version check could be added here
    }
};

/// Import options
pub const ImportOptions = struct {
    force: bool = false,
    dry_run: bool = false,
    verbose: bool = false,
};

/// Import result
pub const ImportResult = struct {
    imported: u32,
    skipped: u32,
    failed: u32,
    total: u32,
};

/// Export options
pub const ExportOptions = struct {
    packages: ?[]const []const u8 = null,
    minimal: bool = false,
    compression: CompressionType = .zstd,
    os_version: ?[]const u8 = null,
    arch: ?[]const u8 = null,
    description: ?[]const u8 = null,
    keep_staging: bool = false,
};

/// Export result
pub const ExportResult = struct {
    packages_exported: u32,
    output_path: []const u8,
    size_bytes: u64,
};

/// Compression types for bootstrap tarball
pub const CompressionType = enum {
    none,
    gzip,
    zstd,
    xz,

    pub fn extension(self: CompressionType) []const u8 {
        return switch (self) {
            .none => ".tar",
            .gzip => ".tar.gz",
            .zstd => ".tar.zst",
            .xz => ".tar.xz",
        };
    }

    pub fn fromExtension(path: []const u8) CompressionType {
        if (std.mem.endsWith(u8, path, ".tar.zst")) return .zstd;
        if (std.mem.endsWith(u8, path, ".tar.gz") or std.mem.endsWith(u8, path, ".tgz")) return .gzip;
        if (std.mem.endsWith(u8, path, ".tar.xz")) return .xz;
        return .none;
    }
};
