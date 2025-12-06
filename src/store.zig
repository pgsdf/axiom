const std = @import("std");
const zfs = @import("zfs.zig");
const types = @import("types.zig");
const manifest = @import("manifest.zig");

const ZfsHandle = zfs.ZfsHandle;
const PackageId = types.PackageId;
const Version = types.Version;
const Manifest = manifest.Manifest;
const DependencyManifest = manifest.DependencyManifest;
const Provenance = manifest.Provenance;

/// Errors that can occur during package store operations
pub const StoreError = error{
    PackageExists,
    PackageNotFound,
    InvalidPackage,
    InvalidManifest,
    StorageError,
    ZfsError,
    // Phase 26: Path validation errors
    InvalidPathComponent,
    PathValidationFailed,
};

/// Dataset path configuration
pub const DatasetPaths = struct {
    store_root: []const u8 = "zroot/axiom/store/pkg",
    profile_root: []const u8 = "zroot/axiom/profiles",
    env_root: []const u8 = "zroot/axiom/env",

    /// Get the full dataset path for a package with validation (Phase 26)
    pub fn packageDataset(
        self: DatasetPaths,
        allocator: std.mem.Allocator,
        pkg: PackageId,
    ) ![]u8 {
        // Phase 26: Validate path components before building path
        const validator = zfs.ZfsPathValidator.init(allocator, self.store_root);

        // Validate each component
        validator.validateComponent(pkg.name) catch |err| {
            std.debug.print("Invalid package name '{s}': {s}\n", .{
                pkg.name,
                zfs.ZfsPathValidator.errorMessage(err),
            });
            return StoreError.InvalidPathComponent;
        };

        // Convert version to string for validation
        var version_buf: [64]u8 = undefined;
        const version_str = std.fmt.bufPrint(&version_buf, "{}", .{pkg.version}) catch {
            return StoreError.InvalidPathComponent;
        };

        validator.validateComponent(version_str) catch |err| {
            std.debug.print("Invalid version '{s}': {s}\n", .{
                version_str,
                zfs.ZfsPathValidator.errorMessage(err),
            });
            return StoreError.InvalidPathComponent;
        };

        validator.validateComponent(pkg.build_id) catch |err| {
            std.debug.print("Invalid build_id '{s}': {s}\n", .{
                pkg.build_id,
                zfs.ZfsPathValidator.errorMessage(err),
            });
            return StoreError.InvalidPathComponent;
        };

        // Build the validated path
        const path = try std.fmt.allocPrint(allocator, "{s}/{s}/{}/{d}/{s}", .{
            self.store_root,
            pkg.name,
            pkg.version,
            pkg.revision,
            pkg.build_id,
        });
        errdefer allocator.free(path);

        // Final validation of complete path
        validator.validateDatasetPath(path) catch |err| {
            std.debug.print("Invalid dataset path '{s}': {s}\n", .{
                path,
                zfs.ZfsPathValidator.errorMessage(err),
            });
            allocator.free(path);
            return StoreError.PathValidationFailed;
        };

        return path;
    }

    /// Get the full dataset path for a package without validation (internal use only)
    /// WARNING: Use packageDataset() for user-provided data
    pub fn packageDatasetUnchecked(
        self: DatasetPaths,
        allocator: std.mem.Allocator,
        pkg: PackageId,
    ) ![]u8 {
        return std.fmt.allocPrint(allocator, "{s}/{s}/{}/{d}/{s}", .{
            self.store_root,
            pkg.name,
            pkg.version,
            pkg.revision,
            pkg.build_id,
        });
    }

    /// Get the mountpoint path for a package
    pub fn packageMountpoint(
        self: DatasetPaths,
        allocator: std.mem.Allocator,
        pkg: PackageId,
    ) ![]u8 {
        _ = self; // May be used for custom mount roots in future
        return std.fmt.allocPrint(allocator, "/axiom/store/pkg/{s}/{}/{d}/{s}", .{
            pkg.name,
            pkg.version,
            pkg.revision,
            pkg.build_id,
        });
    }

    /// Validate a profile path (Phase 26)
    pub fn validateProfilePath(
        self: DatasetPaths,
        allocator: std.mem.Allocator,
        profile_name: []const u8,
    ) !void {
        const validator = zfs.ZfsPathValidator.init(allocator, self.profile_root);
        validator.validateComponent(profile_name) catch |err| {
            std.debug.print("Invalid profile name '{s}': {s}\n", .{
                profile_name,
                zfs.ZfsPathValidator.errorMessage(err),
            });
            return StoreError.InvalidPathComponent;
        };
    }

    /// Validate an environment path (Phase 26)
    pub fn validateEnvPath(
        self: DatasetPaths,
        allocator: std.mem.Allocator,
        env_name: []const u8,
    ) !void {
        const validator = zfs.ZfsPathValidator.init(allocator, self.env_root);
        validator.validateComponent(env_name) catch |err| {
            std.debug.print("Invalid environment name '{s}': {s}\n", .{
                env_name,
                zfs.ZfsPathValidator.errorMessage(err),
            });
            return StoreError.InvalidPathComponent;
        };
    }
};

/// Package metadata stored in the index
pub const PackageMetadata = struct {
    id: PackageId,
    manifest: Manifest,
    dependencies: []types.Dependency,
    dataset_path: []const u8,
};

/// Package store managing immutable package datasets
pub const PackageStore = struct {
    allocator: std.mem.Allocator,
    zfs_handle: *ZfsHandle,
    paths: DatasetPaths,
    // TODO: Add index database

    /// Initialize package store
    pub fn init(
        allocator: std.mem.Allocator,
        zfs_handle: *ZfsHandle,
    ) !PackageStore {
        return PackageStore{
            .allocator = allocator,
            .zfs_handle = zfs_handle,
            .paths = .{},
        };
    }

    /// Add a package to the store
    pub fn addPackage(
        self: *PackageStore,
        pkg_id: PackageId,
        source_dir: []const u8,
        pkg_manifest: Manifest,
        deps: DependencyManifest,
        prov: Provenance,
    ) !void {
        // 1. Generate dataset path
        const dataset_path = try self.paths.packageDataset(self.allocator, pkg_id);
        defer self.allocator.free(dataset_path);

        std.debug.print("Adding package {s} to store...\n", .{dataset_path});

        // 2. Check if package already exists
        const exists = try self.zfs_handle.datasetExists(
            self.allocator,
            dataset_path,
            .filesystem,
        );

        if (exists) {
            return StoreError.PackageExists;
        }

        // 3. Create immutable dataset (with parent creation for nested paths)
        try self.zfs_handle.createDatasetWithParents(self.allocator, dataset_path, .{
            .compression = "lz4",
            .atime = false,
            .readonly = false, // We'll set to readonly after populating
        });

        // 4. Get mountpoint and copy files
        const mountpoint = try self.zfs_handle.getMountpoint(self.allocator, dataset_path);
        defer self.allocator.free(mountpoint);

        std.debug.print("  Mountpoint: {s}\n", .{mountpoint});

        // 5. Copy package files to root/ subdirectory
        const root_dir = try std.fs.path.join(self.allocator, &[_][]const u8{ mountpoint, "root" });
        defer self.allocator.free(root_dir);

        try self.copyDirectory(source_dir, root_dir);

        // 6. Write manifests
        try self.writeManifest(mountpoint, "manifest.yaml", pkg_manifest);
        try self.writeDepManifest(mountpoint, "deps.yaml", deps);
        try self.writeProvenance(mountpoint, "provenance.yaml", prov);

        // 7. Set dataset to readonly
        try self.zfs_handle.setProperty(self.allocator, dataset_path, "readonly", "on");

        // 8. Create snapshot
        try self.zfs_handle.snapshot(self.allocator, dataset_path, "installed", false);

        std.debug.print("  ✓ Package added successfully\n", .{});
    }

    /// Remove a package from the store
    pub fn removePackage(
        self: *PackageStore,
        pkg_id: PackageId,
    ) !void {
        const dataset_path = try self.paths.packageDataset(self.allocator, pkg_id);
        defer self.allocator.free(dataset_path);

        std.debug.print("Removing package {s}...\n", .{dataset_path});

        // TODO: Check if package is referenced by any profiles/environments

        // Destroy dataset (including snapshots)
        try self.zfs_handle.destroyDataset(self.allocator, dataset_path, true);

        std.debug.print("  ✓ Package removed\n", .{});
    }

    /// Check if a package exists in the store
    pub fn packageExists(
        self: *PackageStore,
        pkg_id: PackageId,
    ) !bool {
        const dataset_path = try self.paths.packageDataset(self.allocator, pkg_id);
        defer self.allocator.free(dataset_path);

        return self.zfs_handle.datasetExists(self.allocator, dataset_path, .filesystem);
    }

    /// Check if any version of a package exists in the store by name
    pub fn packageNameExists(
        self: *PackageStore,
        name: []const u8,
    ) !bool {
        // Build path to the package name directory: {store_root}/{name}
        const dataset_path = try std.fmt.allocPrint(
            self.allocator,
            "{s}/{s}",
            .{ self.paths.store_root, name },
        );
        defer self.allocator.free(dataset_path);

        return self.zfs_handle.datasetExists(self.allocator, dataset_path, .filesystem);
    }

    /// Get the origin of an existing package by name (reads from first found version)
    /// Returns null if package doesn't exist or has no origin
    pub fn getPackageOriginByName(
        self: *PackageStore,
        name: []const u8,
    ) !?[]const u8 {
        // Path structure: {store_root}/{name}/{version}/{revision}/{build-id}/manifest.yaml
        const pkg_dir_path = try std.fmt.allocPrint(
            self.allocator,
            "{s}/{s}",
            .{ self.paths.store_root, name },
        );
        defer self.allocator.free(pkg_dir_path);

        // Get mountpoint for the pkg directory
        const mountpoint = self.zfs_handle.getMountpoint(self.allocator, pkg_dir_path) catch {
            return null;
        };
        defer self.allocator.free(mountpoint);

        // Traverse to find first manifest: name/version/revision/build-id/manifest.yaml
        var pkg_dir = std.fs.cwd().openDir(mountpoint, .{ .iterate = true }) catch {
            return null;
        };
        defer pkg_dir.close();

        // Find first version
        var version_iter = pkg_dir.iterate();
        const version_entry = (version_iter.next() catch return null) orelse return null;
        if (version_entry.kind != .directory) return null;

        const version_path = std.fs.path.join(self.allocator, &[_][]const u8{
            mountpoint,
            version_entry.name,
        }) catch return null;
        defer self.allocator.free(version_path);

        var version_dir = std.fs.cwd().openDir(version_path, .{ .iterate = true }) catch {
            return null;
        };
        defer version_dir.close();

        // Find first revision
        var revision_iter = version_dir.iterate();
        const revision_entry = (revision_iter.next() catch return null) orelse return null;
        if (revision_entry.kind != .directory) return null;

        const revision_path = std.fs.path.join(self.allocator, &[_][]const u8{
            version_path,
            revision_entry.name,
        }) catch return null;
        defer self.allocator.free(revision_path);

        var revision_dir = std.fs.cwd().openDir(revision_path, .{ .iterate = true }) catch {
            return null;
        };
        defer revision_dir.close();

        // Find first build-id
        var build_iter = revision_dir.iterate();
        const build_entry = (build_iter.next() catch return null) orelse return null;
        if (build_entry.kind != .directory) return null;

        // Read manifest.yaml
        const manifest_path = std.fs.path.join(self.allocator, &[_][]const u8{
            revision_path,
            build_entry.name,
            "manifest.yaml",
        }) catch return null;
        defer self.allocator.free(manifest_path);

        const manifest_content = std.fs.cwd().readFileAlloc(self.allocator, manifest_path, 1024 * 1024) catch {
            return null;
        };
        defer self.allocator.free(manifest_content);

        // Parse manifest to get origin
        var pkg_manifest = Manifest.parse(self.allocator, manifest_content) catch {
            return null;
        };
        defer pkg_manifest.deinit(self.allocator);

        // Return duplicated origin (or null if not set)
        if (pkg_manifest.origin) |origin| {
            return try self.allocator.dupe(u8, origin);
        }
        return null;
    }

    /// Get package metadata
    pub fn getPackage(
        self: *PackageStore,
        pkg_id: PackageId,
    ) !PackageMetadata {
        const dataset_path = try self.paths.packageDataset(self.allocator, pkg_id);
        defer self.allocator.free(dataset_path);

        // Check existence
        const exists = try self.zfs_handle.datasetExists(
            self.allocator,
            dataset_path,
            .filesystem,
        );

        if (!exists) {
            return StoreError.PackageNotFound;
        }

        // Get mountpoint
        const mountpoint = try self.zfs_handle.getMountpoint(self.allocator, dataset_path);
        defer self.allocator.free(mountpoint);

        // Read manifests
        const manifest_path = try std.fs.path.join(
            self.allocator,
            &[_][]const u8{ mountpoint, "manifest.yaml" },
        );
        defer self.allocator.free(manifest_path);

        const manifest_content = try std.fs.cwd().readFileAlloc(
            self.allocator,
            manifest_path,
            1024 * 1024,
        );
        defer self.allocator.free(manifest_content);

        const pkg_manifest = try Manifest.parse(self.allocator, manifest_content);

        // Read dependencies
        const deps_path = try std.fs.path.join(
            self.allocator,
            &[_][]const u8{ mountpoint, "deps.yaml" },
        );
        defer self.allocator.free(deps_path);

        const deps_content = try std.fs.cwd().readFileAlloc(
            self.allocator,
            deps_path,
            1024 * 1024,
        );
        defer self.allocator.free(deps_content);

        const deps_manifest = try DependencyManifest.parse(self.allocator, deps_content);

        return PackageMetadata{
            .id = pkg_id,
            .manifest = pkg_manifest,
            .dependencies = deps_manifest.dependencies,
            .dataset_path = try self.allocator.dupe(u8, dataset_path),
        };
    }

    /// List all packages in the store
    pub fn listPackages(
        self: *PackageStore,
    ) ![]PackageId {
        // TODO: Implement by traversing ZFS datasets or querying index
        _ = self;
        return &[_]PackageId{};
    }

    // Private helper methods

    /// Copy directory recursively
    fn copyDirectory(self: *PackageStore, source: []const u8, dest: []const u8) !void {
        // Create destination directory
        try std.fs.cwd().makePath(dest);

        // Use system cp command for now (more efficient than Zig file-by-file)
        const cmd = try std.fmt.allocPrint(
            self.allocator,
            "cp -R {s}/. {s}/",
            .{ source, dest },
        );
        defer self.allocator.free(cmd);

        var child = std.process.Child.init(&[_][]const u8{ "sh", "-c", cmd }, self.allocator);
        child.stdout_behavior = .Ignore;
        child.stderr_behavior = .Ignore;

        try child.spawn();
        const term = try child.wait();

        if (term.Exited != 0) {
            return StoreError.StorageError;
        }
    }

    /// Write manifest to file
    fn writeManifest(
        self: *PackageStore,
        base_path: []const u8,
        filename: []const u8,
        mani: Manifest,
    ) !void {
        const path = try std.fs.path.join(
            self.allocator,
            &[_][]const u8{ base_path, filename },
        );
        defer self.allocator.free(path);

        const file = try std.fs.cwd().createFile(path, .{});
        defer file.close();

        const writer = file.writer();

        // Write manifest in YAML format
        try writer.print("name: {s}\n", .{mani.name});
        try writer.print("version: {}\n", .{mani.version});
        try writer.print("revision: {d}\n", .{mani.revision});

        if (mani.description) |desc| {
            try writer.print("description: {s}\n", .{desc});
        }
        if (mani.license) |lic| {
            try writer.print("license: {s}\n", .{lic});
        }
        if (mani.homepage) |home| {
            try writer.print("homepage: {s}\n", .{home});
        }
        if (mani.maintainer) |maint| {
            try writer.print("maintainer: {s}\n", .{maint});
        }

        if (mani.tags.len > 0) {
            try writer.writeAll("tags:\n");
            for (mani.tags) |tag| {
                try writer.print("  - {s}\n", .{tag});
            }
        }
    }

    /// Write dependency manifest to file
    fn writeDepManifest(
        self: *PackageStore,
        base_path: []const u8,
        filename: []const u8,
        deps: DependencyManifest,
    ) !void {
        const path = try std.fs.path.join(
            self.allocator,
            &[_][]const u8{ base_path, filename },
        );
        defer self.allocator.free(path);

        const file = try std.fs.cwd().createFile(path, .{});
        defer file.close();

        const writer = file.writer();

        try writer.writeAll("dependencies:\n");
        for (deps.dependencies) |dep| {
            try writer.print("  - name: {s}\n", .{dep.name});

            switch (dep.constraint) {
                .exact => |v| {
                    try writer.print("    version: \"{}\"\n", .{v});
                    try writer.writeAll("    constraint: exact\n");
                },
                .tilde => |v| {
                    try writer.print("    version: \"~{}\"\n", .{v});
                    try writer.writeAll("    constraint: tilde\n");
                },
                .caret => |v| {
                    try writer.print("    version: \"^{}\"\n", .{v});
                    try writer.writeAll("    constraint: caret\n");
                },
                .any => {
                    try writer.writeAll("    version: \"*\"\n");
                    try writer.writeAll("    constraint: any\n");
                },
                .range => |r| {
                    try writer.writeAll("    version: \"");
                    if (r.min) |min| {
                        if (r.min_inclusive) {
                            try writer.print(">={}", .{min});
                        } else {
                            try writer.print(">{}", .{min});
                        }
                    }
                    if (r.max) |max| {
                        if (r.min != null) {
                            try writer.writeAll(",");
                        }
                        if (r.max_inclusive) {
                            try writer.print("<={}", .{max});
                        } else {
                            try writer.print("<{}", .{max});
                        }
                    }
                    try writer.writeAll("\"\n");
                    try writer.writeAll("    constraint: range\n");
                },
            }
        }
    }

    /// Write provenance to file
    fn writeProvenance(
        self: *PackageStore,
        base_path: []const u8,
        filename: []const u8,
        prov: Provenance,
    ) !void {
        const path = try std.fs.path.join(
            self.allocator,
            &[_][]const u8{ base_path, filename },
        );
        defer self.allocator.free(path);

        const file = try std.fs.cwd().createFile(path, .{});
        defer file.close();

        const writer = file.writer();

        try writer.print("build_time: {d}\n", .{prov.build_time});
        try writer.print("builder: {s}\n", .{prov.builder});

        if (prov.build_user) |u| {
            try writer.print("build_user: {s}\n", .{u});
        }
        if (prov.source_url) |u| {
            try writer.print("source_url: {s}\n", .{u});
        }
        if (prov.source_hash) |h| {
            try writer.print("source_hash: {s}\n", .{h});
        }
        if (prov.compiler) |c| {
            try writer.print("compiler: {s}\n", .{c});
        }
        if (prov.compiler_version) |v| {
            try writer.print("compiler_version: {s}\n", .{v});
        }

        if (prov.build_flags.len > 0) {
            try writer.writeAll("build_flags:\n");
            for (prov.build_flags) |flag| {
                try writer.print("  - {s}\n", .{flag});
            }
        }
    }
};
