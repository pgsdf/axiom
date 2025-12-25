const std = @import("std");
const zfs = @import("zfs.zig");
const types = @import("types.zig");
const store = @import("store.zig");
const profile = @import("profile.zig");
const conflict = @import("conflict.zig");
const config = @import("config.zig");
const realization_spec = @import("realization_spec.zig");

const ZfsHandle = zfs.ZfsHandle;
const PackageId = types.PackageId;
const PackageStore = store.PackageStore;
const ProfileLock = profile.ProfileLock;
const ResolvedPackage = profile.ResolvedPackage;
const ConflictConfig = conflict.ConflictConfig;
const ConflictTracker = conflict.ConflictTracker;
const ConflictPolicy = conflict.ConflictPolicy;
const FileConflict = conflict.FileConflict;
const ConflictResolution = conflict.ConflictResolution;

// Phase 44: Realization Specification types
const RealizationSpec = realization_spec.RealizationSpec;
const MergeStrategy = realization_spec.MergeStrategy;
const AbiBoundary = realization_spec.AbiBoundary;
const AbiReport = realization_spec.AbiReport;
const EnvironmentMetadata = realization_spec.EnvironmentMetadata;

/// Errors that can occur during realization
pub const RealizationError = error{
    EnvironmentExists,
    EnvironmentNotFound,
    PackageNotFound,
    RealizationFailed,
    ActivationFailed,
    FileConflict,
};

/// An environment is a realized profile - a set of package clones
pub const Environment = struct {
    name: []const u8,
    profile_name: []const u8,
    dataset_path: []const u8,
    packages: []PackageId,
    active: bool = false,
};

/// Realization engine - creates environments from lock files
pub const RealizationEngine = struct {
    allocator: std.mem.Allocator,
    zfs_handle: *ZfsHandle,
    store: *PackageStore,
    env_root: []const u8 = config.DEFAULT_POOL ++ "/" ++ config.DEFAULT_DATASET ++ "/env",
    conflict_policy: ConflictPolicy = .error_on_conflict,

    /// Initialize realization engine
    pub fn init(
        allocator: std.mem.Allocator,
        zfs_handle_ptr: *ZfsHandle,
        store_ptr: *PackageStore,
    ) RealizationEngine {
        return RealizationEngine{
            .allocator = allocator,
            .zfs_handle = zfs_handle_ptr,
            .store = store_ptr,
        };
    }

    /// Set conflict resolution policy
    pub fn setConflictPolicy(self: *RealizationEngine, policy: ConflictPolicy) void {
        self.conflict_policy = policy;
    }

    /// Create an environment from a lock file
    pub fn realize(
        self: *RealizationEngine,
        env_name: []const u8,
        lock: ProfileLock,
    ) !Environment {
        std.debug.print("Realizing environment: {s}\n", .{env_name});
        std.debug.print("  Profile: {s}\n", .{lock.profile_name});
        std.debug.print("  Packages: {d}\n", .{lock.resolved.len});

        // Create environment dataset
        const env_dataset = try std.fmt.allocPrint(
            self.allocator,
            "{s}/{s}",
            .{ self.env_root, env_name },
        );
        defer self.allocator.free(env_dataset);

        // Check if environment already exists
        const exists = try self.zfs_handle.datasetExists(
            self.allocator,
            env_dataset,
            .filesystem,
        );

        if (exists) {
            return RealizationError.EnvironmentExists;
        }

        std.debug.print("\nCreating environment dataset...\n", .{});
        
        // Create environment root dataset
        try self.zfs_handle.createDataset(self.allocator, env_dataset, .{
            .compression = "lz4",
            .atime = false,
        });

        // Get environment mountpoint
        const env_mountpoint = try self.zfs_handle.getMountpoint(
            self.allocator,
            env_dataset,
        );
        defer self.allocator.free(env_mountpoint);

        std.debug.print("  Environment root: {s}\n", .{env_mountpoint});

        // Create directory structure
        const bin_dir = try std.fs.path.join(self.allocator, &[_][]const u8{ env_mountpoint, "bin" });
        defer self.allocator.free(bin_dir);
        try std.fs.cwd().makePath(bin_dir);

        const lib_dir = try std.fs.path.join(self.allocator, &[_][]const u8{ env_mountpoint, "lib" });
        defer self.allocator.free(lib_dir);
        try std.fs.cwd().makePath(lib_dir);

        const share_dir = try std.fs.path.join(self.allocator, &[_][]const u8{ env_mountpoint, "share" });
        defer self.allocator.free(share_dir);
        try std.fs.cwd().makePath(share_dir);

        // Set up conflict tracking
        var conflict_config = ConflictConfig.init(self.allocator);
        defer conflict_config.deinit();
        conflict_config.default_policy = self.conflict_policy;

        var conflict_tracker = ConflictTracker.init(self.allocator, &conflict_config);
        defer conflict_tracker.deinit();

        // Clone and merge all packages
        std.debug.print("\nCloning packages...\n", .{});

        var package_ids: std.ArrayList(PackageId) = .empty;
        defer package_ids.deinit(self.allocator);

        // Track files already in environment for conflict detection
        var env_files = std.StringHashMap(PackageId).init(self.allocator);
        defer env_files.deinit();

        for (lock.resolved, 0..) |pkg, i| {
            std.debug.print("  [{d}/{d}] {s} {}\n", .{
                i + 1,
                lock.resolved.len,
                pkg.id.name,
                pkg.id.version,
            });

            // Get package dataset path
            const pkg_dataset = try self.store.paths.packageDataset(self.allocator, pkg.id);
            defer self.allocator.free(pkg_dataset);

            // Verify package exists
            const pkg_exists = try self.zfs_handle.datasetExists(
                self.allocator,
                pkg_dataset,
                .filesystem,
            );

            if (!pkg_exists) {
                std.debug.print("    ✗ Package not found in store\n", .{});
                return RealizationError.PackageNotFound;
            }

            // Clone package to environment with conflict detection
            const conflicts_found = try self.clonePackageWithConflicts(
                env_mountpoint,
                pkg_dataset,
                pkg.id,
                &env_files,
                &conflict_tracker,
            );

            if (conflicts_found > 0) {
                std.debug.print("    ⚠ {d} file conflict(s) detected\n", .{conflicts_found});
            }

            try package_ids.append(self.allocator, .{
                .name = try self.allocator.dupe(u8, pkg.id.name),
                .version = pkg.id.version,
                .revision = pkg.id.revision,
                .build_id = try self.allocator.dupe(u8, pkg.id.build_id),
            });
        }

        // Check for blocking conflicts
        if (conflict_tracker.hasBlockingConflicts()) {
            const summary = conflict_tracker.getSummary();
            std.debug.print("\n✗ Realization blocked by {d} unresolved conflict(s)\n", .{summary.total});
            for (conflict_tracker.conflicts.items) |file_conflict| {
                std.debug.print("  - {s}\n", .{file_conflict.path});
            }
            return RealizationError.FileConflict;
        }

        // Show conflict summary if any were found
        const summary = conflict_tracker.getSummary();
        if (summary.total > 0) {
            std.debug.print("\nConflict Summary:\n", .{});
            std.debug.print("  Total conflicts: {d}\n", .{summary.total});
            if (summary.same_content > 0)
                std.debug.print("  - Identical files: {d} (no action needed)\n", .{summary.same_content});
            if (summary.different_content > 0)
                std.debug.print("  - Different content: {d}\n", .{summary.different_content});
            if (summary.type_mismatch > 0)
                std.debug.print("  - Type mismatch: {d}\n", .{summary.type_mismatch});
            if (summary.permission_diff > 0)
                std.debug.print("  - Permission diff: {d}\n", .{summary.permission_diff});
            std.debug.print("  Resolved: {d}\n", .{summary.resolved});
        }

        // Create activation script
        try self.createActivationScript(env_mountpoint, env_name);

        // Snapshot the environment
        std.debug.print("\nCreating snapshot...\n", .{});
        try self.zfs_handle.snapshot(self.allocator, env_dataset, "initial", false);

        std.debug.print("\n✓ Environment '{s}' realized successfully\n", .{env_name});
        std.debug.print("  Location: {s}\n", .{env_mountpoint});

        return Environment{
            .name = try self.allocator.dupe(u8, env_name),
            .profile_name = try self.allocator.dupe(u8, lock.profile_name),
            .dataset_path = try self.allocator.dupe(u8, env_dataset),
            .packages = try package_ids.toOwnedSlice(self.allocator),
            .active = false,
        };
    }

    /// Create an environment with advanced realization specification (Phase 44)
    pub fn realizeWithSpec(
        self: *RealizationEngine,
        env_name: []const u8,
        lock: ProfileLock,
        spec: *const RealizationSpec,
    ) !Environment {
        std.debug.print("Realizing environment: {s} (with spec)\n", .{env_name});
        std.debug.print("  Profile: {s}\n", .{lock.profile_name});
        std.debug.print("  Packages: {d}\n", .{lock.resolved.len});
        std.debug.print("  Default strategy: {s}\n", .{spec.default_strategy.toString()});

        // Create environment dataset
        const env_dataset = try std.fmt.allocPrint(
            self.allocator,
            "{s}/{s}",
            .{ self.env_root, env_name },
        );
        defer self.allocator.free(env_dataset);

        // Check if environment already exists
        const exists = try self.zfs_handle.datasetExists(
            self.allocator,
            env_dataset,
            .filesystem,
        );

        if (exists) {
            return RealizationError.EnvironmentExists;
        }

        std.debug.print("\nCreating environment dataset...\n", .{});

        // Create environment root dataset
        try self.zfs_handle.createDataset(self.allocator, env_dataset, .{
            .compression = "lz4",
            .atime = false,
        });

        // Get environment mountpoint
        const env_mountpoint = try self.zfs_handle.getMountpoint(
            self.allocator,
            env_dataset,
        );
        defer self.allocator.free(env_mountpoint);

        std.debug.print("  Environment root: {s}\n", .{env_mountpoint});

        // Create directory structure
        try self.createDirectoryStructure(env_mountpoint);

        // Create .axiom metadata directory if specified
        if (spec.create_metadata) {
            try self.createMetadataDir(env_mountpoint);
        }

        // Set up conflict tracking based on spec
        var conflict_config = ConflictConfig.init(self.allocator);
        defer conflict_config.deinit();
        conflict_config.default_policy = self.conflict_policy;

        var conflict_tracker = ConflictTracker.init(self.allocator, &conflict_config);
        defer conflict_tracker.deinit();

        // Clone and merge all packages
        std.debug.print("\nCloning packages with spec...\n", .{});

        var package_ids: std.ArrayList(PackageId) = .empty;
        defer package_ids.deinit(self.allocator);

        var env_files = std.StringHashMap(PackageId).init(self.allocator);
        defer env_files.deinit();

        for (lock.resolved, 0..) |pkg, i| {
            std.debug.print("  [{d}/{d}] {s} {}\n", .{
                i + 1,
                lock.resolved.len,
                pkg.id.name,
                pkg.id.version,
            });

            // Check output selection for this package
            const output_sel = spec.getOutputSelection(pkg.id.name);
            if (output_sel) |sel| {
                std.debug.print("    Outputs: ", .{});
                for (sel.outputs) |o| std.debug.print("{s} ", .{o});
                std.debug.print("\n", .{});
            }

            // Get package dataset path
            const pkg_dataset = try self.store.paths.packageDataset(self.allocator, pkg.id);
            defer self.allocator.free(pkg_dataset);

            // Verify package exists
            const pkg_exists = try self.zfs_handle.datasetExists(
                self.allocator,
                pkg_dataset,
                .filesystem,
            );

            if (!pkg_exists) {
                std.debug.print("    ✗ Package not found in store\n", .{});
                return RealizationError.PackageNotFound;
            }

            // Clone package with spec-aware strategy
            const conflicts_found = try self.clonePackageWithSpec(
                env_mountpoint,
                pkg_dataset,
                pkg.id,
                &env_files,
                &conflict_tracker,
                spec,
                output_sel,
            );

            if (conflicts_found > 0) {
                std.debug.print("    ⚠ {d} file conflict(s) detected\n", .{conflicts_found});
            }

            try package_ids.append(self.allocator, .{
                .name = try self.allocator.dupe(u8, pkg.id.name),
                .version = pkg.id.version,
                .revision = pkg.id.revision,
                .build_id = try self.allocator.dupe(u8, pkg.id.build_id),
            });
        }

        // Check for blocking conflicts
        if (conflict_tracker.hasBlockingConflicts()) {
            const summary = conflict_tracker.getSummary();
            std.debug.print("\n✗ Realization blocked by {d} unresolved conflict(s)\n", .{summary.total});
            return RealizationError.FileConflict;
        }

        // Verify ABI if enabled
        if (spec.verify_abi) {
            std.debug.print("\nVerifying ABI boundaries...\n", .{});
            var abi_report = try self.verifyAbi(env_mountpoint, &spec.abi_boundary);
            defer abi_report.deinit();

            if (!abi_report.valid) {
                std.debug.print("  ⚠ ABI verification found issues\n", .{});
                for (abi_report.warnings.items) |w| {
                    std.debug.print("    Warning: {s}\n", .{w});
                }
            } else {
                std.debug.print("  ✓ ABI boundaries respected\n", .{});
            }
        }

        // Create activation script if enabled
        if (spec.create_activation_script) {
            try self.createActivationScript(env_mountpoint, env_name);
        }

        // Write environment metadata
        if (spec.create_metadata) {
            try self.writeEnvironmentMetadata(env_mountpoint, env_name, lock, package_ids.items);
        }

        // Snapshot the environment
        std.debug.print("\nCreating snapshot...\n", .{});
        try self.zfs_handle.snapshot(self.allocator, env_dataset, "initial", false);

        std.debug.print("\n✓ Environment '{s}' realized successfully\n", .{env_name});
        std.debug.print("  Location: {s}\n", .{env_mountpoint});

        return Environment{
            .name = try self.allocator.dupe(u8, env_name),
            .profile_name = try self.allocator.dupe(u8, lock.profile_name),
            .dataset_path = try self.allocator.dupe(u8, env_dataset),
            .packages = try package_ids.toOwnedSlice(self.allocator),
            .active = false,
        };
    }

    /// Clone a package with spec-aware merge strategy (Phase 44)
    fn clonePackageWithSpec(
        self: *RealizationEngine,
        env_mountpoint: []const u8,
        pkg_dataset: []const u8,
        pkg_id: PackageId,
        env_files: *std.StringHashMap(PackageId),
        tracker: *ConflictTracker,
        spec: *const RealizationSpec,
        output_sel: ?*const realization_spec.OutputSelection,
    ) !usize {
        // Get package mountpoint
        const pkg_mountpoint = try self.zfs_handle.getMountpoint(
            self.allocator,
            pkg_dataset,
        );
        defer self.allocator.free(pkg_mountpoint);

        // Package files are in root/ subdirectory
        const pkg_root = try std.fs.path.join(
            self.allocator,
            &[_][]const u8{ pkg_mountpoint, "root" },
        );
        defer self.allocator.free(pkg_root);

        // Use recursive copy with spec-aware strategy
        return copyDirRecursiveWithSpec(
            self.allocator,
            pkg_root,
            env_mountpoint,
            pkg_id,
            env_files,
            tracker,
            spec,
            output_sel,
        );
    }

    /// Create standard directory structure for environment
    fn createDirectoryStructure(self: *RealizationEngine, env_mountpoint: []const u8) !void {
        const dirs = [_][]const u8{ "bin", "lib", "share", "include", "etc", "libexec", "sbin" };
        for (dirs) |dir| {
            const full_path = try std.fs.path.join(self.allocator, &[_][]const u8{ env_mountpoint, dir });
            defer self.allocator.free(full_path);
            try std.fs.cwd().makePath(full_path);
        }
    }

    /// Create .axiom metadata directory
    fn createMetadataDir(self: *RealizationEngine, env_mountpoint: []const u8) !void {
        const axiom_dir = try std.fs.path.join(self.allocator, &[_][]const u8{ env_mountpoint, ".axiom" });
        defer self.allocator.free(axiom_dir);
        try std.fs.cwd().makePath(axiom_dir);

        const packages_dir = try std.fs.path.join(self.allocator, &[_][]const u8{ env_mountpoint, ".axiom", "packages" });
        defer self.allocator.free(packages_dir);
        try std.fs.cwd().makePath(packages_dir);
    }

    /// Write environment metadata to .axiom/manifest.yaml
    fn writeEnvironmentMetadata(
        self: *RealizationEngine,
        env_mountpoint: []const u8,
        env_name: []const u8,
        lock: ProfileLock,
        packages: []const PackageId,
    ) !void {
        const metadata = EnvironmentMetadata{
            .name = env_name,
            .profile_name = lock.profile_name,
            .realized_at = std.time.timestamp(),
            .packages = packages,
            .output_selections = &[_]realization_spec.OutputSelection{},
            .abi_verified = true,
        };

        const yaml_content = try metadata.toYaml(self.allocator);
        defer self.allocator.free(yaml_content);

        const manifest_path = try std.fs.path.join(self.allocator, &[_][]const u8{ env_mountpoint, ".axiom", "manifest.yaml" });
        defer self.allocator.free(manifest_path);

        const file = try std.fs.createFileAbsolute(manifest_path, .{});
        defer file.close();
        try file.writeAll(yaml_content);
    }

    /// Verify ABI boundaries in the environment
    fn verifyAbi(
        self: *RealizationEngine,
        env_mountpoint: []const u8,
        boundary: *const AbiBoundary,
    ) !AbiReport {
        var report = AbiReport.init(self.allocator);

        // Check lib directory for system library violations
        const lib_path = try std.fs.path.join(self.allocator, &[_][]const u8{ env_mountpoint, "lib" });
        defer self.allocator.free(lib_path);

        var lib_dir = std.fs.openDirAbsolute(lib_path, .{ .iterate = true }) catch {
            // No lib directory is fine
            return report;
        };
        defer lib_dir.close();

        var iter = lib_dir.iterate();
        while (try iter.next()) |entry| {
            if (entry.kind != .file and entry.kind != .sym_link) continue;

            // Check if this is a system library
            if (boundary.isSystemLibrary(entry.name)) {
                try report.addWarning(try std.fmt.allocPrint(
                    self.allocator,
                    "System library '{s}' found in environment - should use base system version",
                    .{entry.name},
                ));
            }
        }

        return report;
    }

    /// Clone a package into the environment (legacy - no conflict detection)
    /// Uses native file operations instead of shell commands for security
    fn clonePackage(
        self: *RealizationEngine,
        env_mountpoint: []const u8,
        pkg_dataset: []const u8,
        pkg_id: PackageId,
    ) !void {
        _ = pkg_id; // Reserved for future metadata use

        // Get package mountpoint
        const pkg_mountpoint = try self.zfs_handle.getMountpoint(
            self.allocator,
            pkg_dataset,
        );
        defer self.allocator.free(pkg_mountpoint);

        // Package files are in root/ subdirectory
        const pkg_root = try std.fs.path.join(
            self.allocator,
            &[_][]const u8{ pkg_mountpoint, "root" },
        );
        defer self.allocator.free(pkg_root);

        // Use native file operations instead of shell execution
        try copyDirRecursiveSimple(self.allocator, pkg_root, env_mountpoint);
    }

    /// Clone a package into the environment with conflict detection
    fn clonePackageWithConflicts(
        self: *RealizationEngine,
        env_mountpoint: []const u8,
        pkg_dataset: []const u8,
        pkg_id: PackageId,
        env_files: *std.StringHashMap(PackageId),
        tracker: *ConflictTracker,
    ) !usize {
        // Get package mountpoint
        const pkg_mountpoint = try self.zfs_handle.getMountpoint(
            self.allocator,
            pkg_dataset,
        );
        defer self.allocator.free(pkg_mountpoint);

        // Package files are in root/ subdirectory
        const pkg_root = try std.fs.path.join(
            self.allocator,
            &[_][]const u8{ pkg_mountpoint, "root" },
        );
        defer self.allocator.free(pkg_root);

        // Use recursive copy with conflict detection
        return copyDirRecursive(
            self.allocator,
            pkg_root,
            env_mountpoint,
            pkg_id,
            env_files,
            tracker,
        );
    }

    /// Create activation script for the environment
    fn createActivationScript(
        self: *RealizationEngine,
        env_mountpoint: []const u8,
        env_name: []const u8,
    ) !void {
        const script_path = try std.fs.path.join(
            self.allocator,
            &[_][]const u8{ env_mountpoint, "activate" },
        );
        defer self.allocator.free(script_path);

        const file = try std.fs.cwd().createFile(script_path, .{ .mode = 0o755 });
        defer file.close();

        try file.writeAll("#!/bin/sh\n");
        try file.writeAll("# Axiom environment activation script\n");

        const env_comment = try std.fmt.allocPrint(self.allocator, "# Environment: {s}\n\n", .{env_name});
        defer self.allocator.free(env_comment);
        try file.writeAll(env_comment);

        const axiom_env = try std.fmt.allocPrint(self.allocator, "export AXIOM_ENV=\"{s}\"\n", .{env_name});
        defer self.allocator.free(axiom_env);
        try file.writeAll(axiom_env);

        const path_export = try std.fmt.allocPrint(self.allocator, "export PATH=\"{s}/bin:$PATH\"\n", .{env_mountpoint});
        defer self.allocator.free(path_export);
        try file.writeAll(path_export);

        const ld_export = try std.fmt.allocPrint(self.allocator, "export LD_LIBRARY_PATH=\"{s}/lib:$LD_LIBRARY_PATH\"\n", .{env_mountpoint});
        defer self.allocator.free(ld_export);
        try file.writeAll(ld_export);

        const man_export = try std.fmt.allocPrint(self.allocator, "export MANPATH=\"{s}/share/man:$MANPATH\"\n", .{env_mountpoint});
        defer self.allocator.free(man_export);
        try file.writeAll(man_export);

        const echo_msg = try std.fmt.allocPrint(self.allocator, "\necho \"Axiom environment '{s}' activated\"\n", .{env_name});
        defer self.allocator.free(echo_msg);
        try file.writeAll(echo_msg);

        try file.writeAll("echo \"To deactivate, run: deactivate\"\n\n");
        try file.writeAll("deactivate() {\n");
        try file.writeAll("  unset AXIOM_ENV\n");
        try file.writeAll("  # PATH and other vars are inherited from parent shell\n");
        try file.writeAll("  echo \"Environment deactivated\"\n");
        try file.writeAll("}\n");
    }

    /// Activate an environment (mount to standard location)
    pub fn activate(
        self: *RealizationEngine,
        env_name: []const u8,
    ) !void {
        const env_dataset = try std.fmt.allocPrint(
            self.allocator,
            "{s}/{s}",
            .{ self.env_root, env_name },
        );
        defer self.allocator.free(env_dataset);

        // Verify environment exists
        const exists = try self.zfs_handle.datasetExists(
            self.allocator,
            env_dataset,
            .filesystem,
        );

        if (!exists) {
            return RealizationError.EnvironmentNotFound;
        }

        std.debug.print("Activating environment: {s}\n", .{env_name});
        
        const env_mountpoint = try self.zfs_handle.getMountpoint(
            self.allocator,
            env_dataset,
        );
        defer self.allocator.free(env_mountpoint);

        std.debug.print("  Mountpoint: {s}\n", .{env_mountpoint});
        std.debug.print("\nTo activate in your shell, run:\n", .{});
        std.debug.print("  source {s}/activate\n", .{env_mountpoint});
    }

    /// Deactivate an environment
    pub fn deactivate(
        self: *RealizationEngine,
        env_name: []const u8,
    ) !void {
        _ = self;
        std.debug.print("Deactivating environment: {s}\n", .{env_name});
        std.debug.print("Run: deactivate\n", .{});
    }

    /// Destroy an environment
    pub fn destroy(
        self: *RealizationEngine,
        env_name: []const u8,
    ) !void {
        const env_dataset = try std.fmt.allocPrint(
            self.allocator,
            "{s}/{s}",
            .{ self.env_root, env_name },
        );
        defer self.allocator.free(env_dataset);

        std.debug.print("Destroying environment: {s}\n", .{env_name});

        // Destroy dataset (this unmounts and removes everything)
        try self.zfs_handle.destroyDataset(self.allocator, env_dataset, true);

        std.debug.print("  ✓ Environment destroyed\n", .{});
    }

    /// List all environments
    /// Queries ZFS datasets under env_root to enumerate all realized environments
    pub fn listEnvironments(
        self: *RealizationEngine,
    ) ![][]const u8 {
        var envs: std.ArrayList([]const u8) = .empty;
        errdefer {
            for (envs.items) |env| {
                self.allocator.free(env);
            }
            envs.deinit(self.allocator);
        }

        // Get mountpoint for the env root
        const env_mountpoint = self.zfs_handle.getMountpoint(
            self.allocator,
            self.env_root,
        ) catch {
            // Env root doesn't exist or isn't mounted
            return envs.toOwnedSlice(self.allocator);
        };
        defer self.allocator.free(env_mountpoint);

        // Open the environments directory
        var env_dir = std.fs.cwd().openDir(env_mountpoint, .{ .iterate = true }) catch {
            return envs.toOwnedSlice(self.allocator);
        };
        defer env_dir.close();

        // Iterate through environments
        var iter = env_dir.iterate();
        while (try iter.next()) |entry| {
            if (entry.kind != .directory) continue;

            try envs.append(self.allocator, try self.allocator.dupe(u8, entry.name));
        }

        return envs.toOwnedSlice(self.allocator);
    }

    /// Get environment information
    pub fn getEnvironment(
        self: *RealizationEngine,
        env_name: []const u8,
    ) !Environment {
        const env_dataset = try std.fmt.allocPrint(
            self.allocator,
            "{s}/{s}",
            .{ self.env_root, env_name },
        );
        defer self.allocator.free(env_dataset);

        const exists = try self.zfs_handle.datasetExists(
            self.allocator,
            env_dataset,
            .filesystem,
        );

        if (!exists) {
            return RealizationError.EnvironmentNotFound;
        }

        // TODO: Read metadata to get profile name and packages
        // For now, return minimal environment info
        return Environment{
            .name = try self.allocator.dupe(u8, env_name),
            .profile_name = try self.allocator.dupe(u8, "unknown"),
            .dataset_path = try self.allocator.dupe(u8, env_dataset),
            .packages = &[_]PackageId{},
            .active = false,
        };
    }
};

/// Copy a file from source to destination, creating directories as needed
fn copyFile(src_path: []const u8, dst_path: []const u8) !void {
    // Create parent directory if needed
    if (std.fs.path.dirname(dst_path)) |parent| {
        std.fs.cwd().makePath(parent) catch |err| {
            if (err != error.PathAlreadyExists) return err;
        };
    }

    // Open source file
    const src_file = try std.fs.cwd().openFile(src_path, .{});
    defer src_file.close();

    // Get source file stats for permissions
    const stat = try src_file.stat();

    // Create destination file with same permissions
    const dst_file = try std.fs.cwd().createFile(dst_path, .{
        .mode = @intCast(stat.mode & 0o7777),
    });
    defer dst_file.close();

    // Copy content in chunks
    var buffer: [8192]u8 = undefined;
    while (true) {
        const bytes_read = try src_file.read(&buffer);
        if (bytes_read == 0) break;
        try dst_file.writeAll(buffer[0..bytes_read]);
    }
}

/// Copy a directory recursively from source to destination
fn copyDirRecursive(
    allocator: std.mem.Allocator,
    src_dir: []const u8,
    dst_dir: []const u8,
    pkg_id: PackageId,
    env_files: *std.StringHashMap(PackageId),
    tracker: *ConflictTracker,
) !usize {
    var conflicts_found: usize = 0;

    // Open source directory
    var dir = std.fs.cwd().openDir(src_dir, .{ .iterate = true }) catch |err| {
        if (err == error.FileNotFound or err == error.NotDir) return 0;
        return err;
    };
    defer dir.close();

    // Create destination directory
    std.fs.cwd().makePath(dst_dir) catch |err| {
        if (err != error.PathAlreadyExists) return err;
    };

    var iter = dir.iterate();
    while (try iter.next()) |entry| {
        const src_path = try std.fs.path.join(allocator, &[_][]const u8{ src_dir, entry.name });
        defer allocator.free(src_path);

        const dst_path = try std.fs.path.join(allocator, &[_][]const u8{ dst_dir, entry.name });
        defer allocator.free(dst_path);

        switch (entry.kind) {
            .directory => {
                // Recurse into subdirectory
                conflicts_found += try copyDirRecursive(
                    allocator,
                    src_path,
                    dst_path,
                    pkg_id,
                    env_files,
                    tracker,
                );
            },
            .file => {
                // Get relative path for tracking
                const rel_path = try allocator.dupe(u8, entry.name);

                // Check if file already exists from another package
                if (env_files.get(rel_path)) |existing_pkg| {
                    // In this branch, rel_path is not stored in env_files, so we must free it
                    defer allocator.free(rel_path);

                    // Potential conflict
                    if (try tracker.checkFileConflict(
                        rel_path,
                        existing_pkg,
                        dst_path,
                        pkg_id,
                        src_path,
                    )) |file_conflict| {
                        try tracker.recordConflict(file_conflict);
                        conflicts_found += 1;

                        // Resolve and apply
                        const resolution = try tracker.resolveConflict(file_conflict);
                        switch (resolution) {
                            .use_package => |selected_pkg| {
                                if (std.mem.eql(u8, selected_pkg.name, pkg_id.name)) {
                                    try copyFile(src_path, dst_path);
                                }
                            },
                            .keep_both => {
                                const renamed = try conflict.applyRenameStrategy(
                                    allocator,
                                    dst_path,
                                    pkg_id.name,
                                    .{ .pattern = "{name}.{package}{ext}" },
                                );
                                defer allocator.free(renamed);
                                try copyFile(src_path, renamed);
                            },
                            .skip => {},
                            .@"error" => {},
                            .rename => |strategy| {
                                const renamed = try conflict.applyRenameStrategy(
                                    allocator,
                                    dst_path,
                                    pkg_id.name,
                                    strategy,
                                );
                                defer allocator.free(renamed);
                                try copyFile(src_path, renamed);
                            },
                            .merge => {},
                        }
                    }
                } else {
                    // No conflict - copy file
                    try copyFile(src_path, dst_path);
                    try env_files.put(rel_path, pkg_id);
                }
            },
            .sym_link => {
                // Handle symlinks
                var target_buf: [std.fs.max_path_bytes]u8 = undefined;
                const target = try dir.readLink(entry.name, &target_buf);
                try std.fs.cwd().symLink(target, dst_path, .{});
            },
            else => {},
        }
    }

    return conflicts_found;
}

/// Copy a directory recursively with spec-aware merge strategy (Phase 44)
fn copyDirRecursiveWithSpec(
    allocator: std.mem.Allocator,
    src_dir: []const u8,
    dst_dir: []const u8,
    pkg_id: PackageId,
    env_files: *std.StringHashMap(PackageId),
    tracker: *ConflictTracker,
    spec: *const RealizationSpec,
    output_sel: ?*const realization_spec.OutputSelection,
) !usize {
    var conflicts_found: usize = 0;

    // Open source directory
    var dir = std.fs.cwd().openDir(src_dir, .{ .iterate = true }) catch |err| {
        if (err == error.FileNotFound or err == error.NotDir) return 0;
        return err;
    };
    defer dir.close();

    // Create destination directory
    std.fs.cwd().makePath(dst_dir) catch |err| {
        if (err != error.PathAlreadyExists) return err;
    };

    var iter = dir.iterate();
    while (try iter.next()) |entry| {
        const src_path = try std.fs.path.join(allocator, &[_][]const u8{ src_dir, entry.name });
        defer allocator.free(src_path);

        const dst_path = try std.fs.path.join(allocator, &[_][]const u8{ dst_dir, entry.name });
        defer allocator.free(dst_path);

        // Get relative path for output filtering
        const rel_path_from_root = getRelativePathFromPkgRoot(src_path, src_dir) catch entry.name;

        // Check if this path matches the output selection (if specified)
        if (output_sel) |sel| {
            if (!pathMatchesOutputSelection(rel_path_from_root, sel)) {
                continue; // Skip files not in selected outputs
            }
        }

        switch (entry.kind) {
            .directory => {
                // Recurse into subdirectory
                conflicts_found += try copyDirRecursiveWithSpec(
                    allocator,
                    src_path,
                    dst_path,
                    pkg_id,
                    env_files,
                    tracker,
                    spec,
                    output_sel,
                );
            },
            .file => {
                // Determine merge strategy for this file
                const strategy = spec.getStrategyForPath(rel_path_from_root);

                // Apply the appropriate strategy
                switch (strategy) {
                    .symlink => {
                        // Create symlink to source
                        std.fs.cwd().deleteFile(dst_path) catch {};
                        try std.fs.cwd().symLink(src_path, dst_path, .{});
                    },
                    .hardlink => {
                        // Create hardlink
                        std.fs.cwd().deleteFile(dst_path) catch {};
                        const src_file = try std.fs.cwd().openFile(src_path, .{});
                        src_file.close();
                        // Note: hardLink requires same filesystem
                        try std.posix.link(src_path, dst_path);
                    },
                    .copy => {
                        // Copy the file
                        try copyFile(src_path, dst_path);
                    },
                    .zfs_clone => {
                        // For ZFS clone, we'd use ZFS cloning at dataset level
                        // For file-level, fall back to symlink
                        std.fs.cwd().deleteFile(dst_path) catch {};
                        try std.fs.cwd().symLink(src_path, dst_path, .{});
                    },
                }

                // Track file for conflict detection
                const rel_path = try allocator.dupe(u8, entry.name);
                if (env_files.get(rel_path)) |_| {
                    allocator.free(rel_path);
                    conflicts_found += 1;
                } else {
                    try env_files.put(rel_path, pkg_id);
                }
            },
            .sym_link => {
                // Handle symlinks (always copy as symlink)
                var target_buf: [std.fs.max_path_bytes]u8 = undefined;
                const target = try dir.readLink(entry.name, &target_buf);
                std.fs.cwd().deleteFile(dst_path) catch {};
                try std.fs.cwd().symLink(target, dst_path, .{});
            },
            else => {},
        }
    }

    return conflicts_found;
}

/// Get relative path from package root (helper for output filtering)
fn getRelativePathFromPkgRoot(full_path: []const u8, base_path: []const u8) ![]const u8 {
    if (std.mem.startsWith(u8, full_path, base_path)) {
        var result = full_path[base_path.len..];
        if (result.len > 0 and result[0] == '/') {
            result = result[1..];
        }
        return result;
    }
    return full_path;
}

/// Check if a path matches the output selection
fn pathMatchesOutputSelection(path: []const u8, sel: *const realization_spec.OutputSelection) bool {
    // If "*" is in outputs, include everything
    if (sel.includesAll()) return true;

    // Check against standard output patterns
    for (sel.outputs) |output_name| {
        if (std.mem.eql(u8, output_name, "bin")) {
            if (std.mem.startsWith(u8, path, "bin/") or std.mem.startsWith(u8, path, "sbin/")) return true;
        }
        if (std.mem.eql(u8, output_name, "lib")) {
            if (std.mem.startsWith(u8, path, "lib/")) {
                // Check for .so files
                if (std.mem.indexOf(u8, path, ".so") != null) return true;
            }
        }
        if (std.mem.eql(u8, output_name, "dev")) {
            if (std.mem.startsWith(u8, path, "include/")) return true;
            if (std.mem.startsWith(u8, path, "lib/") and std.mem.endsWith(u8, path, ".a")) return true;
            if (std.mem.indexOf(u8, path, "pkgconfig/") != null) return true;
        }
        if (std.mem.eql(u8, output_name, "doc")) {
            if (std.mem.startsWith(u8, path, "share/doc/")) return true;
            if (std.mem.startsWith(u8, path, "share/man/")) return true;
            if (std.mem.startsWith(u8, path, "share/info/")) return true;
        }
        if (std.mem.eql(u8, output_name, "data")) {
            if (std.mem.startsWith(u8, path, "share/")) return true;
        }
    }

    return false;
}

/// Copy a directory recursively without conflict tracking (simple merge)
/// This is a simpler version of copyDirRecursive for legacy use
fn copyDirRecursiveSimple(
    allocator: std.mem.Allocator,
    src_dir: []const u8,
    dst_dir: []const u8,
) !void {
    // Open source directory
    var dir = std.fs.cwd().openDir(src_dir, .{ .iterate = true }) catch |err| {
        if (err == error.FileNotFound or err == error.NotDir) return;
        return err;
    };
    defer dir.close();

    // Create destination directory
    std.fs.cwd().makePath(dst_dir) catch |err| {
        if (err != error.PathAlreadyExists) return err;
    };

    var iter = dir.iterate();
    while (try iter.next()) |entry| {
        const src_path = try std.fs.path.join(allocator, &[_][]const u8{ src_dir, entry.name });
        defer allocator.free(src_path);

        const dst_path = try std.fs.path.join(allocator, &[_][]const u8{ dst_dir, entry.name });
        defer allocator.free(dst_path);

        switch (entry.kind) {
            .directory => {
                // Recurse into subdirectory
                try copyDirRecursiveSimple(allocator, src_path, dst_path);
            },
            .file => {
                // Check if destination exists - skip if it does (no-clobber behavior)
                const dst_exists = std.fs.cwd().access(dst_path, .{}) catch |err| {
                    if (err == error.FileNotFound) {
                        // File doesn't exist, safe to copy
                        try copyFile(src_path, dst_path);
                    }
                    // Other errors - skip this file
                    continue;
                };
                _ = dst_exists;
                // File exists, skip (no-clobber)
            },
            .sym_link => {
                // Handle symlinks - skip if destination exists
                const dst_exists = std.fs.cwd().access(dst_path, .{}) catch |err| {
                    if (err == error.FileNotFound) {
                        var target_buf: [std.fs.max_path_bytes]u8 = undefined;
                        const target = dir.readLink(entry.name, &target_buf) catch continue;
                        std.fs.cwd().symLink(target, dst_path, .{}) catch {};
                    }
                    continue;
                };
                _ = dst_exists;
                // Symlink destination exists, skip
            },
            else => {},
        }
    }
}

/// Free environment memory
pub fn freeEnvironment(env: *Environment, allocator: std.mem.Allocator) void {
    allocator.free(env.name);
    allocator.free(env.profile_name);
    allocator.free(env.dataset_path);
    for (env.packages) |pkg| {
        allocator.free(pkg.name);
        allocator.free(pkg.build_id);
    }
    allocator.free(env.packages);
}
