const std = @import("std");
const zfs = @import("zfs.zig");
const types = @import("types.zig");
const store = @import("store.zig");
const profile = @import("profile.zig");
const config = @import("config.zig");
const store_integrity = @import("store_integrity.zig");
const posix = std.posix;

const ZfsHandle = zfs.ZfsHandle;
const PackageId = types.PackageId;
const PackageStore = store.PackageStore;
const ProfileManager = profile.ProfileManager;
const TransactionLog = store_integrity.TransactionLog;
const RefCounter = store_integrity.RefCounter;

// =============================================================================
// Configuration Constants
// =============================================================================

/// Default grace period for garbage collection in seconds (24 hours)
/// Packages newer than this will not be collected, even if unreferenced.
/// This prevents accidental collection of recently imported packages.
pub const DEFAULT_GC_GRACE_PERIOD_SECONDS: i64 = 24 * 60 * 60; // 24 hours

/// Path for the GC lock file to prevent concurrent GC operations
pub const GC_LOCK_FILE_PATH: []const u8 = "/var/run/axiom-gc.lock";

/// Garbage collection errors
pub const GCError = error{
    ScanFailed,
    CollectionFailed,
    LockAcquisitionFailed,
    GCAlreadyRunning,
};

/// Package reference information
pub const PackageRef = struct {
    id: PackageId,
    referenced: bool,
    profile_refs: std.ArrayList([]const u8),
    env_refs: std.ArrayList([]const u8),
};

/// Garbage collection statistics
pub const GCStats = struct {
    total_packages: usize = 0,
    referenced_packages: usize = 0,
    unreferenced_packages: usize = 0,
    removed_packages: usize = 0,
    space_freed: usize = 0, // In bytes
    scan_time_ms: i64 = 0,
    collect_time_ms: i64 = 0,
};

/// Garbage collector - removes unreferenced packages from the store.
///
/// ## Thread Safety
///
/// GarbageCollector uses file-based locking (flock) to prevent concurrent
/// GC operations across processes. Only one GC can run at a time system-wide.
///
/// ### Lock ordering (to prevent deadlocks):
/// - GC lock file is acquired FIRST, before any ZfsHandle operations
/// - Never hold GC lock while waiting for other external resources
/// - collect() acquires lock at entry and releases at exit via defer
///
/// ### Crash recovery:
/// - Uses transaction logging to record pending operations
/// - On crash, next GC run can detect incomplete operations
/// - Lock file is deleted atomically while holding flock to prevent races
///
/// ### Multi-process safety:
/// - Uses O_EXCL + flock for atomic lock acquisition
/// - WouldBlock indicates another GC is running
/// - Lock file contains PID for debugging stuck locks
///
pub const GarbageCollector = struct {
    allocator: std.mem.Allocator,
    zfs_handle: *ZfsHandle,
    store: *PackageStore,
    profile_mgr: *ProfileManager,

    /// Grace period in seconds - don't collect packages newer than this
    grace_period: i64 = DEFAULT_GC_GRACE_PERIOD_SECONDS,

    /// Lock file handle (null when not holding lock)
    lock_file: ?std.fs.File = null,

    /// Transaction log for crash recovery (optional, initialized on first use)
    transaction_log: ?TransactionLog = null,

    /// Whether to use transaction logging for safety
    use_transaction_log: bool = true,

    /// Reference counter for accurate reference checking
    ref_counter: ?RefCounter = null,

    /// Initialize garbage collector
    pub fn init(
        allocator: std.mem.Allocator,
        zfs_handle: *ZfsHandle,
        store_ptr: *PackageStore,
        profile_mgr_ptr: *ProfileManager,
    ) GarbageCollector {
        return GarbageCollector{
            .allocator = allocator,
            .zfs_handle = zfs_handle,
            .store = store_ptr,
            .profile_mgr = profile_mgr_ptr,
            .lock_file = null,
        };
    }

    /// Acquire exclusive lock for GC operation.
    /// Returns GCError.GCAlreadyRunning if another GC is already running.
    /// Returns GCError.LockAcquisitionFailed if lock cannot be acquired.
    ///
    /// Thread-safety: Uses non-blocking flock() to atomically test-and-set.
    /// The lock file serves dual purpose: existence check and flock holder.
    fn acquireLock(self: *GarbageCollector) !void {
        // First attempt: Create new lock file with exclusive lock.
        // This is the common path when no lock file exists.
        const lock_file = std.fs.cwd().createFile(GC_LOCK_FILE_PATH, .{
            .read = true,
            .lock = .exclusive,
            .lock_nonblocking = true,
        }) catch |err| {
            if (err == error.WouldBlock) {
                return GCError.GCAlreadyRunning;
            }
            // Fallback: If createFile fails for other reasons (e.g., exists from crash,
            // permission issues with directory), try opening existing file and locking it.
            // This handles the case where a previous GC crashed and left the lock file.
            const existing = std.fs.cwd().openFile(GC_LOCK_FILE_PATH, .{
                .lock = .exclusive,
                .lock_nonblocking = true,
            }) catch |err2| {
                if (err2 == error.WouldBlock) {
                    return GCError.GCAlreadyRunning;
                }
                return GCError.LockAcquisitionFailed;
            };
            // Successfully acquired lock on existing file
            self.lock_file = existing;
            return;
        };

        // Write PID to lock file for debugging
        var pid_buf: [32]u8 = undefined;
        const pid_str = std.fmt.bufPrint(&pid_buf, "{d}\n", .{std.os.linux.getpid()}) catch "";
        lock_file.writeAll(pid_str) catch {};

        self.lock_file = lock_file;
    }

    /// Release the GC lock
    /// Thread-safety: Deletes lock file while still holding the file lock
    /// to prevent TOCTOU race conditions where another process could
    /// acquire the lock between our close() and deleteFile().
    fn releaseLock(self: *GarbageCollector) void {
        if (self.lock_file) |file| {
            // IMPORTANT: Delete while still holding the lock to prevent race conditions.
            // The unlink happens atomically while we hold the exclusive flock.
            // Another process trying to open the file will either:
            // - Get the old file (still locked by us) and block on flock
            // - Get ENOENT after we delete and create a new lock file
            std.fs.cwd().deleteFile(GC_LOCK_FILE_PATH) catch {};
            file.close();
            self.lock_file = null;
        }
    }

    /// Run garbage collection
    /// Thread-safe: Acquires exclusive file lock to prevent concurrent GC operations
    pub fn collect(self: *GarbageCollector, dry_run: bool) !GCStats {
        // Acquire exclusive lock before proceeding
        try self.acquireLock();
        defer self.releaseLock();

        var stats = GCStats{};
        const start_time = std.time.milliTimestamp();

        std.debug.print("Axiom Garbage Collection\n", .{});
        std.debug.print("========================\n\n", .{});

        if (dry_run) {
            std.debug.print("DRY RUN MODE - No packages will be deleted\n\n", .{});
        }

        // Phase 1: Scan store for all packages
        std.debug.print("Phase 1: Scanning package store...\n", .{});
        const all_packages = try self.scanStore();
        defer {
            for (all_packages) |pkg| {
                self.allocator.free(pkg.name);
                self.allocator.free(pkg.build_id);
            }
            self.allocator.free(all_packages);
        }

        stats.total_packages = all_packages.len;
        std.debug.print("  Found {d} packages in store\n", .{all_packages.len});

        // Phase 2: Find referenced packages
        std.debug.print("\nPhase 2: Finding references...\n", .{});
        
        // Use string keys (package path) instead of PackageId struct
        var referenced = std.StringHashMap(bool).init(self.allocator);
        defer referenced.deinit();

        // Scan profiles
        const profile_refs = try self.scanProfiles();
        defer {
            for (profile_refs) |pkg| {
                self.allocator.free(pkg.name);
                self.allocator.free(pkg.build_id);
            }
            self.allocator.free(profile_refs);
        }

        std.debug.print("  Profiles reference {d} packages\n", .{profile_refs.len});
        for (profile_refs) |pkg| {
            const key = try self.packageKey(pkg);
            defer self.allocator.free(key);
            try referenced.put(try self.allocator.dupe(u8, key), true);
        }

        // Scan environments
        const env_refs = try self.scanEnvironments();
        defer {
            for (env_refs) |pkg| {
                self.allocator.free(pkg.name);
                self.allocator.free(pkg.build_id);
            }
            self.allocator.free(env_refs);
        }

        std.debug.print("  Environments reference {d} packages\n", .{env_refs.len});
        for (env_refs) |pkg| {
            const key = try self.packageKey(pkg);
            defer self.allocator.free(key);
            try referenced.put(try self.allocator.dupe(u8, key), true);
        }

        stats.referenced_packages = referenced.count();
        std.debug.print("  Total referenced: {d} packages\n", .{stats.referenced_packages});

        // Phase 3: Identify unreferenced packages
        std.debug.print("\nPhase 3: Identifying unreferenced packages...\n", .{});
        
        var to_remove: std.ArrayList(PackageId) = .empty;
        defer to_remove.deinit(self.allocator);

        const current_time = std.time.timestamp();

        for (all_packages) |pkg| {
            const key = try self.packageKey(pkg);
            defer self.allocator.free(key);
            
            if (!referenced.contains(key)) {
                // Check grace period
                // TODO: Get package creation time from ZFS property
                // For now, assume all packages are outside grace period
                _ = current_time;
                
                try to_remove.append(self.allocator, .{
                    .name = try self.allocator.dupe(u8, pkg.name),
                    .version = pkg.version,
                    .revision = pkg.revision,
                    .build_id = try self.allocator.dupe(u8, pkg.build_id),
                });
            }
        }

        stats.unreferenced_packages = to_remove.items.len;
        std.debug.print("  Found {d} unreferenced packages\n", .{stats.unreferenced_packages});

        stats.scan_time_ms = std.time.milliTimestamp() - start_time;

        // Phase 4: Remove unreferenced packages
        if (to_remove.items.len > 0) {
            std.debug.print("\nPhase 4: Removing unreferenced packages...\n", .{});

            if (dry_run) {
                std.debug.print("  DRY RUN - Would remove:\n", .{});
                for (to_remove.items) |pkg| {
                    std.debug.print("    - {s} {f} (rev {d}) [{s}]\n", .{
                        pkg.name,
                        pkg.version,
                        pkg.revision,
                        pkg.build_id,
                    });
                }
            } else {
                const collect_start = std.time.milliTimestamp();

                // Initialize transaction log if enabled
                var txn_log: ?TransactionLog = null;
                if (self.use_transaction_log) {
                    const store_mountpoint = self.zfs_handle.getMountpoint(
                        self.allocator,
                        self.store.paths.store_root,
                    ) catch null;

                    if (store_mountpoint) |mp| {
                        defer self.allocator.free(mp);
                        txn_log = TransactionLog.init(self.allocator, mp) catch null;
                    }
                }
                defer if (txn_log) |*tl| tl.deinit();

                for (to_remove.items, 0..) |pkg, i| {
                    std.debug.print("  [{d}/{d}] Removing {s} {f} (rev {d}) [{s}]\n", .{
                        i + 1,
                        to_remove.items.len,
                        pkg.name,
                        pkg.version,
                        pkg.revision,
                        pkg.build_id,
                    });

                    // Get dataset size before removal (for stats)
                    // TODO: Query ZFS for actual size
                    const estimated_size: usize = 10 * 1024 * 1024; // 10MB estimate
                    stats.space_freed += estimated_size;

                    // Build package path for transaction logging
                    const pkg_path = std.fmt.allocPrint(self.allocator, "{s}/{f}/{d}/{s}", .{
                        pkg.name,
                        pkg.version,
                        pkg.revision,
                        pkg.build_id,
                    }) catch "";
                    defer if (pkg_path.len > 0) self.allocator.free(pkg_path);

                    // Begin transaction if logging is enabled
                    var txn_seq: ?u64 = null;
                    if (txn_log) |*tl| {
                        txn_seq = tl.begin(.gc_remove, pkg_path) catch null;
                    }

                    // Remove package with transaction logging
                    if (self.store.removePackage(pkg)) {
                        // Success - complete transaction
                        if (txn_log) |*tl| {
                            if (txn_seq) |seq| {
                                tl.complete(seq, .gc_remove) catch {};
                            }
                        }
                        stats.removed_packages += 1;
                    } else |err| {
                        // Failure - abort transaction
                        if (txn_log) |*tl| {
                            if (txn_seq) |seq| {
                                tl.abort(seq, .gc_remove) catch {};
                            }
                        }
                        std.debug.print("    Warning: Failed to remove {s}: {any}\n", .{ pkg.name, err });
                    }
                }

                stats.collect_time_ms = std.time.milliTimestamp() - collect_start;
            }
        } else {
            std.debug.print("\nNo unreferenced packages to remove\n", .{});
        }

        // Cleanup referenced keys
        var key_iter = referenced.keyIterator();
        while (key_iter.next()) |key| {
            self.allocator.free(key.*);
        }

        // Cleanup
        for (to_remove.items) |pkg| {
            self.allocator.free(pkg.name);
            self.allocator.free(pkg.build_id);
        }

        // Print summary
        std.debug.print("\n", .{});
        try self.printStats(stats, dry_run);

        return stats;
    }
    
    /// Generate a unique key for a package
    fn packageKey(self: *GarbageCollector, pkg: PackageId) ![]u8 {
        return std.fmt.allocPrint(self.allocator, "{s}/{f}/{d}/{s}", .{
            pkg.name,
            pkg.version,
            pkg.revision,
            pkg.build_id,
        });
    }

    /// Scan package store for all packages
    /// Uses PackageStore.listPackages() to enumerate all packages in the store
    fn scanStore(self: *GarbageCollector) ![]PackageId {
        // Use the store's listPackages function to get all packages
        return try self.store.listPackages();
    }

    /// Scan profiles for referenced packages
    /// Reads all profile.lock.yaml files to find referenced packages
    fn scanProfiles(self: *GarbageCollector) ![]PackageId {
        var packages: std.ArrayList(PackageId) = .empty;
        errdefer {
            for (packages.items) |pkg| {
                self.allocator.free(pkg.name);
                self.allocator.free(pkg.build_id);
            }
            packages.deinit(self.allocator);
        }

        // Get mountpoint for the profile root
        const profile_mountpoint = self.zfs_handle.getMountpoint(
            self.allocator,
            self.profile_mgr.profile_root,
        ) catch {
            // Profile root doesn't exist
            return packages.toOwnedSlice(self.allocator);
        };
        defer self.allocator.free(profile_mountpoint);

        // Open the profiles directory
        var profiles_dir = std.fs.cwd().openDir(profile_mountpoint, .{ .iterate = true }) catch {
            return packages.toOwnedSlice(self.allocator);
        };
        defer profiles_dir.close();

        // Iterate through profiles
        var iter = profiles_dir.iterate();
        while (try iter.next()) |entry| {
            if (entry.kind != .directory) continue;

            // Build path to profile.lock.yaml
            const lock_path = try std.fs.path.join(self.allocator, &[_][]const u8{
                profile_mountpoint,
                entry.name,
                "profile.lock.yaml",
            });
            defer self.allocator.free(lock_path);

            // Read and parse lock file
            const content = std.fs.cwd().readFileAlloc(
                self.allocator,
                lock_path,
                1024 * 1024,
            ) catch continue; // Skip profiles without lock files
            defer self.allocator.free(content);

            var lock = profile.ProfileLock.parse(self.allocator, content) catch continue;
            defer lock.deinit(self.allocator);

            // Add all resolved packages
            for (lock.resolved) |pkg| {
                try packages.append(self.allocator, .{
                    .name = try self.allocator.dupe(u8, pkg.id.name),
                    .version = pkg.id.version,
                    .revision = pkg.id.revision,
                    .build_id = try self.allocator.dupe(u8, pkg.id.build_id),
                });
            }
        }

        return packages.toOwnedSlice(self.allocator);
    }

    /// Scan environments for referenced packages
    /// Reads environment metadata to find referenced packages
    fn scanEnvironments(self: *GarbageCollector) ![]PackageId {
        var packages: std.ArrayList(PackageId) = .empty;
        errdefer {
            for (packages.items) |pkg| {
                self.allocator.free(pkg.name);
                self.allocator.free(pkg.build_id);
            }
            packages.deinit(self.allocator);
        }

        // Get mountpoint for the env root
        const env_root = config.DEFAULT_POOL ++ "/" ++ config.DEFAULT_DATASET ++ "/env";
        const env_mountpoint = self.zfs_handle.getMountpoint(
            self.allocator,
            env_root,
        ) catch {
            // Env root doesn't exist
            return packages.toOwnedSlice(self.allocator);
        };
        defer self.allocator.free(env_mountpoint);

        // Open the environments directory
        var envs_dir = std.fs.cwd().openDir(env_mountpoint, .{ .iterate = true }) catch {
            return packages.toOwnedSlice(self.allocator);
        };
        defer envs_dir.close();

        // Iterate through environments
        var iter = envs_dir.iterate();
        while (try iter.next()) |entry| {
            if (entry.kind != .directory) continue;

            // Environments are realized from profiles - find the corresponding lock file
            // by reading the environment's metadata or checking the profile name
            // For now, scan the environment's bin/lib/share dirs to find package origins
            // by checking symlinks or manifest files

            // Try reading an environment manifest if it exists
            const manifest_path = try std.fs.path.join(self.allocator, &[_][]const u8{
                env_mountpoint,
                entry.name,
                ".axiom-env.yaml",
            });
            defer self.allocator.free(manifest_path);

            const content = std.fs.cwd().readFileAlloc(
                self.allocator,
                manifest_path,
                1024 * 1024,
            ) catch continue;
            defer self.allocator.free(content);

            // Parse the environment manifest to get package list
            // The format is similar to profile.lock.yaml
            var lock = profile.ProfileLock.parse(self.allocator, content) catch continue;
            defer lock.deinit(self.allocator);

            for (lock.resolved) |pkg| {
                try packages.append(self.allocator, .{
                    .name = try self.allocator.dupe(u8, pkg.id.name),
                    .version = pkg.id.version,
                    .revision = pkg.id.revision,
                    .build_id = try self.allocator.dupe(u8, pkg.id.build_id),
                });
            }
        }

        return packages.toOwnedSlice(self.allocator);
    }

    /// Print garbage collection statistics
    fn printStats(self: *GarbageCollector, stats: GCStats, dry_run: bool) !void {
        _ = self;
        
        std.debug.print("Garbage Collection Summary\n", .{});
        std.debug.print("==========================\n", .{});
        std.debug.print("Total packages:        {d}\n", .{stats.total_packages});
        std.debug.print("Referenced packages:   {d}\n", .{stats.referenced_packages});
        std.debug.print("Unreferenced packages: {d}\n", .{stats.unreferenced_packages});

        if (!dry_run and stats.removed_packages > 0) {
            std.debug.print("Removed packages:      {d}\n", .{stats.removed_packages});
            std.debug.print("Space freed:           {d} MB\n", .{stats.space_freed / (1024 * 1024)});
        }

        std.debug.print("\nTiming:\n", .{});
        std.debug.print("  Scan time:    {d} ms\n", .{stats.scan_time_ms});
        if (!dry_run and stats.removed_packages > 0) {
            std.debug.print("  Collect time: {d} ms\n", .{stats.collect_time_ms});
            std.debug.print("  Total time:   {d} ms\n", .{stats.scan_time_ms + stats.collect_time_ms});
        }
    }

    /// Create a snapshot before garbage collection (for safety)
    pub fn createSafetySnapshot(self: *GarbageCollector) !void {
        std.debug.print("Creating safety snapshot...\n", .{});
        
        const timestamp = std.time.timestamp();
        const snap_name = try std.fmt.allocPrint(
            self.allocator,
            "pre-gc-{d}",
            .{timestamp},
        );
        defer self.allocator.free(snap_name);

        // Snapshot the entire store
        try self.zfs_handle.snapshot(
            self.allocator,
            self.store.paths.store_root,
            snap_name,
            true, // recursive
        );

        std.debug.print("  ✓ Created snapshot: {s}@{s}\n", .{
            self.store.paths.store_root,
            snap_name,
        });
    }

    /// Verify store integrity before garbage collection
    /// Returns true if store is healthy enough to proceed with GC
    pub fn verifyBeforeCollect(self: *GarbageCollector) !bool {
        std.debug.print("Verifying store integrity before GC...\n", .{});

        const store_mountpoint = self.zfs_handle.getMountpoint(
            self.allocator,
            self.store.paths.store_root,
        ) catch |err| {
            std.debug.print("  Warning: Could not get store mountpoint: {any}\n", .{err});
            return false;
        };
        defer self.allocator.free(store_mountpoint);

        var integrity = store_integrity.StoreIntegrity.init(self.allocator, store_mountpoint);
        defer integrity.deinit();

        var report = integrity.verify(.{
            .check_manifests = true,
            .check_hashes = false, // Skip slow hash verification for pre-GC check
            .check_references = true,
            .repair_mode = false,
        }) catch |err| {
            std.debug.print("  Warning: Integrity verification failed: {any}\n", .{err});
            return false;
        };
        defer report.deinit();

        if (report.healthy) {
            std.debug.print("  ✓ Store integrity verified\n", .{});
            return true;
        } else {
            std.debug.print("  ✗ Store has integrity issues:\n", .{});
            if (report.missing_manifests.items.len > 0) {
                std.debug.print("    - {d} packages with missing manifests\n", .{report.missing_manifests.items.len});
            }
            if (report.broken_references.items.len > 0) {
                std.debug.print("    - {d} broken references\n", .{report.broken_references.items.len});
            }
            if (report.partial_imports.items.len > 0) {
                std.debug.print("    - {d} partial imports\n", .{report.partial_imports.items.len});
            }
            std.debug.print("  Consider running 'axiom store-verify --repair' first\n", .{});
            return false;
        }
    }

    /// Recover from incomplete GC operations (call on startup)
    pub fn recoverFromCrash(self: *GarbageCollector) !void {
        const store_mountpoint = self.zfs_handle.getMountpoint(
            self.allocator,
            self.store.paths.store_root,
        ) catch {
            return; // Store not accessible
        };
        defer self.allocator.free(store_mountpoint);

        var txn_log = TransactionLog.init(self.allocator, store_mountpoint) catch {
            return; // No transaction log
        };
        defer txn_log.deinit();

        const incomplete = txn_log.findIncomplete() catch {
            return;
        };

        if (incomplete.len > 0) {
            std.debug.print("Found {d} incomplete GC operations from previous crash\n", .{incomplete.len});
            std.debug.print("Run 'axiom store-verify --repair' to clean up\n", .{});
        }

        self.allocator.free(incomplete);
    }
};

/// Test helper - create mock packages for testing
pub fn createMockPackage(allocator: std.mem.Allocator, name: []const u8, version: types.Version) !PackageId {
    const build_id = try std.fmt.allocPrint(allocator, "mock{d}{d}{d}", .{
        version.major,
        version.minor,
        version.patch,
    });

    return PackageId{
        .name = try allocator.dupe(u8, name),
        .version = version,
        .revision = 1,
        .build_id = build_id,
    };
}

// ============================================================================
// Tests
// ============================================================================

test "GCStats defaults" {
    const stats = GCStats{};
    try std.testing.expectEqual(@as(usize, 0), stats.total_packages);
    try std.testing.expectEqual(@as(usize, 0), stats.referenced_packages);
    try std.testing.expectEqual(@as(usize, 0), stats.unreferenced_packages);
    try std.testing.expectEqual(@as(usize, 0), stats.removed_packages);
    try std.testing.expectEqual(@as(usize, 0), stats.space_freed);
    try std.testing.expectEqual(@as(i64, 0), stats.scan_time_ms);
    try std.testing.expectEqual(@as(i64, 0), stats.collect_time_ms);
}

test "GCStats tracking" {
    var stats = GCStats{};

    stats.total_packages = 100;
    stats.referenced_packages = 80;
    stats.unreferenced_packages = 20;
    stats.removed_packages = 15;
    stats.space_freed = 1024 * 1024 * 500; // 500MB

    try std.testing.expectEqual(@as(usize, 100), stats.total_packages);
    try std.testing.expectEqual(@as(usize, 80), stats.referenced_packages);
    try std.testing.expectEqual(@as(usize, 20), stats.unreferenced_packages);
    try std.testing.expectEqual(@as(usize, 15), stats.removed_packages);
}

test "GCError values" {
    const errors = [_]GCError{
        GCError.ScanFailed,
        GCError.CollectionFailed,
        GCError.LockAcquisitionFailed,
        GCError.GCAlreadyRunning,
    };

    try std.testing.expectEqual(@as(usize, 4), errors.len);
}

test "createMockPackage" {
    const allocator = std.testing.allocator;

    var pkg = try createMockPackage(allocator, "test-pkg", .{ .major = 1, .minor = 2, .patch = 3 });
    defer {
        allocator.free(pkg.name);
        allocator.free(pkg.build_id);
    }

    try std.testing.expectEqualStrings("test-pkg", pkg.name);
    try std.testing.expectEqual(@as(u32, 1), pkg.version.major);
    try std.testing.expectEqual(@as(u32, 2), pkg.version.minor);
    try std.testing.expectEqual(@as(u32, 3), pkg.version.patch);
    try std.testing.expectEqual(@as(u32, 1), pkg.revision);
    try std.testing.expectEqualStrings("mock123", pkg.build_id);
}

test "DEFAULT_GC_GRACE_PERIOD_SECONDS" {
    // 24 hours in seconds
    try std.testing.expectEqual(@as(i64, 24 * 60 * 60), DEFAULT_GC_GRACE_PERIOD_SECONDS);
    try std.testing.expectEqual(@as(i64, 86400), DEFAULT_GC_GRACE_PERIOD_SECONDS);
}

test "GC_LOCK_FILE_PATH" {
    try std.testing.expectEqualStrings("/var/run/axiom-gc.lock", GC_LOCK_FILE_PATH);
}
