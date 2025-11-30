const std = @import("std");
const zfs = @import("zfs.zig");
const types = @import("types.zig");
const store = @import("store.zig");
const profile = @import("profile.zig");

const ZfsHandle = zfs.ZfsHandle;
const PackageId = types.PackageId;
const PackageStore = store.PackageStore;
const ProfileManager = profile.ProfileManager;

/// Garbage collection errors
pub const GCError = error{
    ScanFailed,
    CollectionFailed,
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

/// Garbage collector - removes unreferenced packages
pub const GarbageCollector = struct {
    allocator: std.mem.Allocator,
    zfs_handle: *ZfsHandle,
    store: *PackageStore,
    profile_mgr: *ProfileManager,
    
    /// Grace period in seconds - don't collect packages newer than this
    grace_period: i64 = 86400, // 24 hours default

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
        };
    }

    /// Run garbage collection
    pub fn collect(self: *GarbageCollector, dry_run: bool) !GCStats {
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
        
        var to_remove = std.ArrayList(PackageId).init(self.allocator);
        defer to_remove.deinit();

        const current_time = std.time.timestamp();

        for (all_packages) |pkg| {
            const key = try self.packageKey(pkg);
            defer self.allocator.free(key);
            
            if (!referenced.contains(key)) {
                // Check grace period
                // TODO: Get package creation time from ZFS property
                // For now, assume all packages are outside grace period
                _ = current_time;
                
                try to_remove.append(.{
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
                    std.debug.print("    - {s} {} (rev {d})\n", .{
                        pkg.name,
                        pkg.version,
                        pkg.revision,
                    });
                }
            } else {
                const collect_start = std.time.milliTimestamp();
                
                for (to_remove.items, 0..) |pkg, i| {
                    std.debug.print("  [{d}/{d}] Removing {s} {}\n", .{
                        i + 1,
                        to_remove.items.len,
                        pkg.name,
                        pkg.version,
                    });

                    // Get dataset size before removal (for stats)
                    // TODO: Query ZFS for actual size
                    const estimated_size: usize = 10 * 1024 * 1024; // 10MB estimate
                    stats.space_freed += estimated_size;

                    // Remove package
                    try self.store.removePackage(pkg);
                    stats.removed_packages += 1;
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
        return std.fmt.allocPrint(self.allocator, "{s}/{}/{d}/{s}", .{
            pkg.name,
            pkg.version,
            pkg.revision,
            pkg.build_id,
        });
    }

    /// Scan package store for all packages
    fn scanStore(self: *GarbageCollector) ![]PackageId {
        // TODO: Implement by querying ZFS datasets under store_root
        // For now, return empty list as placeholder
        
        // This would use: zfs list -H -o name -r zroot/axiom/store/pkg
        // Parse dataset paths to extract package IDs
        
        var packages = std.ArrayList(PackageId).init(self.allocator);
        defer packages.deinit();

        // Placeholder: Would scan actual datasets
        // Example dataset: zroot/axiom/store/pkg/bash/5.2.0/1/abc123
        
        return packages.toOwnedSlice();
    }

    /// Scan profiles for referenced packages
    fn scanProfiles(self: *GarbageCollector) ![]PackageId {
        // TODO: Implement by reading all profile.lock.yaml files
        // For now, return empty list as placeholder
        
        var packages = std.ArrayList(PackageId).init(self.allocator);
        defer packages.deinit();

        // This would:
        // 1. List all datasets under zroot/axiom/profiles
        // 2. Read profile.lock.yaml from each
        // 3. Extract referenced package IDs
        
        return packages.toOwnedSlice();
    }

    /// Scan environments for referenced packages
    fn scanEnvironments(self: *GarbageCollector) ![]PackageId {
        // TODO: Implement by reading environment metadata
        // For now, return empty list as placeholder
        
        var packages = std.ArrayList(PackageId).init(self.allocator);
        defer packages.deinit();

        // This would:
        // 1. List all datasets under zroot/axiom/env
        // 2. Read environment metadata or package manifests
        // 3. Extract referenced package IDs
        
        return packages.toOwnedSlice();
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
