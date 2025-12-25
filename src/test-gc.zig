const std = @import("std");
const zfs = @import("zfs.zig");
const types = @import("types.zig");
const store = @import("store.zig");
const profile = @import("profile.zig");
const gc = @import("gc.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("Axiom Garbage Collector - Phase 8 Test\n", .{});
    std.debug.print("=======================================\n\n", .{});

    // Initialize ZFS
    var zfs_handle = zfs.ZfsHandle.init() catch |err| {
        std.debug.print("Failed to initialize ZFS: {}\n", .{err});
        std.debug.print("Running mock GC test instead...\n\n", .{});
        try runMockTest(allocator);
        return;
    };
    defer zfs_handle.deinit();

    // Initialize subsystems
    var pkg_store = try store.PackageStore.init(allocator, &zfs_handle);
    var profile_mgr = profile.ProfileManager.init(allocator, &zfs_handle);

    // Initialize garbage collector
    var collector = gc.GarbageCollector.init(
        allocator,
        &zfs_handle,
        &pkg_store,
        &profile_mgr,
    );

    std.debug.print("Testing Garbage Collector\n", .{});
    std.debug.print("-------------------------\n\n", .{});

    // Run dry-run first
    std.debug.print("=== DRY RUN ===\n\n", .{});
    const dry_stats = try collector.collect(true);
    _ = dry_stats;

    std.debug.print("\n\n", .{});

    // Ask if user wants to run actual collection
    std.debug.print("Run actual garbage collection? (y/N): ", .{});

    var buffer: [10]u8 = undefined;
    const stdin_file = std.fs.File.stdin();
    var stdin_buf: [256]u8 = undefined;
    const stdin = stdin_file.reader(&stdin_buf);
    const input = try stdin.readUntilDelimiterOrEof(&buffer, '\n');
    
    if (input) |line| {
        if (line.len > 0 and (line[0] == 'y' or line[0] == 'Y')) {
            std.debug.print("\n=== ACTUAL COLLECTION ===\n\n", .{});
            
            // Create safety snapshot
            try collector.createSafetySnapshot();
            
            std.debug.print("\n", .{});
            
            // Run collection
            const real_stats = try collector.collect(false);
            _ = real_stats;
        } else {
            std.debug.print("\nCancelled - no packages removed\n", .{});
        }
    }

    std.debug.print("\n✓ Garbage collection test completed\n", .{});
}

fn runMockTest(allocator: std.mem.Allocator) !void {
    std.debug.print("Mock Garbage Collection Test\n", .{});
    std.debug.print("============================\n\n", .{});

    // Simulate package scanning
    std.debug.print("Phase 1: Scanning package store...\n", .{});
    
    var all_packages = std.ArrayList(types.PackageId).empty;
    defer {
        for (all_packages.items) |pkg| {
            allocator.free(pkg.name);
            allocator.free(pkg.build_id);
        }
        all_packages.deinit();
    }

    // Create mock packages
    const mock_packages = [_]struct { name: []const u8, version: types.Version }{
        .{ .name = "bash", .version = .{ .major = 5, .minor = 2, .patch = 0 } },
        .{ .name = "bash", .version = .{ .major = 5, .minor = 1, .patch = 0 } },
        .{ .name = "git", .version = .{ .major = 2, .minor = 43, .patch = 0 } },
        .{ .name = "vim", .version = .{ .major = 9, .minor = 0, .patch = 0 } },
        .{ .name = "old-package", .version = .{ .major = 1, .minor = 0, .patch = 0 } },
    };

    for (mock_packages) |pkg_info| {
        const pkg = try gc.createMockPackage(allocator, pkg_info.name, pkg_info.version);
        try all_packages.append(pkg);
    }

    std.debug.print("  Found {d} packages in store\n", .{all_packages.items.len});

    // Simulate profile references
    std.debug.print("\nPhase 2: Finding references...\n", .{});
    
    var referenced = std.StringHashMap(bool).init(allocator);
    defer {
        var key_iter = referenced.keyIterator();
        while (key_iter.next()) |key| {
            allocator.free(key.*);
        }
        referenced.deinit();
    }

    // Mock: bash 5.2.0 and git 2.43.0 are referenced
    // Create keys for referenced packages
    const key1 = try std.fmt.allocPrint(allocator, "{s}/{}/{d}/{s}", .{
        all_packages.items[0].name,
        all_packages.items[0].version,
        all_packages.items[0].revision,
        all_packages.items[0].build_id,
    });
    try referenced.put(key1, true);
    
    const key2 = try std.fmt.allocPrint(allocator, "{s}/{}/{d}/{s}", .{
        all_packages.items[2].name,
        all_packages.items[2].version,
        all_packages.items[2].revision,
        all_packages.items[2].build_id,
    });
    try referenced.put(key2, true);

    std.debug.print("  Profiles reference 2 packages\n", .{});
    std.debug.print("  Total referenced: {d} packages\n", .{referenced.count()});

    // Identify unreferenced
    std.debug.print("\nPhase 3: Identifying unreferenced packages...\n", .{});
    
    var unreferenced = std.ArrayList(types.PackageId).empty;
    defer unreferenced.deinit();

    for (all_packages.items) |pkg| {
        const key = try std.fmt.allocPrint(allocator, "{s}/{}/{d}/{s}", .{
            pkg.name,
            pkg.version,
            pkg.revision,
            pkg.build_id,
        });
        defer allocator.free(key);
        
        if (!referenced.contains(key)) {
            try unreferenced.append(pkg);
        }
    }

    std.debug.print("  Found {d} unreferenced packages\n", .{unreferenced.items.len});

    // Show what would be removed
    std.debug.print("\nPhase 4: Packages to remove:\n", .{});
    for (unreferenced.items) |pkg| {
        std.debug.print("  - {s} {} (rev {d})\n", .{
            pkg.name,
            pkg.version,
            pkg.revision,
        });
    }

    // Summary
    std.debug.print("\nGarbage Collection Summary\n", .{});
    std.debug.print("==========================\n", .{});
    std.debug.print("Total packages:        {d}\n", .{all_packages.items.len});
    std.debug.print("Referenced packages:   {d}\n", .{referenced.count()});
    std.debug.print("Unreferenced packages: {d}\n", .{unreferenced.items.len});

    std.debug.print("\n✓ Mock GC test completed\n", .{});
}
