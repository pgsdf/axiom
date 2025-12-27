const std = @import("std");
const zfs = @import("zfs.zig");
const types = @import("types.zig");
const profile = @import("profile.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("Axiom Profile Management - Phase 4 Test\n", .{});
    std.debug.print("========================================\n\n", .{});

    // Test profile parsing
    std.debug.print("1. Testing Profile Parsing\n", .{});
    std.debug.print("--------------------------\n", .{});
    
    const profile_content = try std.fs.cwd().readFileAlloc(
        allocator,
        "examples/profile.yaml",
        1024 * 1024,
    );
    defer allocator.free(profile_content);

    var test_profile = try profile.Profile.parse(allocator, profile_content);
    defer test_profile.deinit(allocator);

    std.debug.print("Profile: {s}\n", .{test_profile.name});
    if (test_profile.description) |desc| {
        std.debug.print("Description: {s}\n", .{desc});
    }
    std.debug.print("Packages ({d}):\n", .{test_profile.packages.len});
    for (test_profile.packages) |pkg| {
        std.debug.print("  - {s}: ", .{pkg.name});
        switch (pkg.constraint) {
            .exact => |v| std.debug.print("={f}\n", .{v}),
            .tilde => |v| std.debug.print("~{f}\n", .{v}),
            .caret => |v| std.debug.print("^{f}\n", .{v}),
            .any => std.debug.print("*\n", .{}),
            .range => |r| {
                if (r.min) |min| {
                    std.debug.print("{s}{f}", .{ if (r.min_inclusive) ">=" else ">", min });
                }
                if (r.max) |max| {
                    if (r.min != null) std.debug.print(",", .{});
                    std.debug.print("{s}{f}", .{ if (r.max_inclusive) "<=" else "<", max });
                }
                std.debug.print("\n", .{});
            },
        }
    }

    // Test lock file parsing
    std.debug.print("\n2. Testing Lock File Parsing\n", .{});
    std.debug.print("-----------------------------\n", .{});

    const lock_content = try std.fs.cwd().readFileAlloc(
        allocator,
        "examples/profile.lock.yaml",
        1024 * 1024,
    );
    defer allocator.free(lock_content);

    var test_lock = try profile.ProfileLock.parse(allocator, lock_content);
    defer test_lock.deinit(allocator);

    std.debug.print("Lock for profile: {s}\n", .{test_lock.profile_name});
    std.debug.print("Lock version: {d}\n", .{test_lock.lock_version});
    std.debug.print("Resolved packages ({d}):\n", .{test_lock.resolved.len});
    for (test_lock.resolved) |pkg| {
        const marker: []const u8 = if (pkg.requested) "*" else " ";
        std.debug.print("  {s} {s} {f} (rev {d}, build {s})\n", .{
            marker,
            pkg.id.name,
            pkg.id.version,
            pkg.id.revision,
            pkg.id.build_id,
        });
    }
    std.debug.print("  (* = directly requested)\n", .{});

    // Test profile manager (requires ZFS and root)
    std.debug.print("\n3. Testing Profile Manager\n", .{});
    std.debug.print("--------------------------\n", .{});

    var zfs_handle = zfs.ZfsHandle.init() catch |err| {
        std.debug.print("Cannot initialize ZFS: {any}\n", .{err});
        std.debug.print("Skipping profile manager tests (requires root)\n", .{});
        std.debug.print("\n✓ Profile parsing tests completed successfully!\n", .{});
        return;
    };
    defer zfs_handle.deinit();

    var mgr = profile.ProfileManager.init(allocator, &zfs_handle);

    // Create a test profile
    const test_profile_name = "test-profile";
    
    // Allocate packages array on heap
    var packages = try allocator.alloc(profile.PackageRequest, 1);
    packages[0] = .{
        .name = try allocator.dupe(u8, "bash"),
        .constraint = types.VersionConstraint{
            .caret = types.Version{ .major = 5, .minor = 0, .patch = 0 },
        },
    };
    
    const create_profile = profile.Profile{
        .name = try allocator.dupe(u8, test_profile_name),
        .description = try allocator.dupe(u8, "Test profile for Axiom"),
        .packages = packages,
    };
    defer {
        allocator.free(create_profile.name);
        if (create_profile.description) |d| allocator.free(d);
        for (create_profile.packages) |pkg| {
            allocator.free(pkg.name);
        }
        allocator.free(create_profile.packages);
    }

    std.debug.print("Creating profile '{s}'...\n", .{test_profile_name});
    mgr.createProfile(create_profile) catch |err| {
        if (err == profile.ProfileError.ProfileExists) {
            std.debug.print("Profile exists, deleting and recreating...\n", .{});
            try mgr.deleteProfile(test_profile_name);
            try mgr.createProfile(create_profile);
        } else {
            return err;
        }
    };

    // Load the profile back
    std.debug.print("Loading profile '{s}'...\n", .{test_profile_name});
    var loaded_profile = try mgr.loadProfile(test_profile_name);
    defer loaded_profile.deinit(allocator);

    std.debug.print("  Loaded: {s}\n", .{loaded_profile.name});
    std.debug.print("  Packages: {d}\n", .{loaded_profile.packages.len});

    // Create and save a lock file
    std.debug.print("Creating lock file...\n", .{});
    
    // Allocate resolved packages array on heap
    var resolved = try allocator.alloc(profile.ResolvedPackage, 1);
    resolved[0] = .{
        .id = .{
            .name = try allocator.dupe(u8, "bash"),
            .version = types.Version{ .major = 5, .minor = 2, .patch = 0 },
            .revision = 1,
            .build_id = try allocator.dupe(u8, "test123"),
        },
        .requested = true,
    };
    
    const test_lock_create = profile.ProfileLock{
        .profile_name = try allocator.dupe(u8, test_profile_name),
        .lock_version = 1,
        .resolved = resolved,
    };
    defer {
        allocator.free(test_lock_create.profile_name);
        for (test_lock_create.resolved) |pkg| {
            allocator.free(pkg.id.name);
            allocator.free(pkg.id.build_id);
        }
        allocator.free(test_lock_create.resolved);
    }

    try mgr.saveLock(test_profile_name, test_lock_create);

    // Load the lock file back
    std.debug.print("Loading lock file...\n", .{});
    var loaded_lock = try mgr.loadLock(test_profile_name);
    defer loaded_lock.deinit(allocator);

    std.debug.print("  Profile: {s}\n", .{loaded_lock.profile_name});
    std.debug.print("  Resolved: {d} packages\n", .{loaded_lock.resolved.len});

    // Clean up
    std.debug.print("Cleaning up test profile...\n", .{});
    try mgr.deleteProfile(test_profile_name);

    std.debug.print("\n✓ All profile tests completed successfully!\n", .{});
}
