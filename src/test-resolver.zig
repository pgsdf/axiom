const std = @import("std");
const zfs = @import("zfs.zig");
const types = @import("types.zig");
const store = @import("store.zig");
const profile = @import("profile.zig");
const resolver = @import("resolver.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("Axiom Dependency Resolver - Phase 5 Test\n", .{});
    std.debug.print("=========================================\n\n", .{});

    // Initialize ZFS (for store, even though we'll use mock data)
    var zfs_handle = zfs.ZfsHandle.init() catch |err| {
        std.debug.print("Cannot initialize ZFS: {}\n", .{err});
        std.debug.print("Note: Some tests will use mock data instead\n\n", .{});
        // Continue without ZFS - we'll use mock store
        try runMockTests(allocator);
        return;
    };
    defer zfs_handle.deinit();

    var pkg_store = try store.PackageStore.init(allocator, &zfs_handle);

    try runTests(allocator, &pkg_store);
}

fn runMockTests(allocator: std.mem.Allocator) !void {
    std.debug.print("Running resolver tests with mock data...\n\n", .{});

    // Create a mock store (we'll pass null ZFS handle, resolver only needs the store interface)
    // For this test, we'll create profiles and test constraint logic

    std.debug.print("1. Testing Version Constraints\n", .{});
    std.debug.print("-------------------------------\n", .{});

    const test_version = types.Version{ .major = 5, .minor = 2, .patch = 0 };

    // Test exact
    const exact = types.VersionConstraint{ .exact = test_version };
    std.debug.print("  Version {f} satisfies ={f}: {}\n", .{
        test_version,
        test_version,
        exact.satisfies(test_version),
    });

    // Test tilde
    const tilde = types.VersionConstraint{
        .tilde = types.Version{ .major = 5, .minor = 2, .patch = 0 },
    };
    std.debug.print("  Version {f} satisfies ~5.2.0: {}\n", .{
        test_version,
        tilde.satisfies(test_version),
    });
    std.debug.print("  Version 5.3.0 satisfies ~5.2.0: {}\n", .{
        tilde.satisfies(types.Version{ .major = 5, .minor = 3, .patch = 0 }),
    });

    // Test caret
    const caret = types.VersionConstraint{
        .caret = types.Version{ .major = 5, .minor = 0, .patch = 0 },
    };
    std.debug.print("  Version {f} satisfies ^5.0.0: {}\n", .{
        test_version,
        caret.satisfies(test_version),
    });
    std.debug.print("  Version 6.0.0 satisfies ^5.0.0: {}\n", .{
        caret.satisfies(types.Version{ .major = 6, .minor = 0, .patch = 0 }),
    });

    // Test range
    const range = types.VersionConstraint{
        .range = .{
            .min = types.Version{ .major = 5, .minor = 0, .patch = 0 },
            .max = types.Version{ .major = 6, .minor = 0, .patch = 0 },
            .min_inclusive = true,
            .max_inclusive = false,
        },
    };
    std.debug.print("  Version {f} satisfies >=5.0.0,<6.0.0: {}\n", .{
        test_version,
        range.satisfies(test_version),
    });

    std.debug.print("\n2. Testing Profile Resolution Workflow\n", .{});
    std.debug.print("---------------------------------------\n", .{});

    // Create a test profile
    var packages = try allocator.alloc(profile.PackageRequest, 3);
    packages[0] = .{
        .name = try allocator.dupe(u8, "bash"),
        .constraint = types.VersionConstraint{
            .caret = types.Version{ .major = 5, .minor = 0, .patch = 0 },
        },
    };
    packages[1] = .{
        .name = try allocator.dupe(u8, "git"),
        .constraint = types.VersionConstraint{
            .range = .{
                .min = types.Version{ .major = 2, .minor = 40, .patch = 0 },
                .max = null,
                .min_inclusive = true,
                .max_inclusive = false,
            },
        },
    };
    packages[2] = .{
        .name = try allocator.dupe(u8, "vim"),
        .constraint = types.VersionConstraint{ .any = {} },
    };

    const test_profile = profile.Profile{
        .name = try allocator.dupe(u8, "test-env"),
        .description = try allocator.dupe(u8, "Test environment"),
        .packages = packages,
    };
    defer {
        allocator.free(test_profile.name);
        if (test_profile.description) |d| allocator.free(d);
        for (test_profile.packages) |pkg| {
            allocator.free(pkg.name);
        }
        allocator.free(test_profile.packages);
    }

    std.debug.print("Profile: {s}\n", .{test_profile.name});
    std.debug.print("Packages to resolve:\n", .{});
    for (test_profile.packages) |pkg| {
        std.debug.print("  - {s}\n", .{pkg.name});
    }

    std.debug.print("\n✓ Mock resolver tests completed!\n", .{});
    std.debug.print("\nNote: Full resolution requires a populated package store.\n", .{});
    std.debug.print("Run 'sudo ./test-resolver' after adding packages to test full resolution.\n", .{});
}

fn runTests(allocator: std.mem.Allocator, pkg_store: *store.PackageStore) !void {
    std.debug.print("Running resolver tests with package store...\n\n", .{});

    // Create resolver
    var res = resolver.Resolver.init(allocator, pkg_store);

    std.debug.print("1. Creating Test Profile\n", .{});
    std.debug.print("------------------------\n", .{});

    // Create a simple profile
    var packages = try allocator.alloc(profile.PackageRequest, 2);
    packages[0] = .{
        .name = try allocator.dupe(u8, "bash"),
        .constraint = types.VersionConstraint{
            .caret = types.Version{ .major = 5, .minor = 0, .patch = 0 },
        },
    };
    packages[1] = .{
        .name = try allocator.dupe(u8, "git"),
        .constraint = types.VersionConstraint{
            .range = .{
                .min = types.Version{ .major = 2, .minor = 40, .patch = 0 },
                .max = null,
                .min_inclusive = true,
                .max_inclusive = false,
            },
        },
    };

    const test_profile = profile.Profile{
        .name = try allocator.dupe(u8, "development"),
        .description = try allocator.dupe(u8, "Development environment"),
        .packages = packages,
    };
    defer {
        allocator.free(test_profile.name);
        if (test_profile.description) |d| allocator.free(d);
        for (test_profile.packages) |pkg| {
            allocator.free(pkg.name);
        }
        allocator.free(test_profile.packages);
    }

    std.debug.print("Profile: {s}\n", .{test_profile.name});
    std.debug.print("Requested packages:\n", .{});
    for (test_profile.packages) |pkg| {
        std.debug.print("  - {s}\n", .{pkg.name});
    }

    std.debug.print("\n2. Resolving Dependencies\n", .{});
    std.debug.print("-------------------------\n", .{});

    // Resolve profile
    var lock = try res.resolve(test_profile);
    defer lock.deinit(allocator);

    std.debug.print("\n3. Resolution Results\n", .{});
    std.debug.print("--------------------\n", .{});
    std.debug.print("Lock file for: {s}\n", .{lock.profile_name});
    std.debug.print("Resolved packages:\n", .{});

    var requested_count: usize = 0;
    var dep_count: usize = 0;

    for (lock.resolved) |pkg| {
        const marker: []const u8 = if (pkg.requested) "*" else " ";
        std.debug.print("  {s} {s} {f} (rev {d})\n", .{
            marker,
            pkg.id.name,
            pkg.id.version,
            pkg.id.revision,
        });
        if (pkg.requested) {
            requested_count += 1;
        } else {
            dep_count += 1;
        }
    }

    std.debug.print("\nSummary:\n", .{});
    std.debug.print("  Requested: {d}\n", .{requested_count});
    std.debug.print("  Dependencies: {d}\n", .{dep_count});
    std.debug.print("  Total: {d}\n", .{lock.resolved.len});

    std.debug.print("\n✓ Dependency resolution completed successfully!\n", .{});
}
