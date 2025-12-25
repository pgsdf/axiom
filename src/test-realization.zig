const std = @import("std");
const zfs = @import("zfs.zig");
const types = @import("types.zig");
const store = @import("store.zig");
const profile = @import("profile.zig");
const realization = @import("realization.zig");
const manifest = @import("manifest.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("Axiom Realization Engine - Phase 6 Test\n", .{});
    std.debug.print("========================================\n\n", .{});

    // Initialize ZFS
    var zfs_handle = zfs.ZfsHandle.init() catch |err| {
        std.debug.print("Failed to initialize ZFS: {}\n", .{err});
        std.debug.print("This test requires root privileges.\n", .{});
        return err;
    };
    defer zfs_handle.deinit();

    // Initialize package store
    var pkg_store = try store.PackageStore.init(allocator, &zfs_handle);

    // Initialize realization engine
    var engine = realization.RealizationEngine.init(allocator, &zfs_handle, &pkg_store);

    std.debug.print("1. Creating Test Packages\n", .{});
    std.debug.print("-------------------------\n\n", .{});

    // Create some test packages for the environment
    const test_packages = [_]struct {
        name: []const u8,
        version: types.Version,
    }{
        .{ .name = "test-bash", .version = .{ .major = 5, .minor = 2, .patch = 0 } },
        .{ .name = "test-git", .version = .{ .major = 2, .minor = 43, .patch = 0 } },
    };

    for (test_packages) |pkg_info| {
        const pkg_id = types.PackageId{
            .name = pkg_info.name,
            .version = pkg_info.version,
            .revision = 1,
            .build_id = "test123",
        };

        // Check if package already exists
        const exists = try pkg_store.packageExists(pkg_id);
        if (!exists) {
            std.debug.print("Creating package: {s} {}\n", .{ pkg_info.name, pkg_info.version });

            // Create temporary package files
            const temp_dir = try std.fmt.allocPrint(allocator, "/tmp/axiom-pkg-{s}", .{pkg_info.name});
            defer allocator.free(temp_dir);

            try std.fs.cwd().makePath(temp_dir);
            defer std.fs.cwd().deleteTree(temp_dir) catch {};

            // Create a test file
            const test_file = try std.fs.path.join(allocator, &[_][]const u8{ temp_dir, "README.txt" });
            defer allocator.free(test_file);

            const file = try std.fs.cwd().createFile(test_file, .{});
            defer file.close();
            var write_buf: [256]u8 = undefined;
            try file.writer(&write_buf).print("Test package: {s}\n", .{pkg_info.name});

            // Create manifests
            const pkg_manifest = manifest.Manifest{
                .name = pkg_info.name,
                .version = pkg_info.version,
                .revision = 1,
                .description = try allocator.dupe(u8, "Test package"),
                .license = try allocator.dupe(u8, "BSD-2-Clause"),
                .tags = &[_][]const u8{},
            };
            defer {
                if (pkg_manifest.description) |d| allocator.free(d);
                if (pkg_manifest.license) |l| allocator.free(l);
            }

            const deps_manifest = manifest.DependencyManifest{
                .dependencies = &[_]types.Dependency{},
            };

            const prov = manifest.Provenance{
                .build_time = std.time.timestamp(),
                .builder = try allocator.dupe(u8, "test-builder"),
                .build_flags = &[_][]const u8{},
            };
            defer allocator.free(prov.builder);

            // Add package to store
            try pkg_store.addPackage(pkg_id, temp_dir, pkg_manifest, deps_manifest, prov);
        } else {
            std.debug.print("Package already exists: {s} {}\n", .{ pkg_info.name, pkg_info.version });
        }
    }

    std.debug.print("\n2. Creating Profile Lock File\n", .{});
    std.debug.print("------------------------------\n\n", .{});

    // Create a lock file with our test packages
    var resolved = try allocator.alloc(profile.ResolvedPackage, test_packages.len);
    for (test_packages, 0..) |pkg_info, i| {
        resolved[i] = .{
            .id = .{
                .name = try allocator.dupe(u8, pkg_info.name),
                .version = pkg_info.version,
                .revision = 1,
                .build_id = try allocator.dupe(u8, "test123"),
            },
            .requested = true,
        };
    }

    const lock = profile.ProfileLock{
        .profile_name = try allocator.dupe(u8, "test-profile"),
        .lock_version = 1,
        .resolved = resolved,
    };
    defer {
        allocator.free(lock.profile_name);
        for (lock.resolved) |pkg| {
            allocator.free(pkg.id.name);
            allocator.free(pkg.id.build_id);
        }
        allocator.free(lock.resolved);
    }

    std.debug.print("Lock file created with {d} packages\n", .{lock.resolved.len});

    std.debug.print("\n3. Realizing Environment\n", .{});
    std.debug.print("------------------------\n\n", .{});

    const env_name = "test-env";

    // Clean up if environment already exists
    engine.destroy(env_name) catch |err| {
        if (err != realization.RealizationError.EnvironmentNotFound) {
            return err;
        }
    };

    // Realize environment
    var env = try engine.realize(env_name, lock);
    defer realization.freeEnvironment(&env, allocator);

    std.debug.print("\n4. Environment Information\n", .{});
    std.debug.print("--------------------------\n", .{});
    std.debug.print("Name: {s}\n", .{env.name});
    std.debug.print("Profile: {s}\n", .{env.profile_name});
    std.debug.print("Dataset: {s}\n", .{env.dataset_path});
    std.debug.print("Packages: {d}\n", .{env.packages.len});

    std.debug.print("\n5. Activating Environment\n", .{});
    std.debug.print("-------------------------\n", .{});
    try engine.activate(env_name);

    std.debug.print("\n6. Cleaning Up\n", .{});
    std.debug.print("--------------\n", .{});

    // Destroy environment
    try engine.destroy(env_name);

    // Clean up test packages
    std.debug.print("Removing test packages...\n", .{});
    for (test_packages) |pkg_info| {
        const pkg_id = types.PackageId{
            .name = pkg_info.name,
            .version = pkg_info.version,
            .revision = 1,
            .build_id = "test123",
        };
        try pkg_store.removePackage(pkg_id);
    }

    std.debug.print("\n✓ Realization engine test completed successfully!\n", .{});
}
