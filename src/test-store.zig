const std = @import("std");
const zfs = @import("zfs.zig");
const types = @import("types.zig");
const manifest = @import("manifest.zig");
const store = @import("store.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("Axiom Package Store - Phase 3 Test\n", .{});
    std.debug.print("===================================\n\n", .{});

    // Initialize ZFS
    var zfs_handle = zfs.ZfsHandle.init() catch |err| {
        std.debug.print("Failed to initialize ZFS: {}\n", .{err});
        std.debug.print("This test requires root privileges.\n", .{});
        return err;
    };
    defer zfs_handle.deinit();

    // Initialize package store
    var pkg_store = try store.PackageStore.init(allocator, &zfs_handle);

    // Create a test package
    std.debug.print("Creating test package...\n", .{});

    const pkg_id = types.PackageId{
        .name = "test-package",
        .version = types.Version{ .major = 1, .minor = 0, .patch = 0 },
        .revision = 1,
        .build_id = "test123",
    };

    // Create test package manifest
    const pkg_manifest = manifest.Manifest{
        .name = "test-package",
        .version = types.Version{ .major = 1, .minor = 0, .patch = 0 },
        .revision = 1,
        .description = try allocator.dupe(u8, "Test package for Axiom"),
        .license = try allocator.dupe(u8, "BSD-2-Clause"),
        .tags = &[_][]const u8{},
    };
    defer {
        if (pkg_manifest.description) |d| allocator.free(d);
        if (pkg_manifest.license) |l| allocator.free(l);
    }

    // Create test dependencies
    const deps_manifest = manifest.DependencyManifest{
        .dependencies = &[_]types.Dependency{},
    };

    // Create test provenance
    const prov = manifest.Provenance{
        .build_time = std.time.timestamp(),
        .builder = try allocator.dupe(u8, "test-builder"),
        .build_flags = &[_][]const u8{},
    };
    defer allocator.free(prov.builder);

    // Create a temporary source directory with test files
    const temp_dir = "/tmp/axiom-test-pkg";
    try std.fs.cwd().makePath(temp_dir);
    defer std.fs.cwd().deleteTree(temp_dir) catch {};

    // Create a test file
    const test_file_path = try std.fs.path.join(
        allocator,
        &[_][]const u8{ temp_dir, "README.txt" },
    );
    defer allocator.free(test_file_path);

    const test_file = try std.fs.cwd().createFile(test_file_path, .{});
    defer test_file.close();
    try test_file.writeAll("This is a test package for Axiom.\n");

    std.debug.print("\n", .{});

    // Add package to store
    pkg_store.addPackage(
        pkg_id,
        temp_dir,
        pkg_manifest,
        deps_manifest,
        prov,
    ) catch |err| {
        std.debug.print("Error adding package: {}\n", .{err});
        if (err == store.StoreError.PackageExists) {
            std.debug.print("Package already exists. Removing and retrying...\n\n", .{});
            try pkg_store.removePackage(pkg_id);
            try pkg_store.addPackage(pkg_id, temp_dir, pkg_manifest, deps_manifest, prov);
        } else {
            return err;
        }
    };

    std.debug.print("\n", .{});

    // Check if package exists
    const exists = try pkg_store.packageExists(pkg_id);
    std.debug.print("Package exists in store: {}\n", .{exists});

    // Get package metadata
    std.debug.print("\nRetrieving package metadata...\n", .{});
    var pkg_meta = try pkg_store.getPackage(pkg_id);
    defer {
        pkg_meta.manifest.deinit(allocator);
        allocator.free(pkg_meta.dependencies);
        allocator.free(pkg_meta.dataset_path);
    }

    std.debug.print("  Name: {s}\n", .{pkg_meta.manifest.name});
    std.debug.print("  Version: {}\n", .{pkg_meta.manifest.version});
    std.debug.print("  Dataset: {s}\n", .{pkg_meta.dataset_path});

    // Clean up - remove test package
    std.debug.print("\nCleaning up test package...\n", .{});
    try pkg_store.removePackage(pkg_id);

    std.debug.print("\n✓ Package store operations completed successfully!\n", .{});
}
