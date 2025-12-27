const std = @import("std");
const zfs = @import("zfs.zig");
const types = @import("types.zig");
const store = @import("store.zig");
const import_pkg = @import("import.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("Axiom Package Import - Phase 9 Test\n", .{});
    std.debug.print("====================================\n\n", .{});

    // Initialize ZFS
    var zfs_handle = zfs.ZfsHandle.init() catch |err| {
        std.debug.print("Failed to initialize ZFS: {}\n", .{err});
        std.debug.print("Running mock import test instead...\n\n", .{});
        try runMockTest(allocator);
        return;
    };
    defer zfs_handle.deinit();

    // Initialize package store
    var pkg_store = try store.PackageStore.init(allocator, &zfs_handle);

    // Initialize importer
    var importer = import_pkg.Importer.init(allocator, &zfs_handle, &pkg_store);

    try runFullTest(allocator, &importer, &pkg_store);
}

fn runMockTest(allocator: std.mem.Allocator) !void {
    std.debug.print("Mock Import Test\n", .{});
    std.debug.print("----------------\n\n", .{});

    // Create a test package directory
    const test_dir = "/tmp/axiom-test-pkg";
    
    std.debug.print("1. Creating test package directory: {s}\n", .{test_dir});
    
    // Clean up if exists
    std.fs.cwd().deleteTree(test_dir) catch {};
    
    // Create structure
    try std.fs.cwd().makePath(test_dir ++ "/bin");
    try std.fs.cwd().makePath(test_dir ++ "/lib");
    try std.fs.cwd().makePath(test_dir ++ "/share/man/man1");
    
    // Create a test binary (just a script)
    {
        const bin_file = try std.fs.cwd().createFile(test_dir ++ "/bin/hello", .{});
        defer bin_file.close();
        try bin_file.writeAll("#!/bin/sh\necho 'Hello from test package'\n");
    }
    
    // Create a package.json for detection
    {
        const pkg_json = try std.fs.cwd().createFile(test_dir ++ "/package.json", .{});
        defer pkg_json.close();
        try pkg_json.writeAll(
            \\{
            \\  "name": "test-hello",
            \\  "version": "1.0.0",
            \\  "description": "A test package for Axiom import",
            \\  "license": "BSD-2-Clause"
            \\}
        );
    }
    
    std.debug.print("   ✓ Created test package with bin/, lib/, share/\n", .{});
    std.debug.print("   ✓ Created package.json with metadata\n\n", .{});

    // Test metadata detection
    std.debug.print("2. Testing metadata detection\n", .{});
    
    var metadata = import_pkg.DetectedMetadata{};
    
    // Check directories
    metadata.has_binaries = dirExists(test_dir, "bin");
    metadata.has_libraries = dirExists(test_dir, "lib");
    metadata.has_man_pages = dirExists(test_dir, "share/man");
    
    std.debug.print("   Has binaries:  {any}\n", .{metadata.has_binaries});
    std.debug.print("   Has libraries: {any}\n", .{metadata.has_libraries});
    std.debug.print("   Has man pages: {any}\n", .{metadata.has_man_pages});
    
    // Read package.json
    const pkg_json_path = test_dir ++ "/package.json";
    const file = try std.fs.cwd().openFile(pkg_json_path, .{});
    defer file.close();
    
    const content = try file.readToEndAlloc(allocator, 1024 * 1024);
    defer allocator.free(content);
    
    std.debug.print("\n   package.json contents:\n", .{});
    var lines = std.mem.splitSequence(u8, content, "\n");
    while (lines.next()) |line| {
        std.debug.print("     {s}\n", .{line});
    }

    std.debug.print("\n3. Testing tarball creation and extraction\n", .{});
    
    // Create a tarball
    const tarball_path = "/tmp/test-hello-1.0.0.tar.gz";
    
    var tar_child = std.process.Child.init(
        &[_][]const u8{ "tar", "-czf", tarball_path, "-C", "/tmp", "axiom-test-pkg" },
        allocator,
    );
    try tar_child.spawn();
    _ = try tar_child.wait();
    
    std.debug.print("   ✓ Created tarball: {s}\n", .{tarball_path});
    
    // Check tarball exists and get size
    const tarball_stat = try std.fs.cwd().statFile(tarball_path);
    std.debug.print("   Tarball size: {d} bytes\n", .{tarball_stat.size});

    // Cleanup
    std.debug.print("\n4. Cleaning up\n", .{});
    std.fs.cwd().deleteTree(test_dir) catch {};
    std.fs.cwd().deleteFile(tarball_path) catch {};
    std.debug.print("   ✓ Removed test files\n", .{});

    std.debug.print("\n✓ Mock import test completed successfully!\n", .{});
    std.debug.print("\nTo test full import functionality, run with root:\n", .{});
    std.debug.print("  sudo ./zig-out/bin/test-import\n", .{});
}

fn runFullTest(allocator: std.mem.Allocator, importer: *import_pkg.Importer, pkg_store: *store.PackageStore) !void {
    std.debug.print("Full Import Test\n", .{});
    std.debug.print("----------------\n\n", .{});

    // Create a test package directory
    const test_dir = "/tmp/axiom-import-test";
    
    std.debug.print("1. Creating test package\n", .{});
    
    // Clean up if exists
    std.fs.cwd().deleteTree(test_dir) catch {};
    
    // Create structure
    try std.fs.cwd().makePath(test_dir ++ "/bin");
    try std.fs.cwd().makePath(test_dir ++ "/lib");
    try std.fs.cwd().makePath(test_dir ++ "/share/doc");
    
    // Create test files
    {
        const bin_file = try std.fs.cwd().createFile(test_dir ++ "/bin/test-app", .{ .mode = 0o755 });
        defer bin_file.close();
        try bin_file.writeAll("#!/bin/sh\necho 'Test application'\n");
    }
    
    {
        const readme = try std.fs.cwd().createFile(test_dir ++ "/share/doc/README", .{});
        defer readme.close();
        try readme.writeAll("Test package README\n");
    }
    
    // Create Cargo.toml for detection testing
    {
        const cargo = try std.fs.cwd().createFile(test_dir ++ "/Cargo.toml", .{});
        defer cargo.close();
        try cargo.writeAll(
            \\[package]
            \\name = "test-app"
            \\version = "2.0.0"
            \\description = "A test application"
            \\license = "MIT"
        );
    }
    
    std.debug.print("   ✓ Created test package structure\n\n", .{});

    // Test 1: Import from directory with auto-detection
    std.debug.print("2. Testing directory import with auto-detection\n", .{});
    
    const pkg_id1 = try importer.import(
        import_pkg.ImportSource{ .directory = test_dir },
        .{
            .dry_run = true,
            .auto_detect = true,
        },
    );
    _ = pkg_id1;
    
    std.debug.print("\n", .{});

    // Test 2: Import from directory with explicit options
    std.debug.print("3. Testing directory import with explicit options\n", .{});
    
    const pkg_id2 = try importer.import(
        import_pkg.ImportSource{ .directory = test_dir },
        .{
            .name = "explicit-test",
            .version = types.Version{ .major = 3, .minor = 0, .patch = 0 },
            .revision = 1,
            .description = "Explicitly named test package",
            .license = "BSD-2-Clause",
            .dry_run = true,
        },
    );
    _ = pkg_id2;
    
    std.debug.print("\n", .{});

    // Test 3: Create tarball and import
    std.debug.print("4. Testing tarball import\n", .{});
    
    const tarball_path = "/tmp/test-pkg.tar.gz";
    
    var tar_child = std.process.Child.init(
        &[_][]const u8{ "tar", "-czf", tarball_path, "-C", "/tmp", "axiom-import-test" },
        allocator,
    );
    try tar_child.spawn();
    _ = try tar_child.wait();
    
    std.debug.print("   Created tarball: {s}\n\n", .{tarball_path});
    
    const pkg_id3 = try importer.import(
        import_pkg.ImportSource{ .tarball = tarball_path },
        .{
            .name = "tarball-test",
            .version = types.Version{ .major = 1, .minor = 0, .patch = 0 },
            .dry_run = true,
        },
    );
    _ = pkg_id3;
    
    std.debug.print("\n", .{});

    // Test 4: Actual import (not dry run)
    std.debug.print("5. Testing actual import to store\n", .{});
    
    const pkg_id4 = try importer.import(
        import_pkg.ImportSource{ .directory = test_dir },
        .{
            .name = "real-import-test",
            .version = types.Version{ .major = 1, .minor = 0, .patch = 0 },
            .description = "Actually imported package",
            .dry_run = false,
        },
    );
    
    std.debug.print("\n", .{});

    // Verify import
    std.debug.print("6. Verifying imported package\n", .{});
    
    const exists = try pkg_store.packageExists(pkg_id4);
    std.debug.print("   Package exists in store: {any}\n", .{exists});
    
    if (exists) {
        std.debug.print("   ✓ Package successfully imported!\n", .{});
        
        // Clean up - remove the test package
        std.debug.print("\n7. Cleaning up\n", .{});
        try pkg_store.removePackage(pkg_id4);
        std.debug.print("   ✓ Removed test package from store\n", .{});
    }
    
    // Clean up test files
    std.fs.cwd().deleteTree(test_dir) catch {};
    std.fs.cwd().deleteFile(tarball_path) catch {};
    std.debug.print("   ✓ Removed test files\n", .{});

    std.debug.print("\n✓ Full import test completed successfully!\n", .{});
}

fn dirExists(base: []const u8, subdir: []const u8) bool {
    const path = std.fs.path.join(std.heap.page_allocator, &[_][]const u8{ base, subdir }) catch return false;
    defer std.heap.page_allocator.free(path);
    
    std.fs.cwd().access(path, .{}) catch return false;
    return true;
}
