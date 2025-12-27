const std = @import("std");
const zfs = @import("zfs.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Initialize ZFS
    var zfs_handle = zfs.ZfsHandle.init() catch |err| {
        std.debug.print("Failed to initialize ZFS: {any}\n", .{err});
        return err;
    };
    defer zfs_handle.deinit();

    std.debug.print("Axiom System Manager - ZFS Integration Layer\n", .{});
    std.debug.print("=============================================\n\n", .{});

    // Test basic ZFS operations
    const test_dataset = "zroot/axiom";

    // Check if axiom root dataset exists
    const exists = zfs_handle.datasetExists(allocator, test_dataset, .filesystem) catch |err| {
        std.debug.print("Error checking dataset existence: {any}\n", .{err});
        return err;
    };

    if (exists) {
        std.debug.print("✓ Axiom root dataset exists: {s}\n", .{test_dataset});

        // Get mountpoint
        const mountpoint = zfs_handle.getMountpoint(allocator, test_dataset) catch |err| {
            std.debug.print("Error getting mountpoint: {any}\n", .{err});
            return err;
        };
        defer allocator.free(mountpoint);

        std.debug.print("  Mountpoint: {s}\n", .{mountpoint});

        // Get compression property
        const compression = zfs_handle.getProperty(allocator, test_dataset, "compression") catch |err| {
            std.debug.print("Error getting compression: {any}\n", .{err});
            return err;
        };
        defer allocator.free(compression);

        std.debug.print("  Compression: {s}\n", .{compression});
    } else {
        std.debug.print("✗ Axiom root dataset does not exist: {s}\n", .{test_dataset});
        std.debug.print("  To create it, run: zfs create {s}\n", .{test_dataset});
    }

    std.debug.print("\nZFS integration layer initialized successfully.\n", .{});
}
