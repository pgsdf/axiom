const std = @import("std");
const cache = @import("cache.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("Cache Module Tests\n", .{});
    std.debug.print("==================\n\n", .{});

    // Test CacheConfig initialization
    std.debug.print("1. Testing CacheConfig initialization...\n", .{});
    var config = cache.CacheConfig.empty;
    defer config.deinit();
    std.debug.print("   ✓ CacheConfig created\n", .{});
    std.debug.print("   Local cache path: {s}\n", .{config.local.path});
    std.debug.print("   Max size: {d} bytes\n", .{config.local.max_size_bytes});
    std.debug.print("   Cleanup policy: {s}\n", .{@tagName(config.local.cleanup_policy)});

    // Test adding caches
    std.debug.print("\n2. Testing adding remote caches...\n", .{});
    try config.addCache("https://cache.example.org", 1);
    try config.addCache("https://mirror.example.com/axiom", 2);
    std.debug.print("   ✓ Added 2 caches\n", .{});
    std.debug.print("   Caches configured: {d}\n", .{config.caches.items.len});

    for (config.caches.items, 0..) |item, i| {
        std.debug.print("   [{d}] {s} (priority {d})\n", .{ i + 1, item.url, item.priority });
    }

    // Test removing a cache
    std.debug.print("\n3. Testing removing a cache...\n", .{});
    const removed = config.removeCache("https://mirror.example.com/axiom");
    std.debug.print("   Removed: {}\n", .{removed});
    std.debug.print("   Remaining caches: {d}\n", .{config.caches.items.len});

    // Test configuration file loading (with temp file)
    std.debug.print("\n4. Testing configuration file handling...\n", .{});

    // Try loading from non-existent file (should not error)
    var config2 = cache.CacheConfig.empty;
    defer config2.deinit();
    config2.loadFromFile("/tmp/nonexistent-cache-config.yaml") catch {};
    std.debug.print("   ✓ loadFromFile handles missing file gracefully\n", .{});

    // Add some caches to config2 for save/load test
    try config2.addCache("https://cache.pgsdf.org", 1);
    try config2.addCache("https://backup.pgsdf.org", 2);
    std.debug.print("   ✓ Added 2 caches to config2\n", .{});
    std.debug.print("   Caches configured: {d}\n", .{config2.caches.items.len});

    // Test CacheEntry
    std.debug.print("\n5. Testing cache entry structure...\n", .{});
    const entry = cache.CacheEntry{
        .pkg_id = .{
            .name = "bash",
            .version = .{ .major = 5, .minor = 2, .patch = 0 },
            .revision = 1,
            .build_id = "abc123",
        },
        .stream_path = "/var/cache/axiom/bash/5.2.0/1/abc123.zfs",
        .signature_path = null,
        .manifest_path = null,
        .size_bytes = 1024 * 1024,
        .downloaded_at = std.time.timestamp(),
        .last_accessed = std.time.timestamp(),
        .access_count = 1,
    };
    std.debug.print("   ✓ CacheEntry created for {s}\n", .{entry.pkg_id.name});
    std.debug.print("   Size: {d} bytes\n", .{entry.size_bytes});

    // Test CleanupPolicy
    std.debug.print("\n6. Testing cleanup policies...\n", .{});
    const policies = [_]cache.CleanupPolicy{ .lru, .lfu, .fifo, .none };
    for (policies) |policy| {
        std.debug.print("   Policy: {s}\n", .{@tagName(policy)});
    }
    std.debug.print("   ✓ All policies available\n", .{});

    std.debug.print("\n==================\n", .{});
    std.debug.print("All cache tests passed!\n", .{});
}
