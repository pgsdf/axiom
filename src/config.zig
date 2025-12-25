const std = @import("std");
const posix = std.posix;

// =============================================================================
// Axiom Configuration
// =============================================================================
//
// This module provides configurable paths for Axiom's ZFS datasets and
// filesystem locations. Paths can be overridden via environment variables.
//
// Environment Variables:
//   AXIOM_POOL       - ZFS pool name (default: "zroot")
//   AXIOM_DATASET    - Base dataset name (default: "axiom")
//   AXIOM_MOUNTPOINT - Base mountpoint (default: "/axiom")
//   AXIOM_CONFIG_DIR - Configuration directory (default: "/etc/axiom")
//   AXIOM_CACHE_DIR  - Cache directory (default: "/var/cache/axiom")
//
// ## Thread Safety
//
// The global configuration is managed through ConfigManager which provides:
// - Thread-safe lazy initialization via mutex
// - Reference counting for lifecycle management
// - Proper error propagation (no panics on init failure)
//
// Usage pattern:
//   const cfg = try config.getGlobalConfig(allocator);
//   defer config.releaseGlobalConfig();
//   // use cfg...
//
// =============================================================================

/// Default ZFS pool name
pub const DEFAULT_POOL: []const u8 = "zroot";

/// Default base dataset name under the pool
pub const DEFAULT_DATASET: []const u8 = "axiom";

/// Default mountpoint for Axiom datasets
pub const DEFAULT_MOUNTPOINT: []const u8 = "/axiom";

/// Default configuration directory
pub const DEFAULT_CONFIG_DIR: []const u8 = "/etc/axiom";

/// Default cache directory
pub const DEFAULT_CACHE_DIR: []const u8 = "/var/cache/axiom";

/// Runtime configuration with resolved paths
pub const Config = struct {
    allocator: std.mem.Allocator,

    // ZFS dataset paths
    pool: []const u8,
    base_dataset: []const u8,
    store_dataset: []const u8,
    profile_dataset: []const u8,
    env_dataset: []const u8,
    runtime_dataset: []const u8,
    builds_dataset: []const u8,

    // Filesystem mountpoints
    mountpoint: []const u8,
    store_path: []const u8,
    profile_path: []const u8,
    env_path: []const u8,
    runtime_path: []const u8,
    builds_path: []const u8,

    // Configuration paths
    config_dir: []const u8,
    trust_store_path: []const u8,
    cache_config_path: []const u8,

    // Cache paths
    cache_dir: []const u8,

    // Track which strings we allocated (for cleanup)
    allocated_strings: std.ArrayList([]const u8),

    /// Initialize configuration from environment variables with defaults
    pub fn init(allocator: std.mem.Allocator) !Config {
        var config: Config = undefined;
        config.allocator = allocator;
        config.allocated_strings = std.ArrayList([]const u8).empty;

        // Get base values from environment or use defaults
        const pool = getEnvOrDefault("AXIOM_POOL", DEFAULT_POOL);
        const dataset = getEnvOrDefault("AXIOM_DATASET", DEFAULT_DATASET);
        const mountpoint = getEnvOrDefault("AXIOM_MOUNTPOINT", DEFAULT_MOUNTPOINT);
        const config_dir = getEnvOrDefault("AXIOM_CONFIG_DIR", DEFAULT_CONFIG_DIR);
        const cache_dir = getEnvOrDefault("AXIOM_CACHE_DIR", DEFAULT_CACHE_DIR);

        config.pool = pool;
        config.mountpoint = mountpoint;
        config.config_dir = config_dir;
        config.cache_dir = cache_dir;

        // Build ZFS dataset paths
        config.base_dataset = try config.allocAndTrack("{s}/{s}", .{ pool, dataset });
        config.store_dataset = try config.allocAndTrack("{s}/{s}/store/pkg", .{ pool, dataset });
        config.profile_dataset = try config.allocAndTrack("{s}/{s}/profiles", .{ pool, dataset });
        config.env_dataset = try config.allocAndTrack("{s}/{s}/env", .{ pool, dataset });
        config.runtime_dataset = try config.allocAndTrack("{s}/{s}/runtimes", .{ pool, dataset });
        config.builds_dataset = try config.allocAndTrack("{s}/{s}/builds", .{ pool, dataset });

        // Build filesystem paths
        config.store_path = try config.allocAndTrack("{s}/store/pkg", .{mountpoint});
        config.profile_path = try config.allocAndTrack("{s}/profiles", .{mountpoint});
        config.env_path = try config.allocAndTrack("{s}/env", .{mountpoint});
        config.runtime_path = try config.allocAndTrack("{s}/runtimes", .{mountpoint});
        config.builds_path = try config.allocAndTrack("{s}/builds", .{mountpoint});

        // Build config file paths
        config.trust_store_path = try config.allocAndTrack("{s}/trust.toml", .{config_dir});
        config.cache_config_path = try config.allocAndTrack("{s}/cache.yaml", .{config_dir});

        return config;
    }

    /// Initialize with explicit values (for testing or programmatic use)
    pub fn initWithValues(
        allocator: std.mem.Allocator,
        pool: []const u8,
        dataset: []const u8,
        mountpoint: []const u8,
        config_dir: []const u8,
        cache_dir: []const u8,
    ) !Config {
        var config: Config = undefined;
        config.allocator = allocator;
        config.allocated_strings = std.ArrayList([]const u8).empty;

        config.pool = pool;
        config.mountpoint = mountpoint;
        config.config_dir = config_dir;
        config.cache_dir = cache_dir;

        // Build ZFS dataset paths
        config.base_dataset = try config.allocAndTrack("{s}/{s}", .{ pool, dataset });
        config.store_dataset = try config.allocAndTrack("{s}/{s}/store/pkg", .{ pool, dataset });
        config.profile_dataset = try config.allocAndTrack("{s}/{s}/profiles", .{ pool, dataset });
        config.env_dataset = try config.allocAndTrack("{s}/{s}/env", .{ pool, dataset });
        config.runtime_dataset = try config.allocAndTrack("{s}/{s}/runtimes", .{ pool, dataset });
        config.builds_dataset = try config.allocAndTrack("{s}/{s}/builds", .{ pool, dataset });

        // Build filesystem paths
        config.store_path = try config.allocAndTrack("{s}/store/pkg", .{mountpoint});
        config.profile_path = try config.allocAndTrack("{s}/profiles", .{mountpoint});
        config.env_path = try config.allocAndTrack("{s}/env", .{mountpoint});
        config.runtime_path = try config.allocAndTrack("{s}/runtimes", .{mountpoint});
        config.builds_path = try config.allocAndTrack("{s}/builds", .{mountpoint});

        // Build config file paths
        config.trust_store_path = try config.allocAndTrack("{s}/trust.toml", .{config_dir});
        config.cache_config_path = try config.allocAndTrack("{s}/cache.yaml", .{config_dir});

        return config;
    }

    /// Clean up allocated strings
    pub fn deinit(self: *Config) void {
        for (self.allocated_strings.items) |s| {
            self.allocator.free(s);
        }
        self.allocated_strings.deinit();
    }

    /// Helper to format and track allocated strings
    fn allocAndTrack(self: *Config, comptime fmt: []const u8, args: anytype) ![]const u8 {
        const str = try std.fmt.allocPrint(self.allocator, fmt, args);
        try self.allocated_strings.append(str);
        return str;
    }

    /// Get package path for a specific package
    pub fn getPackagePath(self: *const Config, allocator: std.mem.Allocator, pkg_name: []const u8) ![]const u8 {
        return std.fmt.allocPrint(allocator, "{s}/{s}", .{ self.store_path, pkg_name });
    }

    /// Get dataset path for a specific package
    pub fn getPackageDataset(self: *const Config, allocator: std.mem.Allocator, pkg_name: []const u8) ![]const u8 {
        return std.fmt.allocPrint(allocator, "{s}/{s}", .{ self.store_dataset, pkg_name });
    }

    /// Get runtime dataset path
    pub fn getRuntimeDataset(self: *const Config, allocator: std.mem.Allocator, name: []const u8) ![]const u8 {
        return std.fmt.allocPrint(allocator, "{s}/{s}", .{ self.runtime_dataset, name });
    }

    /// Get runtime snapshot path
    pub fn getRuntimeSnapshot(self: *const Config, allocator: std.mem.Allocator, name: []const u8, snapshot: []const u8) ![]const u8 {
        return std.fmt.allocPrint(allocator, "{s}/{s}@{s}", .{ self.runtime_dataset, name, snapshot });
    }
};

/// Get environment variable or return default
fn getEnvOrDefault(name: []const u8, default: []const u8) []const u8 {
    return posix.getenv(name) orelse default;
}

/// ConfigManager provides proper lifecycle management for global configuration
/// with reference counting to prevent memory leaks and use-after-free.
pub const ConfigManager = struct {
    config: ?Config = null,
    allocator: std.mem.Allocator,
    ref_count: u32 = 0,
    mutex: std.Thread.Mutex = .{},

    /// Acquire a reference to the configuration.
    /// Call release() when done to allow cleanup.
    pub fn acquire(self: *ConfigManager) !*Config {
        self.mutex.lock();
        defer self.mutex.unlock();

        self.ref_count += 1;

        if (self.config) |*cfg| {
            return cfg;
        }

        self.config = try Config.init(self.allocator);
        return &self.config.?;
    }

    /// Release a reference to the configuration.
    /// When ref_count reaches 0, the configuration can be freed.
    pub fn release(self: *ConfigManager) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.ref_count > 0) {
            self.ref_count -= 1;
        }
    }

    /// Force cleanup of the configuration (for shutdown/testing).
    /// Only safe when ref_count is 0.
    pub fn deinit(self: *ConfigManager) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.ref_count > 0) {
            std.log.warn("ConfigManager.deinit called with {d} active references", .{self.ref_count});
        }

        if (self.config) |*cfg| {
            cfg.deinit();
            self.config = null;
        }
    }

    /// Check if config is currently loaded
    pub fn isLoaded(self: *ConfigManager) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.config != null;
    }

    /// Get current reference count (for debugging)
    pub fn getRefCount(self: *ConfigManager) u32 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.ref_count;
    }
};

/// Global configuration manager instance
var global_config_manager: ?ConfigManager = null;
var global_manager_mutex: std.Thread.Mutex = .{};

/// Get or initialize the global configuration manager
fn getConfigManager(allocator: std.mem.Allocator) *ConfigManager {
    global_manager_mutex.lock();
    defer global_manager_mutex.unlock();

    if (global_config_manager == null) {
        global_config_manager = ConfigManager{
            .allocator = allocator,
        };
    }
    return &global_config_manager.?;
}

/// Get or initialize the global configuration (legacy API - acquires reference)
/// IMPORTANT: Callers should call releaseGlobalConfig() when done to enable cleanup.
pub fn getGlobalConfig(allocator: std.mem.Allocator) !*Config {
    const manager = getConfigManager(allocator);
    return manager.acquire();
}

/// Release a reference to the global configuration
pub fn releaseGlobalConfig() void {
    global_manager_mutex.lock();
    defer global_manager_mutex.unlock();

    if (global_config_manager) |*mgr| {
        // Release without holding outer mutex to avoid deadlock
        global_manager_mutex.unlock();
        mgr.release();
        global_manager_mutex.lock();
    }
}

/// Reset global configuration (for testing)
pub fn resetGlobalConfig() void {
    global_manager_mutex.lock();
    defer global_manager_mutex.unlock();

    if (global_config_manager) |*mgr| {
        // Deinit without holding outer mutex to avoid deadlock
        global_manager_mutex.unlock();
        mgr.deinit();
        global_manager_mutex.lock();
        global_config_manager = null;
    }
}

// =============================================================================
// Tests
// =============================================================================

test "Config.init uses defaults" {
    const allocator = std.testing.allocator;
    var config = try Config.empty;
    defer config.deinit();

    // Check default dataset paths
    try std.testing.expectEqualStrings("zroot/axiom", config.base_dataset);
    try std.testing.expectEqualStrings("zroot/axiom/store/pkg", config.store_dataset);
    try std.testing.expectEqualStrings("zroot/axiom/profiles", config.profile_dataset);

    // Check default mountpoints
    try std.testing.expectEqualStrings("/axiom/store/pkg", config.store_path);
    try std.testing.expectEqualStrings("/axiom/profiles", config.profile_path);
}

test "Config.initWithValues uses custom values" {
    const allocator = std.testing.allocator;
    var config = try Config.initWithValues(
        allocator,
        "tank",
        "packages",
        "/pkg",
        "/etc/pkg",
        "/var/cache/pkg",
    );
    defer config.deinit();

    try std.testing.expectEqualStrings("tank/packages", config.base_dataset);
    try std.testing.expectEqualStrings("tank/packages/store/pkg", config.store_dataset);
    try std.testing.expectEqualStrings("/pkg/store/pkg", config.store_path);
    try std.testing.expectEqualStrings("/etc/pkg/trust.toml", config.trust_store_path);
}

test "Config.getPackagePath" {
    const allocator = std.testing.allocator;
    var config = try Config.empty;
    defer config.deinit();

    const path = try config.getPackagePath(allocator, "bash");
    defer allocator.free(path);

    try std.testing.expectEqualStrings("/axiom/store/pkg/bash", path);
}

test "ConfigManager lifecycle" {
    const allocator = std.testing.allocator;
    var manager = ConfigManager{
        .allocator = allocator,
    };

    // Initially no config loaded
    try std.testing.expect(!manager.isLoaded());
    try std.testing.expectEqual(@as(u32, 0), manager.getRefCount());

    // Acquire a reference
    const cfg1 = try manager.acquire();
    try std.testing.expect(manager.isLoaded());
    try std.testing.expectEqual(@as(u32, 1), manager.getRefCount());
    try std.testing.expectEqualStrings("zroot/axiom", cfg1.base_dataset);

    // Acquire another reference (same config)
    const cfg2 = try manager.acquire();
    try std.testing.expectEqual(@as(u32, 2), manager.getRefCount());
    try std.testing.expectEqual(cfg1, cfg2);

    // Release both references
    manager.release();
    try std.testing.expectEqual(@as(u32, 1), manager.getRefCount());
    manager.release();
    try std.testing.expectEqual(@as(u32, 0), manager.getRefCount());

    // Config still loaded (cleanup is explicit)
    try std.testing.expect(manager.isLoaded());

    // Explicit cleanup
    manager.deinit();
    try std.testing.expect(!manager.isLoaded());
}
