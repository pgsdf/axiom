const std = @import("std");
const types = @import("types.zig");
const store = @import("store.zig");
const signature = @import("signature.zig");
const zfs = @import("zfs.zig");
const errors = @import("errors.zig");

const PackageId = types.PackageId;
const Version = types.Version;
const PackageStore = store.PackageStore;
const Verifier = signature.Verifier;
const TrustStore = signature.TrustStore;
const ZfsHandle = zfs.ZfsHandle;

/// Cache operation errors
pub const CacheError = error{
    CacheNotFound,
    PackageNotFound,
    DownloadFailed,
    VerificationFailed,
    InvalidResponse,
    ConnectionFailed,
    InvalidUrl,
    CacheFull,
    InvalidCacheConfig,
    ReceiveFailed,
    SendFailed,
    StreamError,
    Timeout,
    ResumeNotSupported,
    HttpNotSupported, // HTTP client API not available in Zig 0.15+
};

/// Remote cache configuration
pub const RemoteCache = struct {
    url: []const u8,
    priority: u32 = 1,
    trusted_keys: [][]const u8 = &[_][]const u8{},
    enabled: bool = true,

    pub fn deinit(self: *RemoteCache, allocator: std.mem.Allocator) void {
        allocator.free(self.url);
        for (self.trusted_keys) |key| {
            allocator.free(key);
        }
        allocator.free(self.trusted_keys);
    }
};

/// Cleanup policy for local cache
pub const CleanupPolicy = enum {
    lru, // Least recently used
    lfu, // Least frequently used
    fifo, // First in, first out
    none, // No automatic cleanup
};

/// Local cache configuration
pub const LocalCacheConfig = struct {
    path: []const u8 = "/var/cache/axiom",
    max_size_bytes: u64 = 10 * 1024 * 1024 * 1024, // 10GB default
    cleanup_policy: CleanupPolicy = .lru,
    enabled: bool = true,
    path_allocated: bool = false, // Track if path was allocated

    pub fn deinit(self: *LocalCacheConfig, allocator: std.mem.Allocator) void {
        // Only free path if it was allocated (not a string literal)
        if (self.path_allocated) {
            allocator.free(self.path);
        }
    }
};

/// Push configuration for uploading to cache
pub const PushConfig = struct {
    enabled: bool = false,
    url: ?[]const u8 = null,
    key_path: ?[]const u8 = null,

    pub fn deinit(self: *PushConfig, allocator: std.mem.Allocator) void {
        if (self.url) |u| allocator.free(u);
        if (self.key_path) |k| allocator.free(k);
    }
};

/// Full cache configuration
pub const CacheConfig = struct {
    allocator: std.mem.Allocator,
    caches: std.ArrayList(RemoteCache),
    local: LocalCacheConfig,
    push: PushConfig,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .allocator = allocator,
            .caches = .empty,
            .local = LocalCacheConfig{},
            .push = PushConfig{},
        };
    }

    pub fn deinit(self: *Self) void {
        for (self.caches.items) |*cache| {
            cache.deinit(self.allocator);
        }
        self.caches.deinit(self.allocator);
        self.local.deinit(self.allocator);
        self.push.deinit(self.allocator);
    }

    /// Add a remote cache
    pub fn addCache(self: *Self, url: []const u8, priority: u32) !void {
        const url_copy = try self.allocator.dupe(u8, url);
        try self.caches.append(self.allocator, RemoteCache{
            .url = url_copy,
            .priority = priority,
        });
        // Sort by priority (lower number = higher priority)
        std.mem.sort(RemoteCache, self.caches.items, {}, struct {
            fn lessThan(_: void, a: RemoteCache, b: RemoteCache) bool {
                return a.priority < b.priority;
            }
        }.lessThan);
    }

    /// Remove a remote cache by URL
    pub fn removeCache(self: *Self, url: []const u8) bool {
        for (self.caches.items, 0..) |*cache, i| {
            if (std.mem.eql(u8, cache.url, url)) {
                cache.deinit(self.allocator);
                _ = self.caches.orderedRemove(i);
                return true;
            }
        }
        return false;
    }

    /// Load configuration from YAML file
    pub fn loadFromFile(self: *Self, path: []const u8) !void {
        const file = std.fs.openFileAbsolute(path, .{}) catch |err| {
            if (err == error.FileNotFound) {
                // No config file, use defaults
                return;
            }
            return err;
        };
        defer file.close();

        const content = try file.readToEndAlloc(self.allocator, 1024 * 1024);
        defer self.allocator.free(content);

        try self.parseYaml(content);
    }

    /// Parse YAML configuration
    fn parseYaml(self: *Self, content: []const u8) !void {
        var lines = std.mem.splitScalar(u8, content, '\n');
        var in_caches = false;
        var in_local = false;
        var in_push = false;
        var current_cache: ?RemoteCache = null;

        while (lines.next()) |line| {
            const trimmed = std.mem.trim(u8, line, " \t\r");
            if (trimmed.len == 0 or trimmed[0] == '#') continue;

            if (std.mem.eql(u8, trimmed, "caches:")) {
                in_caches = true;
                in_local = false;
                in_push = false;
                continue;
            }
            if (std.mem.eql(u8, trimmed, "local_cache:")) {
                in_caches = false;
                in_local = true;
                in_push = false;
                if (current_cache) |c| {
                    try self.caches.append(self.allocator, c);
                    current_cache = null;
                }
                continue;
            }
            if (std.mem.eql(u8, trimmed, "push:")) {
                in_caches = false;
                in_local = false;
                in_push = true;
                if (current_cache) |c| {
                    try self.caches.append(self.allocator, c);
                    current_cache = null;
                }
                continue;
            }

            if (in_caches) {
                if (std.mem.startsWith(u8, trimmed, "- url:")) {
                    // Save previous cache if exists
                    if (current_cache) |c| {
                        try self.caches.append(self.allocator, c);
                    }
                    const url_value = std.mem.trim(u8, trimmed[6..], " \t");
                    current_cache = RemoteCache{
                        .url = try self.allocator.dupe(u8, url_value),
                        .priority = 1,
                    };
                } else if (std.mem.startsWith(u8, trimmed, "priority:")) {
                    if (current_cache) |*cache| {
                        const priority_str = std.mem.trim(u8, trimmed[9..], " \t");
                        cache.priority = std.fmt.parseInt(u32, priority_str, 10) catch 1;
                    }
                }
            }

            if (in_local) {
                if (std.mem.startsWith(u8, trimmed, "path:")) {
                    const path_value = std.mem.trim(u8, trimmed[5..], " \t");
                    self.local.path = try self.allocator.dupe(u8, path_value);
                    self.local.path_allocated = true;
                } else if (std.mem.startsWith(u8, trimmed, "max_size:")) {
                    const size_str = std.mem.trim(u8, trimmed[9..], " \t");
                    self.local.max_size_bytes = parseSize(size_str) catch self.local.max_size_bytes;
                } else if (std.mem.startsWith(u8, trimmed, "cleanup_policy:")) {
                    const policy_str = std.mem.trim(u8, trimmed[15..], " \t");
                    self.local.cleanup_policy = std.meta.stringToEnum(CleanupPolicy, policy_str) orelse .lru;
                }
            }

            if (in_push) {
                if (std.mem.startsWith(u8, trimmed, "enabled:")) {
                    const enabled_str = std.mem.trim(u8, trimmed[8..], " \t");
                    self.push.enabled = std.mem.eql(u8, enabled_str, "true");
                } else if (std.mem.startsWith(u8, trimmed, "url:")) {
                    const url_value = std.mem.trim(u8, trimmed[4..], " \t");
                    self.push.url = try self.allocator.dupe(u8, url_value);
                } else if (std.mem.startsWith(u8, trimmed, "key:")) {
                    const key_value = std.mem.trim(u8, trimmed[4..], " \t");
                    self.push.key_path = try self.allocator.dupe(u8, key_value);
                }
            }
        }

        // Save last cache
        if (current_cache) |c| {
            try self.caches.append(self.allocator, c);
        }

        // Sort caches by priority
        std.mem.sort(RemoteCache, self.caches.items, {}, struct {
            fn lessThan(_: void, a: RemoteCache, b: RemoteCache) bool {
                return a.priority < b.priority;
            }
        }.lessThan);
    }

    /// Save configuration to YAML file
    pub fn saveToFile(self: *Self, path: []const u8) !void {
        var file = try std.fs.createFileAbsolute(path, .{});
        defer file.close();

        var buffer: std.ArrayList(u8) = .empty;
        defer buffer.deinit(self.allocator);
        const writer = buffer.writer(self.allocator);

        // Write caches
        try writer.print("caches:\n", .{});
        for (self.caches.items) |cache| {
            try writer.print("  - url: {s}\n", .{cache.url});
            try writer.print("    priority: {d}\n", .{cache.priority});
            if (cache.trusted_keys.len > 0) {
                try writer.print("    trusted_keys:\n", .{});
                for (cache.trusted_keys) |key| {
                    try writer.print("      - {s}\n", .{key});
                }
            }
        }

        // Write local cache config
        try writer.print("\nlocal_cache:\n", .{});
        try writer.print("  path: {s}\n", .{self.local.path});
        try writer.print("  max_size: {d}\n", .{self.local.max_size_bytes});
        try writer.print("  cleanup_policy: {s}\n", .{@tagName(self.local.cleanup_policy)});

        // Write push config
        try writer.print("\npush:\n", .{});
        try writer.print("  enabled: {}\n", .{self.push.enabled});
        if (self.push.url) |url| {
            try writer.print("  url: {s}\n", .{url});
        }
        if (self.push.key_path) |key| {
            try writer.print("  key: {s}\n", .{key});
        }

        _ = try file.writeAll(buffer.items);
    }
};

/// Parse size string like "10G", "500M", "1024K"
fn parseSize(s: []const u8) !u64 {
    if (s.len == 0) return error.InvalidSize;

    const last = s[s.len - 1];
    const multiplier: u64 = switch (last) {
        'K', 'k' => 1024,
        'M', 'm' => 1024 * 1024,
        'G', 'g' => 1024 * 1024 * 1024,
        'T', 't' => 1024 * 1024 * 1024 * 1024,
        else => 1,
    };

    const num_str = if (multiplier == 1) s else s[0 .. s.len - 1];
    const num = try std.fmt.parseInt(u64, num_str, 10);
    return num * multiplier;
}

/// Download progress callback
pub const ProgressCallback = *const fn (downloaded: u64, total: ?u64, user_data: ?*anyopaque) void;

/// Download state for resumable downloads
pub const DownloadState = struct {
    url: []const u8,
    local_path: []const u8,
    bytes_downloaded: u64,
    total_bytes: ?u64,
    etag: ?[]const u8,
    last_modified: ?[]const u8,

    pub fn deinit(self: *DownloadState, allocator: std.mem.Allocator) void {
        allocator.free(self.url);
        allocator.free(self.local_path);
        if (self.etag) |e| allocator.free(e);
        if (self.last_modified) |lm| allocator.free(lm);
    }
};

/// Local cache entry metadata
pub const CacheEntry = struct {
    pkg_id: PackageId,
    stream_path: []const u8,
    signature_path: ?[]const u8,
    manifest_path: ?[]const u8,
    size_bytes: u64,
    downloaded_at: i64,
    last_accessed: i64,
    access_count: u32,

    pub fn deinit(self: *CacheEntry, allocator: std.mem.Allocator) void {
        allocator.free(self.pkg_id.name);
        allocator.free(self.pkg_id.build_id);
        allocator.free(self.stream_path);
        if (self.signature_path) |p| allocator.free(p);
        if (self.manifest_path) |p| allocator.free(p);
    }
};

/// Cache client for downloading packages from remote caches
pub const CacheClient = struct {
    allocator: std.mem.Allocator,
    config: *CacheConfig,
    trust_store: *TrustStore,
    zfs_handle: *ZfsHandle,
    pkg_store: *PackageStore,
    http_client: std.http.Client,

    const Self = @This();

    /// Initialize cache client
    pub fn init(
        allocator: std.mem.Allocator,
        config: *CacheConfig,
        trust_store: *TrustStore,
        zfs_handle: *ZfsHandle,
        pkg_store: *PackageStore,
    ) Self {
        return Self{
            .allocator = allocator,
            .config = config,
            .trust_store = trust_store,
            .zfs_handle = zfs_handle,
            .pkg_store = pkg_store,
            .http_client = std.http.Client{ .allocator = allocator },
        };
    }

    pub fn deinit(self: *Self) void {
        self.http_client.deinit();
    }

    /// Build URL for package endpoint
    fn buildPackageUrl(self: *Self, base_url: []const u8, pkg_id: PackageId) ![]u8 {
        return std.fmt.allocPrint(self.allocator, "{s}/v1/packages/{s}/{f}/{d}/{s}", .{
            base_url,
            pkg_id.name,
            pkg_id.version,
            pkg_id.revision,
            pkg_id.build_id,
        });
    }

    /// Build URL for manifest endpoint
    fn buildManifestUrl(self: *Self, base_url: []const u8, pkg_id: PackageId) ![]u8 {
        return std.fmt.allocPrint(self.allocator, "{s}/v1/packages/{s}/{f}/{d}/{s}/manifest", .{
            base_url,
            pkg_id.name,
            pkg_id.version,
            pkg_id.revision,
            pkg_id.build_id,
        });
    }

    /// Build URL for signature endpoint
    fn buildSignatureUrl(self: *Self, base_url: []const u8, pkg_id: PackageId) ![]u8 {
        return std.fmt.allocPrint(self.allocator, "{s}/v1/packages/{s}/{f}/{d}/{s}/signature", .{
            base_url,
            pkg_id.name,
            pkg_id.version,
            pkg_id.revision,
            pkg_id.build_id,
        });
    }

    /// Build URL for delta endpoint
    fn buildDeltaUrl(self: *Self, base_url: []const u8, from_build_id: []const u8, to_build_id: []const u8) ![]u8 {
        return std.fmt.allocPrint(self.allocator, "{s}/v1/delta/{s}/{s}", .{
            base_url,
            from_build_id,
            to_build_id,
        });
    }

    /// Check local cache for package
    pub fn checkLocalCache(self: *Self, pkg_id: PackageId) !?[]const u8 {
        const cache_path = try std.fmt.allocPrint(
            self.allocator,
            "{s}/{s}/{f}/{d}/{s}.zfs",
            .{
                self.config.local.path,
                pkg_id.name,
                pkg_id.version,
                pkg_id.revision,
                pkg_id.build_id,
            },
        );
        errdefer self.allocator.free(cache_path);

        const stat = std.fs.cwd().statFile(cache_path) catch |err| {
            if (err == error.FileNotFound) {
                self.allocator.free(cache_path);
                return null;
            }
            return err;
        };
        _ = stat;

        return cache_path;
    }

    /// Download a file from URL to local path
    /// NOTE: HTTP client API changed in Zig 0.15+ - use external tools like curl
    fn downloadFile(
        self: *Self,
        url: []const u8,
        dest_path: []const u8,
        progress_cb: ?ProgressCallback,
        user_data: ?*anyopaque,
    ) !void {
        _ = self;
        _ = url;
        _ = dest_path;
        _ = progress_cb;
        _ = user_data;
        // HTTP client API changed in Zig 0.15+
        // Use external download tools (curl, wget) until API is updated
        return error.HttpNotSupported;
    }

    /// Fetch package from remote cache
    pub fn fetchPackage(
        self: *Self,
        pkg_id: PackageId,
        verify: bool,
        progress_cb: ?ProgressCallback,
        user_data: ?*anyopaque,
    ) ![]const u8 {
        // Check local cache first
        if (try self.checkLocalCache(pkg_id)) |cached_path| {
            std.debug.print("Found in local cache: {s}\n", .{cached_path});
            return cached_path;
        }

        // Try each remote cache
        for (self.config.caches.items) |cache| {
            if (!cache.enabled) continue;

            std.debug.print("Trying cache: {s}\n", .{cache.url});

            const result = self.tryFetchFromCache(cache, pkg_id, verify, progress_cb, user_data) catch |err| {
                std.debug.print("Cache {s} failed: {}\n", .{ cache.url, err });
                continue;
            };

            return result;
        }

        return error.PackageNotFound;
    }

    /// Try to fetch package from a specific cache
    fn tryFetchFromCache(
        self: *Self,
        cache: RemoteCache,
        pkg_id: PackageId,
        verify: bool,
        progress_cb: ?ProgressCallback,
        user_data: ?*anyopaque,
    ) ![]const u8 {
        // Build local cache path
        const local_path = try std.fmt.allocPrint(
            self.allocator,
            "{s}/{s}/{f}/{d}/{s}.zfs",
            .{
                self.config.local.path,
                pkg_id.name,
                pkg_id.version,
                pkg_id.revision,
                pkg_id.build_id,
            },
        );
        errdefer self.allocator.free(local_path);

        // Download signature first if verification enabled
        if (verify) {
            const sig_url = try self.buildSignatureUrl(cache.url, pkg_id);
            defer self.allocator.free(sig_url);

            const sig_path = try std.fmt.allocPrint(self.allocator, "{s}.sig", .{local_path});
            defer self.allocator.free(sig_path);

            try self.downloadFile(sig_url, sig_path, null, null);
        }

        // Download manifest
        const manifest_url = try self.buildManifestUrl(cache.url, pkg_id);
        defer self.allocator.free(manifest_url);

        const manifest_path = try std.fmt.allocPrint(self.allocator, "{s}.manifest", .{local_path});
        defer self.allocator.free(manifest_path);

        try self.downloadFile(manifest_url, manifest_path, null, null);

        // Download package stream
        const pkg_url = try self.buildPackageUrl(cache.url, pkg_id);
        defer self.allocator.free(pkg_url);

        try self.downloadFile(pkg_url, local_path, progress_cb, user_data);

        // Verify signature if enabled
        if (verify) {
            const parent_dir = std.fs.path.dirname(local_path) orelse ".";
            var verifier = Verifier.init(self.allocator, self.trust_store, .strict);
            const result = verifier.verifyPackage(parent_dir) catch {
                // Clean up failed download
                std.fs.cwd().deleteFile(local_path) catch |err| {
                    errors.logFileCleanup(@src(), err, local_path);
                };
                return error.VerificationFailed;
            };

            if (!result.valid) {
                std.fs.cwd().deleteFile(local_path) catch |err| {
                    errors.logFileCleanup(@src(), err, local_path);
                };
                return error.VerificationFailed;
            }
        }

        return local_path;
    }

    /// Receive ZFS stream into store
    pub fn receiveIntoStore(self: *Self, stream_path: []const u8, pkg_id: PackageId) !void {
        const dataset = try self.pkg_store.paths.packageDataset(self.allocator, pkg_id);
        defer self.allocator.free(dataset);

        // Create parent dataset if needed
        const parent = std.fs.path.dirname(dataset) orelse dataset;
        self.zfs_handle.createDataset(self.allocator, parent, .{}) catch |err| {
            errors.logNonCriticalWithCategory(@src(), err, .zfs, "create parent dataset", parent);
        };

        // Receive the stream
        try self.zfs_handle.receive(dataset, stream_path);
    }

    /// Fetch and install package from cache
    pub fn fetchAndInstall(
        self: *Self,
        pkg_id: PackageId,
        verify: bool,
        progress_cb: ?ProgressCallback,
        user_data: ?*anyopaque,
    ) !void {
        const stream_path = try self.fetchPackage(pkg_id, verify, progress_cb, user_data);
        defer self.allocator.free(stream_path);

        try self.receiveIntoStore(stream_path, pkg_id);
    }

    /// Get cache index from remote
    /// NOTE: HTTP client API changed in Zig 0.15+ - use external tools like curl
    pub fn fetchIndex(self: *Self, cache_url: []const u8) ![]u8 {
        _ = self;
        _ = cache_url;
        // HTTP client API changed in Zig 0.15+
        // Use external download tools (curl, wget) until API is updated
        return error.HttpNotSupported;
    }

    /// Sync local cache with remote
    pub fn sync(self: *Self) !void {
        for (self.config.caches.items) |cache| {
            if (!cache.enabled) continue;

            std.debug.print("Syncing with cache: {s}\n", .{cache.url});

            const index = self.fetchIndex(cache.url) catch |err| {
                std.debug.print("Failed to fetch index from {s}: {}\n", .{ cache.url, err });
                continue;
            };
            defer self.allocator.free(index);

            // Parse and process index
            // For now, just log success
            std.debug.print("Index received ({d} bytes)\n", .{index.len});
        }
    }

    /// Clean local cache based on policy
    pub fn clean(self: *Self, force: bool) !u64 {
        _ = force;

        var cache_dir = std.fs.cwd().openDir(self.config.local.path, .{ .iterate = true }) catch {
            return 0;
        };
        defer cache_dir.close();

        // Calculate current cache size
        var current_size: u64 = 0;
        var entries: std.ArrayList(CacheEntry) = .empty;
        defer {
            for (entries.items) |*entry| {
                entry.deinit(self.allocator);
            }
            entries.deinit(self.allocator);
        }

        var walker = cache_dir.walk(self.allocator) catch return 0;
        defer walker.deinit();

        while (walker.next() catch null) |entry| {
            if (entry.kind != .file) continue;
            if (!std.mem.endsWith(u8, entry.basename, ".zfs")) continue;

            const stat = cache_dir.statFile(entry.path) catch continue;
            current_size += stat.size;
        }

        // If under limit, nothing to clean
        if (current_size <= self.config.local.max_size_bytes) {
            return 0;
        }

        // Clean based on policy until under limit
        const to_free = current_size - self.config.local.max_size_bytes;
        std.debug.print("Cache over limit, need to free {d} bytes\n", .{to_free});

        // For now, just report what would be cleaned
        // Full implementation would delete files based on policy
        return to_free;
    }
};

/// Cache server for serving packages over HTTP
pub const CacheServer = struct {
    allocator: std.mem.Allocator,
    pkg_store: *PackageStore,
    zfs_handle: *ZfsHandle,
    address: std.net.Address,
    server: ?std.net.Server,

    const Self = @This();

    /// Initialize cache server
    pub fn init(
        allocator: std.mem.Allocator,
        pkg_store: *PackageStore,
        zfs_handle: *ZfsHandle,
        bind_address: []const u8,
        port: u16,
    ) !Self {
        const address = try std.net.Address.parseIp(bind_address, port);

        return Self{
            .allocator = allocator,
            .pkg_store = pkg_store,
            .zfs_handle = zfs_handle,
            .address = address,
            .server = null,
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.server) |*server| {
            server.deinit();
        }
    }

    /// Start the cache server
    pub fn start(self: *Self) !void {
        self.server = try self.address.listen(.{});
        std.debug.print("Cache server listening on {}\n", .{self.address});
    }

    /// Handle incoming connections (blocking)
    pub fn serve(self: *Self) !void {
        const server = self.server orelse return error.ServerNotStarted;

        while (true) {
            const connection = try server.accept();
            defer connection.stream.close();

            self.handleConnection(connection) catch |err| {
                std.debug.print("Connection error: {}\n", .{err});
            };
        }
    }

    /// Handle a single connection
    fn handleConnection(self: *Self, connection: std.net.Server.Connection) !void {
        var buf: [4096]u8 = undefined;
        const bytes_read = try connection.stream.read(&buf);
        if (bytes_read == 0) return;

        const request = buf[0..bytes_read];
        const path = self.parseRequestPath(request) orelse {
            try self.sendError(connection.stream, 400, "Bad Request");
            return;
        };

        // Route request
        if (std.mem.startsWith(u8, path, "/v1/packages/")) {
            try self.handlePackageRequest(connection.stream, path);
        } else if (std.mem.startsWith(u8, path, "/v1/index")) {
            try self.handleIndexRequest(connection.stream);
        } else if (std.mem.startsWith(u8, path, "/v1/delta/")) {
            try self.handleDeltaRequest(connection.stream, path);
        } else {
            try self.sendError(connection.stream, 404, "Not Found");
        }
    }

    /// Parse request path from HTTP request
    fn parseRequestPath(self: *Self, request: []const u8) ?[]const u8 {
        _ = self;
        // Simple HTTP request parsing
        // GET /path HTTP/1.1
        var lines = std.mem.splitScalar(u8, request, '\n');
        const first_line = lines.next() orelse return null;

        var parts = std.mem.splitScalar(u8, first_line, ' ');
        _ = parts.next(); // GET
        return parts.next(); // path
    }

    /// Handle package request
    fn handlePackageRequest(self: *Self, stream: std.net.Stream, path: []const u8) !void {
        // Parse: /v1/packages/{name}/{version}/{revision}/{build_id}[/manifest|/signature]
        const pkg_path = path["/v1/packages/".len..];
        var parts = std.mem.splitScalar(u8, pkg_path, '/');

        const name = parts.next() orelse {
            try self.sendError(stream, 400, "Missing package name");
            return;
        };
        const version_str = parts.next() orelse {
            try self.sendError(stream, 400, "Missing version");
            return;
        };
        const revision_str = parts.next() orelse {
            try self.sendError(stream, 400, "Missing revision");
            return;
        };
        const build_id_or_suffix = parts.next() orelse {
            try self.sendError(stream, 400, "Missing build_id");
            return;
        };

        // Check for suffix (manifest/signature)
        const suffix = parts.next();
        const build_id = if (suffix != null) build_id_or_suffix else build_id_or_suffix;

        const version = types.Version.parse(version_str) catch {
            try self.sendError(stream, 400, "Invalid version");
            return;
        };
        const revision = std.fmt.parseInt(u32, revision_str, 10) catch {
            try self.sendError(stream, 400, "Invalid revision");
            return;
        };

        const pkg_id = PackageId{
            .name = name,
            .version = version,
            .revision = revision,
            .build_id = build_id,
        };

        if (suffix) |s| {
            if (std.mem.eql(u8, s, "manifest")) {
                try self.serveManifest(stream, pkg_id);
            } else if (std.mem.eql(u8, s, "signature")) {
                try self.serveSignature(stream, pkg_id);
            } else {
                try self.sendError(stream, 404, "Unknown endpoint");
            }
        } else {
            try self.servePackageStream(stream, pkg_id);
        }
    }

    /// Serve package as ZFS stream
    fn servePackageStream(self: *Self, stream: std.net.Stream, pkg_id: PackageId) !void {
        const dataset = try self.pkg_store.paths.packageDataset(self.allocator, pkg_id);
        defer self.allocator.free(dataset);

        const snapshot = try std.fmt.allocPrint(self.allocator, "{s}@installed", .{dataset});
        defer self.allocator.free(snapshot);

        // Start ZFS send process
        var child = std.process.Child.init(&[_][]const u8{ "zfs", "send", "-c", snapshot }, self.allocator);
        child.stdout_behavior = .Pipe;
        try child.spawn();

        // Send HTTP headers
        try stream.writeAll("HTTP/1.1 200 OK\r\n");
        try stream.writeAll("Content-Type: application/octet-stream\r\n");
        try stream.writeAll("Transfer-Encoding: chunked\r\n");
        try stream.writeAll("\r\n");

        // Stream ZFS output
        var buf: [8192]u8 = undefined;
        while (true) {
            const n = child.stdout.?.read(&buf) catch break;
            if (n == 0) break;

            // Chunked encoding
            var chunk_header: [20]u8 = undefined;
            const header_len = std.fmt.formatIntBuf(&chunk_header, n, 16, .lower, .{});
            try stream.writeAll(chunk_header[0..header_len]);
            try stream.writeAll("\r\n");
            try stream.writeAll(buf[0..n]);
            try stream.writeAll("\r\n");
        }

        // Final chunk
        try stream.writeAll("0\r\n\r\n");

        _ = child.wait() catch |err| {
            errors.logProcessCleanup(@src(), err, "zfs send for cache");
        };
    }

    /// Serve package manifest
    fn serveManifest(self: *Self, stream: std.net.Stream, pkg_id: PackageId) !void {
        const mount_path = try self.pkg_store.paths.packageMountpoint(self.allocator, pkg_id);
        defer self.allocator.free(mount_path);

        const manifest_path = try std.fmt.allocPrint(self.allocator, "{s}/manifest.yaml", .{mount_path});
        defer self.allocator.free(manifest_path);

        const file = std.fs.openFileAbsolute(manifest_path, .{}) catch {
            try self.sendError(stream, 404, "Manifest not found");
            return;
        };
        defer file.close();

        const content = try file.readToEndAlloc(self.allocator, 1024 * 1024);
        defer self.allocator.free(content);

        try stream.writeAll("HTTP/1.1 200 OK\r\n");
        try stream.writeAll("Content-Type: text/yaml\r\n");
        try stream.writer().print("Content-Length: {d}\r\n", .{content.len});
        try stream.writeAll("\r\n");
        try stream.writeAll(content);
    }

    /// Serve package signature
    fn serveSignature(self: *Self, stream: std.net.Stream, pkg_id: PackageId) !void {
        const mount_path = try self.pkg_store.paths.packageMountpoint(self.allocator, pkg_id);
        defer self.allocator.free(mount_path);

        const sig_path = try std.fmt.allocPrint(self.allocator, "{s}/manifest.sig", .{mount_path});
        defer self.allocator.free(sig_path);

        const file = std.fs.openFileAbsolute(sig_path, .{}) catch {
            try self.sendError(stream, 404, "Signature not found");
            return;
        };
        defer file.close();

        const content = try file.readToEndAlloc(self.allocator, 1024 * 1024);
        defer self.allocator.free(content);

        try stream.writeAll("HTTP/1.1 200 OK\r\n");
        try stream.writeAll("Content-Type: text/yaml\r\n");
        try stream.writer().print("Content-Length: {d}\r\n", .{content.len});
        try stream.writeAll("\r\n");
        try stream.writeAll(content);
    }

    /// Handle index request
    fn handleIndexRequest(self: *Self, stream: std.net.Stream) !void {
        _ = self;
        // Return package index
        // For now, return empty JSON array
        try stream.writeAll("HTTP/1.1 200 OK\r\n");
        try stream.writeAll("Content-Type: application/json\r\n");
        try stream.writeAll("Content-Length: 2\r\n");
        try stream.writeAll("\r\n");
        try stream.writeAll("[]");
    }

    /// Handle delta request
    fn handleDeltaRequest(self: *Self, stream: std.net.Stream, path: []const u8) !void {
        // Parse: /v1/delta/{from_build_id}/{to_build_id}
        const delta_path = path["/v1/delta/".len..];
        var parts = std.mem.splitScalar(u8, delta_path, '/');

        const from_id = parts.next() orelse {
            try self.sendError(stream, 400, "Missing from_build_id");
            return;
        };
        const to_id = parts.next() orelse {
            try self.sendError(stream, 400, "Missing to_build_id");
            return;
        };

        _ = from_id;
        _ = to_id;

        // TODO: Implement incremental ZFS send
        try self.sendError(stream, 501, "Delta transfers not yet implemented");
    }

    /// Send HTTP error response
    fn sendError(self: *Self, stream: std.net.Stream, status: u16, message: []const u8) !void {
        _ = self;
        const status_text = switch (status) {
            400 => "Bad Request",
            404 => "Not Found",
            500 => "Internal Server Error",
            501 => "Not Implemented",
            else => "Error",
        };

        try stream.writer().print("HTTP/1.1 {d} {s}\r\n", .{ status, status_text });
        try stream.writeAll("Content-Type: text/plain\r\n");
        try stream.writer().print("Content-Length: {d}\r\n", .{message.len});
        try stream.writeAll("\r\n");
        try stream.writeAll(message);
    }
};

/// Push a package to remote cache
pub fn pushPackage(
    allocator: std.mem.Allocator,
    config: *CacheConfig,
    pkg_store: *PackageStore,
    zfs_handle: *ZfsHandle,
    pkg_id: PackageId,
) !void {
    if (!config.push.enabled) {
        return error.PushNotEnabled;
    }

    const push_url = config.push.url orelse return error.NoPushUrl;

    // Get package dataset
    const dataset = try pkg_store.paths.packageDataset(allocator, pkg_id);
    defer allocator.free(dataset);

    const snapshot = try std.fmt.allocPrint(allocator, "{s}@installed", .{dataset});
    defer allocator.free(snapshot);

    // Create temporary file for ZFS stream
    const tmp_path = try std.fmt.allocPrint(allocator, "/tmp/axiom-push-{s}.zfs", .{pkg_id.build_id});
    defer allocator.free(tmp_path);
    defer std.fs.deleteFileAbsolute(tmp_path) catch |err| {
        errors.logFileCleanup(@src(), err, tmp_path);
    };

    // Send ZFS stream to file
    try zfs_handle.sendToFile(snapshot, tmp_path);

    // Upload to cache server
    const url = try std.fmt.allocPrint(allocator, "{s}/v1/packages/{s}/{f}/{d}/{s}", .{
        push_url,
        pkg_id.name,
        pkg_id.version,
        pkg_id.revision,
        pkg_id.build_id,
    });
    defer allocator.free(url);

    // TODO: Implement HTTP PUT upload
    std.debug.print("Would upload {s} to {s}\n", .{ tmp_path, url });
}
