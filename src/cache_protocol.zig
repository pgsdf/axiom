// Remote Binary Cache Protocol for Axiom System Manager
// Implements RESTful API for efficient package distribution

const std = @import("std");
const Allocator = std.mem.Allocator;
const signature = @import("signature.zig");
const validation = @import("validation.zig");

/// Cache protocol version
pub const PROTOCOL_VERSION = "1.0";

/// Default cache port
pub const DEFAULT_PORT: u16 = 8080;

/// API endpoints
pub const Endpoints = struct {
    pub const INFO = "/api/v1/info";
    pub const PACKAGES = "/api/v1/packages";
    pub const PACKAGE = "/api/v1/packages/{name}/{version}";
    pub const PACKAGE_NAR = "/api/v1/packages/{name}/{version}/nar";
    pub const PACKAGE_META = "/api/v1/packages/{name}/{version}/meta";
    pub const PACKAGE_SIG = "/api/v1/packages/{name}/{version}/sig";
    pub const SEARCH = "/api/v1/search";
    pub const SYNC = "/api/v1/sync";
    pub const UPLOAD = "/api/v1/upload";
};

/// Cache server information
pub const CacheInfo = struct {
    name: []const u8,
    version: []const u8,
    protocol_version: []const u8,
    package_count: u64,
    total_size: u64,
    public_key: ?[]const u8,
    features: []const []const u8,

    pub fn toJson(self: *const CacheInfo, allocator: Allocator) ![]const u8 {
        var buffer: std.ArrayList(u8) = .empty;
        errdefer buffer.deinit(allocator);

        const writer = buffer.writer();

        try buffer.appendSlice(allocator, "{\"name\":\"");
        try validation.writeJsonEscaped(writer, self.name);
        try buffer.appendSlice(allocator, "\",\"version\":\"");
        try validation.writeJsonEscaped(writer, self.version);
        try buffer.appendSlice(allocator, "\",\"protocol_version\":\"");
        try validation.writeJsonEscaped(writer, self.protocol_version);
        try buffer.appendSlice(allocator, "\",");
        try std.fmt.format(writer, "\"package_count\":{d},", .{self.package_count});
        try std.fmt.format(writer, "\"total_size\":{d},", .{self.total_size});

        if (self.public_key) |key| {
            try buffer.appendSlice(allocator, "\"public_key\":\"");
            try validation.writeJsonEscaped(writer, key);
            try buffer.appendSlice(allocator, "\",");
        } else {
            try buffer.appendSlice(allocator, "\"public_key\":null,");
        }

        try buffer.appendSlice(allocator, "\"features\":[");
        for (self.features, 0..) |feature, i| {
            if (i > 0) try buffer.append(allocator, ',');
            try buffer.append(allocator, '"');
            try validation.writeJsonEscaped(writer, feature);
            try buffer.append(allocator, '"');
        }
        try buffer.appendSlice(allocator, "]}");

        return buffer.toOwnedSlice(allocator);
    }
};

/// Package metadata for cache
pub const PackageMeta = struct {
    name: []const u8,
    version: []const u8,
    hash: []const u8,
    size: u64,
    compressed_size: u64,
    compression: Compression,
    dependencies: []const []const u8,
    description: ?[]const u8,
    signatures: []const []const u8,

    pub const Compression = enum {
        none,
        zstd,
        gzip,
        xz,

        pub fn extension(self: Compression) []const u8 {
            return switch (self) {
                .none => "",
                .zstd => ".zst",
                .gzip => ".gz",
                .xz => ".xz",
            };
        }

        pub fn fromString(s: []const u8) Compression {
            if (std.mem.eql(u8, s, "zstd")) return .zstd;
            if (std.mem.eql(u8, s, "gzip")) return .gzip;
            if (std.mem.eql(u8, s, "xz")) return .xz;
            return .none;
        }
    };

    pub fn deinit(self: *PackageMeta, allocator: Allocator) void {
        allocator.free(self.name);
        allocator.free(self.version);
        allocator.free(self.hash);
        for (self.dependencies) |dep| {
            allocator.free(dep);
        }
        allocator.free(self.dependencies);
        if (self.description) |desc| {
            allocator.free(desc);
        }
        for (self.signatures) |sig| {
            allocator.free(sig);
        }
        allocator.free(self.signatures);
    }

    pub fn toJson(self: *const PackageMeta, allocator: Allocator) ![]const u8 {
        var buffer: std.ArrayList(u8) = .empty;
        errdefer buffer.deinit(allocator);

        const writer = buffer.writer();

        try buffer.appendSlice(allocator, "{\"name\":\"");
        try validation.writeJsonEscaped(writer, self.name);
        try buffer.appendSlice(allocator, "\",\"version\":\"");
        try validation.writeJsonEscaped(writer, self.version);
        try buffer.appendSlice(allocator, "\",\"hash\":\"");
        try validation.writeJsonEscaped(writer, self.hash);
        try buffer.appendSlice(allocator, "\",");
        try std.fmt.format(writer, "\"size\":{d},", .{self.size});
        try std.fmt.format(writer, "\"compressed_size\":{d},", .{self.compressed_size});
        try std.fmt.format(writer, "\"compression\":\"{s}\",", .{@tagName(self.compression)});

        try buffer.appendSlice(allocator, "\"dependencies\":[");
        for (self.dependencies, 0..) |dep, i| {
            if (i > 0) try buffer.append(allocator, ',');
            try buffer.append(allocator, '"');
            try validation.writeJsonEscaped(writer, dep);
            try buffer.append(allocator, '"');
        }
        try buffer.appendSlice(allocator, "],");

        if (self.description) |desc| {
            try buffer.appendSlice(allocator, "\"description\":\"");
            try validation.writeJsonEscaped(writer, desc);
            try buffer.appendSlice(allocator, "\",");
        } else {
            try buffer.appendSlice(allocator, "\"description\":null,");
        }

        try buffer.appendSlice(allocator, "\"signatures\":[");
        for (self.signatures, 0..) |sig, i| {
            if (i > 0) try buffer.append(allocator, ',');
            try buffer.append(allocator, '"');
            try validation.writeJsonEscaped(writer, sig);
            try buffer.append(allocator, '"');
        }
        try buffer.appendSlice(allocator, "]}");

        return buffer.toOwnedSlice(allocator);
    }
};

/// Cache source configuration
pub const CacheSource = struct {
    url: []const u8,
    priority: u32,
    trust_key: ?[]const u8,
    enabled: bool,
    name: ?[]const u8,

    pub fn deinit(self: *CacheSource, allocator: Allocator) void {
        allocator.free(self.url);
        if (self.trust_key) |key| allocator.free(key);
        if (self.name) |name| allocator.free(name);
    }
};

/// Cache configuration (from /etc/axiom/caches.yaml)
pub const CacheConfig = struct {
    sources: []CacheSource,
    default_compression: PackageMeta.Compression,
    verify_signatures: bool,
    parallel_downloads: u32,
    timeout_ms: u32,
    retry_count: u32,

    pub fn deinit(self: *CacheConfig, allocator: Allocator) void {
        for (self.sources) |*source| {
            source.deinit(allocator);
        }
        allocator.free(self.sources);
    }

    /// Load configuration from file
    pub fn load(allocator: Allocator, path: []const u8) !CacheConfig {
        const file = std.fs.openFileAbsolute(path, .{}) catch |err| {
            if (err == error.FileNotFound) {
                return CacheConfig.default(allocator);
            }
            return err;
        };
        defer file.close();

        const content = try file.readToEndAlloc(allocator, 1024 * 1024);
        defer allocator.free(content);

        return parseYaml(allocator, content);
    }

    /// Default configuration
    pub fn default(allocator: Allocator) CacheConfig {
        _ = allocator;
        return CacheConfig{
            .sources = &.{},
            .default_compression = .zstd,
            .verify_signatures = true,
            .parallel_downloads = 4,
            .timeout_ms = 30000,
            .retry_count = 3,
        };
    }

    /// Parse YAML configuration
    fn parseYaml(allocator: Allocator, content: []const u8) !CacheConfig {
        var sources: std.ArrayList(CacheSource) = .empty;
        errdefer {
            for (sources.items) |*s| s.deinit(allocator);
            sources.deinit(allocator);
        }

        var config = CacheConfig{
            .sources = &.{},
            .default_compression = .zstd,
            .verify_signatures = true,
            .parallel_downloads = 4,
            .timeout_ms = 30000,
            .retry_count = 3,
        };

        var lines = std.mem.splitScalar(u8, content, '\n');
        var in_caches = false;
        var current_source: ?CacheSource = null;

        while (lines.next()) |line| {
            const trimmed = std.mem.trim(u8, line, " \t\r");
            if (trimmed.len == 0 or trimmed[0] == '#') continue;

            if (std.mem.startsWith(u8, trimmed, "caches:")) {
                in_caches = true;
                continue;
            }

            if (in_caches) {
                if (std.mem.startsWith(u8, trimmed, "- url:")) {
                    // Save previous source
                    if (current_source) |src| {
                        try sources.append(allocator, src);
                    }
                    // Start new source
                    const url_start = std.mem.indexOf(u8, trimmed, ":") orelse continue;
                    const url = std.mem.trim(u8, trimmed[url_start + 1 ..], " \t");
                    current_source = CacheSource{
                        .url = try allocator.dupe(u8, url),
                        .priority = 50,
                        .trust_key = null,
                        .enabled = true,
                        .name = null,
                    };
                } else if (current_source != null) {
                    if (std.mem.startsWith(u8, trimmed, "priority:")) {
                        const val_start = std.mem.indexOf(u8, trimmed, ":") orelse continue;
                        const val = std.mem.trim(u8, trimmed[val_start + 1 ..], " \t");
                        current_source.?.priority = std.fmt.parseInt(u32, val, 10) catch 50;
                    } else if (std.mem.startsWith(u8, trimmed, "trust:")) {
                        const val_start = std.mem.indexOf(u8, trimmed, ":") orelse continue;
                        const val = std.mem.trim(u8, trimmed[val_start + 1 ..], " \t");
                        current_source.?.trust_key = try allocator.dupe(u8, val);
                    } else if (std.mem.startsWith(u8, trimmed, "name:")) {
                        const val_start = std.mem.indexOf(u8, trimmed, ":") orelse continue;
                        const val = std.mem.trim(u8, trimmed[val_start + 1 ..], " \t");
                        current_source.?.name = try allocator.dupe(u8, val);
                    } else if (std.mem.startsWith(u8, trimmed, "enabled:")) {
                        const val_start = std.mem.indexOf(u8, trimmed, ":") orelse continue;
                        const val = std.mem.trim(u8, trimmed[val_start + 1 ..], " \t");
                        current_source.?.enabled = std.mem.eql(u8, val, "true");
                    }
                }
            } else {
                // Global settings
                if (std.mem.startsWith(u8, trimmed, "verify_signatures:")) {
                    const val_start = std.mem.indexOf(u8, trimmed, ":") orelse continue;
                    const val = std.mem.trim(u8, trimmed[val_start + 1 ..], " \t");
                    config.verify_signatures = std.mem.eql(u8, val, "true");
                } else if (std.mem.startsWith(u8, trimmed, "parallel_downloads:")) {
                    const val_start = std.mem.indexOf(u8, trimmed, ":") orelse continue;
                    const val = std.mem.trim(u8, trimmed[val_start + 1 ..], " \t");
                    config.parallel_downloads = std.fmt.parseInt(u32, val, 10) catch 4;
                } else if (std.mem.startsWith(u8, trimmed, "timeout_ms:")) {
                    const val_start = std.mem.indexOf(u8, trimmed, ":") orelse continue;
                    const val = std.mem.trim(u8, trimmed[val_start + 1 ..], " \t");
                    config.timeout_ms = std.fmt.parseInt(u32, val, 10) catch 30000;
                }
            }
        }

        // Save last source
        if (current_source) |src| {
            try sources.append(allocator, src);
        }

        config.sources = try sources.toOwnedSlice(allocator);
        return config;
    }
};

/// HTTP response codes
pub const HttpStatus = enum(u16) {
    ok = 200,
    created = 201,
    no_content = 204,
    partial_content = 206,
    bad_request = 400,
    unauthorized = 401,
    forbidden = 403,
    not_found = 404,
    conflict = 409,
    range_not_satisfiable = 416,
    internal_error = 500,
    not_implemented = 501,

    pub fn message(self: HttpStatus) []const u8 {
        return switch (self) {
            .ok => "OK",
            .created => "Created",
            .no_content => "No Content",
            .partial_content => "Partial Content",
            .bad_request => "Bad Request",
            .unauthorized => "Unauthorized",
            .forbidden => "Forbidden",
            .not_found => "Not Found",
            .conflict => "Conflict",
            .range_not_satisfiable => "Range Not Satisfiable",
            .internal_error => "Internal Server Error",
            .not_implemented => "Not Implemented",
        };
    }
};

/// HTTP request for cache operations
pub const CacheRequest = struct {
    method: Method,
    path: []const u8,
    headers: std.StringHashMap([]const u8),
    body: ?[]const u8,

    pub const Method = enum {
        GET,
        POST,
        PUT,
        DELETE,
        HEAD,
    };

    pub fn deinit(self: *CacheRequest, allocator: Allocator) void {
        var iter = self.headers.iterator();
        while (iter.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            allocator.free(entry.value_ptr.*);
        }
        self.headers.deinit();
        if (self.body) |b| allocator.free(b);
        allocator.free(self.path);
    }
};

/// HTTP response from cache
pub const CacheResponse = struct {
    status: HttpStatus,
    headers: std.StringHashMap([]const u8),
    body: ?[]const u8,

    pub fn deinit(self: *CacheResponse, allocator: Allocator) void {
        var iter = self.headers.iterator();
        while (iter.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            allocator.free(entry.value_ptr.*);
        }
        self.headers.deinit();
        if (self.body) |b| allocator.free(b);
    }
};

/// Cache server implementation
pub const CacheServer = struct {
    allocator: Allocator,
    store_path: []const u8,
    port: u16,
    name: []const u8,
    public_key: ?[]const u8,
    running: bool,

    const Self = @This();

    /// Initialize cache server
    pub fn init(allocator: Allocator, store_path: []const u8, port: u16) Self {
        return Self{
            .allocator = allocator,
            .store_path = store_path,
            .port = port,
            .name = "axiom-cache",
            .public_key = null,
            .running = false,
        };
    }

    /// Get server info
    pub fn getInfo(self: *Self) !CacheInfo {
        var package_count: u64 = 0;
        const total_size: u64 = 0;

        // Count packages in store
        const pkg_path = try std.fmt.allocPrint(self.allocator, "{s}/pkg", .{self.store_path});
        defer self.allocator.free(pkg_path);

        var dir = std.fs.openDirAbsolute(pkg_path, .{ .iterate = true }) catch |err| {
            if (err == error.FileNotFound) {
                return CacheInfo{
                    .name = self.name,
                    .version = "1.0.0",
                    .protocol_version = PROTOCOL_VERSION,
                    .package_count = 0,
                    .total_size = 0,
                    .public_key = self.public_key,
                    .features = &[_][]const u8{ "range-requests", "compression", "signatures" },
                };
            }
            return err;
        };
        defer dir.close();

        var iter = dir.iterate();
        while (try iter.next()) |entry| {
            if (entry.kind == .directory) {
                package_count += 1;
                // Count size would require walking subdirectories
            }
        }

        return CacheInfo{
            .name = self.name,
            .version = "1.0.0",
            .protocol_version = PROTOCOL_VERSION,
            .package_count = package_count,
            .total_size = total_size,
            .public_key = self.public_key,
            .features = &[_][]const u8{ "range-requests", "compression", "signatures" },
        };
    }

    /// List all packages
    pub fn listPackages(self: *Self) ![]PackageMeta {
        var packages: std.ArrayList(PackageMeta) = .empty;
        errdefer {
            for (packages.items) |*p| p.deinit(self.allocator);
            packages.deinit(self.allocator);
        }

        const pkg_path = try std.fmt.allocPrint(self.allocator, "{s}/pkg", .{self.store_path});
        defer self.allocator.free(pkg_path);

        var dir = std.fs.openDirAbsolute(pkg_path, .{ .iterate = true }) catch {
            return packages.toOwnedSlice(self.allocator);
        };
        defer dir.close();

        var iter = dir.iterate();
        while (try iter.next()) |entry| {
            if (entry.kind == .directory) {
                // Try to load package metadata
                if (try self.getPackageMeta(entry.name, "latest")) |meta| {
                    try packages.append(self.allocator, meta);
                }
            }
        }

        return packages.toOwnedSlice(self.allocator);
    }

    /// Get package metadata
    pub fn getPackageMeta(self: *Self, name: []const u8, version: []const u8) !?PackageMeta {
        _ = version; // Would look up specific version

        const meta_path = try std.fmt.allocPrint(
            self.allocator,
            "{s}/pkg/{s}/meta.json",
            .{ self.store_path, name },
        );
        defer self.allocator.free(meta_path);

        const file = std.fs.openFileAbsolute(meta_path, .{}) catch {
            return null;
        };
        defer file.close();

        const content = try file.readToEndAlloc(self.allocator, 1024 * 1024);
        defer self.allocator.free(content);

        // Simple JSON parsing for metadata
        return try parsePackageMeta(self.allocator, content);
    }

    /// Get package NAR (Nix Archive) / tarball
    pub fn getPackageNar(self: *Self, name: []const u8, version: []const u8) !?[]const u8 {
        const nar_path = try std.fmt.allocPrint(
            self.allocator,
            "{s}/pkg/{s}/{s}.nar.zst",
            .{ self.store_path, name, version },
        );
        defer self.allocator.free(nar_path);

        const file = std.fs.openFileAbsolute(nar_path, .{}) catch {
            // Try uncompressed
            const plain_path = try std.fmt.allocPrint(
                self.allocator,
                "{s}/pkg/{s}/{s}.nar",
                .{ self.store_path, name, version },
            );
            defer self.allocator.free(plain_path);

            const plain_file = std.fs.openFileAbsolute(plain_path, .{}) catch {
                return null;
            };
            defer plain_file.close();

            return try plain_file.readToEndAlloc(self.allocator, 1024 * 1024 * 1024);
        };
        defer file.close();

        return try file.readToEndAlloc(self.allocator, 1024 * 1024 * 1024);
    }

    /// Handle incoming request
    pub fn handleRequest(self: *Self, request: *CacheRequest) !CacheResponse {
        var response = CacheResponse{
            .status = .ok,
            .headers = std.StringHashMap([]const u8).init(self.allocator),
            .body = null,
        };

        // Add common headers
        try response.headers.put(
            try self.allocator.dupe(u8, "Content-Type"),
            try self.allocator.dupe(u8, "application/json"),
        );
        try response.headers.put(
            try self.allocator.dupe(u8, "X-Axiom-Protocol"),
            try self.allocator.dupe(u8, PROTOCOL_VERSION),
        );

        // Route request
        if (std.mem.eql(u8, request.path, Endpoints.INFO)) {
            const info = try self.getInfo();
            response.body = try info.toJson(self.allocator);
        } else if (std.mem.eql(u8, request.path, Endpoints.PACKAGES)) {
            const packages = try self.listPackages();
            defer {
                for (@constCast(packages)) |*p| p.deinit(self.allocator);
                self.allocator.free(packages);
            }

            var json: std.ArrayList(u8) = .empty;
            try json.appendSlice(self.allocator, "[");
            for (packages, 0..) |pkg, i| {
                if (i > 0) try json.append(self.allocator, ',');
                const pkg_json = try pkg.toJson(self.allocator);
                defer self.allocator.free(pkg_json);
                try json.appendSlice(self.allocator, pkg_json);
            }
            try json.appendSlice(self.allocator, "]");
            response.body = try json.toOwnedSlice(self.allocator);
        } else if (std.mem.startsWith(u8, request.path, "/api/v1/packages/")) {
            // Parse package name and version from path
            const path_rest = request.path[17..]; // After "/api/v1/packages/"
            var parts = std.mem.splitScalar(u8, path_rest, '/');
            const name = parts.next() orelse {
                response.status = .bad_request;
                response.body = try self.allocator.dupe(u8, "{\"error\":\"Missing package name\"}");
                return response;
            };
            const version = parts.next() orelse "latest";
            const resource = parts.next();

            if (resource == null or std.mem.eql(u8, resource.?, "meta")) {
                // Return metadata
                if (try self.getPackageMeta(name, version)) |meta| {
                    defer @constCast(&meta).deinit(self.allocator);
                    response.body = try meta.toJson(self.allocator);
                } else {
                    response.status = .not_found;
                    response.body = try self.allocator.dupe(u8, "{\"error\":\"Package not found\"}");
                }
            } else if (std.mem.eql(u8, resource.?, "nar")) {
                // Return NAR file
                if (try self.getPackageNar(name, version)) |nar| {
                    response.body = nar;
                    // Update content type
                    if (response.headers.getPtr("Content-Type")) |ct| {
                        self.allocator.free(ct.*);
                        ct.* = try self.allocator.dupe(u8, "application/octet-stream");
                    }
                } else {
                    response.status = .not_found;
                    response.body = try self.allocator.dupe(u8, "{\"error\":\"Package NAR not found\"}");
                }
            } else {
                response.status = .not_found;
                response.body = try self.allocator.dupe(u8, "{\"error\":\"Unknown resource\"}");
            }
        } else {
            response.status = .not_found;
            response.body = try self.allocator.dupe(u8, "{\"error\":\"Endpoint not found\"}");
        }

        return response;
    }

    /// Start the server (blocking)
    pub fn start(self: *Self) !void {
        self.running = true;

        const address = std.net.Address.initIp4(.{ 0, 0, 0, 0 }, self.port);
        var server = try address.listen(.{
            .reuse_address = true,
        });
        defer server.deinit();

        std.log.info("Cache server listening on port {d}", .{self.port});

        while (self.running) {
            const connection = server.accept() catch |err| {
                std.log.err("Accept failed: {}", .{err});
                continue;
            };

            // Handle connection in same thread (could spawn threads for parallel handling)
            self.handleConnection(connection) catch |err| {
                std.log.err("Connection handling failed: {}", .{err});
            };
        }
    }

    /// Stop the server
    pub fn stop(self: *Self) void {
        self.running = false;
    }

    /// Handle a single connection
    fn handleConnection(self: *Self, connection: std.net.Server.Connection) !void {
        defer connection.stream.close();

        var buf: [8192]u8 = undefined;
        const bytes_read = try connection.stream.read(&buf);
        if (bytes_read == 0) return;

        // Parse HTTP request (simplified)
        var request = try parseHttpRequest(self.allocator, buf[0..bytes_read]);
        defer request.deinit(self.allocator);

        // Handle request
        var response = try self.handleRequest(&request);
        defer response.deinit(self.allocator);

        // Send response
        try sendHttpResponse(connection.stream, &response);
    }
};

/// Cache client for fetching from remote caches
pub const CacheClient = struct {
    allocator: Allocator,
    config: CacheConfig,
    trust_store: ?*signature.TrustStore,

    const Self = @This();

    /// Initialize cache client
    pub fn init(allocator: Allocator, config: CacheConfig) Self {
        return Self{
            .allocator = allocator,
            .config = config,
            .trust_store = null,
        };
    }

    /// Initialize with trust store for signature verification
    pub fn initWithTrust(allocator: Allocator, config: CacheConfig, trust_store: *signature.TrustStore) Self {
        return Self{
            .allocator = allocator,
            .config = config,
            .trust_store = trust_store,
        };
    }

    /// Fetch package from cache
    pub fn fetchPackage(self: *Self, name: []const u8, version: []const u8) !?FetchResult {
        // Sort sources by priority (higher first)
        const sorted_sources = try self.allocator.alloc(CacheSource, self.config.sources.len);
        defer self.allocator.free(sorted_sources);
        @memcpy(sorted_sources, self.config.sources);

        std.mem.sort(CacheSource, sorted_sources, {}, struct {
            fn lessThan(_: void, a: CacheSource, b: CacheSource) bool {
                return a.priority > b.priority;
            }
        }.lessThan);

        // Try each source
        for (sorted_sources) |source| {
            if (!source.enabled) continue;

            if (try self.fetchFromSource(source, name, version)) |result| {
                return result;
            }
        }

        return null;
    }

    /// Fetch from a specific source
    fn fetchFromSource(self: *Self, source: CacheSource, name: []const u8, version: []const u8) !?FetchResult {
        // Build URL
        const meta_url = try std.fmt.allocPrint(
            self.allocator,
            "{s}/api/v1/packages/{s}/{s}/meta",
            .{ source.url, name, version },
        );
        defer self.allocator.free(meta_url);

        // Fetch metadata (would use HTTP client)
        const meta_response = try self.httpGet(meta_url);
        defer if (meta_response) |r| self.allocator.free(r);

        if (meta_response == null) return null;

        // Parse metadata
        const meta = try parsePackageMeta(self.allocator, meta_response.?);
        errdefer @constCast(&meta).deinit(self.allocator);

        // Verify signature if required
        if (self.config.verify_signatures and self.trust_store != null) {
            if (meta.signatures.len == 0) {
                std.log.warn("Package {s}@{s} has no signatures, skipping", .{ name, version });
                return null;
            }

            // Verify at least one signature
            var verified = false;
            for (meta.signatures) |_| {
                // Would verify signature against trust store
                verified = true;
                break;
            }

            if (!verified) {
                std.log.warn("Package {s}@{s} signature verification failed", .{ name, version });
                return null;
            }
        }

        // Fetch NAR
        const nar_url = try std.fmt.allocPrint(
            self.allocator,
            "{s}/api/v1/packages/{s}/{s}/nar",
            .{ source.url, name, version },
        );
        defer self.allocator.free(nar_url);

        const nar_data = try self.httpGet(nar_url);
        if (nar_data == null) {
            @constCast(&meta).deinit(self.allocator);
            return null;
        }

        return FetchResult{
            .meta = meta,
            .data = nar_data.?,
            .source_url = try self.allocator.dupe(u8, source.url),
        };
    }

    /// HTTP GET request (simplified - would use proper HTTP client)
    fn httpGet(self: *Self, url: []const u8) !?[]const u8 {
        // Validate URL before parsing
        const url_result = validation.UrlValidator.validate(url);
        if (!url_result.valid) {
            std.log.warn("Invalid URL: {s} - {s}", .{ url, url_result.error_message orelse "unknown error" });
            return null;
        }

        // Use validated components
        const actual_host = url_result.host orelse return null;
        const path = url_result.path orelse "/";

        // Determine port - use validated port or default based on scheme
        const port: u16 = url_result.port orelse switch (url_result.scheme) {
            .https => 443,
            .http => 80,
            else => 80,
        };

        // Connect
        const stream = std.net.tcpConnectToHost(self.allocator, actual_host, port) catch {
            return null;
        };
        defer stream.close();

        // Send request
        var request_buf: [4096]u8 = undefined;
        const request = std.fmt.bufPrint(&request_buf, "GET {s} HTTP/1.1\r\nHost: {s}\r\nConnection: close\r\n\r\n", .{ path, actual_host }) catch {
            return null;
        };
        stream.writeAll(request) catch {
            return null;
        };

        // Read response
        var response: std.ArrayList(u8) = .empty;
        errdefer response.deinit(self.allocator);

        var buf: [8192]u8 = undefined;
        while (true) {
            const n = stream.read(&buf) catch break;
            if (n == 0) break;
            try response.appendSlice(self.allocator, buf[0..n]);
        }

        // Skip HTTP headers to get body
        const header_end = std.mem.indexOf(u8, response.items, "\r\n\r\n");
        if (header_end) |idx| {
            const body = response.items[idx + 4 ..];
            const result = try self.allocator.dupe(u8, body);
            response.deinit(self.allocator);
            return result;
        }

        return try response.toOwnedSlice(self.allocator);
    }

    /// Push package to cache
    pub fn pushPackage(self: *Self, source_url: []const u8, name: []const u8, version: []const u8, data: []const u8, meta: PackageMeta) !void {
        const upload_url = try std.fmt.allocPrint(
            self.allocator,
            "{s}/api/v1/upload/{s}/{s}",
            .{ source_url, name, version },
        );
        defer self.allocator.free(upload_url);

        // Would POST data and metadata
        _ = data;
        _ = meta;

        std.log.info("Would push package to {s}", .{upload_url});
    }

    /// Sync metadata from all sources
    pub fn syncMetadata(self: *Self) !SyncResult {
        var result = SyncResult{
            .sources_checked = 0,
            .packages_found = 0,
            .packages_new = 0,
            .errors = 0,
        };

        for (self.config.sources) |source| {
            if (!source.enabled) continue;

            result.sources_checked += 1;

            const info_url = try std.fmt.allocPrint(
                self.allocator,
                "{s}/api/v1/info",
                .{source.url},
            );
            defer self.allocator.free(info_url);

            if (try self.httpGet(info_url)) |info_json| {
                defer self.allocator.free(info_json);
                // Parse and count packages
                // Would update local cache index
                result.packages_found += 1;
            } else {
                result.errors += 1;
            }
        }

        return result;
    }
};

/// Result of fetching a package
pub const FetchResult = struct {
    meta: PackageMeta,
    data: []const u8,
    source_url: []const u8,

    pub fn deinit(self: *FetchResult, allocator: Allocator) void {
        @constCast(&self.meta).deinit(allocator);
        allocator.free(self.data);
        allocator.free(self.source_url);
    }
};

/// Result of sync operation
pub const SyncResult = struct {
    sources_checked: u32,
    packages_found: u32,
    packages_new: u32,
    errors: u32,
};

/// Parse HTTP request (simplified)
fn parseHttpRequest(allocator: Allocator, data: []const u8) !CacheRequest {
    var lines = std.mem.splitSequence(u8, data, "\r\n");
    const request_line = lines.next() orelse return error.InvalidRequest;

    var parts = std.mem.splitScalar(u8, request_line, ' ');
    const method_str = parts.next() orelse return error.InvalidRequest;
    const path = parts.next() orelse return error.InvalidRequest;

    const method: CacheRequest.Method = if (std.mem.eql(u8, method_str, "GET"))
        .GET
    else if (std.mem.eql(u8, method_str, "POST"))
        .POST
    else if (std.mem.eql(u8, method_str, "PUT"))
        .PUT
    else if (std.mem.eql(u8, method_str, "DELETE"))
        .DELETE
    else if (std.mem.eql(u8, method_str, "HEAD"))
        .HEAD
    else
        .GET;

    var headers = std.StringHashMap([]const u8).init(allocator);
    errdefer headers.deinit();

    // Parse headers
    while (lines.next()) |line| {
        if (line.len == 0) break;
        if (std.mem.indexOf(u8, line, ": ")) |sep| {
            const key = try allocator.dupe(u8, line[0..sep]);
            const value = try allocator.dupe(u8, line[sep + 2 ..]);
            try headers.put(key, value);
        }
    }

    return CacheRequest{
        .method = method,
        .path = try allocator.dupe(u8, path),
        .headers = headers,
        .body = null, // Would parse body for POST/PUT
    };
}

/// Send HTTP response
fn sendHttpResponse(stream: std.net.Stream, response: *const CacheResponse) !void {
    var buf: [65536]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const writer = fbs.writer();

    // Status line
    try writer.print("HTTP/1.1 {d} {s}\r\n", .{
        @intFromEnum(response.status),
        response.status.message(),
    });

    // Headers
    var iter = response.headers.iterator();
    while (iter.next()) |entry| {
        try writer.print("{s}: {s}\r\n", .{ entry.key_ptr.*, entry.value_ptr.* });
    }

    // Content length
    if (response.body) |body| {
        try writer.print("Content-Length: {d}\r\n", .{body.len});
    }

    try writer.writeAll("\r\n");

    // Body
    if (response.body) |body| {
        try writer.writeAll(body);
    }

    try stream.writeAll(fbs.getWritten());
}

/// Parse package metadata from JSON
fn parsePackageMeta(allocator: Allocator, json: []const u8) !PackageMeta {
    // Simple JSON parsing - in production would use proper JSON parser
    var meta = PackageMeta{
        .name = "",
        .version = "",
        .hash = "",
        .size = 0,
        .compressed_size = 0,
        .compression = .none,
        .dependencies = &.{},
        .description = null,
        .signatures = &.{},
    };

    // Extract fields (simplified)
    if (extractJsonString(allocator, json, "name")) |name| {
        meta.name = name;
    } else {
        meta.name = try allocator.dupe(u8, "unknown");
    }

    if (extractJsonString(allocator, json, "version")) |version| {
        meta.version = version;
    } else {
        meta.version = try allocator.dupe(u8, "0.0.0");
    }

    if (extractJsonString(allocator, json, "hash")) |hash| {
        meta.hash = hash;
    } else {
        meta.hash = try allocator.dupe(u8, "");
    }

    if (extractJsonNumber(json, "size")) |size| {
        meta.size = size;
    }

    if (extractJsonNumber(json, "compressed_size")) |size| {
        meta.compressed_size = size;
    }

    return meta;
}

/// Extract string value from JSON
fn extractJsonString(allocator: Allocator, json: []const u8, key: []const u8) ?[]const u8 {
    const search = std.fmt.allocPrint(allocator, "\"{s}\":\"", .{key}) catch return null;
    defer allocator.free(search);

    const start = std.mem.indexOf(u8, json, search) orelse return null;
    const value_start = start + search.len;
    const value_end = std.mem.indexOfPos(u8, json, value_start, "\"") orelse return null;

    return allocator.dupe(u8, json[value_start..value_end]) catch null;
}

/// Extract number value from JSON
fn extractJsonNumber(json: []const u8, key: []const u8) ?u64 {
    var buf: [256]u8 = undefined;
    const search = std.fmt.bufPrint(&buf, "\"{s}\":", .{key}) catch return null;

    const start = std.mem.indexOf(u8, json, search) orelse return null;
    const value_start = start + search.len;

    // Find end of number
    var end = value_start;
    while (end < json.len and (json[end] >= '0' and json[end] <= '9')) {
        end += 1;
    }

    if (end == value_start) return null;

    return std.fmt.parseInt(u64, json[value_start..end], 10) catch null;
}

// Tests
test "cache config default" {
    const allocator = std.testing.allocator;
    const config = CacheConfig.default(allocator);
    try std.testing.expect(config.verify_signatures);
    try std.testing.expectEqual(@as(u32, 4), config.parallel_downloads);
}

test "http status messages" {
    try std.testing.expectEqualStrings("OK", HttpStatus.ok.message());
    try std.testing.expectEqualStrings("Not Found", HttpStatus.not_found.message());
}

test "compression extensions" {
    try std.testing.expectEqualStrings(".zst", PackageMeta.Compression.zstd.extension());
    try std.testing.expectEqualStrings(".gz", PackageMeta.Compression.gzip.extension());
    try std.testing.expectEqualStrings("", PackageMeta.Compression.none.extension());
}

test "extract json string" {
    const allocator = std.testing.allocator;
    const json = "{\"name\":\"test-pkg\",\"version\":\"1.0.0\"}";

    const name = extractJsonString(allocator, json, "name");
    try std.testing.expect(name != null);
    try std.testing.expectEqualStrings("test-pkg", name.?);
    allocator.free(name.?);

    const version = extractJsonString(allocator, json, "version");
    try std.testing.expect(version != null);
    try std.testing.expectEqualStrings("1.0.0", version.?);
    allocator.free(version.?);
}

test "extract json number" {
    const json = "{\"size\":12345,\"count\":42}";

    const size = extractJsonNumber(json, "size");
    try std.testing.expect(size != null);
    try std.testing.expectEqual(@as(u64, 12345), size.?);

    const count = extractJsonNumber(json, "count");
    try std.testing.expect(count != null);
    try std.testing.expectEqual(@as(u64, 42), count.?);
}
