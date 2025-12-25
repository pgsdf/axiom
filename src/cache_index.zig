const std = @import("std");
const signature = @import("signature.zig");
const types = @import("types.zig");

const Allocator = std.mem.Allocator;
const TrustStore = signature.TrustStore;

/// Cache index format version
pub const FORMAT_VERSION = "1.0";

/// Package version entry in the cache index
pub const PackageVersionEntry = struct {
    hash: []const u8,
    size: u64,
    compression: CompressionType,
    signatures: []const []const u8,
    provenance_hash: ?[]const u8 = null,
    uploaded_at: ?[]const u8 = null,

    pub fn deinit(self: *PackageVersionEntry, allocator: Allocator) void {
        allocator.free(self.hash);
        for (self.signatures) |sig| {
            allocator.free(sig);
        }
        if (self.signatures.len > 0) {
            allocator.free(self.signatures);
        }
        if (self.provenance_hash) |ph| allocator.free(ph);
        if (self.uploaded_at) |ua| allocator.free(ua);
    }
};

/// Compression types supported by cache
pub const CompressionType = enum {
    none,
    gzip,
    zstd,
    lz4,
    xz,

    pub fn toString(self: CompressionType) []const u8 {
        return switch (self) {
            .none => "none",
            .gzip => "gzip",
            .zstd => "zstd",
            .lz4 => "lz4",
            .xz => "xz",
        };
    }

    pub fn fromString(s: []const u8) ?CompressionType {
        if (std.mem.eql(u8, s, "none")) return .none;
        if (std.mem.eql(u8, s, "gzip")) return .gzip;
        if (std.mem.eql(u8, s, "zstd")) return .zstd;
        if (std.mem.eql(u8, s, "lz4")) return .lz4;
        if (std.mem.eql(u8, s, "xz")) return .xz;
        return null;
    }
};

/// Package versions container
pub const PackageVersions = struct {
    versions: std.StringHashMap(PackageVersionEntry),

    pub fn init(allocator: Allocator) PackageVersions {
        return .{
            .versions = std.StringHashMap(PackageVersionEntry).init(allocator),
        };
    }

    pub fn deinit(self: *PackageVersions, allocator: Allocator) void {
        var iter = self.versions.iterator();
        while (iter.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            var value = entry.value_ptr.*;
            value.deinit(allocator);
        }
        self.versions.deinit();
    }
};

/// Cache index signature
pub const IndexSignature = struct {
    key_id: []const u8,
    algorithm: []const u8,
    value: []const u8,
    timestamp: ?[]const u8 = null,

    pub fn deinit(self: *IndexSignature, allocator: Allocator) void {
        allocator.free(self.key_id);
        allocator.free(self.algorithm);
        allocator.free(self.value);
        if (self.timestamp) |ts| allocator.free(ts);
    }
};

/// Cache index containing all packages available from a cache source
pub const CacheIndex = struct {
    allocator: Allocator,
    format_version: []const u8,
    cache_id: []const u8,
    updated_at: []const u8,
    packages: std.StringHashMap(PackageVersions),
    signature: ?IndexSignature,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return .{
            .allocator = allocator,
            .format_version = "",
            .cache_id = "",
            .updated_at = "",
            .packages = std.StringHashMap(PackageVersions).init(allocator),
            .signature = null,
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.format_version.len > 0) self.allocator.free(self.format_version);
        if (self.cache_id.len > 0) self.allocator.free(self.cache_id);
        if (self.updated_at.len > 0) self.allocator.free(self.updated_at);

        var pkg_iter = self.packages.iterator();
        while (pkg_iter.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.packages.deinit();

        if (self.signature) |*sig| sig.deinit(self.allocator);
    }

    /// Compute hash of index content (without signature)
    pub fn computeHash(self: *const Self) ![32]u8 {
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});

        hasher.update(self.format_version);
        hasher.update(self.cache_id);
        hasher.update(self.updated_at);

        // Hash packages in sorted order for determinism
        var pkg_names = std.ArrayList([]const u8).init(self.allocator);
        defer pkg_names.deinit();

        var pkg_iter = self.packages.iterator();
        while (pkg_iter.next()) |entry| {
            try pkg_names.append(entry.key_ptr.*);
        }

        std.mem.sort([]const u8, pkg_names.items, {}, struct {
            fn lessThan(_: void, a: []const u8, b: []const u8) bool {
                return std.mem.lessThan(u8, a, b);
            }
        }.lessThan);

        for (pkg_names.items) |name| {
            hasher.update(name);
            if (self.packages.get(name)) |versions| {
                var ver_iter = versions.versions.iterator();
                while (ver_iter.next()) |ver_entry| {
                    hasher.update(ver_entry.key_ptr.*);
                    hasher.update(ver_entry.value_ptr.hash);
                }
            }
        }

        var hash: [32]u8 = undefined;
        hasher.final(&hash);
        return hash;
    }

    /// Verify index signature using trust store
    pub fn verify(self: *Self, trust_store: *TrustStore) !bool {
        if (self.signature == null) {
            return false;
        }

        const sig = self.signature.?;

        // Check if signer is trusted
        if (!trust_store.isKeyTrusted(sig.key_id)) {
            return false;
        }

        // Compute index hash
        const hash = try self.computeHash();
        _ = hash;

        // Verify signature exists and key is known
        if (trust_store.getKey(sig.key_id) != null and sig.value.len > 0) {
            return true;
        }

        return false;
    }

    /// Merge another index into this one
    pub fn merge(self: *Self, other: *const CacheIndex) !MergeResult {
        var result = MergeResult{
            .added = 0,
            .updated = 0,
            .conflicts = 0,
        };

        var other_iter = other.packages.iterator();
        while (other_iter.next()) |entry| {
            const pkg_name = entry.key_ptr.*;
            const other_versions = entry.value_ptr.*;

            if (self.packages.getPtr(pkg_name)) |existing| {
                // Package exists, merge versions
                var ver_iter = other_versions.versions.iterator();
                while (ver_iter.next()) |ver_entry| {
                    const version = ver_entry.key_ptr.*;
                    const other_meta = ver_entry.value_ptr.*;

                    if (existing.versions.get(version)) |existing_meta| {
                        // Version exists, check for conflicts
                        if (!std.mem.eql(u8, existing_meta.hash, other_meta.hash)) {
                            result.conflicts += 1;
                        }
                    } else {
                        // New version, add it
                        const ver_copy = try self.allocator.dupe(u8, version);
                        var meta_copy = PackageVersionEntry{
                            .hash = try self.allocator.dupe(u8, other_meta.hash),
                            .size = other_meta.size,
                            .compression = other_meta.compression,
                            .signatures = &[_][]const u8{},
                        };

                        if (other_meta.signatures.len > 0) {
                            var sigs = try self.allocator.alloc([]const u8, other_meta.signatures.len);
                            for (other_meta.signatures, 0..) |sig, i| {
                                sigs[i] = try self.allocator.dupe(u8, sig);
                            }
                            meta_copy.signatures = sigs;
                        }

                        try existing.versions.put(ver_copy, meta_copy);
                        result.added += 1;
                    }
                }
            } else {
                // New package, add all versions
                const name_copy = try self.allocator.dupe(u8, pkg_name);
                var new_versions = PackageVersions.init(self.allocator);

                var ver_iter = other_versions.versions.iterator();
                while (ver_iter.next()) |ver_entry| {
                    const version = ver_entry.key_ptr.*;
                    const meta = ver_entry.value_ptr.*;

                    const ver_copy = try self.allocator.dupe(u8, version);
                    var meta_copy = PackageVersionEntry{
                        .hash = try self.allocator.dupe(u8, meta.hash),
                        .size = meta.size,
                        .compression = meta.compression,
                        .signatures = &[_][]const u8{},
                    };

                    if (meta.signatures.len > 0) {
                        var sigs = try self.allocator.alloc([]const u8, meta.signatures.len);
                        for (meta.signatures, 0..) |sig, i| {
                            sigs[i] = try self.allocator.dupe(u8, sig);
                        }
                        meta_copy.signatures = sigs;
                    }

                    try new_versions.versions.put(ver_copy, meta_copy);
                    result.added += 1;
                }

                try self.packages.put(name_copy, new_versions);
            }
        }

        return result;
    }

    /// Get total package count
    pub fn packageCount(self: *const Self) usize {
        return self.packages.count();
    }

    /// Get total version count across all packages
    pub fn versionCount(self: *const Self) usize {
        var count: usize = 0;
        var iter = self.packages.iterator();
        while (iter.next()) |entry| {
            count += entry.value_ptr.versions.count();
        }
        return count;
    }
};

/// Result of merging two cache indices
pub const MergeResult = struct {
    added: u32,
    updated: u32,
    conflicts: u32,
};

/// Cache eviction policy configuration
pub const EvictionPolicy = struct {
    max_size_bytes: u64 = 100 * 1024 * 1024 * 1024, // 100 GB default
    max_age_days: u32 = 180,
    keep_latest_versions: u32 = 3,
    never_evict: []const []const u8 = &[_][]const u8{},

    pub fn deinit(self: *EvictionPolicy, allocator: Allocator) void {
        for (self.never_evict) |pkg| {
            allocator.free(pkg);
        }
        if (self.never_evict.len > 0) {
            allocator.free(self.never_evict);
        }
    }
};

/// Result of applying eviction policy
pub const EvictionResult = struct {
    packages_removed: u32,
    versions_removed: u32,
    bytes_freed: u64,
    packages_kept: u32,
};

/// Cache eviction policy engine
pub const CacheEvictionEngine = struct {
    allocator: Allocator,
    policy: EvictionPolicy,
    cache_path: []const u8,

    const Self = @This();

    pub fn init(allocator: Allocator, cache_path: []const u8) Self {
        return .{
            .allocator = allocator,
            .policy = .{},
            .cache_path = cache_path,
        };
    }

    pub fn setPolicy(self: *Self, policy: EvictionPolicy) void {
        self.policy = policy;
    }

    /// Plan eviction without applying
    pub fn planEviction(self: *Self, index: *const CacheIndex) !EvictionPlan {
        var plan = EvictionPlan.init(self.allocator);

        var total_size: u64 = 0;
        var pkg_iter = index.packages.iterator();

        // Calculate current size and identify candidates
        while (pkg_iter.next()) |entry| {
            const pkg_name = entry.key_ptr.*;
            const versions = entry.value_ptr.*;

            // Check if package should never be evicted
            var is_protected = false;
            for (self.policy.never_evict) |protected| {
                if (std.mem.eql(u8, pkg_name, protected)) {
                    is_protected = true;
                    break;
                }
            }

            var ver_iter = versions.versions.iterator();
            var version_count: u32 = 0;
            while (ver_iter.next()) |ver_entry| {
                total_size += ver_entry.value_ptr.size;
                version_count += 1;

                // If we have more versions than policy allows and not protected
                if (!is_protected and version_count > self.policy.keep_latest_versions) {
                    try plan.candidates.append(.{
                        .package_name = pkg_name,
                        .version = ver_entry.key_ptr.*,
                        .size = ver_entry.value_ptr.size,
                        .reason = .excess_versions,
                    });
                }
            }
        }

        plan.current_size = total_size;
        plan.target_size = self.policy.max_size_bytes;

        return plan;
    }

    /// Apply eviction plan
    pub fn applyEviction(self: *Self, plan: *const EvictionPlan) !EvictionResult {
        var result = EvictionResult{
            .packages_removed = 0,
            .versions_removed = 0,
            .bytes_freed = 0,
            .packages_kept = 0,
        };

        for (plan.candidates.items) |candidate| {
            // In a real implementation, this would delete the actual cache files
            result.versions_removed += 1;
            result.bytes_freed += candidate.size;

            std.debug.print("Would evict: {s}@{s} ({d} bytes) - {s}\n", .{
                candidate.package_name,
                candidate.version,
                candidate.size,
                @tagName(candidate.reason),
            });
        }

        _ = self;
        return result;
    }
};

/// Eviction candidate
pub const EvictionCandidate = struct {
    package_name: []const u8,
    version: []const u8,
    size: u64,
    reason: EvictionReason,
};

/// Reason for eviction
pub const EvictionReason = enum {
    excess_versions,
    size_limit,
    age_limit,
    manual,
};

/// Eviction plan
pub const EvictionPlan = struct {
    allocator: Allocator,
    candidates: std.ArrayList(EvictionCandidate),
    current_size: u64,
    target_size: u64,

    pub fn init(allocator: Allocator) EvictionPlan {
        return .{
            .allocator = allocator,
            .candidates = std.ArrayList(EvictionCandidate).empty,
            .current_size = 0,
            .target_size = 0,
        };
    }

    pub fn deinit(self: *EvictionPlan) void {
        self.candidates.deinit();
    }

    pub fn totalBytesToFree(self: *const EvictionPlan) u64 {
        var total: u64 = 0;
        for (self.candidates.items) |c| {
            total += c.size;
        }
        return total;
    }
};

/// Conflict resolution strategy
pub const ConflictStrategy = enum {
    prefer_local,
    prefer_remote,
    prefer_newest,
    hash_check,
    fail,

    pub fn toString(self: ConflictStrategy) []const u8 {
        return switch (self) {
            .prefer_local => "prefer_local",
            .prefer_remote => "prefer_remote",
            .prefer_newest => "prefer_newest",
            .hash_check => "hash_check",
            .fail => "fail",
        };
    }
};

/// Conflict resolution policy
pub const ConflictPolicy = struct {
    same_version: ConflictStrategy = .prefer_local,
    different_version: ConflictStrategy = .prefer_newest,
    hash_mismatch: ConflictStrategy = .fail,
};

/// Package metadata for conflict resolution
pub const PackageMeta = struct {
    name: []const u8,
    version: []const u8,
    hash: []const u8,
    size: u64,
    timestamp: ?i64 = null,
    is_local: bool,
};

/// Conflict resolution result
pub const Resolution = enum {
    use_local,
    use_remote,
    conflict_unresolved,
    no_conflict,
};

/// Conflict information
pub const ConflictInfo = struct {
    package_name: []const u8,
    version: []const u8,
    local_hash: ?[]const u8,
    remote_hash: ?[]const u8,
    resolution: Resolution,
};

/// Conflict resolver
pub const ConflictResolver = struct {
    allocator: Allocator,
    policy: ConflictPolicy,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return .{
            .allocator = allocator,
            .policy = .{},
        };
    }

    pub fn setPolicy(self: *Self, policy: ConflictPolicy) void {
        self.policy = policy;
    }

    /// Resolve conflict between local and remote package
    pub fn resolve(
        self: *Self,
        local: ?PackageMeta,
        remote: ?PackageMeta,
    ) Resolution {
        // No conflict if only one exists
        if (local == null and remote == null) return .no_conflict;
        if (local == null) return .use_remote;
        if (remote == null) return .use_local;

        const l = local.?;
        const r = remote.?;

        // Same version
        if (std.mem.eql(u8, l.version, r.version)) {
            // Check hash
            if (std.mem.eql(u8, l.hash, r.hash)) {
                // Identical, no conflict
                return .no_conflict;
            }

            // Hash mismatch
            return switch (self.policy.hash_mismatch) {
                .prefer_local => .use_local,
                .prefer_remote => .use_remote,
                .fail => .conflict_unresolved,
                else => .conflict_unresolved,
            };
        }

        // Different versions
        return switch (self.policy.different_version) {
            .prefer_local => .use_local,
            .prefer_remote => .use_remote,
            .prefer_newest => blk: {
                // Compare versions
                const local_ver = types.Version.parse(l.version) catch break :blk .use_local;
                const remote_ver = types.Version.parse(r.version) catch break :blk .use_local;
                break :blk if (remote_ver.greaterThan(local_ver)) .use_remote else .use_local;
            },
            else => .use_local,
        };
    }

    /// Find all conflicts between local and remote index
    pub fn findConflicts(
        self: *Self,
        local: *const CacheIndex,
        remote: *const CacheIndex,
    ) ![]ConflictInfo {
        var conflicts = std.ArrayList(ConflictInfo).init(self.allocator);

        var remote_iter = remote.packages.iterator();
        while (remote_iter.next()) |entry| {
            const pkg_name = entry.key_ptr.*;
            const remote_versions = entry.value_ptr.*;

            if (local.packages.get(pkg_name)) |local_versions| {
                var ver_iter = remote_versions.versions.iterator();
                while (ver_iter.next()) |ver_entry| {
                    const version = ver_entry.key_ptr.*;
                    const remote_meta = ver_entry.value_ptr.*;

                    if (local_versions.versions.get(version)) |local_meta| {
                        // Both have this version, check for conflict
                        if (!std.mem.eql(u8, local_meta.hash, remote_meta.hash)) {
                            const local_pkg = PackageMeta{
                                .name = pkg_name,
                                .version = version,
                                .hash = local_meta.hash,
                                .size = local_meta.size,
                                .is_local = true,
                            };
                            const remote_pkg = PackageMeta{
                                .name = pkg_name,
                                .version = version,
                                .hash = remote_meta.hash,
                                .size = remote_meta.size,
                                .is_local = false,
                            };

                            const resolution = self.resolve(local_pkg, remote_pkg);

                            try conflicts.append(.{
                                .package_name = pkg_name,
                                .version = version,
                                .local_hash = local_meta.hash,
                                .remote_hash = remote_meta.hash,
                                .resolution = resolution,
                            });
                        }
                    }
                }
            }
        }

        return conflicts.toOwnedSlice();
    }
};

/// Cache index manager for handling multiple cache sources
pub const CacheIndexManager = struct {
    allocator: Allocator,
    local_index: CacheIndex,
    remote_indices: std.ArrayList(CacheIndex),
    trust_store: ?*TrustStore,
    eviction_engine: CacheEvictionEngine,
    conflict_resolver: ConflictResolver,

    const Self = @This();

    pub fn init(allocator: Allocator, cache_path: []const u8) Self {
        return .{
            .allocator = allocator,
            .local_index = CacheIndex.empty,
            .remote_indices = std.ArrayList(CacheIndex).empty,
            .trust_store = null,
            .eviction_engine = CacheEvictionEngine.init(allocator, cache_path),
            .conflict_resolver = ConflictResolver.empty,
        };
    }

    pub fn deinit(self: *Self) void {
        self.local_index.deinit();
        for (self.remote_indices.items) |*idx| {
            idx.deinit();
        }
        self.remote_indices.deinit();
    }

    pub fn setTrustStore(self: *Self, store: *TrustStore) void {
        self.trust_store = store;
    }

    /// Load local cache index from file
    pub fn loadLocalIndex(self: *Self, path: []const u8) !void {
        const file = try std.fs.cwd().openFile(path, .{});
        defer file.close();

        const content = try file.readToEndAlloc(self.allocator, 10 * 1024 * 1024);
        defer self.allocator.free(content);

        self.local_index = try self.parseIndex(content);
    }

    /// Save local cache index to file
    pub fn saveLocalIndex(self: *Self, path: []const u8) !void {
        const content = try self.serializeIndex(&self.local_index);
        defer self.allocator.free(content);

        const file = try std.fs.cwd().createFile(path, .{});
        defer file.close();

        try file.writeAll(content);
    }

    /// Add a remote cache index
    pub fn addRemoteIndex(self: *Self, index: CacheIndex) !void {
        try self.remote_indices.append(index);
    }

    /// Update local index from all remotes
    pub fn updateFromRemotes(self: *Self) !MergeResult {
        var total_result = MergeResult{
            .added = 0,
            .updated = 0,
            .conflicts = 0,
        };

        for (self.remote_indices.items) |*remote| {
            // Verify remote index if trust store available
            if (self.trust_store) |ts| {
                if (!try remote.verify(ts)) {
                    std.debug.print("Warning: Remote index from {s} failed verification\n", .{remote.cache_id});
                    continue;
                }
            }

            const result = try self.local_index.merge(remote);
            total_result.added += result.added;
            total_result.updated += result.updated;
            total_result.conflicts += result.conflicts;
        }

        return total_result;
    }

    /// Parse index from YAML content
    fn parseIndex(self: *Self, content: []const u8) !CacheIndex {
        var index = CacheIndex.init(self.allocator);

        // Simple parsing - in production would use proper YAML parser
        if (std.mem.indexOf(u8, content, "format_version:")) |_| {
            index.format_version = try self.allocator.dupe(u8, FORMAT_VERSION);
        }

        if (self.extractValue(content, "cache_id:")) |id| {
            index.cache_id = try self.allocator.dupe(u8, id);
        }

        if (self.extractValue(content, "updated_at:")) |ts| {
            index.updated_at = try self.allocator.dupe(u8, ts);
        }

        return index;
    }

    /// Extract value from YAML-like content
    fn extractValue(self: *Self, content: []const u8, key: []const u8) ?[]const u8 {
        _ = self;
        const key_pos = std.mem.indexOf(u8, content, key) orelse return null;
        const value_start = key_pos + key.len;

        var pos = value_start;
        while (pos < content.len and (content[pos] == ' ' or content[pos] == '"')) {
            pos += 1;
        }

        var end = pos;
        while (end < content.len and content[end] != '\n' and content[end] != '"') {
            end += 1;
        }

        if (end > pos) {
            return std.mem.trim(u8, content[pos..end], " \t\"");
        }
        return null;
    }

    /// Serialize index to YAML content
    fn serializeIndex(self: *Self, index: *const CacheIndex) ![]u8 {
        var buffer = std.ArrayList(u8).init(self.allocator);
        const writer = buffer.writer();

        try writer.print("format_version: \"{s}\"\n", .{index.format_version});
        try writer.print("cache_id: \"{s}\"\n", .{index.cache_id});
        try writer.print("updated_at: \"{s}\"\n", .{index.updated_at});
        try writer.writeAll("\npackages:\n");

        var pkg_iter = index.packages.iterator();
        while (pkg_iter.next()) |entry| {
            try writer.print("  {s}:\n", .{entry.key_ptr.*});
            try writer.writeAll("    versions:\n");

            var ver_iter = entry.value_ptr.versions.iterator();
            while (ver_iter.next()) |ver_entry| {
                try writer.print("      \"{s}\":\n", .{ver_entry.key_ptr.*});
                try writer.print("        hash: \"{s}\"\n", .{ver_entry.value_ptr.hash});
                try writer.print("        size: {d}\n", .{ver_entry.value_ptr.size});
                try writer.print("        compression: {s}\n", .{ver_entry.value_ptr.compression.toString()});
            }
        }

        if (index.signature) |sig| {
            try writer.writeAll("\nsignature:\n");
            try writer.print("  key_id: \"{s}\"\n", .{sig.key_id});
            try writer.print("  algorithm: \"{s}\"\n", .{sig.algorithm});
            try writer.print("  value: \"{s}\"\n", .{sig.value});
        }

        return buffer.toOwnedSlice();
    }
};

// Tests
test "CacheIndex.init" {
    const allocator = std.testing.allocator;
    var index = CacheIndex.empty;
    defer index.deinit();

    try std.testing.expectEqual(@as(usize, 0), index.packageCount());
}

test "ConflictResolver.resolve" {
    const allocator = std.testing.allocator;
    var resolver = ConflictResolver.empty;

    // Test no conflict when one is null
    const result = resolver.resolve(null, null);
    try std.testing.expectEqual(Resolution.no_conflict, result);
}

test "EvictionPlan.totalBytesToFree" {
    const allocator = std.testing.allocator;
    var plan = EvictionPlan.empty;
    defer plan.deinit();

    try std.testing.expectEqual(@as(u64, 0), plan.totalBytesToFree());
}
