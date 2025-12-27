const std = @import("std");
const types = @import("types.zig");

const PackageId = types.PackageId;
const Version = types.Version;

/// Types of file conflicts that can occur during realization
pub const ConflictType = enum {
    same_content,      // Files are identical (no real conflict)
    different_content, // Files have different content
    type_mismatch,     // File vs directory conflict
    permission_diff,   // Same content but different permissions
};

/// A file conflict between packages
pub const FileConflict = struct {
    path: []const u8,
    packages: []PackageId,
    conflict_type: ConflictType,

    /// First package's file info
    first_size: u64,
    first_hash: ?[32]u8,

    /// Second package's file info
    second_size: u64,
    second_hash: ?[32]u8,
};

/// Strategy for renaming conflicting files
pub const RenameStrategy = struct {
    pattern: []const u8,  // e.g., "{name}.{package}"
};

/// Strategy for merging config files
pub const MergeStrategy = enum {
    concatenate,     // Append contents
    union_lines,     // Unique lines from both
    json_merge,      // Deep merge JSON objects
    ini_merge,       // Merge INI sections
};

/// How a conflict should be resolved
pub const ConflictResolution = union(enum) {
    use_package: PackageId,      // Use file from specific package
    rename: RenameStrategy,      // Rename to avoid conflict
    merge: MergeStrategy,        // Attempt to merge
    skip: void,                  // Skip the file
    @"error": void,              // Fail on conflict
    keep_both: void,             // Keep both with suffix
};

/// Default conflict policy
pub const ConflictPolicy = enum {
    error_on_conflict,  // Fail immediately on any conflict
    priority_wins,      // Later package in priority order wins
    interactive,        // Ask user (not implemented yet)
    keep_both,          // Keep both files with package suffix
};

/// Rule for handling conflicts in specific paths
pub const ConflictRule = struct {
    path_pattern: []const u8,    // Glob pattern for matching paths
    strategy: ConflictResolution,
    priority_order: ?[][]const u8 = null,  // Package names in priority order
};

/// Configuration for conflict resolution
pub const ConflictConfig = struct {
    allocator: std.mem.Allocator,
    default_policy: ConflictPolicy,
    rules: std.ArrayList(ConflictRule),

    pub fn init(allocator: std.mem.Allocator) ConflictConfig {
        return ConflictConfig{
            .allocator = allocator,
            .default_policy = .error_on_conflict,
            .rules = .empty,
        };
    }

    pub fn deinit(self: *ConflictConfig) void {
        self.rules.deinit(self.allocator);
    }

    /// Add a rule for handling conflicts in specific paths
    pub fn addRule(self: *ConflictConfig, rule: ConflictRule) !void {
        try self.rules.append(self.allocator, rule);
    }

    /// Find the best matching rule for a path
    pub fn findRule(self: *ConflictConfig, path: []const u8) ?ConflictRule {
        // Check rules in reverse order (last added = highest priority)
        var i: usize = self.rules.items.len;
        while (i > 0) {
            i -= 1;
            const rule = self.rules.items[i];
            if (matchesPattern(path, rule.path_pattern)) {
                return rule;
            }
        }
        return null;
    }
};

/// Record of how a conflict was resolved
pub const ConflictRecord = struct {
    path: []const u8,
    conflict: FileConflict,
    resolution: ConflictResolution,
    timestamp: i64,
};

/// Tracks conflicts and resolutions during realization
pub const ConflictTracker = struct {
    allocator: std.mem.Allocator,
    conflicts: std.ArrayList(FileConflict),
    resolutions: std.ArrayList(ConflictRecord),
    config: *ConflictConfig,

    pub fn init(allocator: std.mem.Allocator, config: *ConflictConfig) ConflictTracker {
        return ConflictTracker{
            .allocator = allocator,
            .conflicts = .empty,
            .resolutions = .empty,
            .config = config,
        };
    }

    pub fn deinit(self: *ConflictTracker) void {
        self.conflicts.deinit(self.allocator);
        self.resolutions.deinit(self.allocator);
    }

    /// Check if two files conflict
    pub fn checkFileConflict(
        self: *ConflictTracker,
        path: []const u8,
        pkg1: PackageId,
        pkg1_path: []const u8,
        pkg2: PackageId,
        pkg2_path: []const u8,
    ) !?FileConflict {
        // Get file stats
        const stat1 = std.fs.cwd().statFile(pkg1_path) catch |err| {
            if (err == error.FileNotFound) return null;
            return err;
        };
        const stat2 = std.fs.cwd().statFile(pkg2_path) catch |err| {
            if (err == error.FileNotFound) return null;
            return err;
        };

        // Check for type mismatch
        const is_dir1 = stat1.kind == .directory;
        const is_dir2 = stat2.kind == .directory;
        if (is_dir1 != is_dir2) {
            var packages = try self.allocator.alloc(PackageId, 2);
            packages[0] = pkg1;
            packages[1] = pkg2;
            return FileConflict{
                .path = try self.allocator.dupe(u8, path),
                .packages = packages,
                .conflict_type = .type_mismatch,
                .first_size = stat1.size,
                .first_hash = null,
                .second_size = stat2.size,
                .second_hash = null,
            };
        }

        // Skip directories
        if (is_dir1) return null;

        // Check if sizes are different (quick check)
        if (stat1.size != stat2.size) {
            var packages = try self.allocator.alloc(PackageId, 2);
            packages[0] = pkg1;
            packages[1] = pkg2;
            return FileConflict{
                .path = try self.allocator.dupe(u8, path),
                .packages = packages,
                .conflict_type = .different_content,
                .first_size = stat1.size,
                .first_hash = null,
                .second_size = stat2.size,
                .second_hash = null,
            };
        }

        // Compare content hashes for same-size files
        const hash1 = try hashFile(pkg1_path);
        const hash2 = try hashFile(pkg2_path);

        if (std.mem.eql(u8, &hash1, &hash2)) {
            // Same content - check permissions
            if (stat1.mode != stat2.mode) {
                var packages = try self.allocator.alloc(PackageId, 2);
                packages[0] = pkg1;
                packages[1] = pkg2;
                return FileConflict{
                    .path = try self.allocator.dupe(u8, path),
                    .packages = packages,
                    .conflict_type = .permission_diff,
                    .first_size = stat1.size,
                    .first_hash = hash1,
                    .second_size = stat2.size,
                    .second_hash = hash2,
                };
            }
            // Identical files - no real conflict
            return null;
        }

        // Different content
        var packages = try self.allocator.alloc(PackageId, 2);
        packages[0] = pkg1;
        packages[1] = pkg2;
        return FileConflict{
            .path = try self.allocator.dupe(u8, path),
            .packages = packages,
            .conflict_type = .different_content,
            .first_size = stat1.size,
            .first_hash = hash1,
            .second_size = stat2.size,
            .second_hash = hash2,
        };
    }

    /// Record a detected conflict
    pub fn recordConflict(self: *ConflictTracker, conflict: FileConflict) !void {
        try self.conflicts.append(self.allocator, conflict);
    }

    /// Resolve a conflict according to policy
    pub fn resolveConflict(
        self: *ConflictTracker,
        conflict: FileConflict,
    ) !ConflictResolution {
        // Check for path-specific rule
        if (self.config.findRule(conflict.path)) |rule| {
            try self.resolutions.append(self.allocator, .{
                .path = conflict.path,
                .conflict = conflict,
                .resolution = rule.strategy,
                .timestamp = std.time.timestamp(),
            });
            return rule.strategy;
        }

        // Apply default policy
        const resolution: ConflictResolution = switch (self.config.default_policy) {
            .error_on_conflict => .{ .@"error" = {} },
            .priority_wins => blk: {
                // Use the second package (later in realization order)
                if (conflict.packages.len > 1) {
                    break :blk .{ .use_package = conflict.packages[1] };
                }
                break :blk .{ .@"error" = {} };
            },
            .interactive => .{ .@"error" = {} }, // Not implemented
            .keep_both => .{ .keep_both = {} },
        };

        try self.resolutions.append(self.allocator, .{
            .path = conflict.path,
            .conflict = conflict,
            .resolution = resolution,
            .timestamp = std.time.timestamp(),
        });

        return resolution;
    }

    /// Get summary of all conflicts
    pub fn getSummary(self: *ConflictTracker) ConflictSummary {
        var same_content: usize = 0;
        var different_content: usize = 0;
        var type_mismatch: usize = 0;
        var permission_diff: usize = 0;

        for (self.conflicts.items) |conflict| {
            switch (conflict.conflict_type) {
                .same_content => same_content += 1,
                .different_content => different_content += 1,
                .type_mismatch => type_mismatch += 1,
                .permission_diff => permission_diff += 1,
            }
        }

        return ConflictSummary{
            .total = self.conflicts.items.len,
            .same_content = same_content,
            .different_content = different_content,
            .type_mismatch = type_mismatch,
            .permission_diff = permission_diff,
            .resolved = self.resolutions.items.len,
        };
    }

    /// Check if there are any unresolved conflicts that would block realization
    pub fn hasBlockingConflicts(self: *ConflictTracker) bool {
        for (self.resolutions.items) |record| {
            switch (record.resolution) {
                .@"error" => return true,
                else => {},
            }
        }
        return false;
    }
};

/// Summary of conflicts detected
pub const ConflictSummary = struct {
    total: usize,
    same_content: usize,
    different_content: usize,
    type_mismatch: usize,
    permission_diff: usize,
    resolved: usize,
};

/// Compute SHA256 hash of a file
fn hashFile(path: []const u8) ![32]u8 {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();

    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    var buffer: [8192]u8 = undefined;

    while (true) {
        const bytes_read = try file.read(&buffer);
        if (bytes_read == 0) break;
        hasher.update(buffer[0..bytes_read]);
    }

    return hasher.finalResult();
}

/// Check if a path matches a glob pattern
fn matchesPattern(path: []const u8, pattern: []const u8) bool {
    // Simple glob matching - supports * and **
    if (std.mem.eql(u8, pattern, "*")) return true;
    if (std.mem.eql(u8, pattern, "**")) return true;

    // Check for prefix match with wildcard
    if (std.mem.endsWith(u8, pattern, "/*")) {
        const prefix = pattern[0 .. pattern.len - 2];
        return std.mem.startsWith(u8, path, prefix);
    }
    if (std.mem.endsWith(u8, pattern, "/**")) {
        const prefix = pattern[0 .. pattern.len - 3];
        return std.mem.startsWith(u8, path, prefix);
    }

    // Exact match
    return std.mem.eql(u8, path, pattern);
}

/// Apply a rename strategy to generate a new filename
pub fn applyRenameStrategy(
    allocator: std.mem.Allocator,
    path: []const u8,
    package_name: []const u8,
    strategy: RenameStrategy,
) ![]const u8 {
    // Parse the pattern and replace placeholders
    var result: std.ArrayList(u8) = .empty;
    defer result.deinit(allocator);

    // Get the base name and extension
    const basename = std.fs.path.basename(path);
    const dirname = std.fs.path.dirname(path) orelse "";

    var ext_start: usize = basename.len;
    for (basename, 0..) |c, i| {
        if (c == '.') ext_start = i;
    }
    const name_part = basename[0..ext_start];
    const ext_part = if (ext_start < basename.len) basename[ext_start..] else "";

    var i: usize = 0;
    while (i < strategy.pattern.len) {
        if (std.mem.startsWith(u8, strategy.pattern[i..], "{name}")) {
            try result.appendSlice(allocator, name_part);
            i += 6;
        } else if (std.mem.startsWith(u8, strategy.pattern[i..], "{package}")) {
            try result.appendSlice(allocator, package_name);
            i += 9;
        } else if (std.mem.startsWith(u8, strategy.pattern[i..], "{ext}")) {
            try result.appendSlice(allocator, ext_part);
            i += 5;
        } else {
            try result.append(allocator, strategy.pattern[i]);
            i += 1;
        }
    }

    // Combine with directory
    if (dirname.len > 0) {
        var full_path: std.ArrayList(u8) = .empty;
        try full_path.appendSlice(allocator, dirname);
        try full_path.append(allocator, '/');
        try full_path.appendSlice(allocator, result.items);
        return full_path.toOwnedSlice(allocator);
    }

    return result.toOwnedSlice(allocator);
}

// Tests
test "ConflictConfig.findRule" {
    var config = ConflictConfig.init(std.testing.allocator);
    defer config.deinit();

    try config.addRule(.{
        .path_pattern = "/etc/*",
        .strategy = .{ .skip = {} },
    });
    try config.addRule(.{
        .path_pattern = "/bin/*",
        .strategy = .{ .@"error" = {} },
    });

    // Test matching
    const rule1 = config.findRule("/etc/config.conf");
    try std.testing.expect(rule1 != null);

    const rule2 = config.findRule("/bin/ls");
    try std.testing.expect(rule2 != null);

    const rule3 = config.findRule("/usr/lib/libfoo.so");
    try std.testing.expect(rule3 == null);
}

test "matchesPattern" {
    try std.testing.expect(matchesPattern("/etc/foo", "/etc/*"));
    try std.testing.expect(matchesPattern("/etc/sub/foo", "/etc/**"));
    try std.testing.expect(!matchesPattern("/bin/foo", "/etc/*"));
    try std.testing.expect(matchesPattern("/bin/ls", "/bin/ls"));
}

test "applyRenameStrategy" {
    const allocator = std.testing.allocator;

    const strategy = RenameStrategy{ .pattern = "{name}.{package}{ext}" };
    const result = try applyRenameStrategy(allocator, "/bin/ls", "coreutils", strategy);
    defer allocator.free(result);

    try std.testing.expectEqualStrings("/bin/ls.coreutils", result);
}

test "applyRenameStrategy with extension" {
    const allocator = std.testing.allocator;

    const strategy = RenameStrategy{ .pattern = "{name}.{package}{ext}" };
    const result = try applyRenameStrategy(allocator, "/lib/libfoo.so", "foo-pkg", strategy);
    defer allocator.free(result);

    try std.testing.expectEqualStrings("/lib/libfoo.foo-pkg.so", result);
}

test "ConflictSummary" {
    const allocator = std.testing.allocator;

    var config = ConflictConfig.init(allocator);
    defer config.deinit();

    var tracker = ConflictTracker.init(allocator, &config);
    defer tracker.deinit();

    const summary = tracker.getSummary();
    try std.testing.expectEqual(@as(usize, 0), summary.total);
    try std.testing.expectEqual(@as(usize, 0), summary.resolved);
}
