const std = @import("std");
const Allocator = std.mem.Allocator;

/// Current format versions for all Axiom data structures
/// Increment minor version for backwards-compatible changes
/// Increment major version for breaking changes
pub const FormatVersions = struct {
    /// Package manifest format (manifest.yaml)
    pub const manifest: []const u8 = "1.0";

    /// Profile format (profile.yaml)
    pub const profile: []const u8 = "1.0";

    /// Lock file format (profile.lock.yaml)
    pub const lock: []const u8 = "1.0";

    /// Store layout version (.store_version)
    pub const store: []const u8 = "1.0";

    /// Build provenance format (provenance.yaml)
    pub const provenance: []const u8 = "1.0";

    /// Cache index format (cache-index.yaml)
    pub const cache_index: []const u8 = "1.0";
};

/// Parsed semantic version for comparison
pub const SemanticVersion = struct {
    major: u32,
    minor: u32,
    patch: u32 = 0,

    /// Parse a version string like "1.0" or "1.2.3"
    pub fn parse(version_str: []const u8) !SemanticVersion {
        var parts = std.mem.splitScalar(u8, version_str, '.');
        const major_str = parts.next() orelse return error.InvalidVersion;
        const minor_str = parts.next() orelse return error.InvalidVersion;
        const patch_str = parts.next();

        const major = std.fmt.parseInt(u32, major_str, 10) catch return error.InvalidVersion;
        const minor = std.fmt.parseInt(u32, minor_str, 10) catch return error.InvalidVersion;
        const patch = if (patch_str) |p| std.fmt.parseInt(u32, p, 10) catch return error.InvalidVersion else 0;

        return .{ .major = major, .minor = minor, .patch = patch };
    }

    /// Format version as string
    pub fn format(self: SemanticVersion, allocator: Allocator) ![]const u8 {
        if (self.patch == 0) {
            return std.fmt.allocPrint(allocator, "{d}.{d}", .{ self.major, self.minor });
        } else {
            return std.fmt.allocPrint(allocator, "{d}.{d}.{d}", .{ self.major, self.minor, self.patch });
        }
    }

    /// Check if this version is compatible with expected version
    /// Compatible means: same major version, file minor <= expected minor
    pub fn isCompatibleWith(self: SemanticVersion, expected: SemanticVersion) bool {
        // Same major version required
        if (self.major != expected.major) return false;
        // File minor version must be <= expected (we can read older formats)
        return self.minor <= expected.minor;
    }

    /// Check if versions are exactly equal
    pub fn eql(self: SemanticVersion, other: SemanticVersion) bool {
        return self.major == other.major and self.minor == other.minor and self.patch == other.patch;
    }

    /// Compare versions: returns -1 if self < other, 0 if equal, 1 if self > other
    pub fn compare(self: SemanticVersion, other: SemanticVersion) i32 {
        if (self.major < other.major) return -1;
        if (self.major > other.major) return 1;
        if (self.minor < other.minor) return -1;
        if (self.minor > other.minor) return 1;
        if (self.patch < other.patch) return -1;
        if (self.patch > other.patch) return 1;
        return 0;
    }
};

/// Version compatibility check result
pub const CompatibilityResult = struct {
    compatible: bool,
    file_version: SemanticVersion,
    expected_version: SemanticVersion,
    needs_migration: bool,
    migration_available: bool,

    pub fn format(self: CompatibilityResult, allocator: Allocator) ![]const u8 {
        const file_str = try self.file_version.format(allocator);
        defer allocator.free(file_str);
        const expected_str = try self.expected_version.format(allocator);
        defer allocator.free(expected_str);

        if (self.compatible and !self.needs_migration) {
            return std.fmt.allocPrint(allocator, "Version {s} is current", .{file_str});
        } else if (self.compatible and self.needs_migration) {
            return std.fmt.allocPrint(allocator, "Version {s} is compatible but older than {s} - migration recommended", .{ file_str, expected_str });
        } else if (self.migration_available) {
            return std.fmt.allocPrint(allocator, "Version {s} is incompatible with {s} - migration required", .{ file_str, expected_str });
        } else {
            return std.fmt.allocPrint(allocator, "Version {s} is incompatible with {s} - no migration path available", .{ file_str, expected_str });
        }
    }
};

/// Format type for version checking
pub const FormatType = enum {
    manifest,
    profile,
    lock,
    store,
    provenance,
    cache_index,

    /// Get the current expected version for this format type
    pub fn currentVersion(self: FormatType) []const u8 {
        return switch (self) {
            .manifest => FormatVersions.manifest,
            .profile => FormatVersions.profile,
            .lock => FormatVersions.lock,
            .store => FormatVersions.store,
            .provenance => FormatVersions.provenance,
            .cache_index => FormatVersions.cache_index,
        };
    }

    /// Get human-readable name
    pub fn name(self: FormatType) []const u8 {
        return switch (self) {
            .manifest => "manifest",
            .profile => "profile",
            .lock => "lock file",
            .store => "store layout",
            .provenance => "provenance",
            .cache_index => "cache index",
        };
    }
};

/// Version validation errors
pub const VersionError = error{
    /// Version string could not be parsed
    InvalidVersion,
    /// Major version mismatch - incompatible format
    IncompatibleMajorVersion,
    /// Minor version too new - file from future version
    VersionTooNew,
    /// No format_version field found
    MissingVersion,
    /// Migration required but not available
    MigrationUnavailable,
};

/// Check compatibility of a format version
pub fn checkCompatibility(format_type: FormatType, file_version_str: []const u8) !CompatibilityResult {
    const file_version = try SemanticVersion.parse(file_version_str);
    const expected_version = try SemanticVersion.parse(format_type.currentVersion());

    const compatible = file_version.isCompatibleWith(expected_version);
    const needs_migration = file_version.compare(expected_version) < 0;
    const migration_available = hasMigrationPath(format_type, file_version, expected_version);

    return .{
        .compatible = compatible,
        .file_version = file_version,
        .expected_version = expected_version,
        .needs_migration = needs_migration,
        .migration_available = migration_available,
    };
}

/// Validate that a file version is usable (compatible or migratable)
pub fn validateVersion(format_type: FormatType, file_version_str: ?[]const u8) VersionError!void {
    const version_str = file_version_str orelse {
        // No version specified - assume compatible for backwards compat with pre-versioned files
        // In strict mode, this would return error.MissingVersion
        return;
    };

    const result = checkCompatibility(format_type, version_str) catch |err| {
        return switch (err) {
            error.InvalidVersion => VersionError.InvalidVersion,
            else => VersionError.InvalidVersion,
        };
    };

    if (!result.compatible) {
        if (result.file_version.major != result.expected_version.major) {
            return VersionError.IncompatibleMajorVersion;
        }
        if (result.file_version.minor > result.expected_version.minor) {
            return VersionError.VersionTooNew;
        }
        if (!result.migration_available) {
            return VersionError.MigrationUnavailable;
        }
    }
}

/// Migration function type
pub const MigrateFn = *const fn (allocator: Allocator, data: []const u8) anyerror![]const u8;

/// A registered migration path
pub const Migration = struct {
    format_type: FormatType,
    from_version: SemanticVersion,
    to_version: SemanticVersion,
    migrate: MigrateFn,
    description: []const u8,
};

/// Registry of available migrations
const migrations: []const Migration = &[_]Migration{
    // Future migrations will be added here
    // Example:
    // .{
    //     .format_type = .manifest,
    //     .from_version = .{ .major = 1, .minor = 0 },
    //     .to_version = .{ .major = 1, .minor = 1 },
    //     .migrate = migrateManifest_1_0_to_1_1,
    //     .description = "Add support for feature flags",
    // },
};

/// Check if a migration path exists between two versions
pub fn hasMigrationPath(format_type: FormatType, from: SemanticVersion, to: SemanticVersion) bool {
    // Direct migration available?
    for (migrations) |m| {
        if (m.format_type == format_type and
            m.from_version.eql(from) and
            m.to_version.eql(to))
        {
            return true;
        }
    }

    // Check for multi-step migration path
    // For now, just check for direct paths
    // TODO: Implement transitive migration path finding

    // If versions are equal, no migration needed
    if (from.eql(to)) return true;

    // If from is older but same major, we can read it without migration
    if (from.major == to.major and from.minor <= to.minor) return true;

    return false;
}

/// Find and execute migration from one version to another
pub fn migrate(allocator: Allocator, format_type: FormatType, data: []const u8, from: SemanticVersion, to: SemanticVersion) ![]const u8 {
    // No migration needed if versions match
    if (from.eql(to)) {
        return try allocator.dupe(u8, data);
    }

    // Find direct migration
    for (migrations) |m| {
        if (m.format_type == format_type and
            m.from_version.eql(from) and
            m.to_version.eql(to))
        {
            return try m.migrate(allocator, data);
        }
    }

    // If from is older but compatible, no transformation needed
    if (from.major == to.major and from.minor <= to.minor) {
        return try allocator.dupe(u8, data);
    }

    return error.MigrationUnavailable;
}

/// Store version file management
pub const StoreVersion = struct {
    const STORE_VERSION_FILE = ".store_version";

    /// Read the store version from .store_version file
    pub fn read(store_path: []const u8, allocator: Allocator) !?[]const u8 {
        const version_path = try std.fs.path.join(allocator, &.{ store_path, STORE_VERSION_FILE });
        defer allocator.free(version_path);

        const file = std.fs.openFileAbsolute(version_path, .{}) catch |err| {
            if (err == error.FileNotFound) return null;
            return err;
        };
        defer file.close();

        var buf: [64]u8 = undefined;
        const bytes_read = try file.readAll(&buf);
        const content = std.mem.trim(u8, buf[0..bytes_read], " \t\r\n");

        return try allocator.dupe(u8, content);
    }

    /// Write the store version to .store_version file
    pub fn write(store_path: []const u8, version: []const u8, allocator: Allocator) !void {
        const version_path = try std.fs.path.join(allocator, &.{ store_path, STORE_VERSION_FILE });
        defer allocator.free(version_path);

        const file = try std.fs.createFileAbsolute(version_path, .{});
        defer file.close();

        try file.writeAll(version);
        try file.writeAll("\n");
    }

    /// Initialize store version file if it doesn't exist
    pub fn initIfMissing(store_path: []const u8, allocator: Allocator) !void {
        const existing = try read(store_path, allocator);
        if (existing) |v| {
            allocator.free(v);
            return;
        }

        try write(store_path, FormatVersions.store, allocator);
    }

    /// Check store version compatibility
    pub fn check(store_path: []const u8, allocator: Allocator) !CompatibilityResult {
        const version = try read(store_path, allocator) orelse FormatVersions.store;
        defer allocator.free(version);

        return try checkCompatibility(.store, version);
    }
};

/// Utility to extract format_version from YAML content
pub fn extractFormatVersion(yaml_content: []const u8) ?[]const u8 {
    var lines = std.mem.splitScalar(u8, yaml_content, '\n');

    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len == 0) continue;
        if (std.mem.startsWith(u8, trimmed, "#")) continue;

        // Look for format_version: key
        if (std.mem.startsWith(u8, trimmed, "format_version:")) {
            var parts = std.mem.splitScalar(u8, trimmed, ':');
            _ = parts.next(); // skip key
            const value = std.mem.trim(u8, parts.rest(), " \t\"'");
            if (value.len > 0) {
                return value;
            }
        }
    }

    return null;
}

/// Generate YAML header with format_version
pub fn generateVersionHeader(allocator: Allocator, format_type: FormatType) ![]const u8 {
    return std.fmt.allocPrint(allocator, "format_version: \"{s}\"\n", .{format_type.currentVersion()});
}

// Tests
test "SemanticVersion.parse" {
    const v1 = try SemanticVersion.parse("1.0");
    try std.testing.expectEqual(@as(u32, 1), v1.major);
    try std.testing.expectEqual(@as(u32, 0), v1.minor);
    try std.testing.expectEqual(@as(u32, 0), v1.patch);

    const v2 = try SemanticVersion.parse("2.3.4");
    try std.testing.expectEqual(@as(u32, 2), v2.major);
    try std.testing.expectEqual(@as(u32, 3), v2.minor);
    try std.testing.expectEqual(@as(u32, 4), v2.patch);
}

test "SemanticVersion.isCompatibleWith" {
    const v1_0 = try SemanticVersion.parse("1.0");
    const v1_1 = try SemanticVersion.parse("1.1");
    const v2_0 = try SemanticVersion.parse("2.0");

    // Same version is compatible
    try std.testing.expect(v1_0.isCompatibleWith(v1_0));

    // Older minor version is compatible
    try std.testing.expect(v1_0.isCompatibleWith(v1_1));

    // Newer minor version is NOT compatible (file is from future)
    try std.testing.expect(!v1_1.isCompatibleWith(v1_0));

    // Different major version is NOT compatible
    try std.testing.expect(!v1_0.isCompatibleWith(v2_0));
    try std.testing.expect(!v2_0.isCompatibleWith(v1_0));
}

test "extractFormatVersion" {
    const yaml1 =
        \\format_version: "1.0"
        \\name: test
        \\version: "1.2.3"
    ;
    try std.testing.expectEqualStrings("1.0", extractFormatVersion(yaml1).?);

    const yaml2 =
        \\# Comment
        \\format_version: 2.1
        \\name: test
    ;
    try std.testing.expectEqualStrings("2.1", extractFormatVersion(yaml2).?);

    const yaml3 =
        \\name: test
        \\version: "1.0"
    ;
    try std.testing.expect(extractFormatVersion(yaml3) == null);
}

test "checkCompatibility" {
    const result = try checkCompatibility(.manifest, "1.0");
    try std.testing.expect(result.compatible);
    try std.testing.expect(!result.needs_migration);
}
