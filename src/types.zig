const std = @import("std");

/// Semantic version with major.minor.patch
pub const Version = struct {
    major: u32,
    minor: u32,
    patch: u32,

    /// Parse a semantic version string
    /// Accepts 1, 2, or 3 part versions (e.g., "1", "1.07", "1.2.3")
    pub fn parse(s: []const u8) !Version {
        var parts = std.mem.splitScalar(u8, s, '.');

        const major_str = parts.next() orelse return error.InvalidVersion;
        const minor_str = parts.next();
        const patch_str = if (minor_str != null) parts.next() else null;

        return Version{
            .major = try std.fmt.parseInt(u32, major_str, 10),
            .minor = if (minor_str) |m| try std.fmt.parseInt(u32, m, 10) else 0,
            .patch = if (patch_str) |p| try std.fmt.parseInt(u32, p, 10) else 0,
        };
    }

    /// Format version as string (major.minor.patch)
    pub fn format(
        self: Version,
        writer: anytype,
    ) !void {
        var buf: [32]u8 = undefined;
        const str = std.fmt.bufPrint(&buf, "{d}.{d}.{d}", .{ self.major, self.minor, self.patch }) catch unreachable;
        try writer.writeAll(str);
    }

    /// Compare two versions
    pub fn compare(self: Version, other: Version) std.math.Order {
        if (self.major != other.major) {
            return std.math.order(self.major, other.major);
        }
        if (self.minor != other.minor) {
            return std.math.order(self.minor, other.minor);
        }
        return std.math.order(self.patch, other.patch);
    }

    /// Check if this version is less than another
    pub fn lessThan(self: Version, other: Version) bool {
        return self.compare(other) == .lt;
    }

    /// Check if this version equals another
    pub fn equal(self: Version, other: Version) bool {
        return self.compare(other) == .eq;
    }

    /// Check if this version is greater than another
    pub fn greaterThan(self: Version, other: Version) bool {
        return self.compare(other) == .gt;
    }
};

/// Version constraint types
pub const VersionConstraint = union(enum) {
    /// Exact version match (1.2.3)
    exact: Version,
    
    /// Version range (>=1.2.0,<2.0.0)
    range: struct {
        min: ?Version,
        max: ?Version,
        min_inclusive: bool,
        max_inclusive: bool,
    },
    
    /// Tilde constraint (~1.2.3 means >=1.2.3,<1.3.0)
    tilde: Version,
    
    /// Caret constraint (^1.2.3 means >=1.2.3,<2.0.0)
    caret: Version,
    
    /// Any version
    any: void,

    /// Check if a version satisfies this constraint
    pub fn satisfies(self: VersionConstraint, version: Version) bool {
        return switch (self) {
            .exact => |v| version.equal(v),
            .any => true,
            .tilde => |v| {
                // ~1.2.3 means >=1.2.3 and <1.3.0
                if (version.lessThan(v)) return false;
                if (version.major != v.major) return false;
                if (version.minor != v.minor) return false;
                return true;
            },
            .caret => |v| {
                // ^1.2.3 means >=1.2.3 and <2.0.0
                if (version.lessThan(v)) return false;
                if (version.major != v.major) return false;
                return true;
            },
            .range => |r| {
                if (r.min) |min| {
                    const cmp = version.compare(min);
                    if (r.min_inclusive) {
                        if (cmp == .lt) return false;
                    } else {
                        if (cmp != .gt) return false;
                    }
                }
                if (r.max) |max| {
                    const cmp = version.compare(max);
                    if (r.max_inclusive) {
                        if (cmp == .gt) return false;
                    } else {
                        if (cmp != .lt) return false;
                    }
                }
                return true;
            },
        };
    }
};

/// Package dependency specification
pub const Dependency = struct {
    name: []const u8,
    constraint: VersionConstraint,

    /// If true, this dependency is optional (can be omitted)
    optional: bool = false,

    /// If true, this is a virtual dependency (satisfied by providers)
    virtual: bool = false,

    /// Human-readable description (mainly for optional dependencies)
    description: ?[]const u8 = null,

    /// Feature that enables this dependency (null = always enabled)
    feature: ?[]const u8 = null,

    /// Create a simple required dependency
    pub fn required(name: []const u8, constraint: VersionConstraint) Dependency {
        return .{ .name = name, .constraint = constraint };
    }

    /// Create an optional dependency
    pub fn optionalDep(name: []const u8, constraint: VersionConstraint, desc: ?[]const u8) Dependency {
        return .{
            .name = name,
            .constraint = constraint,
            .optional = true,
            .description = desc,
        };
    }

    /// Create a virtual dependency
    pub fn virtualDep(name: []const u8) Dependency {
        return .{
            .name = name,
            .constraint = .any,
            .virtual = true,
        };
    }

    /// Create a feature-gated dependency
    pub fn forFeature(name: []const u8, constraint: VersionConstraint, feat: []const u8) Dependency {
        return .{
            .name = name,
            .constraint = constraint,
            .feature = feat,
        };
    }
};

/// Unique package identifier
pub const PackageId = struct {
    name: []const u8,
    version: Version,
    revision: u32,
    build_id: []const u8,

    pub fn format(
        self: PackageId,
        writer: anytype,
    ) !void {
        try writer.writeAll(self.name);
        try writer.writeAll("/");
        try self.version.format(writer);
        var rev_buf: [16]u8 = undefined;
        const rev_str = std.fmt.bufPrint(&rev_buf, "/{d}/", .{self.revision}) catch unreachable;
        try writer.writeAll(rev_str);
        try writer.writeAll(self.build_id);
    }
};

// Tests
test "Version.parse" {
    const v = try Version.parse("1.2.3");
    try std.testing.expectEqual(@as(u32, 1), v.major);
    try std.testing.expectEqual(@as(u32, 2), v.minor);
    try std.testing.expectEqual(@as(u32, 3), v.patch);
}

test "Version.compare" {
    const v1 = Version{ .major = 1, .minor = 2, .patch = 3 };
    const v2 = Version{ .major = 1, .minor = 2, .patch = 4 };
    const v3 = Version{ .major = 1, .minor = 3, .patch = 0 };

    try std.testing.expect(v1.lessThan(v2));
    try std.testing.expect(v2.lessThan(v3));
    try std.testing.expect(v1.equal(v1));
}

test "VersionConstraint.exact" {
    const v = Version{ .major = 1, .minor = 2, .patch = 3 };
    const constraint = VersionConstraint{ .exact = v };

    try std.testing.expect(constraint.satisfies(v));
    try std.testing.expect(!constraint.satisfies(Version{ .major = 1, .minor = 2, .patch = 4 }));
}

test "VersionConstraint.tilde" {
    const v = Version{ .major = 1, .minor = 2, .patch = 3 };
    const constraint = VersionConstraint{ .tilde = v };

    try std.testing.expect(constraint.satisfies(Version{ .major = 1, .minor = 2, .patch = 3 }));
    try std.testing.expect(constraint.satisfies(Version{ .major = 1, .minor = 2, .patch = 5 }));
    try std.testing.expect(!constraint.satisfies(Version{ .major = 1, .minor = 3, .patch = 0 }));
}

test "VersionConstraint.caret" {
    const v = Version{ .major = 1, .minor = 2, .patch = 3 };
    const constraint = VersionConstraint{ .caret = v };

    try std.testing.expect(constraint.satisfies(Version{ .major = 1, .minor = 2, .patch = 3 }));
    try std.testing.expect(constraint.satisfies(Version{ .major = 1, .minor = 5, .patch = 0 }));
    try std.testing.expect(!constraint.satisfies(Version{ .major = 2, .minor = 0, .patch = 0 }));
}

test "VersionConstraint.range" {
    // Range: >=1.0.0 and <2.0.0
    const constraint = VersionConstraint{
        .range = .{
            .min = Version{ .major = 1, .minor = 0, .patch = 0 },
            .max = Version{ .major = 2, .minor = 0, .patch = 0 },
            .min_inclusive = true,
            .max_inclusive = false,
        },
    };

    try std.testing.expect(constraint.satisfies(Version{ .major = 1, .minor = 0, .patch = 0 })); // min inclusive
    try std.testing.expect(constraint.satisfies(Version{ .major = 1, .minor = 5, .patch = 0 })); // middle
    try std.testing.expect(constraint.satisfies(Version{ .major = 1, .minor = 99, .patch = 99 })); // near max
    try std.testing.expect(!constraint.satisfies(Version{ .major = 0, .minor = 9, .patch = 0 })); // below min
    try std.testing.expect(!constraint.satisfies(Version{ .major = 2, .minor = 0, .patch = 0 })); // max exclusive
    try std.testing.expect(!constraint.satisfies(Version{ .major = 3, .minor = 0, .patch = 0 })); // above max
}

test "VersionConstraint.any" {
    const constraint = VersionConstraint{ .any = {} };

    try std.testing.expect(constraint.satisfies(Version{ .major = 0, .minor = 0, .patch = 0 }));
    try std.testing.expect(constraint.satisfies(Version{ .major = 1, .minor = 2, .patch = 3 }));
    try std.testing.expect(constraint.satisfies(Version{ .major = 999, .minor = 999, .patch = 999 }));
}

test "Version.parse edge cases" {
    // Single digit version
    const v1 = try Version.parse("5");
    try std.testing.expectEqual(@as(u32, 5), v1.major);
    try std.testing.expectEqual(@as(u32, 0), v1.minor);
    try std.testing.expectEqual(@as(u32, 0), v1.patch);

    // Two part version
    const v2 = try Version.parse("2.3");
    try std.testing.expectEqual(@as(u32, 2), v2.major);
    try std.testing.expectEqual(@as(u32, 3), v2.minor);
    try std.testing.expectEqual(@as(u32, 0), v2.patch);

    // Large version numbers
    const v3 = try Version.parse("100.200.300");
    try std.testing.expectEqual(@as(u32, 100), v3.major);
    try std.testing.expectEqual(@as(u32, 200), v3.minor);
    try std.testing.expectEqual(@as(u32, 300), v3.patch);
}

test "Version.compare ordering" {
    const versions = [_]Version{
        .{ .major = 0, .minor = 0, .patch = 1 },
        .{ .major = 0, .minor = 1, .patch = 0 },
        .{ .major = 1, .minor = 0, .patch = 0 },
        .{ .major = 1, .minor = 0, .patch = 1 },
        .{ .major = 1, .minor = 1, .patch = 0 },
        .{ .major = 2, .minor = 0, .patch = 0 },
    };

    // Each version should be less than the next
    for (0..versions.len - 1) |i| {
        try std.testing.expect(versions[i].lessThan(versions[i + 1]));
        try std.testing.expect(versions[i + 1].greaterThan(versions[i]));
        try std.testing.expect(!versions[i].equal(versions[i + 1]));
    }
}

test "Dependency creation helpers" {
    const required_dep = Dependency.required("openssl", .{ .caret = .{ .major = 1, .minor = 1, .patch = 0 } });
    try std.testing.expect(!required_dep.optional);
    try std.testing.expect(!required_dep.virtual);

    const optional_dep = Dependency.optionalDep("gui", .any, "Optional GUI support");
    try std.testing.expect(optional_dep.optional);
    try std.testing.expectEqualStrings("Optional GUI support", optional_dep.description.?);

    const virtual_dep = Dependency.virtualDep("database-driver");
    try std.testing.expect(virtual_dep.virtual);

    const feature_dep = Dependency.forFeature("ssl", .any, "tls");
    try std.testing.expectEqualStrings("tls", feature_dep.feature.?);
}

test "VersionConstraint.tilde boundary" {
    // ~1.2.0 means >=1.2.0 and <1.3.0
    const constraint = VersionConstraint{ .tilde = .{ .major = 1, .minor = 2, .patch = 0 } };

    try std.testing.expect(constraint.satisfies(Version{ .major = 1, .minor = 2, .patch = 0 }));
    try std.testing.expect(constraint.satisfies(Version{ .major = 1, .minor = 2, .patch = 99 }));
    try std.testing.expect(!constraint.satisfies(Version{ .major = 1, .minor = 1, .patch = 99 })); // below
    try std.testing.expect(!constraint.satisfies(Version{ .major = 1, .minor = 3, .patch = 0 })); // above
    try std.testing.expect(!constraint.satisfies(Version{ .major = 0, .minor = 2, .patch = 0 })); // wrong major
    try std.testing.expect(!constraint.satisfies(Version{ .major = 2, .minor = 2, .patch = 0 })); // wrong major
}

test "VersionConstraint.caret boundary" {
    // ^1.2.0 means >=1.2.0 and <2.0.0
    const constraint = VersionConstraint{ .caret = .{ .major = 1, .minor = 2, .patch = 0 } };

    try std.testing.expect(constraint.satisfies(Version{ .major = 1, .minor = 2, .patch = 0 }));
    try std.testing.expect(constraint.satisfies(Version{ .major = 1, .minor = 99, .patch = 99 }));
    try std.testing.expect(!constraint.satisfies(Version{ .major = 1, .minor = 1, .patch = 99 })); // below
    try std.testing.expect(!constraint.satisfies(Version{ .major = 2, .minor = 0, .patch = 0 })); // above
    try std.testing.expect(!constraint.satisfies(Version{ .major = 0, .minor = 2, .patch = 0 })); // wrong major
}
