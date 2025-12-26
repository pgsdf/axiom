const std = @import("std");
const types = @import("types.zig");

const Allocator = std.mem.Allocator;
const PackageId = types.PackageId;

// =============================================================================
// Merge Strategies
// =============================================================================

/// Strategy for merging files from packages into environments
pub const MergeStrategy = enum {
    /// Create symlink to store package (default, most space-efficient)
    symlink,

    /// Create hardlink (same filesystem only, shares inode)
    hardlink,

    /// Copy file (allows modification, uses more space)
    copy,

    /// Use ZFS clone/overlay (copy-on-write, efficient for modifications)
    zfs_clone,

    pub fn toString(self: MergeStrategy) []const u8 {
        return switch (self) {
            .symlink => "symlink",
            .hardlink => "hardlink",
            .copy => "copy",
            .zfs_clone => "zfs_clone",
        };
    }

    pub fn fromString(s: []const u8) ?MergeStrategy {
        if (std.mem.eql(u8, s, "symlink")) return .symlink;
        if (std.mem.eql(u8, s, "hardlink")) return .hardlink;
        if (std.mem.eql(u8, s, "copy")) return .copy;
        if (std.mem.eql(u8, s, "zfs_clone")) return .zfs_clone;
        if (std.mem.eql(u8, s, "overlay")) return .zfs_clone;
        return null;
    }
};

/// Policy for handling file conflicts during realization
pub const ConflictPolicy = enum {
    /// Error on any conflict
    error_on_conflict,

    /// Keep first file encountered
    keep_first,

    /// Use latest file (by package priority or alphabetical)
    use_latest,

    /// Keep both with renamed suffix
    rename_conflicts,

    /// Interactive prompt (CLI only)
    interactive,
};

// =============================================================================
// Directory Rules
// =============================================================================

/// Rule for how a specific directory pattern should be merged
pub const DirectoryRule = struct {
    /// Glob pattern (e.g., "bin/*", "lib/*.so", "etc/**")
    pattern: []const u8,

    /// Merge strategy for files matching this pattern
    strategy: MergeStrategy,

    /// Conflict handling for this directory
    conflict_policy: ConflictPolicy = .error_on_conflict,

    /// Whether to preserve directory structure
    preserve_structure: bool = true,

    /// Optional prefix to add to target paths
    target_prefix: ?[]const u8 = null,

    pub fn deinit(self: *DirectoryRule, allocator: Allocator) void {
        allocator.free(self.pattern);
        if (self.target_prefix) |tp| allocator.free(tp);
    }
};

/// Default directory rules for standard environment layout
pub const DEFAULT_DIRECTORY_RULES = [_]DirectoryRule{
    .{ .pattern = "bin/*", .strategy = .symlink, .conflict_policy = .error_on_conflict },
    .{ .pattern = "sbin/*", .strategy = .symlink, .conflict_policy = .error_on_conflict },
    .{ .pattern = "lib/*.so*", .strategy = .symlink, .conflict_policy = .error_on_conflict },
    .{ .pattern = "lib/*.a", .strategy = .symlink, .conflict_policy = .keep_first },
    .{ .pattern = "libexec/**", .strategy = .symlink, .conflict_policy = .error_on_conflict },
    .{ .pattern = "include/**", .strategy = .symlink, .conflict_policy = .keep_first },
    .{ .pattern = "share/man/**", .strategy = .symlink, .conflict_policy = .keep_first },
    .{ .pattern = "share/doc/**", .strategy = .symlink, .conflict_policy = .keep_first },
    .{ .pattern = "share/info/**", .strategy = .symlink, .conflict_policy = .keep_first },
    .{ .pattern = "share/**", .strategy = .symlink, .conflict_policy = .keep_first },
    .{ .pattern = "etc/**", .strategy = .copy, .conflict_policy = .keep_first },
};

// =============================================================================
// Package Outputs (Multiple Output Support)
// =============================================================================

/// Definition of a package output (subset of package files)
pub const OutputDefinition = struct {
    /// Output name (e.g., "bin", "lib", "dev", "doc")
    name: []const u8,

    /// Human-readable description
    description: ?[]const u8 = null,

    /// Path patterns included in this output
    paths: []const []const u8,

    /// Dependencies required for this output
    dependencies: []const []const u8 = &[_][]const u8{},

    /// Whether this output is included by default
    default: bool = true,

    pub fn deinit(self: *OutputDefinition, allocator: Allocator) void {
        allocator.free(self.name);
        if (self.description) |d| allocator.free(d);
        for (self.paths) |p| allocator.free(p);
        allocator.free(self.paths);
        for (self.dependencies) |d| allocator.free(d);
        allocator.free(self.dependencies);
    }
};

/// Standard output definitions used when package doesn't define its own
pub const STANDARD_OUTPUTS = [_]OutputDefinition{
    .{
        .name = "bin",
        .description = "Runtime executables",
        .paths = &[_][]const u8{ "bin/", "sbin/" },
        .default = true,
    },
    .{
        .name = "lib",
        .description = "Runtime libraries",
        .paths = &[_][]const u8{ "lib/*.so*", "lib64/*.so*" },
        .default = true,
    },
    .{
        .name = "dev",
        .description = "Development headers and static libraries",
        .paths = &[_][]const u8{ "include/", "lib/*.a", "lib/pkgconfig/", "share/aclocal/" },
        .default = false,
    },
    .{
        .name = "doc",
        .description = "Documentation",
        .paths = &[_][]const u8{ "share/doc/", "share/man/", "share/info/" },
        .default = false,
    },
    .{
        .name = "data",
        .description = "Shared data files",
        .paths = &[_][]const u8{"share/"},
        .default = true,
    },
};

/// Selection of which outputs to include for a package
pub const OutputSelection = struct {
    /// Package name
    package: []const u8,

    /// Output names to include (empty = use defaults, "*" = all)
    outputs: []const []const u8,

    pub fn includesAll(self: *const OutputSelection) bool {
        for (self.outputs) |o| {
            if (std.mem.eql(u8, o, "*")) return true;
        }
        return false;
    }

    pub fn includes(self: *const OutputSelection, output_name: []const u8) bool {
        if (self.includesAll()) return true;
        for (self.outputs) |o| {
            if (std.mem.eql(u8, o, output_name)) return true;
        }
        return false;
    }

    pub fn deinit(self: *OutputSelection, allocator: Allocator) void {
        allocator.free(self.package);
        for (self.outputs) |o| allocator.free(o);
        allocator.free(self.outputs);
    }
};

// =============================================================================
// ABI Boundary Definition
// =============================================================================

/// Defines the ABI boundary between system and Axiom-managed libraries
pub const AbiBoundary = struct {
    /// Libraries that must come from the base system (never from Axiom)
    system_libraries: []const []const u8,

    /// Libraries that should come from Axiom store
    axiom_libraries: []const []const u8,

    /// Whether to enforce strict ABI separation
    strict_mode: bool = true,

    /// Minimum FreeBSD version for ABI compatibility
    min_freebsd_version: ?u32 = null,

    /// Initialize with default FreeBSD system libraries
    pub fn initDefault() AbiBoundary {
        return .{
            .system_libraries = &DEFAULT_SYSTEM_LIBRARIES,
            .axiom_libraries = &[_][]const u8{},
        };
    }

    /// Check if a library is a system library
    pub fn isSystemLibrary(self: *const AbiBoundary, lib_name: []const u8) bool {
        for (self.system_libraries) |sys_lib| {
            if (std.mem.eql(u8, lib_name, sys_lib)) return true;
            // Also match with .so suffix variations
            if (std.mem.startsWith(u8, lib_name, sys_lib)) {
                const suffix = lib_name[sys_lib.len..];
                if (suffix.len == 0 or suffix[0] == '.') return true;
            }
        }
        return false;
    }
};

/// Default system libraries that should never come from Axiom
pub const DEFAULT_SYSTEM_LIBRARIES = [_][]const u8{
    // Core C library
    "libc.so",
    "libm.so",
    "libpthread.so",
    "libthr.so",
    "librt.so",
    "libdl.so",

    // FreeBSD system libraries
    "libutil.so",
    "libkvm.so",
    "libdevstat.so",
    "libgeom.so",
    "libjail.so",
    "libcam.so",
    "libsbuf.so",
    "libnv.so",

    // Security/crypto from base
    "libcrypt.so",
    "libmd.so",

    // System infrastructure
    "ld-elf.so",
    "libelf.so",
    "libexecinfo.so",
};

// =============================================================================
// Realization Specification
// =============================================================================

/// Complete specification for environment realization
pub const RealizationSpec = struct {
    allocator: Allocator,

    /// Directory-specific merge rules
    directory_rules: std.ArrayList(DirectoryRule),

    /// Default merge strategy for files not matching any rule
    default_strategy: MergeStrategy = .symlink,

    /// Default conflict policy
    default_conflict_policy: ConflictPolicy = .error_on_conflict,

    /// Per-package output selections
    output_selections: std.ArrayList(OutputSelection),

    /// Whether to use default outputs when not specified
    use_default_outputs: bool = true,

    /// ABI boundary definition
    abi_boundary: AbiBoundary,

    /// Whether to create .axiom metadata directory
    create_metadata: bool = true,

    /// Whether to create activation script
    create_activation_script: bool = true,

    /// Whether to verify ABI after realization
    verify_abi: bool = true,

    pub fn init(allocator: Allocator) RealizationSpec {
        return .{
            .allocator = allocator,
            .directory_rules = .empty,
            .output_selections = .empty,
            .abi_boundary = AbiBoundary.initDefault(),
        };
    }

    pub fn deinit(self: *RealizationSpec) void {
        for (self.directory_rules.items) |*rule| {
            rule.deinit(self.allocator);
        }
        self.directory_rules.deinit(self.allocator);

        for (self.output_selections.items) |*sel| {
            sel.deinit(self.allocator);
        }
        self.output_selections.deinit(self.allocator);
    }

    /// Add a directory rule
    pub fn addRule(self: *RealizationSpec, rule: DirectoryRule) !void {
        try self.directory_rules.append(self.allocator, rule);
    }

    /// Add output selection for a package
    pub fn selectOutputs(self: *RealizationSpec, package: []const u8, outputs: []const []const u8) !void {
        try self.output_selections.append(self.allocator, .{
            .package = try self.allocator.dupe(u8, package),
            .outputs = blk: {
                var out = try self.allocator.alloc([]const u8, outputs.len);
                for (outputs, 0..) |o, i| {
                    out[i] = try self.allocator.dupe(u8, o);
                }
                break :blk out;
            },
        });
    }

    /// Set merge strategy for a directory pattern
    pub fn setStrategy(self: *RealizationSpec, pattern: []const u8, strategy: MergeStrategy) !void {
        try self.directory_rules.append(self.allocator, .{
            .pattern = try self.allocator.dupe(u8, pattern),
            .strategy = strategy,
        });
    }

    /// Get the merge strategy for a given path
    pub fn getStrategyForPath(self: *const RealizationSpec, path: []const u8) MergeStrategy {
        // Check custom rules first (last match wins)
        var strategy = self.default_strategy;
        for (self.directory_rules.items) |rule| {
            if (matchesPattern(path, rule.pattern)) {
                strategy = rule.strategy;
            }
        }
        // Check default rules
        for (&DEFAULT_DIRECTORY_RULES) |rule| {
            if (matchesPattern(path, rule.pattern)) {
                strategy = rule.strategy;
            }
        }
        return strategy;
    }

    /// Get output selection for a package
    pub fn getOutputSelection(self: *const RealizationSpec, package: []const u8) ?*const OutputSelection {
        for (self.output_selections.items) |*sel| {
            if (std.mem.eql(u8, sel.package, package)) {
                return sel;
            }
        }
        return null;
    }
};

/// Simple glob pattern matching
fn matchesPattern(path: []const u8, pattern: []const u8) bool {
    // Handle ** (match any path)
    if (std.mem.eql(u8, pattern, "**")) return true;

    // Handle simple prefix patterns like "bin/*"
    if (std.mem.endsWith(u8, pattern, "/*")) {
        const prefix = pattern[0 .. pattern.len - 2];
        return std.mem.startsWith(u8, path, prefix);
    }

    // Handle recursive patterns like "share/**"
    if (std.mem.endsWith(u8, pattern, "/**")) {
        const prefix = pattern[0 .. pattern.len - 3];
        return std.mem.startsWith(u8, path, prefix);
    }

    // Handle extension patterns like "lib/*.so*"
    if (std.mem.indexOf(u8, pattern, "*")) |star_pos| {
        const prefix = pattern[0..star_pos];
        const suffix = pattern[star_pos + 1 ..];

        if (!std.mem.startsWith(u8, path, prefix)) return false;
        if (suffix.len > 0 and suffix[suffix.len - 1] == '*') {
            // Pattern like "*.so*" - just check the middle part
            const middle = suffix[0 .. suffix.len - 1];
            return std.mem.indexOf(u8, path, middle) != null;
        }
        return std.mem.endsWith(u8, path, suffix);
    }

    // Exact match
    return std.mem.eql(u8, path, pattern);
}

// =============================================================================
// ABI Verification Report
// =============================================================================

/// Report from ABI verification
pub const AbiReport = struct {
    allocator: Allocator,

    /// Whether ABI boundaries are respected
    valid: bool = true,

    /// System libraries found in environment (violations)
    system_lib_violations: std.ArrayList(Violation),

    /// Missing library dependencies
    missing_dependencies: std.ArrayList([]const u8),

    /// Warnings (non-fatal issues)
    warnings: std.ArrayList([]const u8),

    pub const Violation = struct {
        library: []const u8,
        found_in: []const u8,
        expected: []const u8,
    };

    pub fn init(allocator: Allocator) AbiReport {
        return .{
            .allocator = allocator,
            .system_lib_violations = .empty,
            .missing_dependencies = .empty,
            .warnings = .empty,
        };
    }

    pub fn deinit(self: *AbiReport) void {
        self.system_lib_violations.deinit(self.allocator);
        for (self.missing_dependencies.items) |d| {
            self.allocator.free(d);
        }
        self.missing_dependencies.deinit(self.allocator);
        for (self.warnings.items) |w| {
            self.allocator.free(w);
        }
        self.warnings.deinit(self.allocator);
    }

    pub fn addViolation(self: *AbiReport, library: []const u8, found_in: []const u8, expected: []const u8) !void {
        try self.system_lib_violations.append(self.allocator, .{
            .library = library,
            .found_in = found_in,
            .expected = expected,
        });
        self.valid = false;
    }

    pub fn addWarning(self: *AbiReport, warning: []const u8) !void {
        try self.warnings.append(self.allocator, try self.allocator.dupe(u8, warning));
    }

    pub fn format(self: *const AbiReport, writer: anytype) !void {
        if (self.valid) {
            try writer.writeAll("ABI Verification: PASSED\n");
        } else {
            try writer.writeAll("ABI Verification: FAILED\n");
        }

        if (self.system_lib_violations.items.len > 0) {
            try writer.writeAll("\nSystem Library Violations:\n");
            for (self.system_lib_violations.items) |v| {
                try writer.print("  - {s}: found in {s}, expected {s}\n", .{
                    v.library,
                    v.found_in,
                    v.expected,
                });
            }
        }

        if (self.missing_dependencies.items.len > 0) {
            try writer.writeAll("\nMissing Dependencies:\n");
            for (self.missing_dependencies.items) |d| {
                try writer.print("  - {s}\n", .{d});
            }
        }

        if (self.warnings.items.len > 0) {
            try writer.writeAll("\nWarnings:\n");
            for (self.warnings.items) |w| {
                try writer.print("  - {s}\n", .{w});
            }
        }
    }
};

// =============================================================================
// Environment Metadata
// =============================================================================

/// Metadata stored in .axiom/ directory of realized environment
pub const EnvironmentMetadata = struct {
    /// Environment name
    name: []const u8,

    /// Profile this environment was realized from
    profile_name: []const u8,

    /// Timestamp of realization
    realized_at: i64,

    /// Realization specification used
    spec_version: []const u8 = "1.0",

    /// List of packages in the environment
    packages: []const PackageId,

    /// Output selections used
    output_selections: []const OutputSelection,

    /// ABI verification result
    abi_verified: bool = false,

    /// Serialize to YAML format
    pub fn toYaml(self: *const EnvironmentMetadata, allocator: Allocator) ![]u8 {
        var buffer: std.ArrayList(u8) = .empty;
        const writer = buffer.writer();

        try writer.print("name: {s}\n", .{self.name});
        try writer.print("profile: {s}\n", .{self.profile_name});
        try writer.print("realized_at: {d}\n", .{self.realized_at});
        try writer.print("spec_version: {s}\n", .{self.spec_version});
        try writer.print("abi_verified: {}\n", .{self.abi_verified});

        try writer.writeAll("packages:\n");
        for (self.packages) |pkg| {
            try writer.print("  - name: {s}\n", .{pkg.name});
            try writer.print("    version: {}.{}.{}\n", .{
                pkg.version.major,
                pkg.version.minor,
                pkg.version.patch,
            });
            try writer.print("    revision: {d}\n", .{pkg.revision});
            try writer.print("    build_id: {s}\n", .{pkg.build_id});
        }

        return buffer.toOwnedSlice(allocator);
    }
};

// =============================================================================
// Tests
// =============================================================================

test "MergeStrategy.fromString" {
    try std.testing.expectEqual(MergeStrategy.symlink, MergeStrategy.fromString("symlink").?);
    try std.testing.expectEqual(MergeStrategy.copy, MergeStrategy.fromString("copy").?);
    try std.testing.expectEqual(MergeStrategy.zfs_clone, MergeStrategy.fromString("overlay").?);
    try std.testing.expect(MergeStrategy.fromString("invalid") == null);
}

test "matchesPattern" {
    try std.testing.expect(matchesPattern("bin/bash", "bin/*"));
    try std.testing.expect(matchesPattern("lib/libz.so.1", "lib/*.so*"));
    try std.testing.expect(matchesPattern("share/doc/readme.txt", "share/**"));
    try std.testing.expect(!matchesPattern("etc/config", "bin/*"));
}

test "AbiBoundary.isSystemLibrary" {
    const boundary = AbiBoundary.initDefault();
    try std.testing.expect(boundary.isSystemLibrary("libc.so"));
    try std.testing.expect(boundary.isSystemLibrary("libc.so.7"));
    try std.testing.expect(boundary.isSystemLibrary("libm.so"));
    try std.testing.expect(!boundary.isSystemLibrary("libssl.so"));
    try std.testing.expect(!boundary.isSystemLibrary("libz.so"));
}

test "OutputSelection.includes" {
    var sel = OutputSelection{
        .package = "test",
        .outputs = &[_][]const u8{ "bin", "lib" },
    };
    try std.testing.expect(sel.includes("bin"));
    try std.testing.expect(sel.includes("lib"));
    try std.testing.expect(!sel.includes("dev"));

    sel.outputs = &[_][]const u8{"*"};
    try std.testing.expect(sel.includes("anything"));
}
