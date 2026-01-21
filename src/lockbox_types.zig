const std = @import("std");
const Allocator = std.mem.Allocator;
const canonical_json = @import("canonical_json.zig");
const JsonValue = canonical_json.JsonValue;
const JsonKeyValue = canonical_json.JsonKeyValue;
const JsonObjectBuilder = canonical_json.JsonObjectBuilder;
const JsonArrayBuilder = canonical_json.JsonArrayBuilder;

/// Lockbox format version
pub const FORMAT_VERSION = "1.0";

/// Schema version for canonical JSON
pub const SCHEMA_VERSION = "1.0";

// ============================================================================
// Vendor Information
// ============================================================================

/// Vendor metadata for artifact provenance
pub const Vendor = struct {
    /// Vendor identifier (e.g., "oracle", "microsoft", "vmware")
    name: []const u8,

    /// Vendor display name
    display_name: ?[]const u8 = null,

    /// Vendor contact URL
    url: ?[]const u8 = null,

    pub fn deinit(self: *Vendor, allocator: Allocator) void {
        allocator.free(self.name);
        if (self.display_name) |dn| allocator.free(dn);
        if (self.url) |u| allocator.free(u);
    }

    pub fn toJson(self: *const Vendor, allocator: Allocator) !JsonValue {
        var builder = JsonObjectBuilder.init(allocator);
        defer builder.deinit();

        try builder.putString("name", self.name);
        if (self.display_name) |dn| try builder.putString("display_name", dn);
        if (self.url) |u| try builder.putString("url", u);

        return builder.build();
    }
};

// ============================================================================
// Source Information
// ============================================================================

/// Source artifact information
pub const Source = struct {
    /// Original download URL
    url: []const u8,

    /// SHA-256 hash of the original artifact
    sha256: []const u8,

    /// Original filename
    filename: ?[]const u8 = null,

    /// Size in bytes
    size: ?u64 = null,

    /// Fetch timestamp (RFC 3339 UTC)
    fetched_at: ?[]const u8 = null,

    pub fn deinit(self: *Source, allocator: Allocator) void {
        allocator.free(self.url);
        allocator.free(self.sha256);
        if (self.filename) |f| allocator.free(f);
        if (self.fetched_at) |t| allocator.free(t);
    }

    pub fn toJson(self: *const Source, allocator: Allocator) !JsonValue {
        var builder = JsonObjectBuilder.init(allocator);
        defer builder.deinit();

        try builder.putString("sha256", self.sha256);
        try builder.putString("url", self.url);
        if (self.fetched_at) |t| try builder.putString("fetched_at", t);
        if (self.filename) |f| try builder.putString("filename", f);
        if (self.size) |s| try builder.putInt("size", @intCast(s));

        return builder.build();
    }
};

// ============================================================================
// File Entry
// ============================================================================

/// File permission mode (stored as string to avoid YAML implicit typing)
pub const FileMode = struct {
    value: []const u8, // e.g., "0755", "0644"

    pub fn deinit(self: *FileMode, allocator: Allocator) void {
        allocator.free(self.value);
    }

    /// Parse octal mode string to integer
    pub fn toOctal(self: *const FileMode) !u32 {
        return std.fmt.parseInt(u32, self.value, 8);
    }
};

/// Single file entry in the filesystem manifest
pub const FileEntry = struct {
    /// Relative path from artifact root
    path: []const u8,

    /// SHA-256 hash of file contents
    sha256: []const u8,

    /// File size in bytes
    size: u64,

    /// File mode (e.g., "0755")
    mode: []const u8,

    /// File type
    file_type: FileType = .regular,

    /// Symlink target (if file_type is symlink)
    link_target: ?[]const u8 = null,

    pub const FileType = enum {
        regular,
        directory,
        symlink,

        pub fn toString(self: FileType) []const u8 {
            return switch (self) {
                .regular => "regular",
                .directory => "directory",
                .symlink => "symlink",
            };
        }

        pub fn fromString(s: []const u8) !FileType {
            if (std.mem.eql(u8, s, "regular")) return .regular;
            if (std.mem.eql(u8, s, "directory")) return .directory;
            if (std.mem.eql(u8, s, "symlink")) return .symlink;
            return error.InvalidFileType;
        }
    };

    pub fn deinit(self: *FileEntry, allocator: Allocator) void {
        allocator.free(self.path);
        allocator.free(self.sha256);
        allocator.free(self.mode);
        if (self.link_target) |lt| allocator.free(lt);
    }

    pub fn toJson(self: *const FileEntry, allocator: Allocator) !JsonValue {
        var builder = JsonObjectBuilder.init(allocator);
        defer builder.deinit();

        try builder.putString("mode", self.mode);
        try builder.putString("path", self.path);
        try builder.putString("sha256", self.sha256);
        try builder.putInt("size", @intCast(self.size));
        try builder.putString("type", self.file_type.toString());
        if (self.link_target) |lt| try builder.putString("link_target", lt);

        return builder.build();
    }
};

// ============================================================================
// Filesystem Manifest
// ============================================================================

/// Complete filesystem manifest for an artifact
pub const FilesystemManifest = struct {
    /// All files in the artifact
    files: []FileEntry,

    /// Merkle root hash of the filesystem tree
    merkle_root: ?[]const u8 = null,

    pub fn deinit(self: *FilesystemManifest, allocator: Allocator) void {
        for (self.files) |*f| {
            var file = f.*;
            file.deinit(allocator);
        }
        if (self.files.len > 0) allocator.free(self.files);
        if (self.merkle_root) |mr| allocator.free(mr);
    }

    /// Compute Merkle root from file entries
    pub fn computeMerkleRoot(self: *FilesystemManifest, allocator: Allocator) ![]u8 {
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});

        // Sort files by path for deterministic ordering
        const sorted = try allocator.alloc(FileEntry, self.files.len);
        defer allocator.free(sorted);
        @memcpy(sorted, self.files);

        std.mem.sort(FileEntry, sorted, {}, struct {
            fn lessThan(_: void, a: FileEntry, b: FileEntry) bool {
                return std.mem.lessThan(u8, a.path, b.path);
            }
        }.lessThan);

        // Hash each file entry
        for (sorted) |file| {
            hasher.update(file.path);
            hasher.update(file.sha256);
            hasher.update(file.mode);

            var size_buf: [32]u8 = undefined;
            const size_str = std.fmt.bufPrint(&size_buf, "{d}", .{file.size}) catch unreachable;
            hasher.update(size_str);
        }

        var hash: [32]u8 = undefined;
        hasher.final(&hash);

        const hex = try allocator.alloc(u8, 64);
        _ = std.fmt.bufPrint(hex, "{x}", .{std.fmt.fmtSliceHexLower(&hash)}) catch unreachable;
        return hex;
    }

    pub fn toJson(self: *const FilesystemManifest, allocator: Allocator) !JsonValue {
        var files_builder = JsonArrayBuilder.init(allocator);
        defer files_builder.deinit();

        // Sort files by path for deterministic output
        const sorted = try allocator.alloc(FileEntry, self.files.len);
        defer allocator.free(sorted);
        @memcpy(sorted, self.files);

        std.mem.sort(FileEntry, sorted, {}, struct {
            fn lessThan(_: void, a: FileEntry, b: FileEntry) bool {
                return std.mem.lessThan(u8, a.path, b.path);
            }
        }.lessThan);

        for (sorted) |*file| {
            try files_builder.append(try file.toJson(allocator));
        }

        var builder = JsonObjectBuilder.init(allocator);
        defer builder.deinit();

        try builder.put("files", files_builder.build());
        if (self.merkle_root) |mr| try builder.putString("merkle_root", mr);

        return builder.build();
    }
};

// ============================================================================
// Artifact Identity
// ============================================================================

/// Human-readable artifact identity
pub const HumanIdentity = struct {
    /// Artifact name
    name: []const u8,

    /// Version string (always stored as string, not parsed)
    version: []const u8,

    /// Vendor information
    vendor: Vendor,

    /// Optional description
    description: ?[]const u8 = null,

    pub fn deinit(self: *HumanIdentity, allocator: Allocator) void {
        allocator.free(self.name);
        allocator.free(self.version);
        self.vendor.deinit(allocator);
        if (self.description) |d| allocator.free(d);
    }

    pub fn toJson(self: *const HumanIdentity, allocator: Allocator) !JsonValue {
        var builder = JsonObjectBuilder.init(allocator);
        defer builder.deinit();

        if (self.description) |d| try builder.putString("description", d);
        try builder.putString("name", self.name);
        try builder.put("vendor", try self.vendor.toJson(allocator));
        try builder.putString("version", self.version);

        return builder.build();
    }
};

/// Machine identity (content-addressed)
pub const MachineIdentity = struct {
    /// Content hash (SHA-256 of canonical JSON + merkle root)
    content_hash: []const u8,

    /// Timestamp when identity was computed (RFC 3339 UTC)
    computed_at: []const u8,

    pub fn deinit(self: *MachineIdentity, allocator: Allocator) void {
        allocator.free(self.content_hash);
        allocator.free(self.computed_at);
    }

    pub fn toJson(self: *const MachineIdentity, allocator: Allocator) !JsonValue {
        var builder = JsonObjectBuilder.init(allocator);
        defer builder.deinit();

        try builder.putString("computed_at", self.computed_at);
        try builder.putString("content_hash", self.content_hash);

        return builder.build();
    }
};

// ============================================================================
// Deployment Configuration
// ============================================================================

/// Deployment target configuration
pub const DeploymentTarget = struct {
    /// Target path on filesystem
    path: []const u8,

    /// ZFS dataset name (optional)
    dataset: ?[]const u8 = null,

    /// Whether to create a ZFS snapshot before deployment
    snapshot: bool = true,

    /// Environment variables to set
    env: []const EnvVar = &[_]EnvVar{},

    pub const EnvVar = struct {
        name: []const u8,
        value: []const u8,
    };

    pub fn deinit(self: *DeploymentTarget, allocator: Allocator) void {
        allocator.free(self.path);
        if (self.dataset) |d| allocator.free(d);
        for (self.env) |e| {
            allocator.free(e.name);
            allocator.free(e.value);
        }
        if (self.env.len > 0) allocator.free(self.env);
    }

    pub fn toJson(self: *const DeploymentTarget, allocator: Allocator) !JsonValue {
        var builder = JsonObjectBuilder.init(allocator);
        defer builder.deinit();

        if (self.dataset) |d| try builder.putString("dataset", d);

        if (self.env.len > 0) {
            var env_builder = JsonObjectBuilder.init(allocator);
            defer env_builder.deinit();
            for (self.env) |e| {
                try env_builder.putString(e.name, e.value);
            }
            try builder.put("env", env_builder.build());
        }

        try builder.putString("path", self.path);
        try builder.putBool("snapshot", self.snapshot);

        return builder.build();
    }
};

// ============================================================================
// Lockbox Specification
// ============================================================================

/// Complete Lockbox specification
/// This is the primary data structure for lockbox.yaml / lockbox.json
pub const LockboxSpec = struct {
    /// Format version
    format_version: []const u8,

    /// Schema version for canonical JSON
    schema_version: []const u8,

    /// Human-readable identity
    identity: HumanIdentity,

    /// Source artifact information
    source: Source,

    /// Filesystem manifest
    filesystem: FilesystemManifest,

    /// Deployment configuration
    deployment: ?DeploymentTarget = null,

    /// Machine identity (computed, not authored)
    machine_identity: ?MachineIdentity = null,

    pub fn deinit(self: *LockboxSpec, allocator: Allocator) void {
        allocator.free(self.format_version);
        allocator.free(self.schema_version);
        self.identity.deinit(allocator);
        self.source.deinit(allocator);
        self.filesystem.deinit(allocator);
        if (self.deployment) |*d| d.deinit(allocator);
        if (self.machine_identity) |*mi| mi.deinit(allocator);
    }

    /// Convert to canonical JSON value
    pub fn toCanonicalJson(self: *const LockboxSpec, allocator: Allocator) !JsonValue {
        var builder = JsonObjectBuilder.init(allocator);
        defer builder.deinit();

        if (self.deployment) |d| try builder.put("deployment", try d.toJson(allocator));
        try builder.put("filesystem", try self.filesystem.toJson(allocator));
        try builder.putString("format_version", self.format_version);
        try builder.put("identity", try self.identity.toJson(allocator));
        if (self.machine_identity) |mi| try builder.put("machine_identity", try mi.toJson(allocator));
        try builder.putString("schema_version", self.schema_version);
        try builder.put("source", try self.source.toJson(allocator));

        return builder.build();
    }

    /// Compute content hash for this specification
    pub fn computeContentHash(self: *LockboxSpec, allocator: Allocator) ![]u8 {
        // First compute merkle root if not present
        if (self.filesystem.merkle_root == null) {
            self.filesystem.merkle_root = try self.filesystem.computeMerkleRoot(allocator);
        }

        // Get canonical JSON (without machine_identity)
        const saved_mi = self.machine_identity;
        self.machine_identity = null;
        defer self.machine_identity = saved_mi;

        var cj = canonical_json.CanonicalJson.init(allocator);
        const json_value = try self.toCanonicalJson(allocator);
        const json = try cj.serialize(json_value);
        defer allocator.free(json);

        // Hash: canonical_json || merkle_root
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(json);
        hasher.update(self.filesystem.merkle_root.?);

        var hash: [32]u8 = undefined;
        hasher.final(&hash);

        const hex = try allocator.alloc(u8, 64);
        _ = std.fmt.bufPrint(hex, "{x}", .{std.fmt.fmtSliceHexLower(&hash)}) catch unreachable;
        return hex;
    }
};

// ============================================================================
// Audit Log Entry
// ============================================================================

/// Audit log entry for tracking operations
pub const AuditEntry = struct {
    /// Operation performed
    operation: Operation,

    /// Timestamp (RFC 3339 UTC)
    timestamp: []const u8,

    /// Content hash at time of operation
    content_hash: []const u8,

    /// Actor (user or system)
    actor: []const u8,

    /// Additional details
    details: ?[]const u8 = null,

    pub const Operation = enum {
        ingest,
        normalize,
        deploy,
        rollback,
        verify,
        delete,

        pub fn toString(self: Operation) []const u8 {
            return switch (self) {
                .ingest => "ingest",
                .normalize => "normalize",
                .deploy => "deploy",
                .rollback => "rollback",
                .verify => "verify",
                .delete => "delete",
            };
        }
    };

    pub fn deinit(self: *AuditEntry, allocator: Allocator) void {
        allocator.free(self.timestamp);
        allocator.free(self.content_hash);
        allocator.free(self.actor);
        if (self.details) |d| allocator.free(d);
    }

    pub fn toJson(self: *const AuditEntry, allocator: Allocator) !JsonValue {
        var builder = JsonObjectBuilder.init(allocator);
        defer builder.deinit();

        try builder.putString("actor", self.actor);
        try builder.putString("content_hash", self.content_hash);
        if (self.details) |d| try builder.putString("details", d);
        try builder.putString("operation", self.operation.toString());
        try builder.putString("timestamp", self.timestamp);

        return builder.build();
    }
};

// ============================================================================
// Validation Errors
// ============================================================================

/// Validation error types
pub const ValidationError = error{
    MissingRequiredField,
    InvalidFormatVersion,
    InvalidSchemaVersion,
    InvalidHash,
    InvalidTimestamp,
    InvalidFileMode,
    InvalidPath,
    HashMismatch,
    MerkleRootMismatch,
    UnknownKey,
    TypeMismatch,
    EmptyValue,
};

/// Validation result
pub const ValidationResult = struct {
    valid: bool,
    errors: []const []const u8,

    pub fn deinit(self: *ValidationResult, allocator: Allocator) void {
        for (self.errors) |e| allocator.free(e);
        if (self.errors.len > 0) allocator.free(self.errors);
    }
};

// ============================================================================
// Tests
// ============================================================================

test "LockboxSpec: create and serialize" {
    const allocator = std.testing.allocator;

    var spec = LockboxSpec{
        .format_version = try allocator.dupe(u8, FORMAT_VERSION),
        .schema_version = try allocator.dupe(u8, SCHEMA_VERSION),
        .identity = .{
            .name = try allocator.dupe(u8, "oracle-jdk"),
            .version = try allocator.dupe(u8, "17.0.2"),
            .vendor = .{
                .name = try allocator.dupe(u8, "oracle"),
            },
        },
        .source = .{
            .url = try allocator.dupe(u8, "https://download.oracle.com/jdk17.tar.gz"),
            .sha256 = try allocator.dupe(u8, "abc123"),
        },
        .filesystem = .{
            .files = &[_]FileEntry{},
        },
    };
    defer spec.deinit(allocator);

    const json_value = try spec.toCanonicalJson(allocator);
    var cj = canonical_json.CanonicalJson.init(allocator);
    const json = try cj.serialize(json_value);
    defer allocator.free(json);

    try std.testing.expect(std.mem.indexOf(u8, json, "\"format_version\":\"1.0\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"oracle-jdk\"") != null);
}

test "FilesystemManifest: compute merkle root determinism" {
    const allocator = std.testing.allocator;

    var files = [_]FileEntry{
        .{
            .path = try allocator.dupe(u8, "bin/app"),
            .sha256 = try allocator.dupe(u8, "abc123"),
            .size = 1024,
            .mode = try allocator.dupe(u8, "0755"),
        },
        .{
            .path = try allocator.dupe(u8, "lib/lib.so"),
            .sha256 = try allocator.dupe(u8, "def456"),
            .size = 2048,
            .mode = try allocator.dupe(u8, "0644"),
        },
    };
    defer {
        for (&files) |*f| f.deinit(allocator);
    }

    var manifest = FilesystemManifest{ .files = &files };

    const root1 = try manifest.computeMerkleRoot(allocator);
    defer allocator.free(root1);

    const root2 = try manifest.computeMerkleRoot(allocator);
    defer allocator.free(root2);

    // Same files must produce same merkle root
    try std.testing.expectEqualStrings(root1, root2);
}

test "FileEntry: toJson" {
    const allocator = std.testing.allocator;

    const entry = FileEntry{
        .path = "bin/test",
        .sha256 = "abc123def456",
        .size = 4096,
        .mode = "0755",
        .file_type = .regular,
    };

    const json_value = try entry.toJson(allocator);
    var cj = canonical_json.CanonicalJson.init(allocator);
    const json = try cj.serialize(json_value);
    defer allocator.free(json);

    // Keys should be sorted
    try std.testing.expect(std.mem.indexOf(u8, json, "\"mode\":\"0755\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"path\":\"bin/test\"") != null);
}

test "Vendor: toJson" {
    const allocator = std.testing.allocator;

    const vendor = Vendor{
        .name = "example",
        .display_name = "Example Corp",
        .url = "https://example.com",
    };

    const json_value = try vendor.toJson(allocator);
    var cj = canonical_json.CanonicalJson.init(allocator);
    const json = try cj.serialize(json_value);
    defer allocator.free(json);

    try std.testing.expect(std.mem.indexOf(u8, json, "\"name\":\"example\"") != null);
}
