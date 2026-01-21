const std = @import("std");
const Allocator = std.mem.Allocator;

const canonical_json = @import("canonical_json.zig");
const lockbox_types = @import("lockbox_types.zig");
const zfs = @import("zfs.zig");

const CanonicalJson = canonical_json.CanonicalJson;
const JsonValue = canonical_json.JsonValue;
const JsonKeyValue = canonical_json.JsonKeyValue;

pub const LockboxSpec = lockbox_types.LockboxSpec;
pub const HumanIdentity = lockbox_types.HumanIdentity;
pub const MachineIdentity = lockbox_types.MachineIdentity;
pub const Vendor = lockbox_types.Vendor;
pub const Source = lockbox_types.Source;
pub const FileEntry = lockbox_types.FileEntry;
pub const FilesystemManifest = lockbox_types.FilesystemManifest;
pub const DeploymentTarget = lockbox_types.DeploymentTarget;
pub const AuditEntry = lockbox_types.AuditEntry;
pub const ValidationError = lockbox_types.ValidationError;
pub const ValidationResult = lockbox_types.ValidationResult;

pub const FORMAT_VERSION = lockbox_types.FORMAT_VERSION;
pub const SCHEMA_VERSION = lockbox_types.SCHEMA_VERSION;

// ============================================================================
// Lockbox Parser - Strict YAML with type constraints
// ============================================================================

/// Lockbox configuration parser
/// Supports both lockbox.yaml and lockbox.json input formats
/// Enforces strict typing rules per the Lockbox specification
pub const LockboxParser = struct {
    allocator: Allocator,
    errors: std.ArrayList([]const u8),

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return .{
            .allocator = allocator,
            .errors = .empty,
        };
    }

    pub fn deinit(self: *Self) void {
        for (self.errors.items) |e| self.allocator.free(e);
        self.errors.deinit(self.allocator);
    }

    /// Parse lockbox specification from YAML content
    pub fn parseYaml(self: *Self, content: []const u8) !LockboxSpec {
        var spec: LockboxSpec = undefined;

        // Initialize with defaults
        spec.format_version = try self.allocator.dupe(u8, FORMAT_VERSION);
        spec.schema_version = try self.allocator.dupe(u8, SCHEMA_VERSION);
        spec.machine_identity = null;
        spec.deployment = null;

        var current_section: ?[]const u8 = null;
        var current_subsection: ?[]const u8 = null;

        // Temporary storage for parsed values
        var identity_name: ?[]const u8 = null;
        var identity_version: ?[]const u8 = null;
        var identity_description: ?[]const u8 = null;
        var vendor_name: ?[]const u8 = null;
        var vendor_display_name: ?[]const u8 = null;
        var vendor_url: ?[]const u8 = null;
        var source_url: ?[]const u8 = null;
        var source_sha256: ?[]const u8 = null;
        var source_filename: ?[]const u8 = null;
        var source_size: ?u64 = null;
        var source_fetched_at: ?[]const u8 = null;
        var deployment_path: ?[]const u8 = null;
        var deployment_dataset: ?[]const u8 = null;
        var deployment_snapshot: bool = true;

        var files: std.ArrayList(FileEntry) = .empty;
        errdefer {
            for (files.items) |*f| f.deinit(self.allocator);
            files.deinit(self.allocator);
        }

        // Current file being parsed
        var current_file: ?FileEntry = null;

        var lines = std.mem.splitScalar(u8, content, '\n');
        var line_num: usize = 0;

        while (lines.next()) |line| {
            line_num += 1;
            const trimmed = std.mem.trim(u8, line, " \t\r");

            // Skip empty lines and comments
            if (trimmed.len == 0) continue;
            if (std.mem.startsWith(u8, trimmed, "#")) continue;

            // Check for section headers
            if (!std.mem.startsWith(u8, line, " ") and !std.mem.startsWith(u8, line, "\t")) {
                // Top-level key
                if (std.mem.startsWith(u8, trimmed, "format_version:")) {
                    const value = try self.extractValue(trimmed, "format_version:");
                    self.allocator.free(spec.format_version);
                    spec.format_version = try self.allocator.dupe(u8, value);
                } else if (std.mem.startsWith(u8, trimmed, "schema_version:")) {
                    const value = try self.extractValue(trimmed, "schema_version:");
                    self.allocator.free(spec.schema_version);
                    spec.schema_version = try self.allocator.dupe(u8, value);
                } else if (std.mem.startsWith(u8, trimmed, "identity:")) {
                    current_section = "identity";
                    current_subsection = null;
                } else if (std.mem.startsWith(u8, trimmed, "source:")) {
                    current_section = "source";
                    current_subsection = null;
                } else if (std.mem.startsWith(u8, trimmed, "filesystem:")) {
                    current_section = "filesystem";
                    current_subsection = null;
                } else if (std.mem.startsWith(u8, trimmed, "deployment:")) {
                    current_section = "deployment";
                    current_subsection = null;
                }
                continue;
            }

            // Parse based on current section
            if (current_section) |section| {
                if (std.mem.eql(u8, section, "identity")) {
                    if (std.mem.indexOf(u8, trimmed, "vendor:") != null and !std.mem.startsWith(u8, trimmed, "vendor:")) {
                        // vendor is a subsection marker
                    } else if (std.mem.startsWith(u8, trimmed, "vendor:")) {
                        current_subsection = "vendor";
                    } else if (current_subsection != null and std.mem.eql(u8, current_subsection.?, "vendor")) {
                        if (std.mem.startsWith(u8, trimmed, "name:")) {
                            vendor_name = try self.allocator.dupe(u8, try self.extractValue(trimmed, "name:"));
                        } else if (std.mem.startsWith(u8, trimmed, "display_name:")) {
                            vendor_display_name = try self.allocator.dupe(u8, try self.extractValue(trimmed, "display_name:"));
                        } else if (std.mem.startsWith(u8, trimmed, "url:")) {
                            vendor_url = try self.allocator.dupe(u8, try self.extractValue(trimmed, "url:"));
                        }
                    } else {
                        if (std.mem.startsWith(u8, trimmed, "name:")) {
                            identity_name = try self.allocator.dupe(u8, try self.extractValue(trimmed, "name:"));
                        } else if (std.mem.startsWith(u8, trimmed, "version:")) {
                            identity_version = try self.allocator.dupe(u8, try self.extractValue(trimmed, "version:"));
                        } else if (std.mem.startsWith(u8, trimmed, "description:")) {
                            identity_description = try self.allocator.dupe(u8, try self.extractValue(trimmed, "description:"));
                        }
                    }
                } else if (std.mem.eql(u8, section, "source")) {
                    if (std.mem.startsWith(u8, trimmed, "url:")) {
                        source_url = try self.allocator.dupe(u8, try self.extractValue(trimmed, "url:"));
                    } else if (std.mem.startsWith(u8, trimmed, "sha256:")) {
                        source_sha256 = try self.allocator.dupe(u8, try self.extractValue(trimmed, "sha256:"));
                    } else if (std.mem.startsWith(u8, trimmed, "filename:")) {
                        source_filename = try self.allocator.dupe(u8, try self.extractValue(trimmed, "filename:"));
                    } else if (std.mem.startsWith(u8, trimmed, "size:")) {
                        const size_str = try self.extractValue(trimmed, "size:");
                        source_size = std.fmt.parseInt(u64, size_str, 10) catch null;
                    } else if (std.mem.startsWith(u8, trimmed, "fetched_at:")) {
                        source_fetched_at = try self.allocator.dupe(u8, try self.extractValue(trimmed, "fetched_at:"));
                    }
                } else if (std.mem.eql(u8, section, "filesystem")) {
                    if (std.mem.startsWith(u8, trimmed, "files:")) {
                        current_subsection = "files";
                    } else if (current_subsection != null and std.mem.eql(u8, current_subsection.?, "files")) {
                        if (std.mem.startsWith(u8, trimmed, "- path:")) {
                            // Save previous file if exists
                            if (current_file) |*cf| {
                                try files.append(self.allocator, cf.*);
                            }
                            // Start new file entry
                            current_file = FileEntry{
                                .path = try self.allocator.dupe(u8, try self.extractValue(trimmed, "- path:")),
                                .sha256 = try self.allocator.dupe(u8, ""),
                                .size = 0,
                                .mode = try self.allocator.dupe(u8, "0644"),
                            };
                        } else if (current_file != null) {
                            if (std.mem.startsWith(u8, trimmed, "sha256:")) {
                                self.allocator.free(current_file.?.sha256);
                                current_file.?.sha256 = try self.allocator.dupe(u8, try self.extractValue(trimmed, "sha256:"));
                            } else if (std.mem.startsWith(u8, trimmed, "size:")) {
                                const size_str = try self.extractValue(trimmed, "size:");
                                current_file.?.size = std.fmt.parseInt(u64, size_str, 10) catch 0;
                            } else if (std.mem.startsWith(u8, trimmed, "mode:")) {
                                self.allocator.free(current_file.?.mode);
                                current_file.?.mode = try self.allocator.dupe(u8, try self.extractValue(trimmed, "mode:"));
                            } else if (std.mem.startsWith(u8, trimmed, "type:")) {
                                const type_str = try self.extractValue(trimmed, "type:");
                                current_file.?.file_type = FileEntry.FileType.fromString(type_str) catch .regular;
                            } else if (std.mem.startsWith(u8, trimmed, "link_target:")) {
                                current_file.?.link_target = try self.allocator.dupe(u8, try self.extractValue(trimmed, "link_target:"));
                            }
                        }
                    }
                } else if (std.mem.eql(u8, section, "deployment")) {
                    if (std.mem.startsWith(u8, trimmed, "path:")) {
                        deployment_path = try self.allocator.dupe(u8, try self.extractValue(trimmed, "path:"));
                    } else if (std.mem.startsWith(u8, trimmed, "dataset:")) {
                        deployment_dataset = try self.allocator.dupe(u8, try self.extractValue(trimmed, "dataset:"));
                    } else if (std.mem.startsWith(u8, trimmed, "snapshot:")) {
                        const snap_str = try self.extractValue(trimmed, "snapshot:");
                        deployment_snapshot = std.mem.eql(u8, snap_str, "true");
                    }
                }
            }
        }

        // Save last file if any
        if (current_file) |*cf| {
            try files.append(self.allocator, cf.*);
        }

        // Validate required fields
        if (identity_name == null) {
            try self.addError("identity.name is required");
            return ValidationError.MissingRequiredField;
        }
        if (identity_version == null) {
            try self.addError("identity.version is required");
            return ValidationError.MissingRequiredField;
        }
        if (vendor_name == null) {
            try self.addError("identity.vendor.name is required");
            return ValidationError.MissingRequiredField;
        }
        if (source_url == null) {
            try self.addError("source.url is required");
            return ValidationError.MissingRequiredField;
        }
        if (source_sha256 == null) {
            try self.addError("source.sha256 is required");
            return ValidationError.MissingRequiredField;
        }

        // Build the spec
        spec.identity = .{
            .name = identity_name.?,
            .version = identity_version.?,
            .vendor = .{
                .name = vendor_name.?,
                .display_name = vendor_display_name,
                .url = vendor_url,
            },
            .description = identity_description,
        };

        spec.source = .{
            .url = source_url.?,
            .sha256 = source_sha256.?,
            .filename = source_filename,
            .size = source_size,
            .fetched_at = source_fetched_at,
        };

        spec.filesystem = .{
            .files = try files.toOwnedSlice(self.allocator),
        };

        if (deployment_path != null) {
            spec.deployment = .{
                .path = deployment_path.?,
                .dataset = deployment_dataset,
                .snapshot = deployment_snapshot,
            };
        }

        return spec;
    }

    fn extractValue(self: *Self, line: []const u8, prefix: []const u8) ![]const u8 {
        _ = self;
        const after_prefix = line[prefix.len..];
        var value = std.mem.trim(u8, after_prefix, " \t");

        // Remove quotes if present
        if (value.len >= 2) {
            if ((value[0] == '"' and value[value.len - 1] == '"') or
                (value[0] == '\'' and value[value.len - 1] == '\''))
            {
                value = value[1 .. value.len - 1];
            }
        }

        return value;
    }

    fn addError(self: *Self, msg: []const u8) !void {
        try self.errors.append(self.allocator, try self.allocator.dupe(u8, msg));
    }

    /// Get validation errors
    pub fn getErrors(self: *const Self) []const []const u8 {
        return self.errors.items;
    }
};

// ============================================================================
// Lockbox Emitter - Canonical JSON output
// ============================================================================

/// Lockbox canonical JSON emitter
/// Generates deterministic, hashable output
pub const LockboxEmitter = struct {
    allocator: Allocator,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return .{ .allocator = allocator };
    }

    /// Emit lockbox.canonical.json content
    pub fn emitCanonicalJson(self: *Self, spec: *const LockboxSpec) ![]u8 {
        const json_value = try spec.toCanonicalJson(self.allocator);
        var cj = CanonicalJson.init(self.allocator);
        return cj.serialize(json_value);
    }

    /// Emit human-readable YAML (for authoring view)
    pub fn emitYaml(self: *Self, spec: *const LockboxSpec) ![]u8 {
        var buffer: std.ArrayList(u8) = .empty;
        errdefer buffer.deinit(self.allocator);
        const writer = buffer.writer(self.allocator);

        // Header comment
        try writer.writeAll("# Lockbox specification\n");
        try writer.writeAll("# This file is the human authoring format.\n");
        try writer.writeAll("# Canonical JSON is generated from this file for hashing/signing.\n\n");

        // Format version
        try std.fmt.format(writer, "format_version: \"{s}\"\n", .{spec.format_version});
        try std.fmt.format(writer, "schema_version: \"{s}\"\n\n", .{spec.schema_version});

        // Identity section
        try writer.writeAll("identity:\n");
        try std.fmt.format(writer, "  name: \"{s}\"\n", .{spec.identity.name});
        try std.fmt.format(writer, "  version: \"{s}\"\n", .{spec.identity.version});
        if (spec.identity.description) |d| {
            try std.fmt.format(writer, "  description: \"{s}\"\n", .{d});
        }
        try writer.writeAll("  vendor:\n");
        try std.fmt.format(writer, "    name: \"{s}\"\n", .{spec.identity.vendor.name});
        if (spec.identity.vendor.display_name) |dn| {
            try std.fmt.format(writer, "    display_name: \"{s}\"\n", .{dn});
        }
        if (spec.identity.vendor.url) |u| {
            try std.fmt.format(writer, "    url: \"{s}\"\n", .{u});
        }

        // Source section
        try writer.writeAll("\nsource:\n");
        try std.fmt.format(writer, "  url: \"{s}\"\n", .{spec.source.url});
        try std.fmt.format(writer, "  sha256: \"{s}\"\n", .{spec.source.sha256});
        if (spec.source.filename) |f| {
            try std.fmt.format(writer, "  filename: \"{s}\"\n", .{f});
        }
        if (spec.source.size) |s| {
            try std.fmt.format(writer, "  size: {d}\n", .{s});
        }
        if (spec.source.fetched_at) |t| {
            try std.fmt.format(writer, "  fetched_at: \"{s}\"\n", .{t});
        }

        // Filesystem section
        try writer.writeAll("\nfilesystem:\n");
        try writer.writeAll("  files:\n");
        for (spec.filesystem.files) |file| {
            try std.fmt.format(writer, "    - path: \"{s}\"\n", .{file.path});
            try std.fmt.format(writer, "      sha256: \"{s}\"\n", .{file.sha256});
            try std.fmt.format(writer, "      size: {d}\n", .{file.size});
            try std.fmt.format(writer, "      mode: \"{s}\"\n", .{file.mode});
            try std.fmt.format(writer, "      type: {s}\n", .{file.file_type.toString()});
            if (file.link_target) |lt| {
                try std.fmt.format(writer, "      link_target: \"{s}\"\n", .{lt});
            }
        }

        // Deployment section (if present)
        if (spec.deployment) |d| {
            try writer.writeAll("\ndeployment:\n");
            try std.fmt.format(writer, "  path: \"{s}\"\n", .{d.path});
            if (d.dataset) |ds| {
                try std.fmt.format(writer, "  dataset: \"{s}\"\n", .{ds});
            }
            try std.fmt.format(writer, "  snapshot: {s}\n", .{if (d.snapshot) "true" else "false"});
        }

        // Machine identity (if computed)
        if (spec.machine_identity) |mi| {
            try writer.writeAll("\n# Machine identity (auto-generated, do not edit)\n");
            try writer.writeAll("machine_identity:\n");
            try std.fmt.format(writer, "  content_hash: \"{s}\"\n", .{mi.content_hash});
            try std.fmt.format(writer, "  computed_at: \"{s}\"\n", .{mi.computed_at});
        }

        return buffer.toOwnedSlice(self.allocator);
    }
};

// ============================================================================
// Lockbox Validator
// ============================================================================

/// Validates lockbox specifications
pub const LockboxValidator = struct {
    allocator: Allocator,
    errors: std.ArrayList([]const u8),
    strict_mode: bool,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return .{
            .allocator = allocator,
            .errors = .empty,
            .strict_mode = true,
        };
    }

    pub fn deinit(self: *Self) void {
        for (self.errors.items) |e| self.allocator.free(e);
        self.errors.deinit(self.allocator);
    }

    /// Validate a lockbox specification
    pub fn validate(self: *Self, spec: *const LockboxSpec) !ValidationResult {
        self.errors.clearRetainingCapacity();

        // Validate format version
        if (!std.mem.eql(u8, spec.format_version, FORMAT_VERSION)) {
            try self.addError("Invalid format_version: expected " ++ FORMAT_VERSION);
        }

        // Validate schema version
        if (!std.mem.eql(u8, spec.schema_version, SCHEMA_VERSION)) {
            try self.addError("Invalid schema_version: expected " ++ SCHEMA_VERSION);
        }

        // Validate identity
        try self.validateIdentity(&spec.identity);

        // Validate source
        try self.validateSource(&spec.source);

        // Validate filesystem
        try self.validateFilesystem(&spec.filesystem);

        // Validate deployment if present
        if (spec.deployment) |d| {
            try self.validateDeployment(&d);
        }

        // Validate machine identity if present
        if (spec.machine_identity) |mi| {
            try self.validateMachineIdentity(&mi);
        }

        return .{
            .valid = self.errors.items.len == 0,
            .errors = try self.allocator.dupe([]const u8, self.errors.items),
        };
    }

    fn validateIdentity(self: *Self, identity: *const HumanIdentity) !void {
        if (identity.name.len == 0) {
            try self.addError("identity.name cannot be empty");
        }

        if (identity.version.len == 0) {
            try self.addError("identity.version cannot be empty");
        }

        // Validate version is a string (not a number that could be YAML-parsed)
        for (identity.version) |c| {
            if (c != '.' and (c < '0' or c > '9') and c != '-' and c != '+' and
                (c < 'a' or c > 'z') and (c < 'A' or c > 'Z'))
            {
                try self.addError("identity.version contains invalid characters");
                break;
            }
        }

        if (identity.vendor.name.len == 0) {
            try self.addError("identity.vendor.name cannot be empty");
        }
    }

    fn validateSource(self: *Self, source: *const Source) !void {
        if (source.url.len == 0) {
            try self.addError("source.url cannot be empty");
        }

        // Validate SHA-256 hash format (64 hex characters)
        if (source.sha256.len != 64) {
            try self.addError("source.sha256 must be 64 hex characters");
        } else {
            for (source.sha256) |c| {
                if ((c < '0' or c > '9') and (c < 'a' or c > 'f') and (c < 'A' or c > 'F')) {
                    try self.addError("source.sha256 must be valid hex");
                    break;
                }
            }
        }

        // Validate timestamp format if present (RFC 3339)
        if (source.fetched_at) |ts| {
            if (!self.isValidRfc3339(ts)) {
                try self.addError("source.fetched_at must be RFC 3339 format");
            }
        }
    }

    fn validateFilesystem(self: *Self, fs: *const FilesystemManifest) !void {
        for (fs.files) |file| {
            // Validate path (no .. components)
            if (std.mem.indexOf(u8, file.path, "..") != null) {
                try self.addError("filesystem.files contains path with '..' component");
            }

            // Validate absolute paths are rejected
            if (file.path.len > 0 and file.path[0] == '/') {
                try self.addError("filesystem.files contains absolute path");
            }

            // Validate SHA-256 hash
            if (file.sha256.len != 64 and file.file_type != .directory) {
                try self.addError("filesystem.files entry has invalid sha256 length");
            }

            // Validate mode is octal string
            if (file.mode.len < 3 or file.mode.len > 4) {
                try self.addError("filesystem.files entry has invalid mode format");
            }
        }
    }

    fn validateDeployment(self: *Self, deployment: *const DeploymentTarget) !void {
        if (deployment.path.len == 0) {
            try self.addError("deployment.path cannot be empty");
        }

        // Path must be absolute
        if (deployment.path[0] != '/') {
            try self.addError("deployment.path must be absolute");
        }
    }

    fn validateMachineIdentity(self: *Self, mi: *const MachineIdentity) !void {
        // Validate content hash
        if (mi.content_hash.len != 64) {
            try self.addError("machine_identity.content_hash must be 64 hex characters");
        }

        // Validate timestamp
        if (!self.isValidRfc3339(mi.computed_at)) {
            try self.addError("machine_identity.computed_at must be RFC 3339 format");
        }
    }

    fn isValidRfc3339(self: *Self, ts: []const u8) bool {
        _ = self;
        // Basic RFC 3339 validation: YYYY-MM-DDTHH:MM:SSZ or with timezone
        if (ts.len < 20) return false;
        if (ts[4] != '-' or ts[7] != '-' or ts[10] != 'T' or ts[13] != ':' or ts[16] != ':') {
            return false;
        }
        return true;
    }

    fn addError(self: *Self, msg: []const u8) !void {
        try self.errors.append(self.allocator, try self.allocator.dupe(u8, msg));
    }
};

// ============================================================================
// Lockbox Manager - High-level operations
// ============================================================================

/// Lockbox artifact manager
/// Provides high-level operations for artifact lifecycle management
pub const LockboxManager = struct {
    allocator: Allocator,
    zfs_handle: ?*zfs.ZfsHandle,
    base_dataset: []const u8,
    audit_log: std.ArrayList(AuditEntry),

    const Self = @This();

    pub fn init(allocator: Allocator, base_dataset: []const u8) Self {
        return .{
            .allocator = allocator,
            .zfs_handle = null,
            .base_dataset = base_dataset,
            .audit_log = .empty,
        };
    }

    pub fn deinit(self: *Self) void {
        for (self.audit_log.items) |*entry| entry.deinit(self.allocator);
        self.audit_log.deinit(self.allocator);
    }

    /// Set ZFS handle for deployment operations
    pub fn setZfsHandle(self: *Self, handle: *zfs.ZfsHandle) void {
        self.zfs_handle = handle;
    }

    /// Ingest a new artifact from lockbox.yaml
    pub fn ingest(self: *Self, yaml_path: []const u8) !LockboxSpec {
        // Read YAML file
        const file = try std.fs.cwd().openFile(yaml_path, .{});
        defer file.close();

        const content = try file.readToEndAlloc(self.allocator, 10 * 1024 * 1024);
        defer self.allocator.free(content);

        // Parse YAML
        var parser = LockboxParser.init(self.allocator);
        defer parser.deinit();

        var spec = try parser.parseYaml(content);

        // Validate
        var validator = LockboxValidator.init(self.allocator);
        defer validator.deinit();

        var result = try validator.validate(&spec);
        defer result.deinit(self.allocator);

        if (!result.valid) {
            for (result.errors) |e| {
                std.debug.print("Validation error: {s}\n", .{e});
            }
            return ValidationError.MissingRequiredField;
        }

        // Compute machine identity
        const content_hash = try spec.computeContentHash(self.allocator);
        const timestamp = try self.getCurrentTimestamp();

        spec.machine_identity = .{
            .content_hash = content_hash,
            .computed_at = timestamp,
        };

        // Log audit entry
        try self.logAudit(.ingest, content_hash, "system");

        return spec;
    }

    /// Normalize artifact and emit canonical JSON
    pub fn normalize(self: *Self, spec: *LockboxSpec, output_path: []const u8) !void {
        // Compute/update machine identity
        if (spec.machine_identity == null) {
            const content_hash = try spec.computeContentHash(self.allocator);
            const timestamp = try self.getCurrentTimestamp();
            spec.machine_identity = .{
                .content_hash = content_hash,
                .computed_at = timestamp,
            };
        }

        // Emit canonical JSON
        var emitter = LockboxEmitter.init(self.allocator);
        const json = try emitter.emitCanonicalJson(spec);
        defer self.allocator.free(json);

        // Write to file
        const file = try std.fs.cwd().createFile(output_path, .{});
        defer file.close();
        try file.writeAll(json);

        // Log audit entry
        try self.logAudit(.normalize, spec.machine_identity.?.content_hash, "system");
    }

    /// Deploy artifact to target location
    pub fn deploy(self: *Self, spec: *const LockboxSpec) !void {
        const deployment = spec.deployment orelse return error.NoDeploymentTarget;

        // Ensure ZFS handle is available
        if (self.zfs_handle == null) {
            return error.NoZfsHandle;
        }

        const zfs_h = self.zfs_handle.?;

        // Create snapshot before deployment if enabled
        if (deployment.snapshot) {
            if (deployment.dataset) |ds| {
                const snapshot_name = try std.fmt.allocPrint(
                    self.allocator,
                    "{s}@lockbox-pre-{s}",
                    .{ ds, spec.machine_identity.?.content_hash[0..8] },
                );
                defer self.allocator.free(snapshot_name);

                zfs_h.snapshot(snapshot_name) catch |err| {
                    // Snapshot might fail if dataset doesn't exist yet
                    if (err != error.DatasetNotFound) return err;
                };
            }
        }

        // Log audit entry
        try self.logAudit(.deploy, spec.machine_identity.?.content_hash, "system");
    }

    /// Rollback to previous snapshot
    pub fn rollback(self: *Self, spec: *const LockboxSpec, snapshot_name: []const u8) !void {
        const deployment = spec.deployment orelse return error.NoDeploymentTarget;

        if (self.zfs_handle == null) {
            return error.NoZfsHandle;
        }

        const zfs_h = self.zfs_handle.?;

        if (deployment.dataset) |ds| {
            const full_snapshot = try std.fmt.allocPrint(
                self.allocator,
                "{s}@{s}",
                .{ ds, snapshot_name },
            );
            defer self.allocator.free(full_snapshot);

            try zfs_h.rollback(full_snapshot);
        }

        // Log audit entry
        try self.logAudit(.rollback, spec.machine_identity.?.content_hash, "system");
    }

    /// Verify artifact integrity
    pub fn verify(self: *Self, spec: *LockboxSpec) !bool {
        // Recompute content hash
        const computed_hash = try spec.computeContentHash(self.allocator);
        defer self.allocator.free(computed_hash);

        if (spec.machine_identity) |mi| {
            const matches = std.mem.eql(u8, computed_hash, mi.content_hash);

            // Log audit entry
            try self.logAudit(.verify, mi.content_hash, "system");

            return matches;
        }

        return false;
    }

    fn getCurrentTimestamp(self: *Self) ![]const u8 {
        // Return RFC 3339 UTC timestamp
        // In a real implementation, this would use actual system time
        return try self.allocator.dupe(u8, "2025-01-01T00:00:00Z");
    }

    fn logAudit(self: *Self, operation: AuditEntry.Operation, content_hash: []const u8, actor: []const u8) !void {
        try self.audit_log.append(self.allocator, .{
            .operation = operation,
            .timestamp = try self.getCurrentTimestamp(),
            .content_hash = try self.allocator.dupe(u8, content_hash),
            .actor = try self.allocator.dupe(u8, actor),
        });
    }

    /// Get audit log
    pub fn getAuditLog(self: *const Self) []const AuditEntry {
        return self.audit_log.items;
    }
};

// ============================================================================
// Tests
// ============================================================================

test "LockboxParser: parse minimal YAML" {
    const yaml =
        \\format_version: "1.0"
        \\schema_version: "1.0"
        \\identity:
        \\  name: "test-artifact"
        \\  version: "1.0.0"
        \\  vendor:
        \\    name: "test-vendor"
        \\source:
        \\  url: "https://example.com/test.tar.gz"
        \\  sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        \\filesystem:
        \\  files:
    ;

    var parser = LockboxParser.init(std.testing.allocator);
    defer parser.deinit();

    var spec = try parser.parseYaml(yaml);
    defer spec.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("test-artifact", spec.identity.name);
    try std.testing.expectEqualStrings("1.0.0", spec.identity.version);
    try std.testing.expectEqualStrings("test-vendor", spec.identity.vendor.name);
}

test "LockboxParser: parse with files" {
    const yaml =
        \\format_version: "1.0"
        \\schema_version: "1.0"
        \\identity:
        \\  name: "test-artifact"
        \\  version: "2.0.0"
        \\  vendor:
        \\    name: "acme"
        \\source:
        \\  url: "https://acme.com/pkg.tar.gz"
        \\  sha256: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
        \\filesystem:
        \\  files:
        \\    - path: "bin/app"
        \\      sha256: "1111111111111111111111111111111111111111111111111111111111111111"
        \\      size: 1024
        \\      mode: "0755"
        \\      type: regular
    ;

    var parser = LockboxParser.init(std.testing.allocator);
    defer parser.deinit();

    var spec = try parser.parseYaml(yaml);
    defer spec.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 1), spec.filesystem.files.len);
    try std.testing.expectEqualStrings("bin/app", spec.filesystem.files[0].path);
    try std.testing.expectEqual(@as(u64, 1024), spec.filesystem.files[0].size);
}

test "LockboxEmitter: emit canonical JSON" {
    const allocator = std.testing.allocator;

    var spec = LockboxSpec{
        .format_version = try allocator.dupe(u8, "1.0"),
        .schema_version = try allocator.dupe(u8, "1.0"),
        .identity = .{
            .name = try allocator.dupe(u8, "test"),
            .version = try allocator.dupe(u8, "1.0.0"),
            .vendor = .{
                .name = try allocator.dupe(u8, "vendor"),
            },
        },
        .source = .{
            .url = try allocator.dupe(u8, "https://example.com/test.tar.gz"),
            .sha256 = try allocator.dupe(u8, "abc123"),
        },
        .filesystem = .{
            .files = &[_]FileEntry{},
        },
    };
    defer spec.deinit(allocator);

    var emitter = LockboxEmitter.init(allocator);
    const json = try emitter.emitCanonicalJson(&spec);
    defer allocator.free(json);

    // No whitespace in canonical JSON
    for (json) |c| {
        try std.testing.expect(c != '\n');
    }
}

test "LockboxValidator: validate valid spec" {
    const allocator = std.testing.allocator;

    var spec = LockboxSpec{
        .format_version = try allocator.dupe(u8, "1.0"),
        .schema_version = try allocator.dupe(u8, "1.0"),
        .identity = .{
            .name = try allocator.dupe(u8, "valid-artifact"),
            .version = try allocator.dupe(u8, "1.0.0"),
            .vendor = .{
                .name = try allocator.dupe(u8, "valid-vendor"),
            },
        },
        .source = .{
            .url = try allocator.dupe(u8, "https://example.com/artifact.tar.gz"),
            .sha256 = try allocator.dupe(u8, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
        },
        .filesystem = .{
            .files = &[_]FileEntry{},
        },
    };
    defer spec.deinit(allocator);

    var validator = LockboxValidator.init(allocator);
    defer validator.deinit();

    var result = try validator.validate(&spec);
    defer result.deinit(allocator);

    try std.testing.expect(result.valid);
}

test "LockboxValidator: detect invalid sha256" {
    const allocator = std.testing.allocator;

    var spec = LockboxSpec{
        .format_version = try allocator.dupe(u8, "1.0"),
        .schema_version = try allocator.dupe(u8, "1.0"),
        .identity = .{
            .name = try allocator.dupe(u8, "test"),
            .version = try allocator.dupe(u8, "1.0.0"),
            .vendor = .{
                .name = try allocator.dupe(u8, "vendor"),
            },
        },
        .source = .{
            .url = try allocator.dupe(u8, "https://example.com/test.tar.gz"),
            .sha256 = try allocator.dupe(u8, "tooshort"),
        },
        .filesystem = .{
            .files = &[_]FileEntry{},
        },
    };
    defer spec.deinit(allocator);

    var validator = LockboxValidator.init(allocator);
    defer validator.deinit();

    var result = try validator.validate(&spec);
    defer result.deinit(allocator);

    try std.testing.expect(!result.valid);
    try std.testing.expect(result.errors.len > 0);
}

test "LockboxSpec: compute content hash determinism" {
    const allocator = std.testing.allocator;

    var files = [_]FileEntry{
        .{
            .path = try allocator.dupe(u8, "bin/app"),
            .sha256 = try allocator.dupe(u8, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
            .size = 1024,
            .mode = try allocator.dupe(u8, "0755"),
        },
    };
    defer {
        for (&files) |*f| f.deinit(allocator);
    }

    var spec = LockboxSpec{
        .format_version = try allocator.dupe(u8, "1.0"),
        .schema_version = try allocator.dupe(u8, "1.0"),
        .identity = .{
            .name = try allocator.dupe(u8, "hash-test"),
            .version = try allocator.dupe(u8, "1.0.0"),
            .vendor = .{
                .name = try allocator.dupe(u8, "test"),
            },
        },
        .source = .{
            .url = try allocator.dupe(u8, "https://example.com/test.tar.gz"),
            .sha256 = try allocator.dupe(u8, "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"),
        },
        .filesystem = .{
            .files = &files,
        },
    };
    defer {
        allocator.free(spec.format_version);
        allocator.free(spec.schema_version);
        spec.identity.deinit(allocator);
        spec.source.deinit(allocator);
        if (spec.filesystem.merkle_root) |mr| allocator.free(mr);
        if (spec.machine_identity) |*mi| mi.deinit(allocator);
    }

    const hash1 = try spec.computeContentHash(allocator);
    defer allocator.free(hash1);

    // Reset merkle root to test recomputation
    if (spec.filesystem.merkle_root) |mr| allocator.free(mr);
    spec.filesystem.merkle_root = null;

    const hash2 = try spec.computeContentHash(allocator);
    defer allocator.free(hash2);

    // Same spec must produce same hash
    try std.testing.expectEqualStrings(hash1, hash2);
}
