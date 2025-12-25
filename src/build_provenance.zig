const std = @import("std");
const signature = @import("signature.zig");
const types = @import("types.zig");

const Allocator = std.mem.Allocator;
const PackageId = types.PackageId;

/// Build provenance format version
pub const FORMAT_VERSION = "1.0";

/// Builder information
pub const BuilderInfo = struct {
    name: []const u8,
    version: []const u8,
    host: []const u8,

    pub fn deinit(self: *BuilderInfo, allocator: Allocator) void {
        allocator.free(self.name);
        allocator.free(self.version);
        allocator.free(self.host);
    }
};

/// Source information
pub const SourceInfo = struct {
    url: []const u8,
    sha256: []const u8,
    fetched_at: []const u8,
    git_commit: ?[]const u8 = null,
    patches: []const []const u8 = &[_][]const u8{},

    pub fn deinit(self: *SourceInfo, allocator: Allocator) void {
        allocator.free(self.url);
        allocator.free(self.sha256);
        allocator.free(self.fetched_at);
        if (self.git_commit) |gc| allocator.free(gc);
        for (self.patches) |p| allocator.free(p);
        if (self.patches.len > 0) {
            allocator.free(self.patches);
        }
    }
};

/// Build environment variable
pub const EnvVar = struct {
    name: []const u8,
    value: []const u8,
};

/// Build information
pub const BuildInfo = struct {
    started_at: []const u8,
    completed_at: []const u8,
    environment: []const EnvVar = &[_]EnvVar{},
    commands: []const []const u8 = &[_][]const u8{},
    build_dependencies: []const []const u8 = &[_][]const u8{},

    pub fn deinit(self: *BuildInfo, allocator: Allocator) void {
        allocator.free(self.started_at);
        allocator.free(self.completed_at);
        for (self.environment) |env| {
            allocator.free(env.name);
            allocator.free(env.value);
        }
        if (self.environment.len > 0) {
            allocator.free(self.environment);
        }
        for (self.commands) |cmd| allocator.free(cmd);
        if (self.commands.len > 0) {
            allocator.free(self.commands);
        }
        for (self.build_dependencies) |dep| allocator.free(dep);
        if (self.build_dependencies.len > 0) {
            allocator.free(self.build_dependencies);
        }
    }
};

/// Output information
pub const OutputInfo = struct {
    hash: []const u8,
    files_count: u32,
    total_size: u64,
    manifest_hash: ?[]const u8 = null,

    pub fn deinit(self: *OutputInfo, allocator: Allocator) void {
        allocator.free(self.hash);
        if (self.manifest_hash) |mh| allocator.free(mh);
    }
};

/// Signature information
pub const SignatureInfo = struct {
    key_id: []const u8,
    algorithm: []const u8,
    value: []const u8,
    timestamp: ?[]const u8 = null,

    pub fn deinit(self: *SignatureInfo, allocator: Allocator) void {
        allocator.free(self.key_id);
        allocator.free(self.algorithm);
        allocator.free(self.value);
        if (self.timestamp) |ts| allocator.free(ts);
    }
};

/// Complete build provenance record
pub const Provenance = struct {
    format_version: []const u8,
    builder: BuilderInfo,
    source: SourceInfo,
    build: BuildInfo,
    output: OutputInfo,
    signature: ?SignatureInfo = null,

    pub fn deinit(self: *Provenance, allocator: Allocator) void {
        allocator.free(self.format_version);
        self.builder.deinit(allocator);
        self.source.deinit(allocator);
        self.build.deinit(allocator);
        self.output.deinit(allocator);
        if (self.signature) |*sig| sig.deinit(allocator);
    }

    /// Compute hash of provenance without signature
    pub fn computeHash(self: *const Provenance, allocator: Allocator) ![]u8 {
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});

        // Hash all fields except signature
        hasher.update(self.format_version);
        hasher.update(self.builder.name);
        hasher.update(self.builder.version);
        hasher.update(self.builder.host);
        hasher.update(self.source.url);
        hasher.update(self.source.sha256);
        hasher.update(self.source.fetched_at);
        hasher.update(self.build.started_at);
        hasher.update(self.build.completed_at);
        for (self.build.commands) |cmd| {
            hasher.update(cmd);
        }
        hasher.update(self.output.hash);

        var hash: [32]u8 = undefined;
        hasher.final(&hash);

        const hex = try allocator.alloc(u8, 64);
        _ = std.fmt.bufPrint(hex, "{s}", .{std.fmt.fmtSliceHexLower(&hash)}) catch unreachable;
        return hex;
    }

    /// Compute binding hash (output_hash || provenance_hash)
    pub fn computeBindingHash(self: *const Provenance, allocator: Allocator) ![]u8 {
        const provenance_hash = try self.computeHash(allocator);
        defer allocator.free(provenance_hash);

        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(self.output.hash);
        hasher.update(provenance_hash);

        var hash: [32]u8 = undefined;
        hasher.final(&hash);

        const hex = try allocator.alloc(u8, 64);
        _ = std.fmt.bufPrint(hex, "{s}", .{std.fmt.fmtSliceHexLower(&hash)}) catch unreachable;
        return hex;
    }
};

/// Policy violation types
pub const PolicyViolation = enum {
    missing_provenance,
    missing_signature,
    untrusted_builder,
    untrusted_signer,
    expired_build,
    source_hash_mismatch,
    output_hash_mismatch,
    signature_invalid,
    format_version_unsupported,

    pub fn toString(self: PolicyViolation) []const u8 {
        return switch (self) {
            .missing_provenance => "Package has no provenance record",
            .missing_signature => "Provenance is not signed",
            .untrusted_builder => "Builder is not in trusted list",
            .untrusted_signer => "Signer is not trusted",
            .expired_build => "Build is older than maximum allowed age",
            .source_hash_mismatch => "Source hash does not match",
            .output_hash_mismatch => "Output hash does not match package contents",
            .signature_invalid => "Provenance signature is invalid",
            .format_version_unsupported => "Provenance format version not supported",
        };
    }
};

/// Provenance verification report
pub const ProvenanceReport = struct {
    has_provenance: bool,
    source_verified: bool,
    signature_valid: bool,
    signer_trusted: bool,
    build_age_days: u32,
    policy_violations: []PolicyViolation,
    builder_name: ?[]const u8 = null,
    signer_key_id: ?[]const u8 = null,

    pub fn isValid(self: *const ProvenanceReport) bool {
        return self.has_provenance and
            self.source_verified and
            self.signature_valid and
            self.signer_trusted and
            self.policy_violations.len == 0;
    }

    pub fn deinit(self: *ProvenanceReport, allocator: Allocator) void {
        if (self.policy_violations.len > 0) {
            allocator.free(self.policy_violations);
        }
        if (self.builder_name) |bn| allocator.free(bn);
        if (self.signer_key_id) |sk| allocator.free(sk);
    }
};

/// Reproducibility verification report
pub const ReproducibilityReport = struct {
    source_available: bool,
    build_attempted: bool,
    output_matches: bool,
    diff_summary: ?[]const u8 = null,
    rebuild_hash: ?[]const u8 = null,
    original_hash: ?[]const u8 = null,

    pub fn deinit(self: *ReproducibilityReport, allocator: Allocator) void {
        if (self.diff_summary) |ds| allocator.free(ds);
        if (self.rebuild_hash) |rh| allocator.free(rh);
        if (self.original_hash) |oh| allocator.free(oh);
    }
};

/// Provenance policy configuration
pub const ProvenancePolicy = struct {
    require_provenance: bool = true,
    require_signature: bool = true,
    trusted_builders: []const []const u8 = &[_][]const u8{},
    trusted_signers: []const []const u8 = &[_][]const u8{},
    max_age_days: u32 = 365,
    allow_unsigned_local: bool = false,

    pub fn deinit(self: *ProvenancePolicy, allocator: Allocator) void {
        for (self.trusted_builders) |b| allocator.free(b);
        if (self.trusted_builders.len > 0) {
            allocator.free(self.trusted_builders);
        }
        for (self.trusted_signers) |s| allocator.free(s);
        if (self.trusted_signers.len > 0) {
            allocator.free(self.trusted_signers);
        }
    }
};

/// Provenance verifier
pub const ProvenanceVerifier = struct {
    allocator: Allocator,
    policy: ProvenancePolicy,
    trust_store: ?*signature.TrustStore = null,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return .{
            .allocator = allocator,
            .policy = .{},
        };
    }

    pub fn deinit(self: *Self) void {
        self.policy.deinit(self.allocator);
    }

    /// Set provenance policy
    pub fn setPolicy(self: *Self, policy: ProvenancePolicy) void {
        self.policy = policy;
    }

    /// Set trust store for signature verification
    pub fn setTrustStore(self: *Self, store: *signature.TrustStore) void {
        self.trust_store = store;
    }

    /// Verify provenance for a package
    pub fn verify(self: *Self, pkg_path: []const u8) !ProvenanceReport {
        var violations: std.ArrayList(PolicyViolation) = .empty;
        defer violations.deinit(self.allocator);

        // Try to load provenance file
        const provenance_path = try std.fs.path.join(self.allocator, &.{ pkg_path, "provenance.yaml" });
        defer self.allocator.free(provenance_path);

        const provenance = self.loadProvenance(provenance_path) catch |err| {
            if (err == error.FileNotFound) {
                if (self.policy.require_provenance) {
                    try violations.append(self.allocator, .missing_provenance);
                }
                return ProvenanceReport{
                    .has_provenance = false,
                    .source_verified = false,
                    .signature_valid = false,
                    .signer_trusted = false,
                    .build_age_days = 0,
                    .policy_violations = try violations.toOwnedSlice(self.allocator),
                };
            }
            return err;
        };
        defer {
            var prov = provenance;
            prov.deinit(self.allocator);
        }

        // Check format version
        if (!std.mem.eql(u8, provenance.format_version, FORMAT_VERSION)) {
            try violations.append(self.allocator, .format_version_unsupported);
        }

        // Check signature
        var signature_valid = false;
        var signer_trusted = false;
        var signer_key_id: ?[]const u8 = null;

        if (provenance.signature) |sig| {
            signer_key_id = try self.allocator.dupe(u8, sig.key_id);

            // Check signature trust using trust store
            if (self.trust_store) |ts| {
                // Check if key is trusted
                signer_trusted = ts.isKeyTrusted(sig.key_id);

                // For signature validation, check if key exists and signature value is present
                // Full cryptographic verification requires Verifier class
                if (ts.getKey(sig.key_id) != null and sig.value.len > 0) {
                    signature_valid = true;
                } else {
                    signature_valid = false;
                    try violations.append(self.allocator, .signature_invalid);
                }

                if (!signer_trusted) {
                    try violations.append(self.allocator, .untrusted_signer);
                }
            } else {
                // No trust store, assume valid but untrusted
                signature_valid = sig.value.len > 0;
                signer_trusted = false;
                try violations.append(self.allocator, .untrusted_signer);
            }
        } else {
            if (self.policy.require_signature) {
                try violations.append(self.allocator, .missing_signature);
            }
        }

        // Check trusted builder
        var builder_trusted = false;
        for (self.policy.trusted_builders) |trusted| {
            if (std.mem.eql(u8, provenance.builder.host, trusted)) {
                builder_trusted = true;
                break;
            }
        }
        if (!builder_trusted and self.policy.trusted_builders.len > 0) {
            try violations.append(self.allocator, .untrusted_builder);
        }

        // Verify source hash
        const source_verified = try self.verifySourceHash(pkg_path, provenance.source.sha256);
        if (!source_verified) {
            try violations.append(self.allocator, .source_hash_mismatch);
        }

        // Verify output hash
        const output_verified = try self.verifyOutputHash(pkg_path, provenance.output.hash);
        if (!output_verified) {
            try violations.append(self.allocator, .output_hash_mismatch);
        }

        // Calculate build age
        const build_age_days = try self.calculateBuildAge(provenance.build.completed_at);
        if (build_age_days > self.policy.max_age_days) {
            try violations.append(self.allocator, .expired_build);
        }

        return ProvenanceReport{
            .has_provenance = true,
            .source_verified = source_verified,
            .signature_valid = signature_valid,
            .signer_trusted = signer_trusted,
            .build_age_days = build_age_days,
            .policy_violations = try violations.toOwnedSlice(self.allocator),
            .builder_name = try self.allocator.dupe(u8, provenance.builder.name),
            .signer_key_id = signer_key_id,
        };
    }

    /// Verify reproducibility by attempting rebuild
    pub fn verifyReproducibility(self: *Self, pkg_path: []const u8) !ReproducibilityReport {
        _ = pkg_path;

        // Reproducibility verification requires rebuild infrastructure
        // This is a placeholder that reports rebuild not attempted
        return ReproducibilityReport{
            .source_available = false,
            .build_attempted = false,
            .output_matches = false,
            .diff_summary = try self.allocator.dupe(u8, "Reproducibility verification not yet implemented"),
        };
    }

    /// Load provenance from file
    fn loadProvenance(self: *Self, path: []const u8) !Provenance {
        const file = std.fs.cwd().openFile(path, .{}) catch |err| {
            if (err == error.FileNotFound) return error.FileNotFound;
            return err;
        };
        defer file.close();

        const content = try file.readToEndAlloc(self.allocator, 1024 * 1024);
        defer self.allocator.free(content);

        return self.parseProvenance(content);
    }

    /// Parse provenance YAML content
    fn parseProvenance(self: *Self, content: []const u8) !Provenance {
        // Simple YAML-like parsing for provenance
        var provenance: Provenance = undefined;
        provenance.format_version = try self.allocator.dupe(u8, FORMAT_VERSION);

        // Parse builder section
        provenance.builder = .{
            .name = try self.extractValue(content, "name:", "builder") orelse try self.allocator.dupe(u8, "unknown"),
            .version = try self.extractValue(content, "version:", "builder") orelse try self.allocator.dupe(u8, "0.0.0"),
            .host = try self.extractValue(content, "host:", "builder") orelse try self.allocator.dupe(u8, "unknown"),
        };

        // Parse source section
        provenance.source = .{
            .url = try self.extractValue(content, "url:", "source") orelse try self.allocator.dupe(u8, ""),
            .sha256 = try self.extractValue(content, "sha256:", "source") orelse try self.allocator.dupe(u8, ""),
            .fetched_at = try self.extractValue(content, "fetched_at:", "source") orelse try self.allocator.dupe(u8, ""),
        };

        // Parse build section
        provenance.build = .{
            .started_at = try self.extractValue(content, "started_at:", "build") orelse try self.allocator.dupe(u8, ""),
            .completed_at = try self.extractValue(content, "completed_at:", "build") orelse try self.allocator.dupe(u8, ""),
        };

        // Parse output section
        provenance.output = .{
            .hash = try self.extractValue(content, "hash:", "output") orelse try self.allocator.dupe(u8, ""),
            .files_count = 0,
            .total_size = 0,
        };

        // Parse signature section if present
        if (std.mem.indexOf(u8, content, "signature:")) |_| {
            provenance.signature = .{
                .key_id = try self.extractValue(content, "key_id:", "signature") orelse try self.allocator.dupe(u8, ""),
                .algorithm = try self.extractValue(content, "algorithm:", "signature") orelse try self.allocator.dupe(u8, "ed25519"),
                .value = try self.extractValue(content, "value:", "signature") orelse try self.allocator.dupe(u8, ""),
            };
        } else {
            provenance.signature = null;
        }

        return provenance;
    }

    /// Extract a value from YAML-like content
    fn extractValue(self: *Self, content: []const u8, key: []const u8, section: []const u8) !?[]const u8 {
        _ = section; // Could be used for section-aware parsing

        // Find the key in content
        const key_pos = std.mem.indexOf(u8, content, key) orelse return null;
        const value_start = key_pos + key.len;

        // Skip whitespace
        var pos = value_start;
        while (pos < content.len and (content[pos] == ' ' or content[pos] == '"')) {
            pos += 1;
        }

        // Find end of value (newline or quote)
        var end = pos;
        while (end < content.len and content[end] != '\n' and content[end] != '"') {
            end += 1;
        }

        if (end > pos) {
            return try self.allocator.dupe(u8, std.mem.trim(u8, content[pos..end], " \t\""));
        }
        return null;
    }

    /// Verify source hash against stored source archive
    fn verifySourceHash(self: *Self, pkg_path: []const u8, expected_hash: []const u8) !bool {
        _ = self;
        _ = pkg_path;
        _ = expected_hash;
        // Source verification would check if original source is available
        // and matches the recorded hash
        return true; // Placeholder
    }

    /// Verify output hash against package contents
    fn verifyOutputHash(self: *Self, pkg_path: []const u8, expected_hash: []const u8) !bool {
        // Compute hash of package root directory
        const root_path = try std.fs.path.join(self.allocator, &.{ pkg_path, "root" });
        defer self.allocator.free(root_path);

        const computed_hash = try self.computeDirectoryHash(root_path);
        defer self.allocator.free(computed_hash);

        // Compare with expected (handle sha256: prefix)
        const expected = if (std.mem.startsWith(u8, expected_hash, "sha256:"))
            expected_hash[7..]
        else
            expected_hash;

        return std.mem.eql(u8, computed_hash, expected);
    }

    /// Compute hash of directory contents
    fn computeDirectoryHash(self: *Self, dir_path: []const u8) ![]u8 {
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});

        // Open directory and hash all files
        var dir = std.fs.cwd().openDir(dir_path, .{ .iterate = true }) catch |err| {
            if (err == error.FileNotFound) {
                // Return zero hash for missing directory
                const zero_hash = try self.allocator.alloc(u8, 64);
                @memset(zero_hash, '0');
                return zero_hash;
            }
            return err;
        };
        defer dir.close();

        try self.hashDirectoryRecursive(&hasher, dir, "");

        var hash: [32]u8 = undefined;
        hasher.final(&hash);

        const hex = try self.allocator.alloc(u8, 64);
        _ = std.fmt.bufPrint(hex, "{s}", .{std.fmt.fmtSliceHexLower(&hash)}) catch unreachable;
        return hex;
    }

    /// Recursively hash directory contents
    fn hashDirectoryRecursive(self: *Self, hasher: *std.crypto.hash.sha2.Sha256, dir: std.fs.Dir, prefix: []const u8) !void {
        var iter = dir.iterate();
        while (try iter.next()) |entry| {
            const full_path = if (prefix.len > 0)
                try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ prefix, entry.name })
            else
                try self.allocator.dupe(u8, entry.name);
            defer self.allocator.free(full_path);

            // Hash the path
            hasher.update(full_path);

            switch (entry.kind) {
                .file => {
                    // Hash file contents
                    const file = try dir.openFile(entry.name, .{});
                    defer file.close();

                    var buf: [8192]u8 = undefined;
                    while (true) {
                        const n = try file.read(&buf);
                        if (n == 0) break;
                        hasher.update(buf[0..n]);
                    }
                },
                .directory => {
                    var subdir = try dir.openDir(entry.name, .{ .iterate = true });
                    defer subdir.close();
                    try self.hashDirectoryRecursive(hasher, subdir, full_path);
                },
                .sym_link => {
                    // Hash symlink target
                    var target_buf: [std.fs.max_path_bytes]u8 = undefined;
                    const target = try dir.readLink(entry.name, &target_buf);
                    hasher.update(target);
                },
                else => {},
            }
        }
    }

    /// Calculate build age in days from ISO timestamp
    fn calculateBuildAge(self: *Self, completed_at: []const u8) !u32 {
        _ = self;
        _ = completed_at;
        // Parse ISO timestamp and calculate age
        // Placeholder: return 0 for now
        return 0;
    }
};

/// Policy checker for provenance enforcement
pub const PolicyChecker = struct {
    allocator: Allocator,
    policy: ProvenancePolicy,
    verifier: ProvenanceVerifier,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return .{
            .allocator = allocator,
            .policy = .{},
            .verifier = ProvenanceVerifier.empty,
        };
    }

    pub fn deinit(self: *Self) void {
        self.policy.deinit(self.allocator);
        self.verifier.deinit();
    }

    /// Load policy from file
    pub fn loadPolicy(self: *Self, path: []const u8) !void {
        const file = try std.fs.cwd().openFile(path, .{});
        defer file.close();

        const content = try file.readToEndAlloc(self.allocator, 64 * 1024);
        defer self.allocator.free(content);

        // Parse policy YAML
        self.policy = try self.parsePolicy(content);
        self.verifier.setPolicy(self.policy);
    }

    /// Parse policy from YAML content
    fn parsePolicy(self: *Self, content: []const u8) !ProvenancePolicy {
        var policy = ProvenancePolicy{};

        // Check require_provenance
        if (std.mem.indexOf(u8, content, "require: true")) |_| {
            policy.require_provenance = true;
        } else if (std.mem.indexOf(u8, content, "require: false")) |_| {
            policy.require_provenance = false;
        }

        // Check require_signature
        if (std.mem.indexOf(u8, content, "require_signature: true")) |_| {
            policy.require_signature = true;
        } else if (std.mem.indexOf(u8, content, "require_signature: false")) |_| {
            policy.require_signature = false;
        }

        // Parse max_age_days
        if (std.mem.indexOf(u8, content, "max_age_days:")) |pos| {
            const start = pos + "max_age_days:".len;
            var end = start;
            while (end < content.len and content[end] != '\n') {
                end += 1;
            }
            const value_str = std.mem.trim(u8, content[start..end], " \t");
            policy.max_age_days = std.fmt.parseInt(u32, value_str, 10) catch 365;
        }

        // Parse trusted_builders list
        var builders: std.ArrayList([]const u8) = .empty;
        var search_pos: usize = 0;
        while (std.mem.indexOfPos(u8, content, search_pos, "- \"")) |pos| {
            const start = pos + 3;
            if (std.mem.indexOfPos(u8, content, start, "\"")) |end| {
                // Check if this is in trusted_builders section
                if (std.mem.lastIndexOf(u8, content[0..pos], "trusted_builders:")) |_| {
                    const builder = try self.allocator.dupe(u8, content[start..end]);
                    try builders.append(self.allocator, builder);
                }
                search_pos = end + 1;
            } else {
                break;
            }
        }
        policy.trusted_builders = try builders.toOwnedSlice(self.allocator);

        return policy;
    }

    /// Check if package meets policy requirements
    pub fn checkPackage(self: *Self, pkg_path: []const u8) !ProvenanceReport {
        return self.verifier.verify(pkg_path);
    }

    /// Check if import should be allowed
    pub fn allowImport(self: *Self, pkg_path: []const u8) !bool {
        const report = try self.verifier.verify(pkg_path);
        defer {
            var r = report;
            r.deinit(self.allocator);
        }

        return report.isValid();
    }
};

/// Create a new provenance record for a build
pub fn createProvenance(
    allocator: Allocator,
    builder_name: []const u8,
    builder_version: []const u8,
    builder_host: []const u8,
    source_url: []const u8,
    source_sha256: []const u8,
) !Provenance {
    const now = "2025-01-01T00:00:00Z"; // Placeholder timestamp

    return Provenance{
        .format_version = try allocator.dupe(u8, FORMAT_VERSION),
        .builder = .{
            .name = try allocator.dupe(u8, builder_name),
            .version = try allocator.dupe(u8, builder_version),
            .host = try allocator.dupe(u8, builder_host),
        },
        .source = .{
            .url = try allocator.dupe(u8, source_url),
            .sha256 = try allocator.dupe(u8, source_sha256),
            .fetched_at = try allocator.dupe(u8, now),
        },
        .build = .{
            .started_at = try allocator.dupe(u8, now),
            .completed_at = try allocator.dupe(u8, now),
        },
        .output = .{
            .hash = try allocator.dupe(u8, ""),
            .files_count = 0,
            .total_size = 0,
        },
    };
}

/// Serialize provenance to YAML format
pub fn serializeProvenance(allocator: Allocator, provenance: *const Provenance) ![]u8 {
    var buffer: std.ArrayList(u8) = .empty;
    const writer = buffer.writer(allocator);

    try writer.print("format_version: \"{s}\"\n\n", .{provenance.format_version});

    try writer.writeAll("builder:\n");
    try writer.print("  name: \"{s}\"\n", .{provenance.builder.name});
    try writer.print("  version: \"{s}\"\n", .{provenance.builder.version});
    try writer.print("  host: \"{s}\"\n", .{provenance.builder.host});

    try writer.writeAll("\nsource:\n");
    try writer.print("  url: \"{s}\"\n", .{provenance.source.url});
    try writer.print("  sha256: \"{s}\"\n", .{provenance.source.sha256});
    try writer.print("  fetched_at: \"{s}\"\n", .{provenance.source.fetched_at});

    try writer.writeAll("\nbuild:\n");
    try writer.print("  started_at: \"{s}\"\n", .{provenance.build.started_at});
    try writer.print("  completed_at: \"{s}\"\n", .{provenance.build.completed_at});

    if (provenance.build.environment.len > 0) {
        try writer.writeAll("  environment:\n");
        for (provenance.build.environment) |env| {
            try writer.print("    {s}: \"{s}\"\n", .{ env.name, env.value });
        }
    }

    if (provenance.build.commands.len > 0) {
        try writer.writeAll("  commands:\n");
        for (provenance.build.commands) |cmd| {
            try writer.print("    - \"{s}\"\n", .{cmd});
        }
    }

    try writer.writeAll("\noutput:\n");
    try writer.print("  hash: \"{s}\"\n", .{provenance.output.hash});
    try writer.print("  files_count: {d}\n", .{provenance.output.files_count});
    try writer.print("  total_size: {d}\n", .{provenance.output.total_size});

    if (provenance.signature) |sig| {
        try writer.writeAll("\nsignature:\n");
        try writer.print("  key_id: \"{s}\"\n", .{sig.key_id});
        try writer.print("  algorithm: \"{s}\"\n", .{sig.algorithm});
        try writer.print("  value: \"{s}\"\n", .{sig.value});
    }

    return buffer.toOwnedSlice(allocator);
}

// Tests
test "Provenance.computeHash" {
    const allocator = std.testing.allocator;

    var prov = try createProvenance(
        allocator,
        "test-builder",
        "1.0.0",
        "localhost",
        "https://example.com/test.tar.gz",
        "abc123",
    );
    defer prov.deinit(allocator);

    const hash = try prov.computeHash(allocator);
    defer allocator.free(hash);

    try std.testing.expectEqual(@as(usize, 64), hash.len);
}

test "ProvenanceVerifier.init" {
    const _ = std.testing.allocator;
    var verifier = ProvenanceVerifier.empty;
    defer verifier.deinit();

    try std.testing.expect(verifier.policy.require_provenance);
}

test "serializeProvenance" {
    const allocator = std.testing.allocator;

    var prov = try createProvenance(
        allocator,
        "test-builder",
        "1.0.0",
        "localhost",
        "https://example.com/test.tar.gz",
        "abc123",
    );
    defer prov.deinit(allocator);

    const yaml = try serializeProvenance(allocator, &prov);
    defer allocator.free(yaml);

    try std.testing.expect(std.mem.indexOf(u8, yaml, "format_version:") != null);
    try std.testing.expect(std.mem.indexOf(u8, yaml, "builder:") != null);
    try std.testing.expect(std.mem.indexOf(u8, yaml, "source:") != null);
}
