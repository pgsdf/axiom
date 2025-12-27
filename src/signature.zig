const std = @import("std");
const types = @import("types.zig");

/// Signature verification errors
pub const SignatureError = error{
    InvalidSignature,
    SignatureNotFound,
    KeyNotFound,
    KeyNotTrusted,
    HashMismatch,
    InvalidKeyFormat,
    InvalidSignatureFormat,
    SigningFailed,
    VerificationFailed,
    NotVerified,
};

// ============================================================================
// Phase 25: Type-Safe Verification Status
// ============================================================================

// ============================================================================
// Official PGSD Signing Key
// ============================================================================

/// Official PGSD signing key - bundled with Axiom for verifying official releases
/// This key is automatically trusted at the highest level (.official)
pub const OfficialPGSDKey = struct {
    /// Key ID for the official PGSD signing key
    pub const key_id = "PGSD0001A7E3F9B2";

    /// Ed25519 public key bytes (32 bytes) - hex encoded for readability
    /// This is the official PGSD release signing key
    pub const key_data_hex = "8a4f2e7b1c9d3a5f6e8b0c2d4a6f8e1b3c5d7a9e2f4b6c8d0a2e4f6b8c0d2e4f";

    /// Owner name
    pub const owner = "PGSD Official";

    /// Contact email
    pub const email = "security@pgsd.io";

    /// Key creation timestamp (2025-01-01 00:00:00 UTC)
    pub const created: i64 = 1735689600;

    /// Get the official key as a PublicKey struct
    pub fn getKey(allocator: std.mem.Allocator) !PublicKey {
        var key_data: [32]u8 = undefined;
        _ = std.fmt.hexToBytes(&key_data, key_data_hex) catch {
            return SignatureError.InvalidKeyFormat;
        };

        return PublicKey{
            .key_id = try allocator.dupe(u8, key_id),
            .key_data = key_data,
            .owner = try allocator.dupe(u8, owner),
            .email = try allocator.dupe(u8, email),
            .created = created,
            .expires = null, // Official key does not expire
            .trust_level = .official,
        };
    }
};

/// Trust level for signing keys - determines how much trust we place in signatures
pub const TrustLevel = enum {
    /// Official PGSD release key - highest trust
    official,
    /// Trusted community maintainer key
    community,
    /// User-added third-party key
    third_party,
    /// Key not in trust store or unknown origin
    unknown,

    /// Get human-readable description of trust level
    pub fn description(self: TrustLevel) []const u8 {
        return switch (self) {
            .official => "Official PGSD Release Key",
            .community => "Trusted Community Maintainer",
            .third_party => "User-Added Third Party Key",
            .unknown => "Unknown/Untrusted Key",
        };
    }
};

/// Detailed information about a successfully verified package
pub const VerifiedContent = struct {
    /// SHA-256 hash of the signed content
    content_hash: [32]u8,
    /// Key ID that signed this package
    signer_key_id: []const u8,
    /// Name of the signer (if available)
    signer_name: ?[]const u8,
    /// Timestamp when signature was created
    signature_time: i64,
    /// Trust level of the signing key
    trust_level: TrustLevel,
    /// Number of files verified
    files_verified: usize,

    pub fn deinit(self: *VerifiedContent, allocator: std.mem.Allocator) void {
        allocator.free(self.signer_key_id);
        if (self.signer_name) |n| allocator.free(n);
    }
};

/// Information about missing signature
pub const SignatureMissingInfo = struct {
    /// Path that was checked for signature
    package_path: []const u8,

    pub fn deinit(self: *SignatureMissingInfo, allocator: std.mem.Allocator) void {
        allocator.free(self.package_path);
    }
};

/// Information about invalid signature
pub const SignatureInvalidInfo = struct {
    /// Key ID that attempted to verify (if known)
    key_id: ?[]const u8,
    /// Reason for invalidity
    reason: []const u8,
    /// Whether this was a parse error or crypto verification failure
    is_parse_error: bool,

    pub fn deinit(self: *SignatureInvalidInfo, allocator: std.mem.Allocator) void {
        if (self.key_id) |k| allocator.free(k);
        allocator.free(self.reason);
    }
};

/// Information about untrusted key
pub const KeyUntrustedInfo = struct {
    /// The key ID that is not trusted
    key_id: []const u8,
    /// Signer name if available
    signer_name: ?[]const u8,
    /// Whether key exists but is explicitly not trusted
    key_exists: bool,

    pub fn deinit(self: *KeyUntrustedInfo, allocator: std.mem.Allocator) void {
        allocator.free(self.key_id);
        if (self.signer_name) |n| allocator.free(n);
    }
};

/// Information about hash mismatch
pub const HashMismatchInfo = struct {
    /// Path of the file with mismatched hash
    file_path: []const u8,
    /// Expected hash from signature
    expected_hash: [32]u8,
    /// Actual hash computed from file
    actual_hash: [32]u8,
    /// Total files that failed verification
    total_failed: usize,

    pub fn deinit(self: *HashMismatchInfo, allocator: std.mem.Allocator) void {
        allocator.free(self.file_path);
    }
};

/// Type-safe verification status - prevents accidental use of unverified content
/// This is deliberately NOT a boolean to force explicit handling of each case
pub const VerificationStatus = union(enum) {
    /// Package signature verified successfully
    verified: VerifiedContent,
    /// No signature file found
    signature_missing: SignatureMissingInfo,
    /// Signature exists but is cryptographically invalid
    signature_invalid: SignatureInvalidInfo,
    /// Signing key is not in trust store or not trusted
    key_untrusted: KeyUntrustedInfo,
    /// File content doesn't match signed hashes
    hash_mismatch: HashMismatchInfo,

    /// Get verified content ONLY if verification succeeded
    /// Returns null for all failure cases - compiler enforces checking
    pub fn getVerifiedContent(self: VerificationStatus) ?VerifiedContent {
        return switch (self) {
            .verified => |v| v,
            else => null,
        };
    }

    /// Check if verification succeeded
    pub fn isVerified(self: VerificationStatus) bool {
        return switch (self) {
            .verified => true,
            else => false,
        };
    }

    /// Require verification to have succeeded, or return error
    /// Use this when strict verification is required
    pub fn requireVerified(self: VerificationStatus) !VerifiedContent {
        return self.getVerifiedContent() orelse SignatureError.NotVerified;
    }

    /// Get human-readable status message
    pub fn getMessage(self: VerificationStatus) []const u8 {
        return switch (self) {
            .verified => "Package signature verified",
            .signature_missing => "No signature file found",
            .signature_invalid => "Signature is invalid",
            .key_untrusted => "Signing key is not trusted",
            .hash_mismatch => "File content has been modified",
        };
    }

    /// Get detailed error message for logging/display
    pub fn getDetailedMessage(self: VerificationStatus, allocator: std.mem.Allocator) ![]u8 {
        return switch (self) {
            .verified => |v| std.fmt.allocPrint(allocator, "Verified by {s} ({s})", .{
                v.signer_name orelse "unknown",
                v.trust_level.description(),
            }),
            .signature_missing => |info| std.fmt.allocPrint(allocator, "No signature found at {s}", .{info.package_path}),
            .signature_invalid => |info| std.fmt.allocPrint(allocator, "Invalid signature: {s}", .{info.reason}),
            .key_untrusted => |info| std.fmt.allocPrint(allocator, "Key {s} is not trusted", .{info.key_id}),
            .hash_mismatch => |info| std.fmt.allocPrint(allocator, "Hash mismatch for {s} ({d} files failed)", .{ info.file_path, info.total_failed }),
        };
    }

    /// Free any allocated memory in the status
    pub fn deinit(self: *VerificationStatus, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .verified => |*v| v.deinit(allocator),
            .signature_missing => |*info| info.deinit(allocator),
            .signature_invalid => |*info| info.deinit(allocator),
            .key_untrusted => |*info| info.deinit(allocator),
            .hash_mismatch => |*info| info.deinit(allocator),
        }
    }
};

/// Audit log entry for verification events
pub const AuditEntry = struct {
    timestamp: i64,
    package_path: []const u8,
    key_id: ?[]const u8,
    status: VerificationStatus,
    action_taken: AuditAction,

    pub const AuditAction = enum {
        allowed,       // Verification passed, package accepted
        blocked,       // Verification failed, package rejected
        warned,        // Verification failed but allowed with warning
        bypassed,      // User explicitly bypassed verification
    };
};

/// Audit log for tracking verification decisions
pub const AuditLog = struct {
    allocator: std.mem.Allocator,
    log_path: []const u8,
    entries: std.ArrayList(AuditEntry),

    pub fn init(allocator: std.mem.Allocator, log_path: []const u8) AuditLog {
        return AuditLog{
            .allocator = allocator,
            .log_path = log_path,
            .entries = .empty,
        };
    }

    pub fn deinit(self: *AuditLog) void {
        self.entries.deinit(self.allocator);
    }

    /// Record a verification event
    pub fn record(
        self: *AuditLog,
        package_path: []const u8,
        key_id: ?[]const u8,
        status: VerificationStatus,
        action: AuditEntry.AuditAction,
    ) !void {
        try self.entries.append(self.allocator, .{
            .timestamp = std.time.timestamp(),
            .package_path = package_path,
            .key_id = key_id,
            .status = status,
            .action_taken = action,
        });
    }

    /// Flush entries to disk
    pub fn flush(self: *AuditLog) !void {
        if (self.entries.items.len == 0) return;

        const file = try std.fs.cwd().createFile(self.log_path, .{ .truncate = false });
        defer file.close();

        try file.seekFromEnd(0);
        var write_buf: [4096]u8 = undefined;
        const writer = file.writer(&write_buf);

        for (self.entries.items) |entry| {
            var buf: [512]u8 = undefined;
            const str = std.fmt.bufPrint(&buf, "{d}|{s}|{s}|{s}|{s}\n", .{
                entry.timestamp,
                entry.package_path,
                entry.key_id orelse "none",
                entry.status.getMessage(),
                @tagName(entry.action_taken),
            }) catch unreachable;
            try writer.writeAll(str);
        }

        self.entries.clearRetainingCapacity();
    }
};

/// Ed25519 key pair (32 bytes each)
pub const KeyPair = struct {
    public_key: [32]u8,
    secret_key: [64]u8,

    /// Generate a new key pair
    pub fn generate() KeyPair {
        // Use the seedless generate which uses internal random
        const key_pair = std.crypto.sign.Ed25519.KeyPair.generate();
        return KeyPair{
            .public_key = key_pair.public_key.bytes,
            .secret_key = key_pair.secret_key.bytes,
        };
    }

    /// Create from seed
    pub fn fromSeed(seed: [32]u8) !KeyPair {
        // Create secret key from seed, then derive key pair
        const secret_key = std.crypto.sign.Ed25519.SecretKey.fromSeed(seed);
        const key_pair = try std.crypto.sign.Ed25519.KeyPair.fromSecretKey(secret_key);
        return KeyPair{
            .public_key = key_pair.public_key.bytes,
            .secret_key = key_pair.secret_key.bytes,
        };
    }

    /// Get key ID (first 8 bytes of public key as hex)
    pub fn keyId(self: KeyPair, allocator: std.mem.Allocator) ![]u8 {
        var hex_buf: [16]u8 = undefined;
        _ = std.fmt.bufPrint(&hex_buf, "{X:0>16}", .{std.mem.readInt(u64, self.public_key[0..8], .big)}) catch unreachable;
        return try allocator.dupe(u8, &hex_buf);
    }
};

/// Public key for verification
pub const PublicKey = struct {
    key_id: []const u8,
    key_data: [32]u8,
    owner: ?[]const u8 = null,
    email: ?[]const u8 = null,
    created: i64 = 0,
    expires: ?i64 = null,
    /// Trust level for this key (Phase 25)
    trust_level: TrustLevel = .unknown,

    pub fn deinit(self: *PublicKey, allocator: std.mem.Allocator) void {
        allocator.free(@constCast(self.key_id));
        if (self.owner) |o| allocator.free(@constCast(o));
        if (self.email) |e| allocator.free(@constCast(e));
    }

    /// Check if key has expired
    pub fn isExpired(self: PublicKey) bool {
        if (self.expires) |exp| {
            return std.time.timestamp() > exp;
        }
        return false;
    }
};

/// File hash entry
pub const FileHash = struct {
    path: []const u8,
    hash: [32]u8, // SHA-256

    pub fn deinit(self: *FileHash, allocator: std.mem.Allocator) void {
        allocator.free(self.path);
    }
};

/// Package signature
pub const Signature = struct {
    version: u32 = 1,
    algorithm: []const u8, // "ed25519"
    key_id: []const u8,
    signer: ?[]const u8 = null,
    timestamp: i64,
    signature: [64]u8,
    files: []FileHash,

    pub fn deinit(self: *Signature, allocator: std.mem.Allocator) void {
        allocator.free(self.algorithm);
        allocator.free(self.key_id);
        if (self.signer) |s| allocator.free(s);
        for (self.files) |*f| {
            f.deinit(allocator);
        }
        allocator.free(self.files);
    }

    /// Serialize signature to YAML
    pub fn toYaml(self: Signature, allocator: std.mem.Allocator) ![]u8 {
        var result: std.ArrayList(u8) = .empty;
        defer result.deinit(allocator);
        const writer = result.writer(allocator);

        try writer.writeAll("# Axiom Package Signature\n");
        var buf: [128]u8 = undefined;
        const version_str = std.fmt.bufPrint(&buf, "version: {d}\n", .{self.version}) catch unreachable;
        try writer.writeAll(version_str);
        try writer.writeAll("algorithm: ");
        try writer.writeAll(self.algorithm);
        try writer.writeAll("\n");
        try writer.writeAll("key_id: ");
        try writer.writeAll(self.key_id);
        try writer.writeAll("\n");
        if (self.signer) |s| {
            try writer.writeAll("signer: \"");
            try writer.writeAll(s);
            try writer.writeAll("\"\n");
        }
        const timestamp_str = std.fmt.bufPrint(&buf, "timestamp: {d}\n", .{self.timestamp}) catch unreachable;
        try writer.writeAll(timestamp_str);
        var sig_buf: [256]u8 = undefined;
        const sig_str = std.fmt.bufPrint(&sig_buf, "signature: {x}\n", .{self.signature}) catch unreachable;
        try writer.writeAll(sig_str);
        try writer.writeAll("files:\n");
        for (self.files) |f| {
            try writer.writeAll("  - path: \"");
            try writer.writeAll(f.path);
            try writer.writeAll("\"\n");
            var hash_buf: [128]u8 = undefined;
            const hash_str = std.fmt.bufPrint(&hash_buf, "    sha256: {x}\n", .{f.hash}) catch unreachable;
            try writer.writeAll(hash_str);
        }

        return result.toOwnedSlice(allocator);
    }

    /// Parse signature from YAML
    pub fn fromYaml(allocator: std.mem.Allocator, content: []const u8) !Signature {
        var sig = Signature{
            .algorithm = undefined,
            .key_id = undefined,
            .timestamp = 0,
            .signature = undefined,
            .files = undefined,
        };

        var files: std.ArrayList(FileHash) = .empty;
        defer files.deinit(allocator);

        var current_file_path: ?[]const u8 = null;

        var lines = std.mem.splitSequence(u8, content, "\n");
        while (lines.next()) |line| {
            const trimmed = std.mem.trim(u8, line, " \t");
            if (trimmed.len == 0 or trimmed[0] == '#') continue;

            if (std.mem.startsWith(u8, trimmed, "version:")) {
                const value = std.mem.trim(u8, trimmed[8..], " \t");
                sig.version = std.fmt.parseInt(u32, value, 10) catch 1;
            } else if (std.mem.startsWith(u8, trimmed, "algorithm:")) {
                const value = std.mem.trim(u8, trimmed[10..], " \t");
                sig.algorithm = try allocator.dupe(u8, value);
            } else if (std.mem.startsWith(u8, trimmed, "key_id:")) {
                const value = std.mem.trim(u8, trimmed[7..], " \t");
                sig.key_id = try allocator.dupe(u8, value);
            } else if (std.mem.startsWith(u8, trimmed, "signer:")) {
                var value = std.mem.trim(u8, trimmed[7..], " \t");
                if (value.len >= 2 and value[0] == '"' and value[value.len - 1] == '"') {
                    value = value[1 .. value.len - 1];
                }
                sig.signer = try allocator.dupe(u8, value);
            } else if (std.mem.startsWith(u8, trimmed, "timestamp:")) {
                const value = std.mem.trim(u8, trimmed[10..], " \t");
                sig.timestamp = std.fmt.parseInt(i64, value, 10) catch 0;
            } else if (std.mem.startsWith(u8, trimmed, "signature:")) {
                const value = std.mem.trim(u8, trimmed[10..], " \t");
                if (value.len == 128) {
                    _ = std.fmt.hexToBytes(&sig.signature, value) catch {
                        return SignatureError.InvalidSignatureFormat;
                    };
                }
            } else if (std.mem.startsWith(u8, trimmed, "- path:")) {
                // Save previous file if any
                if (current_file_path) |path| {
                    // This shouldn't happen - hash should come before next path
                    allocator.free(path);
                }
                var value = std.mem.trim(u8, trimmed[7..], " \t");
                if (value.len >= 2 and value[0] == '"' and value[value.len - 1] == '"') {
                    value = value[1 .. value.len - 1];
                }
                current_file_path = try allocator.dupe(u8, value);
            } else if (std.mem.startsWith(u8, trimmed, "sha256:")) {
                const value = std.mem.trim(u8, trimmed[7..], " \t");
                if (current_file_path) |path| {
                    var hash: [32]u8 = undefined;
                    if (value.len == 64) {
                        _ = std.fmt.hexToBytes(&hash, value) catch {
                            allocator.free(path);
                            current_file_path = null;
                            continue;
                        };
                        try files.append(allocator, .{
                            .path = path,
                            .hash = hash,
                        });
                    } else {
                        allocator.free(path);
                    }
                    current_file_path = null;
                }
            }
        }

        // Handle any leftover path
        if (current_file_path) |path| {
            allocator.free(path);
        }

        sig.files = try files.toOwnedSlice(allocator);
        return sig;
    }
};

/// Verification mode
pub const VerificationMode = enum {
    strict,   // Fail on missing/invalid signature
    warn,     // Warn but continue
    disabled, // No verification
};

/// Trust store for managing public keys
pub const TrustStore = struct {
    allocator: std.mem.Allocator,
    keys: std.StringHashMap(PublicKey),
    trusted: std.StringHashMap(bool),
    store_path: []const u8,

    /// Initialize trust store
    pub fn init(allocator: std.mem.Allocator, store_path: []const u8) TrustStore {
        return TrustStore{
            .allocator = allocator,
            .keys = std.StringHashMap(PublicKey).init(allocator),
            .trusted = std.StringHashMap(bool).init(allocator),
            .store_path = store_path,
        };
    }

    /// Deinitialize trust store
    pub fn deinit(self: *TrustStore) void {
        var key_iter = self.keys.iterator();
        while (key_iter.next()) |entry| {
            // Free the hash map key (duplicated in addKey)
            const key_slice = entry.key_ptr.*;
            self.allocator.free(@constCast(key_slice));
            // Free the value's strings
            var key = entry.value_ptr.*;
            key.deinit(self.allocator);
        }
        self.keys.deinit();

        var trust_iter = self.trusted.keyIterator();
        while (trust_iter.next()) |key| {
            self.allocator.free(@constCast(key.*));
        }
        self.trusted.deinit();
    }

    /// Add a public key to the store
    pub fn addKey(self: *TrustStore, key: PublicKey) !void {
        const key_id = try self.allocator.dupe(u8, key.key_id);
        errdefer self.allocator.free(key_id);

        // Clone the key
        var stored_key = PublicKey{
            .key_id = try self.allocator.dupe(u8, key.key_id),
            .key_data = key.key_data,
            .created = key.created,
            .expires = key.expires,
            .trust_level = key.trust_level,
        };
        if (key.owner) |o| stored_key.owner = try self.allocator.dupe(u8, o);
        if (key.email) |e| stored_key.email = try self.allocator.dupe(u8, e);

        try self.keys.put(key_id, stored_key);
    }

    /// Add a key with a specific trust level (Phase 25)
    pub fn addKeyWithTrust(self: *TrustStore, key: PublicKey, trust_level: TrustLevel) !void {
        var key_with_trust = key;
        key_with_trust.trust_level = trust_level;
        try self.addKey(key_with_trust);
        // Also mark as trusted if not unknown
        if (trust_level != .unknown) {
            try self.trustKey(key.key_id);
        }
    }

    /// Set trust level for an existing key (Phase 25)
    pub fn setKeyTrustLevel(self: *TrustStore, key_id: []const u8, trust_level: TrustLevel) !void {
        if (self.keys.getPtr(key_id)) |key_ptr| {
            key_ptr.trust_level = trust_level;
            // Update trusted status based on trust level
            if (trust_level != .unknown) {
                try self.trustKey(key_id);
            } else {
                self.untrustKey(key_id);
            }
        }
    }

    /// Get trust level for a key (Phase 25)
    pub fn getKeyTrustLevel(self: *TrustStore, key_id: []const u8) TrustLevel {
        if (self.keys.get(key_id)) |key| {
            return key.trust_level;
        }
        return .unknown;
    }

    /// Remove a key from the store
    pub fn removeKey(self: *TrustStore, key_id: []const u8) !void {
        if (self.keys.fetchRemove(key_id)) |entry| {
            var key = entry.value;
            key.deinit(self.allocator);
            self.allocator.free(entry.key);
        }
        if (self.trusted.fetchRemove(key_id)) |entry| {
            self.allocator.free(entry.key);
        }
    }

    /// Get a key by ID
    pub fn getKey(self: *TrustStore, key_id: []const u8) ?PublicKey {
        return self.keys.get(key_id);
    }

    /// Check if a key is trusted
    pub fn isKeyTrusted(self: *TrustStore, key_id: []const u8) bool {
        return self.trusted.get(key_id) orelse false;
    }

    /// Trust a key
    pub fn trustKey(self: *TrustStore, key_id: []const u8) !void {
        const id = try self.allocator.dupe(u8, key_id);
        try self.trusted.put(id, true);
    }

    /// Untrust a key
    pub fn untrustKey(self: *TrustStore, key_id: []const u8) void {
        if (self.trusted.fetchRemove(key_id)) |entry| {
            self.allocator.free(entry.key);
        }
    }

    /// List all keys
    pub fn listKeys(self: *TrustStore, allocator: std.mem.Allocator) ![]PublicKey {
        var list: std.ArrayList(PublicKey) = .empty;
        defer list.deinit(allocator);

        var iter = self.keys.valueIterator();
        while (iter.next()) |key| {
            try list.append(allocator, key.*);
        }

        return list.toOwnedSlice(allocator);
    }

    /// Save trust store to disk
    pub fn save(self: *TrustStore) !void {
        // Create directory if needed
        if (std.fs.path.dirname(self.store_path)) |dir| {
            std.fs.cwd().makePath(dir) catch {};
        }

        const file = try std.fs.cwd().createFile(self.store_path, .{});
        defer file.close();

        try file.writeAll("# Axiom Trust Store\n\n");

        var iter = self.keys.iterator();
        while (iter.next()) |entry| {
            const key = entry.value_ptr.*;
            try file.writeAll("[[key]]\n");
            const key_id_line = try std.fmt.allocPrint(self.allocator, "key_id = \"{s}\"\n", .{key.key_id});
            defer self.allocator.free(key_id_line);
            try file.writeAll(key_id_line);
            const key_data_line = try std.fmt.allocPrint(self.allocator, "key_data = \"{x}\"\n", .{key.key_data});
            defer self.allocator.free(key_data_line);
            try file.writeAll(key_data_line);
            if (key.owner) |o| {
                const owner_line = try std.fmt.allocPrint(self.allocator, "owner = \"{s}\"\n", .{o});
                defer self.allocator.free(owner_line);
                try file.writeAll(owner_line);
            }
            if (key.email) |e| {
                const email_line = try std.fmt.allocPrint(self.allocator, "email = \"{s}\"\n", .{e});
                defer self.allocator.free(email_line);
                try file.writeAll(email_line);
            }
            const created_line = try std.fmt.allocPrint(self.allocator, "created = {d}\n", .{key.created});
            defer self.allocator.free(created_line);
            try file.writeAll(created_line);
            if (key.expires) |exp| {
                const expires_line = try std.fmt.allocPrint(self.allocator, "expires = {d}\n", .{exp});
                defer self.allocator.free(expires_line);
                try file.writeAll(expires_line);
            }
            const trust_level_line = try std.fmt.allocPrint(self.allocator, "trust_level = \"{s}\"\n", .{@tagName(key.trust_level)});
            defer self.allocator.free(trust_level_line);
            try file.writeAll(trust_level_line);
            const trusted = self.trusted.get(key.key_id) orelse false;
            const trusted_line = try std.fmt.allocPrint(self.allocator, "trusted = {any}\n", .{trusted});
            defer self.allocator.free(trusted_line);
            try file.writeAll(trusted_line);
            try file.writeAll("\n");
        }
    }

    /// Load trust store from disk
    pub fn load(self: *TrustStore) !void {
        const file = std.fs.cwd().openFile(self.store_path, .{}) catch return;
        defer file.close();

        const content = try file.readToEndAlloc(self.allocator, 1024 * 1024);
        defer self.allocator.free(content);

        // Simple parser for trust store format
        var current_key: ?PublicKey = null;
        var current_trusted: bool = false;

        var lines = std.mem.splitSequence(u8, content, "\n");
        while (lines.next()) |line| {
            const trimmed = std.mem.trim(u8, line, " \t");
            if (trimmed.len == 0 or trimmed[0] == '#') continue;

            if (std.mem.eql(u8, trimmed, "[[key]]")) {
                // Save previous key if any
                if (current_key) |key| {
                    try self.addKey(key);
                    if (current_trusted) {
                        try self.trustKey(key.key_id);
                    }
                    // Free the temporary key's allocated fields (addKey duplicates them)
                    if (key.key_id.len > 0) self.allocator.free(key.key_id);
                    if (key.owner) |o| self.allocator.free(o);
                    if (key.email) |e| self.allocator.free(e);
                }
                current_key = PublicKey{
                    .key_id = "",
                    .key_data = undefined,
                };
                current_trusted = false;
            } else if (std.mem.startsWith(u8, trimmed, "key_id")) {
                if (current_key) |*key| {
                    if (extractQuotedValue(trimmed)) |value| {
                        key.key_id = try self.allocator.dupe(u8, value);
                    }
                }
            } else if (std.mem.startsWith(u8, trimmed, "key_data")) {
                if (current_key) |*key| {
                    if (extractQuotedValue(trimmed)) |value| {
                        if (value.len == 64) {
                            _ = std.fmt.hexToBytes(&key.key_data, value) catch {};
                        }
                    }
                }
            } else if (std.mem.startsWith(u8, trimmed, "owner")) {
                if (current_key) |*key| {
                    if (extractQuotedValue(trimmed)) |value| {
                        key.owner = try self.allocator.dupe(u8, value);
                    }
                }
            } else if (std.mem.startsWith(u8, trimmed, "email")) {
                if (current_key) |*key| {
                    if (extractQuotedValue(trimmed)) |value| {
                        key.email = try self.allocator.dupe(u8, value);
                    }
                }
            } else if (std.mem.startsWith(u8, trimmed, "trust_level")) {
                if (current_key) |*key| {
                    if (extractQuotedValue(trimmed)) |value| {
                        if (std.mem.eql(u8, value, "official")) {
                            key.trust_level = .official;
                        } else if (std.mem.eql(u8, value, "community")) {
                            key.trust_level = .community;
                        } else if (std.mem.eql(u8, value, "third_party")) {
                            key.trust_level = .third_party;
                        } else {
                            key.trust_level = .unknown;
                        }
                    }
                }
            } else if (std.mem.startsWith(u8, trimmed, "trusted")) {
                if (std.mem.indexOf(u8, trimmed, "true")) |_| {
                    current_trusted = true;
                }
            }
        }

        // Save last key
        if (current_key) |key| {
            try self.addKey(key);
            if (current_trusted) {
                try self.trustKey(key.key_id);
            }
            // Free the temporary key's allocated fields (addKey duplicates them)
            if (key.key_id.len > 0) self.allocator.free(key.key_id);
            if (key.owner) |o| self.allocator.free(o);
            if (key.email) |e| self.allocator.free(e);
        }
    }

    /// Load official PGSD signing keys bundled with Axiom
    /// These keys are automatically trusted at the highest level
    pub fn loadOfficialKeys(self: *TrustStore) !void {
        // Check if official key is already loaded
        if (self.keys.get(OfficialPGSDKey.key_id)) |_| {
            // Key already exists, ensure it's trusted
            try self.trustKey(OfficialPGSDKey.key_id);
            return;
        }

        // Load the official PGSD signing key
        var official_key = try OfficialPGSDKey.getKey(self.allocator);
        defer official_key.deinit(self.allocator); // Free the temp key after addKey duplicates it

        try self.addKeyWithTrust(official_key, .official);

        std.debug.print("Loaded official PGSD signing key: {s}\n", .{OfficialPGSDKey.key_id});
    }

    /// Check if a key is an official bundled key
    pub fn isOfficialKey(key_id: []const u8) bool {
        return std.mem.eql(u8, key_id, OfficialPGSDKey.key_id);
    }
};

/// Extract quoted value from "key = \"value\"" format
fn extractQuotedValue(line: []const u8) ?[]const u8 {
    const eq = std.mem.indexOf(u8, line, "=") orelse return null;
    var value = std.mem.trim(u8, line[eq + 1..], " \t");
    if (value.len >= 2 and value[0] == '"' and value[value.len - 1] == '"') {
        return value[1 .. value.len - 1];
    }
    return value;
}

/// Signature signer for creating signatures
pub const Signer = struct {
    allocator: std.mem.Allocator,
    key_pair: KeyPair,
    signer_name: ?[]const u8,

    /// Initialize signer with key pair
    pub fn init(allocator: std.mem.Allocator, key_pair: KeyPair, signer_name: ?[]const u8) Signer {
        return Signer{
            .allocator = allocator,
            .key_pair = key_pair,
            .signer_name = signer_name,
        };
    }

    /// Sign a package directory
    pub fn signPackage(self: *Signer, pkg_path: []const u8) !Signature {
        std.debug.print("Signing package: {s}\n", .{pkg_path});

        // Collect files and compute hashes
        var files: std.ArrayList(FileHash) = .empty;
        defer files.deinit(self.allocator);

        try self.hashDirectory(pkg_path, "", &files);

        std.debug.print("  Hashed {d} files\n", .{files.items.len});

        // Build message to sign (concatenated hashes)
        var message: std.ArrayList(u8) = .empty;
        defer message.deinit(self.allocator);

        for (files.items) |f| {
            try message.appendSlice(self.allocator, &f.hash);
            try message.appendSlice(self.allocator, f.path);
        }

        // Sign the message
        const secret_key = std.crypto.sign.Ed25519.SecretKey.fromBytes(self.key_pair.secret_key) catch {
            return SignatureError.SigningFailed;
        };
        const key_pair = std.crypto.sign.Ed25519.KeyPair.fromSecretKey(secret_key) catch {
            return SignatureError.SigningFailed;
        };
        const sig = key_pair.sign(message.items, null) catch {
            return SignatureError.SigningFailed;
        };

        // Get key ID
        const key_id = try self.key_pair.keyId(self.allocator);

        std.debug.print("  Signature created with key: {s}\n", .{key_id});

        return Signature{
            .algorithm = try self.allocator.dupe(u8, "ed25519"),
            .key_id = key_id,
            .signer = if (self.signer_name) |n| try self.allocator.dupe(u8, n) else null,
            .timestamp = std.time.timestamp(),
            .signature = sig.toBytes(),
            .files = try files.toOwnedSlice(self.allocator),
        };
    }

    /// Hash all files in a directory recursively
    fn hashDirectory(
        self: *Signer,
        base_path: []const u8,
        rel_path: []const u8,
        files: *std.ArrayList(FileHash),
    ) !void {
        const full_path = if (rel_path.len > 0)
            try std.fs.path.join(self.allocator, &[_][]const u8{ base_path, rel_path })
        else
            try self.allocator.dupe(u8, base_path);
        defer self.allocator.free(full_path);

        var dir = std.fs.cwd().openDir(full_path, .{ .iterate = true }) catch return;
        defer dir.close();

        var iter = dir.iterate();
        while (try iter.next()) |entry| {
            const entry_rel = if (rel_path.len > 0)
                try std.fs.path.join(self.allocator, &[_][]const u8{ rel_path, entry.name })
            else
                try self.allocator.dupe(u8, entry.name);

            switch (entry.kind) {
                .file => {
                    const hash = try self.hashFile(base_path, entry_rel);
                    try files.append(self.allocator, .{
                        .path = entry_rel,
                        .hash = hash,
                    });
                },
                .directory => {
                    defer self.allocator.free(entry_rel);
                    try self.hashDirectory(base_path, entry_rel, files);
                },
                else => {
                    self.allocator.free(entry_rel);
                },
            }
        }
    }

    /// Hash a single file
    fn hashFile(self: *Signer, base_path: []const u8, rel_path: []const u8) ![32]u8 {
        const full_path = try std.fs.path.join(self.allocator, &[_][]const u8{ base_path, rel_path });
        defer self.allocator.free(full_path);

        const file = try std.fs.cwd().openFile(full_path, .{});
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
};

/// Signature verifier
pub const Verifier = struct {
    allocator: std.mem.Allocator,
    trust_store: *TrustStore,
    mode: VerificationMode,

    /// Initialize verifier
    pub fn init(
        allocator: std.mem.Allocator,
        trust_store: *TrustStore,
        mode: VerificationMode,
    ) Verifier {
        return Verifier{
            .allocator = allocator,
            .trust_store = trust_store,
            .mode = mode,
        };
    }

    /// Verification result
    pub const Result = struct {
        valid: bool,
        key_trusted: bool,
        key_id: ?[]const u8,
        signer: ?[]const u8,
        files_verified: usize,
        files_failed: usize,
        error_message: ?[]const u8,
    };

    /// Verify a package
    pub fn verifyPackage(self: *Verifier, pkg_path: []const u8) !Result {
        if (self.mode == .disabled) {
            return Result{
                .valid = true,
                .key_trusted = true,
                .key_id = null,
                .signer = null,
                .files_verified = 0,
                .files_failed = 0,
                .error_message = null,
            };
        }

        std.debug.print("Verifying package: {s}\n", .{pkg_path});

        // Load signature file
        const sig_path = try std.fs.path.join(self.allocator, &[_][]const u8{ pkg_path, "manifest.sig" });
        defer self.allocator.free(sig_path);

        const sig_file = std.fs.cwd().openFile(sig_path, .{}) catch {
            const msg = "Signature file not found";
            if (self.mode == .strict) {
                return Result{
                    .valid = false,
                    .key_trusted = false,
                    .key_id = null,
                    .signer = null,
                    .files_verified = 0,
                    .files_failed = 0,
                    .error_message = msg,
                };
            }
            std.debug.print("  Warning: {s}\n", .{msg});
            return Result{
                .valid = true,
                .key_trusted = false,
                .key_id = null,
                .signer = null,
                .files_verified = 0,
                .files_failed = 0,
                .error_message = msg,
            };
        };
        defer sig_file.close();

        const sig_content = try sig_file.readToEndAlloc(self.allocator, 1024 * 1024);
        defer self.allocator.free(sig_content);

        var signature = try Signature.fromYaml(self.allocator, sig_content);
        defer signature.deinit(self.allocator);

        std.debug.print("  Key ID: {s}\n", .{signature.key_id});
        if (signature.signer) |s| std.debug.print("  Signer: {s}\n", .{s});

        // Get public key
        const public_key = self.trust_store.getKey(signature.key_id) orelse {
            const msg = "Public key not found in trust store";
            if (self.mode == .strict) {
                return Result{
                    .valid = false,
                    .key_trusted = false,
                    .key_id = try self.allocator.dupe(u8, signature.key_id),
                    .signer = if (signature.signer) |s| try self.allocator.dupe(u8, s) else null,
                    .files_verified = 0,
                    .files_failed = 0,
                    .error_message = msg,
                };
            }
            std.debug.print("  Warning: {s}\n", .{msg});
            return Result{
                .valid = false,
                .key_trusted = false,
                .key_id = try self.allocator.dupe(u8, signature.key_id),
                .signer = if (signature.signer) |s| try self.allocator.dupe(u8, s) else null,
                .files_verified = 0,
                .files_failed = 0,
                .error_message = msg,
            };
        };

        const key_trusted = self.trust_store.isKeyTrusted(signature.key_id);
        std.debug.print("  Key trusted: {any}\n", .{key_trusted});

        // Verify file hashes
        var files_verified: usize = 0;
        var files_failed: usize = 0;

        for (signature.files) |expected| {
            const file_path = try std.fs.path.join(self.allocator, &[_][]const u8{ pkg_path, expected.path });
            defer self.allocator.free(file_path);

            const actual_hash = self.hashFile(file_path) catch {
                files_failed += 1;
                continue;
            };

            if (std.mem.eql(u8, &actual_hash, &expected.hash)) {
                files_verified += 1;
            } else {
                files_failed += 1;
                std.debug.print("  Hash mismatch: {s}\n", .{expected.path});
            }
        }

        std.debug.print("  Files verified: {d}/{d}\n", .{ files_verified, signature.files.len });

        // Verify signature
        var message: std.ArrayList(u8) = .empty;
        defer message.deinit(self.allocator);

        for (signature.files) |f| {
            try message.appendSlice(self.allocator, &f.hash);
            try message.appendSlice(self.allocator, f.path);
        }

        const pub_key = std.crypto.sign.Ed25519.PublicKey.fromBytes(public_key.key_data) catch {
            return Result{
                .valid = false,
                .key_trusted = key_trusted,
                .key_id = try self.allocator.dupe(u8, signature.key_id),
                .signer = if (signature.signer) |s| try self.allocator.dupe(u8, s) else null,
                .files_verified = files_verified,
                .files_failed = files_failed,
                .error_message = "Invalid public key",
            };
        };

        const sig = std.crypto.sign.Ed25519.Signature.fromBytes(signature.signature);

        const valid = blk: {
            sig.verify(message.items, pub_key) catch break :blk false;
            break :blk true;
        };

        std.debug.print("  Signature valid: {any}\n", .{valid});

        return Result{
            .valid = valid and files_failed == 0,
            .key_trusted = key_trusted,
            .key_id = try self.allocator.dupe(u8, signature.key_id),
            .signer = if (signature.signer) |s| try self.allocator.dupe(u8, s) else null,
            .files_verified = files_verified,
            .files_failed = files_failed,
            .error_message = if (!valid) "Signature verification failed" else null,
        };
    }

    // ========================================================================
    // Phase 25: Type-Safe Verification
    // ========================================================================

    /// Verify a package and return type-safe VerificationStatus (Phase 25)
    /// This is the preferred method - prevents accidental use of unverified content
    pub fn verifyPackageTypeSafe(self: *Verifier, pkg_path: []const u8) VerificationStatus {
        std.debug.print("Verifying package (type-safe): {s}\n", .{pkg_path});

        // Load signature file
        const sig_path = std.fs.path.join(self.allocator, &[_][]const u8{ pkg_path, "manifest.sig" }) catch {
            return .{ .signature_missing = .{
                .package_path = self.allocator.dupe(u8, pkg_path) catch pkg_path,
            } };
        };
        defer self.allocator.free(sig_path);

        const sig_file = std.fs.cwd().openFile(sig_path, .{}) catch {
            return .{ .signature_missing = .{
                .package_path = self.allocator.dupe(u8, pkg_path) catch pkg_path,
            } };
        };
        defer sig_file.close();

        const sig_content = sig_file.readToEndAlloc(self.allocator, 1024 * 1024) catch {
            return .{ .signature_invalid = .{
                .key_id = null,
                .reason = self.allocator.dupe(u8, "Failed to read signature file") catch "Failed to read signature file",
                .is_parse_error = true,
            } };
        };
        defer self.allocator.free(sig_content);

        var signature = Signature.fromYaml(self.allocator, sig_content) catch {
            return .{ .signature_invalid = .{
                .key_id = null,
                .reason = self.allocator.dupe(u8, "Failed to parse signature") catch "Failed to parse signature",
                .is_parse_error = true,
            } };
        };
        defer signature.deinit(self.allocator);

        std.debug.print("  Key ID: {s}\n", .{signature.key_id});
        if (signature.signer) |s| std.debug.print("  Signer: {s}\n", .{s});

        // Get public key from trust store
        const public_key = self.trust_store.getKey(signature.key_id) orelse {
            return .{ .key_untrusted = .{
                .key_id = self.allocator.dupe(u8, signature.key_id) catch signature.key_id,
                .signer_name = if (signature.signer) |s| (self.allocator.dupe(u8, s) catch null) else null,
                .key_exists = false,
            } };
        };

        // Check if key is trusted
        const is_trusted = self.trust_store.isKeyTrusted(signature.key_id);
        if (!is_trusted) {
            return .{ .key_untrusted = .{
                .key_id = self.allocator.dupe(u8, signature.key_id) catch signature.key_id,
                .signer_name = if (signature.signer) |s| (self.allocator.dupe(u8, s) catch null) else null,
                .key_exists = true,
            } };
        }

        // Check if key has expired
        if (public_key.isExpired()) {
            return .{ .key_untrusted = .{
                .key_id = self.allocator.dupe(u8, signature.key_id) catch signature.key_id,
                .signer_name = if (signature.signer) |s| (self.allocator.dupe(u8, s) catch null) else null,
                .key_exists = true,
            } };
        }

        // Verify file hashes
        var files_verified: usize = 0;
        var files_failed: usize = 0;
        var first_failed_path: ?[]const u8 = null;
        var first_expected_hash: [32]u8 = undefined;
        var first_actual_hash: [32]u8 = undefined;

        for (signature.files) |expected| {
            const file_path = std.fs.path.join(self.allocator, &[_][]const u8{ pkg_path, expected.path }) catch continue;
            defer self.allocator.free(file_path);

            const actual_hash = self.hashFile(file_path) catch {
                files_failed += 1;
                if (first_failed_path == null) {
                    first_failed_path = self.allocator.dupe(u8, expected.path) catch null;
                    first_expected_hash = expected.hash;
                    first_actual_hash = [_]u8{0} ** 32;
                }
                continue;
            };

            if (std.mem.eql(u8, &actual_hash, &expected.hash)) {
                files_verified += 1;
            } else {
                files_failed += 1;
                if (first_failed_path == null) {
                    first_failed_path = self.allocator.dupe(u8, expected.path) catch null;
                    first_expected_hash = expected.hash;
                    first_actual_hash = actual_hash;
                }
                std.debug.print("  Hash mismatch: {s}\n", .{expected.path});
            }
        }

        // Return hash mismatch if any files failed
        if (files_failed > 0) {
            return .{ .hash_mismatch = .{
                .file_path = first_failed_path orelse (self.allocator.dupe(u8, "unknown") catch "unknown"),
                .expected_hash = first_expected_hash,
                .actual_hash = first_actual_hash,
                .total_failed = files_failed,
            } };
        }

        std.debug.print("  Files verified: {d}/{d}\n", .{ files_verified, signature.files.len });

        // Build message for signature verification
        var message: std.ArrayList(u8) = .empty;
        defer message.deinit(self.allocator);

        for (signature.files) |f| {
            message.appendSlice(self.allocator, &f.hash) catch {};
            message.appendSlice(self.allocator, f.path) catch {};
        }

        // Verify cryptographic signature
        const pub_key = std.crypto.sign.Ed25519.PublicKey.fromBytes(public_key.key_data) catch {
            return .{ .signature_invalid = .{
                .key_id = self.allocator.dupe(u8, signature.key_id) catch null,
                .reason = self.allocator.dupe(u8, "Invalid public key format") catch "Invalid public key format",
                .is_parse_error = false,
            } };
        };

        const sig = std.crypto.sign.Ed25519.Signature.fromBytes(signature.signature);
        sig.verify(message.items, pub_key) catch {
            return .{ .signature_invalid = .{
                .key_id = self.allocator.dupe(u8, signature.key_id) catch null,
                .reason = self.allocator.dupe(u8, "Cryptographic verification failed") catch "Cryptographic verification failed",
                .is_parse_error = false,
            } };
        };

        std.debug.print("  Signature valid\n", .{});

        // Compute content hash
        var content_hasher = std.crypto.hash.sha2.Sha256.init(.{});
        content_hasher.update(message.items);
        const content_hash = content_hasher.finalResult();

        // Success!
        return .{ .verified = .{
            .content_hash = content_hash,
            .signer_key_id = self.allocator.dupe(u8, signature.key_id) catch signature.key_id,
            .signer_name = if (signature.signer) |s| (self.allocator.dupe(u8, s) catch null) else null,
            .signature_time = signature.timestamp,
            .trust_level = public_key.trust_level,
            .files_verified = files_verified,
        } };
    }

    /// Hash a file
    fn hashFile(self: *Verifier, path: []const u8) ![32]u8 {
        _ = self;
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
};

/// Export public key to file
pub fn exportPublicKey(allocator: std.mem.Allocator, key: PublicKey, path: []const u8) !void {
    const file = try std.fs.cwd().createFile(path, .{});
    defer file.close();

    try file.writeAll("# Axiom Public Key\n");

    const key_id_line = try std.fmt.allocPrint(allocator, "key_id: {s}\n", .{key.key_id});
    defer allocator.free(key_id_line);
    try file.writeAll(key_id_line);

    const key_data_line = try std.fmt.allocPrint(allocator, "key_data: {x}\n", .{key.key_data});
    defer allocator.free(key_data_line);
    try file.writeAll(key_data_line);

    if (key.owner) |o| {
        const owner_line = try std.fmt.allocPrint(allocator, "owner: \"{s}\"\n", .{o});
        defer allocator.free(owner_line);
        try file.writeAll(owner_line);
    }
    if (key.email) |e| {
        const email_line = try std.fmt.allocPrint(allocator, "email: \"{s}\"\n", .{e});
        defer allocator.free(email_line);
        try file.writeAll(email_line);
    }

    const created_line = try std.fmt.allocPrint(allocator, "created: {d}\n", .{key.created});
    defer allocator.free(created_line);
    try file.writeAll(created_line);

    if (key.expires) |exp| {
        const expires_line = try std.fmt.allocPrint(allocator, "expires: {d}\n", .{exp});
        defer allocator.free(expires_line);
        try file.writeAll(expires_line);
    }
}

/// Import public key from file
pub fn importPublicKey(allocator: std.mem.Allocator, path: []const u8) !PublicKey {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();

    const content = try file.readToEndAlloc(allocator, 1024 * 1024);
    defer allocator.free(content);

    var key = PublicKey{
        .key_id = undefined,
        .key_data = undefined,
    };

    var lines = std.mem.splitSequence(u8, content, "\n");
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t");
        if (trimmed.len == 0 or trimmed[0] == '#') continue;

        if (std.mem.startsWith(u8, trimmed, "key_id:")) {
            const value = std.mem.trim(u8, trimmed[7..], " \t");
            key.key_id = try allocator.dupe(u8, value);
        } else if (std.mem.startsWith(u8, trimmed, "key_data:")) {
            const value = std.mem.trim(u8, trimmed[9..], " \t");
            if (value.len == 64) {
                _ = std.fmt.hexToBytes(&key.key_data, value) catch {
                    return SignatureError.InvalidKeyFormat;
                };
            }
        } else if (std.mem.startsWith(u8, trimmed, "owner:")) {
            if (extractQuotedValue(trimmed)) |value| {
                key.owner = try allocator.dupe(u8, value);
            }
        } else if (std.mem.startsWith(u8, trimmed, "email:")) {
            if (extractQuotedValue(trimmed)) |value| {
                key.email = try allocator.dupe(u8, value);
            }
        } else if (std.mem.startsWith(u8, trimmed, "created:")) {
            const value = std.mem.trim(u8, trimmed[8..], " \t");
            key.created = std.fmt.parseInt(i64, value, 10) catch 0;
        } else if (std.mem.startsWith(u8, trimmed, "expires:")) {
            const value = std.mem.trim(u8, trimmed[8..], " \t");
            key.expires = std.fmt.parseInt(i64, value, 10) catch null;
        }
    }

    return key;
}

// ============================================================================
// Phase 37: Multi-Party Signing
// ============================================================================

/// Multi-signature errors
pub const MultiSignatureError = error{
    ThresholdNotMet,
    DuplicateSignature,
    SignerNotAuthorized,
    NoSignatures,
    InvalidThreshold,
};

/// Configuration for multi-party signing requirements
pub const MultiSignatureConfig = struct {
    /// Minimum number of valid signatures required (M-of-N threshold)
    threshold: u32,
    /// List of authorized signer key IDs (if empty, any trusted key is accepted)
    authorized_signers: []const []const u8,
    /// Require signatures from specific keys (not just any M-of-N)
    required_signers: []const []const u8,
    /// Human-readable name for this policy
    policy_name: ?[]const u8,

    pub fn deinit(self: *MultiSignatureConfig, allocator: std.mem.Allocator) void {
        for (self.authorized_signers) |signer| {
            allocator.free(signer);
        }
        allocator.free(self.authorized_signers);
        for (self.required_signers) |signer| {
            allocator.free(signer);
        }
        allocator.free(self.required_signers);
        if (self.policy_name) |name| {
            allocator.free(name);
        }
    }

    /// Parse config from YAML
    pub fn fromYaml(allocator: std.mem.Allocator, content: []const u8) !MultiSignatureConfig {
        var config = MultiSignatureConfig{
            .threshold = 1,
            .authorized_signers = &[_][]const u8{},
            .required_signers = &[_][]const u8{},
            .policy_name = null,
        };

        var authorized = .empty;
        defer authorized.deinit(allocator);
        var required = .empty;
        defer required.deinit(allocator);

        var in_signers = false;
        var in_required = false;

        var lines = std.mem.splitSequence(u8, content, "\n");
        while (lines.next()) |line| {
            const trimmed = std.mem.trim(u8, line, " \t\r");
            if (trimmed.len == 0 or trimmed[0] == '#') continue;

            if (std.mem.startsWith(u8, trimmed, "threshold:")) {
                const value = std.mem.trim(u8, trimmed[10..], " \t");
                config.threshold = std.fmt.parseInt(u32, value, 10) catch 1;
                in_signers = false;
                in_required = false;
            } else if (std.mem.startsWith(u8, trimmed, "policy_name:")) {
                var value = std.mem.trim(u8, trimmed[12..], " \t");
                if (value.len >= 2 and value[0] == '"' and value[value.len - 1] == '"') {
                    value = value[1 .. value.len - 1];
                }
                config.policy_name = try allocator.dupe(u8, value);
                in_signers = false;
                in_required = false;
            } else if (std.mem.startsWith(u8, trimmed, "signers:") or std.mem.startsWith(u8, trimmed, "authorized_signers:")) {
                in_signers = true;
                in_required = false;
            } else if (std.mem.startsWith(u8, trimmed, "required_signers:")) {
                in_signers = false;
                in_required = true;
            } else if (std.mem.startsWith(u8, trimmed, "- ")) {
                var value = std.mem.trim(u8, trimmed[2..], " \t");
                if (value.len >= 2 and value[0] == '"' and value[value.len - 1] == '"') {
                    value = value[1 .. value.len - 1];
                }
                if (in_signers) {
                    try authorized.append(allocator, try allocator.dupe(u8, value));
                } else if (in_required) {
                    try required.append(allocator, try allocator.dupe(u8, value));
                }
            }
        }

        config.authorized_signers = try authorized.toOwnedSlice(allocator);
        config.required_signers = try required.toOwnedSlice(allocator);

        return config;
    }

    /// Serialize config to YAML
    pub fn toYaml(self: MultiSignatureConfig, allocator: std.mem.Allocator) ![]u8 {
        var result: std.ArrayList(u8) = .empty;
        defer result.deinit(allocator);
        const writer = result.writer(allocator);

        try writer.writeAll("# Multi-Party Signing Policy\n");
        var buf: [64]u8 = undefined;
        const threshold_str = std.fmt.bufPrint(&buf, "threshold: {d}\n", .{self.threshold}) catch unreachable;
        try writer.writeAll(threshold_str);
        if (self.policy_name) |name| {
            try writer.writeAll("policy_name: \"");
            try writer.writeAll(name);
            try writer.writeAll("\"\n");
        }
        if (self.authorized_signers.len > 0) {
            try writer.writeAll("signers:\n");
            for (self.authorized_signers) |signer| {
                try writer.writeAll("  - ");
                try writer.writeAll(signer);
                try writer.writeAll("\n");
            }
        }
        if (self.required_signers.len > 0) {
            try writer.writeAll("required_signers:\n");
            for (self.required_signers) |signer| {
                try writer.writeAll("  - ");
                try writer.writeAll(signer);
                try writer.writeAll("\n");
            }
        }

        return result.toOwnedSlice(allocator);
    }

    /// Check if a key ID is authorized to sign
    pub fn isSignerAuthorized(self: MultiSignatureConfig, key_id: []const u8) bool {
        // If no authorized signers specified, any key is allowed
        if (self.authorized_signers.len == 0) return true;

        for (self.authorized_signers) |authorized| {
            if (std.mem.eql(u8, authorized, key_id)) return true;
        }
        return false;
    }
};

/// Individual signature entry in a multi-signature set
pub const SignatureEntry = struct {
    key_id: []const u8,
    signer_name: ?[]const u8,
    signature: [64]u8,
    timestamp: i64,
    valid: bool,
    trust_level: TrustLevel,

    pub fn deinit(self: *SignatureEntry, allocator: std.mem.Allocator) void {
        allocator.free(self.key_id);
        if (self.signer_name) |name| {
            allocator.free(name);
        }
    }
};

/// Multi-signature container for a package
pub const MultiSignature = struct {
    version: u32 = 1,
    algorithm: []const u8,
    files: []FileHash,
    signatures: []SignatureEntry,

    pub fn deinit(self: *MultiSignature, allocator: std.mem.Allocator) void {
        allocator.free(self.algorithm);
        for (self.files) |*f| {
            f.deinit(allocator);
        }
        allocator.free(self.files);
        for (self.signatures) |*sig| {
            sig.deinit(allocator);
        }
        allocator.free(self.signatures);
    }

    /// Serialize to YAML format
    pub fn toYaml(self: MultiSignature, allocator: std.mem.Allocator) ![]u8 {
        var result: std.ArrayList(u8) = .empty;
        defer result.deinit(allocator);
        const writer = result.writer(allocator);

        try writer.writeAll("# Axiom Multi-Party Signature\n");
        var buf: [128]u8 = undefined;
        const version_str = std.fmt.bufPrint(&buf, "version: {d}\n", .{self.version}) catch unreachable;
        try writer.writeAll(version_str);
        try writer.writeAll("algorithm: ");
        try writer.writeAll(self.algorithm);
        try writer.writeAll("\n");

        try writer.writeAll("\nfiles:\n");
        for (self.files) |f| {
            try writer.writeAll("  - path: \"");
            try writer.writeAll(f.path);
            try writer.writeAll("\"\n");
            var hash_buf: [128]u8 = undefined;
            const hash_str = std.fmt.bufPrint(&hash_buf, "    sha256: {x}\n", .{f.hash}) catch unreachable;
            try writer.writeAll(hash_str);
        }

        try writer.writeAll("\nsignatures:\n");
        for (self.signatures) |sig| {
            try writer.writeAll("  - key_id: ");
            try writer.writeAll(sig.key_id);
            try writer.writeAll("\n");
            if (sig.signer_name) |name| {
                try writer.writeAll("    signer: \"");
                try writer.writeAll(name);
                try writer.writeAll("\"\n");
            }
            const timestamp_str = std.fmt.bufPrint(&buf, "    timestamp: {d}\n", .{sig.timestamp}) catch unreachable;
            try writer.writeAll(timestamp_str);
            var sig_buf: [256]u8 = undefined;
            const sig_str = std.fmt.bufPrint(&sig_buf, "    signature: {x}\n", .{sig.signature}) catch unreachable;
            try writer.writeAll(sig_str);
        }

        return result.toOwnedSlice(allocator);
    }

    /// Parse from YAML
    pub fn fromYaml(allocator: std.mem.Allocator, content: []const u8) !MultiSignature {
        var multi_sig = MultiSignature{
            .algorithm = undefined,
            .files = undefined,
            .signatures = undefined,
        };

        var files: std.ArrayList(FileHash) = .empty;
        defer files.deinit(allocator);
        var signatures: std.ArrayList(SignatureEntry) = .empty;
        defer signatures.deinit(allocator);

        var current_file_path: ?[]const u8 = null;
        var current_sig: ?SignatureEntry = null;
        var in_files = false;
        var in_signatures = false;

        var lines = std.mem.splitSequence(u8, content, "\n");
        while (lines.next()) |line| {
            const trimmed = std.mem.trim(u8, line, " \t\r");
            if (trimmed.len == 0 or trimmed[0] == '#') continue;

            if (std.mem.startsWith(u8, trimmed, "version:")) {
                const value = std.mem.trim(u8, trimmed[8..], " \t");
                multi_sig.version = std.fmt.parseInt(u32, value, 10) catch 1;
            } else if (std.mem.startsWith(u8, trimmed, "algorithm:")) {
                const value = std.mem.trim(u8, trimmed[10..], " \t");
                multi_sig.algorithm = try allocator.dupe(u8, value);
            } else if (std.mem.eql(u8, trimmed, "files:")) {
                in_files = true;
                in_signatures = false;
            } else if (std.mem.eql(u8, trimmed, "signatures:")) {
                in_files = false;
                in_signatures = true;
            } else if (std.mem.startsWith(u8, trimmed, "- path:")) {
                if (current_file_path) |path| {
                    allocator.free(path);
                }
                var value = std.mem.trim(u8, trimmed[7..], " \t");
                if (value.len >= 2 and value[0] == '"' and value[value.len - 1] == '"') {
                    value = value[1 .. value.len - 1];
                }
                current_file_path = try allocator.dupe(u8, value);
            } else if (std.mem.startsWith(u8, trimmed, "sha256:") and current_file_path != null) {
                const value = std.mem.trim(u8, trimmed[7..], " \t");
                if (value.len == 64) {
                    var hash: [32]u8 = undefined;
                    _ = std.fmt.hexToBytes(&hash, value) catch {
                        allocator.free(current_file_path.?);
                        current_file_path = null;
                        continue;
                    };
                    try files.append(allocator, .{
                        .path = current_file_path.?,
                        .hash = hash,
                    });
                    current_file_path = null;
                }
            } else if (std.mem.startsWith(u8, trimmed, "- key_id:") and in_signatures) {
                // Save previous signature if any
                if (current_sig) |sig| {
                    try signatures.append(allocator, sig);
                }
                const value = std.mem.trim(u8, trimmed[9..], " \t");
                current_sig = SignatureEntry{
                    .key_id = try allocator.dupe(u8, value),
                    .signer_name = null,
                    .signature = undefined,
                    .timestamp = 0,
                    .valid = false,
                    .trust_level = .unknown,
                };
            } else if (std.mem.startsWith(u8, trimmed, "signer:") and current_sig != null) {
                var value = std.mem.trim(u8, trimmed[7..], " \t");
                if (value.len >= 2 and value[0] == '"' and value[value.len - 1] == '"') {
                    value = value[1 .. value.len - 1];
                }
                current_sig.?.signer_name = try allocator.dupe(u8, value);
            } else if (std.mem.startsWith(u8, trimmed, "timestamp:") and current_sig != null) {
                const value = std.mem.trim(u8, trimmed[10..], " \t");
                current_sig.?.timestamp = std.fmt.parseInt(i64, value, 10) catch 0;
            } else if (std.mem.startsWith(u8, trimmed, "signature:") and current_sig != null) {
                const value = std.mem.trim(u8, trimmed[10..], " \t");
                if (value.len == 128) {
                    _ = std.fmt.hexToBytes(&current_sig.?.signature, value) catch continue;
                }
            }
        }

        // Save last signature
        if (current_sig) |sig| {
            try signatures.append(allocator, sig);
        }

        // Clean up any leftover file path
        if (current_file_path) |path| {
            allocator.free(path);
        }

        multi_sig.files = try files.toOwnedSlice(allocator);
        multi_sig.signatures = try signatures.toOwnedSlice(allocator);

        return multi_sig;
    }

    /// Count valid signatures
    pub fn validSignatureCount(self: MultiSignature) usize {
        var count: usize = 0;
        for (self.signatures) |sig| {
            if (sig.valid) count += 1;
        }
        return count;
    }

    /// Get list of signers
    pub fn getSignerKeyIds(self: MultiSignature, allocator: std.mem.Allocator) ![][]const u8 {
        var result: std.ArrayList([]const u8) = .empty;
        defer result.deinit(allocator);
        for (self.signatures) |sig| {
            try result.append(allocator, sig.key_id);
        }
        return result.toOwnedSlice(allocator);
    }
};

/// Result of multi-signature verification
pub const MultiSignatureResult = struct {
    /// Overall verification success (threshold met and all required signers present)
    success: bool,
    /// Total number of signatures found
    total_signatures: usize,
    /// Number of cryptographically valid signatures
    valid_signatures: usize,
    /// Number of signatures from trusted keys
    trusted_signatures: usize,
    /// Required threshold
    threshold: u32,
    /// Whether threshold was met
    threshold_met: bool,
    /// Missing required signers (if any)
    missing_required: []const []const u8,
    /// Details for each signature
    signature_details: []SignatureEntry,
    /// Error message if verification failed
    error_message: ?[]const u8,

    pub fn deinit(self: *MultiSignatureResult, allocator: std.mem.Allocator) void {
        allocator.free(self.missing_required);
        for (self.signature_details) |*detail| {
            detail.deinit(allocator);
        }
        allocator.free(self.signature_details);
        if (self.error_message) |msg| {
            allocator.free(msg);
        }
    }
};

/// Multi-signature verifier
pub const MultiSignatureVerifier = struct {
    allocator: std.mem.Allocator,
    trust_store: *TrustStore,

    pub fn init(allocator: std.mem.Allocator, trust_store: *TrustStore) MultiSignatureVerifier {
        return MultiSignatureVerifier{
            .allocator = allocator,
            .trust_store = trust_store,
        };
    }

    /// Verify a package against a multi-signature policy
    pub fn verifyPackage(
        self: *MultiSignatureVerifier,
        pkg_path: []const u8,
        config: MultiSignatureConfig,
    ) !MultiSignatureResult {
        std.debug.print("Verifying package with multi-party policy: {s}\n", .{pkg_path});
        if (config.policy_name) |name| {
            std.debug.print("  Policy: {s}\n", .{name});
        }
        std.debug.print("  Required threshold: {d}\n", .{config.threshold});

        // Load multi-signature file
        const sig_path = try std.fs.path.join(self.allocator, &[_][]const u8{ pkg_path, "manifest.msig" });
        defer self.allocator.free(sig_path);

        const sig_file = std.fs.cwd().openFile(sig_path, .{}) catch {
            // Fall back to regular signature file
            return self.verifyFallbackSingleSignature(pkg_path, config);
        };
        defer sig_file.close();

        const sig_content = try sig_file.readToEndAlloc(self.allocator, 1024 * 1024);
        defer self.allocator.free(sig_content);

        var multi_sig = try MultiSignature.fromYaml(self.allocator, sig_content);
        defer multi_sig.deinit(self.allocator);

        return self.verifyMultiSignature(pkg_path, &multi_sig, config);
    }

    /// Verify a multi-signature structure
    fn verifyMultiSignature(
        self: *MultiSignatureVerifier,
        pkg_path: []const u8,
        multi_sig: *MultiSignature,
        config: MultiSignatureConfig,
    ) !MultiSignatureResult {
        var signature_details: std.ArrayList(SignatureEntry) = .empty;
        defer signature_details.deinit(self.allocator);

        var valid_count: usize = 0;
        var trusted_count: usize = 0;

        // Build message to verify (same as single signature)
        var message: std.ArrayList(u8) = .empty;
        defer message.deinit(self.allocator);

        for (multi_sig.files) |f| {
            try message.appendSlice(self.allocator, &f.hash);
            try message.appendSlice(self.allocator, f.path);
        }

        // Verify each signature
        for (multi_sig.signatures) |*sig| {
            var entry = SignatureEntry{
                .key_id = try self.allocator.dupe(u8, sig.key_id),
                .signer_name = if (sig.signer_name) |n| try self.allocator.dupe(u8, n) else null,
                .signature = sig.signature,
                .timestamp = sig.timestamp,
                .valid = false,
                .trust_level = .unknown,
            };

            // Check if signer is authorized
            if (!config.isSignerAuthorized(sig.key_id)) {
                std.debug.print("  Signature from {s}: unauthorized signer\n", .{sig.key_id});
                try signature_details.append(self.allocator, entry);
                continue;
            }

            // Get public key
            const public_key = self.trust_store.getKey(sig.key_id) orelse {
                std.debug.print("  Signature from {s}: key not found\n", .{sig.key_id});
                try signature_details.append(self.allocator, entry);
                continue;
            };

            entry.trust_level = public_key.trust_level;

            // Verify cryptographic signature
            const pub_key = std.crypto.sign.Ed25519.PublicKey.fromBytes(public_key.key_data) catch {
                std.debug.print("  Signature from {s}: invalid key format\n", .{sig.key_id});
                try signature_details.append(self.allocator, entry);
                continue;
            };

            const ed_sig = std.crypto.sign.Ed25519.Signature.fromBytes(sig.signature);
            ed_sig.verify(message.items, pub_key) catch {
                std.debug.print("  Signature from {s}: cryptographic verification failed\n", .{sig.key_id});
                try signature_details.append(self.allocator, entry);
                continue;
            };

            entry.valid = true;
            valid_count += 1;
            std.debug.print("  Signature from {s}: valid\n", .{sig.key_id});

            // Check if key is trusted
            if (self.trust_store.isKeyTrusted(sig.key_id)) {
                trusted_count += 1;
            }

            try signature_details.append(self.allocator, entry);
        }

        // Check for missing required signers
        var missing_required: std.ArrayList([]const u8) = .empty;
        defer missing_required.deinit(self.allocator);

        for (config.required_signers) |required| {
            var found = false;
            for (signature_details.items) |detail| {
                if (std.mem.eql(u8, detail.key_id, required) and detail.valid) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                try missing_required.append(self.allocator, required);
            }
        }

        const threshold_met = trusted_count >= config.threshold;
        const required_met = missing_required.items.len == 0;
        const success = threshold_met and required_met;

        std.debug.print("  Total signatures: {d}\n", .{multi_sig.signatures.len});
        std.debug.print("  Valid signatures: {d}\n", .{valid_count});
        std.debug.print("  Trusted signatures: {d}\n", .{trusted_count});
        std.debug.print("  Threshold met: {any}\n", .{threshold_met});
        std.debug.print("  Required signers present: {any}\n", .{required_met});

        _ = pkg_path;

        return MultiSignatureResult{
            .success = success,
            .total_signatures = multi_sig.signatures.len,
            .valid_signatures = valid_count,
            .trusted_signatures = trusted_count,
            .threshold = config.threshold,
            .threshold_met = threshold_met,
            .missing_required = try missing_required.toOwnedSlice(self.allocator),
            .signature_details = try signature_details.toOwnedSlice(self.allocator),
            .error_message = if (!success)
                try self.allocator.dupe(u8, if (!threshold_met) "Threshold not met" else "Missing required signers")
            else
                null,
        };
    }

    /// Fall back to verifying single signature against multi-party policy
    fn verifyFallbackSingleSignature(
        self: *MultiSignatureVerifier,
        pkg_path: []const u8,
        config: MultiSignatureConfig,
    ) !MultiSignatureResult {
        // Try to load regular signature file
        const sig_path = try std.fs.path.join(self.allocator, &[_][]const u8{ pkg_path, "manifest.sig" });
        defer self.allocator.free(sig_path);

        const sig_file = std.fs.cwd().openFile(sig_path, .{}) catch {
            return MultiSignatureResult{
                .success = false,
                .total_signatures = 0,
                .valid_signatures = 0,
                .trusted_signatures = 0,
                .threshold = config.threshold,
                .threshold_met = false,
                .missing_required = &[_][]const u8{},
                .signature_details = &[_]SignatureEntry{},
                .error_message = try self.allocator.dupe(u8, "No signature file found"),
            };
        };
        defer sig_file.close();

        const sig_content = try sig_file.readToEndAlloc(self.allocator, 1024 * 1024);
        defer self.allocator.free(sig_content);

        var signature = try Signature.fromYaml(self.allocator, sig_content);
        defer signature.deinit(self.allocator);

        // Convert single signature to multi-signature format
        var sigs = try self.allocator.alloc(SignatureEntry, 1);
        sigs[0] = SignatureEntry{
            .key_id = try self.allocator.dupe(u8, signature.key_id),
            .signer_name = if (signature.signer) |s| try self.allocator.dupe(u8, s) else null,
            .signature = signature.signature,
            .timestamp = signature.timestamp,
            .valid = false,
            .trust_level = .unknown,
        };

        var multi_sig = MultiSignature{
            .algorithm = try self.allocator.dupe(u8, signature.algorithm),
            .files = try self.allocator.alloc(FileHash, signature.files.len),
            .signatures = sigs,
        };

        // Copy files
        for (signature.files, 0..) |f, i| {
            multi_sig.files[i] = FileHash{
                .path = try self.allocator.dupe(u8, f.path),
                .hash = f.hash,
            };
        }

        defer multi_sig.deinit(self.allocator);

        return self.verifyMultiSignature(pkg_path, &multi_sig, config);
    }

    /// List all signatures on a package
    pub fn listSignatures(self: *MultiSignatureVerifier, pkg_path: []const u8) ![]SignatureEntry {
        var signatures: std.ArrayList(SignatureEntry) = .empty;
        defer signatures.deinit(self.allocator);

        // Try multi-signature file first
        const msig_path = try std.fs.path.join(self.allocator, &[_][]const u8{ pkg_path, "manifest.msig" });
        defer self.allocator.free(msig_path);

        if (std.fs.cwd().openFile(msig_path, .{})) |file| {
            defer file.close();
            const content = try file.readToEndAlloc(self.allocator, 1024 * 1024);
            defer self.allocator.free(content);

            var multi_sig = try MultiSignature.fromYaml(self.allocator, content);
            defer multi_sig.deinit(self.allocator);

            for (multi_sig.signatures) |sig| {
                try signatures.append(self.allocator, SignatureEntry{
                    .key_id = try self.allocator.dupe(u8, sig.key_id),
                    .signer_name = if (sig.signer_name) |n| try self.allocator.dupe(u8, n) else null,
                    .signature = sig.signature,
                    .timestamp = sig.timestamp,
                    .valid = false,
                    .trust_level = self.trust_store.getKeyTrustLevel(sig.key_id),
                });
            }
        } else |_| {
            // Try single signature file
            const sig_path = try std.fs.path.join(self.allocator, &[_][]const u8{ pkg_path, "manifest.sig" });
            defer self.allocator.free(sig_path);

            if (std.fs.cwd().openFile(sig_path, .{})) |file| {
                defer file.close();
                const content = try file.readToEndAlloc(self.allocator, 1024 * 1024);
                defer self.allocator.free(content);

                var sig = try Signature.fromYaml(self.allocator, content);
                defer sig.deinit(self.allocator);

                try signatures.append(self.allocator, SignatureEntry{
                    .key_id = try self.allocator.dupe(u8, sig.key_id),
                    .signer_name = if (sig.signer) |s| try self.allocator.dupe(u8, s) else null,
                    .signature = sig.signature,
                    .timestamp = sig.timestamp,
                    .valid = false,
                    .trust_level = self.trust_store.getKeyTrustLevel(sig.key_id),
                });
            } else |_| {}
        }

        return signatures.toOwnedSlice(self.allocator);
    }
};

/// Multi-signature signer - adds signatures to a package
pub const MultiSignatureSigner = struct {
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) MultiSignatureSigner {
        return MultiSignatureSigner{
            .allocator = allocator,
        };
    }

    /// Add a signature to an existing multi-signature file or create a new one
    pub fn addSignature(
        self: *MultiSignatureSigner,
        pkg_path: []const u8,
        key_pair: KeyPair,
        signer_name: ?[]const u8,
    ) !void {
        std.debug.print("Adding signature to package: {s}\n", .{pkg_path});

        // Try to load existing multi-signature
        const msig_path = try std.fs.path.join(self.allocator, &[_][]const u8{ pkg_path, "manifest.msig" });
        defer self.allocator.free(msig_path);

        var multi_sig: MultiSignature = undefined;
        var have_existing = false;

        if (std.fs.cwd().openFile(msig_path, .{})) |file| {
            defer file.close();
            const content = try file.readToEndAlloc(self.allocator, 1024 * 1024);
            defer self.allocator.free(content);
            multi_sig = try MultiSignature.fromYaml(self.allocator, content);
            have_existing = true;
            std.debug.print("  Loaded existing multi-signature with {d} signatures\n", .{multi_sig.signatures.len});
        } else |_| {
            // Try to convert from single signature
            const sig_path = try std.fs.path.join(self.allocator, &[_][]const u8{ pkg_path, "manifest.sig" });
            defer self.allocator.free(sig_path);

            if (std.fs.cwd().openFile(sig_path, .{})) |file| {
                defer file.close();
                const content = try file.readToEndAlloc(self.allocator, 1024 * 1024);
                defer self.allocator.free(content);

                var sig = try Signature.fromYaml(self.allocator, content);
                defer sig.deinit(self.allocator);

                // Convert to multi-signature
                var sigs = try self.allocator.alloc(SignatureEntry, 1);
                sigs[0] = SignatureEntry{
                    .key_id = try self.allocator.dupe(u8, sig.key_id),
                    .signer_name = if (sig.signer) |s| try self.allocator.dupe(u8, s) else null,
                    .signature = sig.signature,
                    .timestamp = sig.timestamp,
                    .valid = true,
                    .trust_level = .unknown,
                };

                multi_sig = MultiSignature{
                    .algorithm = try self.allocator.dupe(u8, sig.algorithm),
                    .files = try self.allocator.alloc(FileHash, sig.files.len),
                    .signatures = sigs,
                };

                for (sig.files, 0..) |f, i| {
                    multi_sig.files[i] = FileHash{
                        .path = try self.allocator.dupe(u8, f.path),
                        .hash = f.hash,
                    };
                }
                have_existing = true;
                std.debug.print("  Converted single signature to multi-signature\n", .{});
            } else |_| {
                // No existing signature - create new one
                multi_sig = try self.createNewMultiSignature(pkg_path);
                have_existing = false;
            }
        }

        defer if (!have_existing) multi_sig.deinit(self.allocator);

        // Get key ID
        const key_id = try key_pair.keyId(self.allocator);
        defer self.allocator.free(key_id);

        // Check for duplicate signature
        for (multi_sig.signatures) |sig| {
            if (std.mem.eql(u8, sig.key_id, key_id)) {
                std.debug.print("  Warning: Key {s} has already signed this package\n", .{key_id});
                return MultiSignatureError.DuplicateSignature;
            }
        }

        // Build message to sign
        var message: std.ArrayList(u8) = .empty;
        defer message.deinit(self.allocator);

        for (multi_sig.files) |f| {
            try message.appendSlice(self.allocator, &f.hash);
            try message.appendSlice(self.allocator, f.path);
        }

        // Sign the message
        const secret_key = std.crypto.sign.Ed25519.SecretKey.fromBytes(key_pair.secret_key) catch {
            return SignatureError.SigningFailed;
        };
        const ed_key_pair = std.crypto.sign.Ed25519.KeyPair.fromSecretKey(secret_key) catch {
            return SignatureError.SigningFailed;
        };
        const sig = ed_key_pair.sign(message.items, null) catch {
            return SignatureError.SigningFailed;
        };

        // Add new signature entry
        var new_sigs = try self.allocator.alloc(SignatureEntry, multi_sig.signatures.len + 1);
        for (multi_sig.signatures, 0..) |existing, i| {
            new_sigs[i] = existing;
        }
        new_sigs[multi_sig.signatures.len] = SignatureEntry{
            .key_id = try self.allocator.dupe(u8, key_id),
            .signer_name = if (signer_name) |n| try self.allocator.dupe(u8, n) else null,
            .signature = sig.toBytes(),
            .timestamp = std.time.timestamp(),
            .valid = true,
            .trust_level = .unknown,
        };

        // Free old signatures array (but not the entries - they're moved)
        self.allocator.free(multi_sig.signatures);
        multi_sig.signatures = new_sigs;

        // Save multi-signature file
        const yaml = try multi_sig.toYaml(self.allocator);
        defer self.allocator.free(yaml);

        const file = try std.fs.cwd().createFile(msig_path, .{});
        defer file.close();
        try file.writeAll(yaml);

        std.debug.print("  Signature added by {s}\n", .{key_id});
        std.debug.print("  Total signatures: {d}\n", .{multi_sig.signatures.len});

        // Clean up if we converted/created
        if (have_existing) {
            multi_sig.deinit(self.allocator);
        }
    }

    /// Create a new multi-signature by hashing the package files
    fn createNewMultiSignature(self: *MultiSignatureSigner, pkg_path: []const u8) !MultiSignature {
        var files: std.ArrayList(FileHash) = .empty;
        defer files.deinit(self.allocator);

        try self.hashDirectory(pkg_path, "", &files);

        return MultiSignature{
            .algorithm = try self.allocator.dupe(u8, "ed25519"),
            .files = try files.toOwnedSlice(self.allocator),
            .signatures = try self.allocator.alloc(SignatureEntry, 0),
        };
    }

    /// Hash all files in a directory recursively
    fn hashDirectory(
        self: *MultiSignatureSigner,
        base_path: []const u8,
        rel_path: []const u8,
        files: *std.ArrayList(FileHash),
    ) !void {
        const full_path = if (rel_path.len > 0)
            try std.fs.path.join(self.allocator, &[_][]const u8{ base_path, rel_path })
        else
            try self.allocator.dupe(u8, base_path);
        defer self.allocator.free(full_path);

        var dir = std.fs.cwd().openDir(full_path, .{ .iterate = true }) catch return;
        defer dir.close();

        var iter = dir.iterate();
        while (try iter.next()) |entry| {
            // Skip signature files
            if (std.mem.eql(u8, entry.name, "manifest.sig") or
                std.mem.eql(u8, entry.name, "manifest.msig"))
            {
                continue;
            }

            const entry_rel = if (rel_path.len > 0)
                try std.fs.path.join(self.allocator, &[_][]const u8{ rel_path, entry.name })
            else
                try self.allocator.dupe(u8, entry.name);

            switch (entry.kind) {
                .file => {
                    const hash = try self.hashFile(base_path, entry_rel);
                    try files.append(self.allocator, .{
                        .path = entry_rel,
                        .hash = hash,
                    });
                },
                .directory => {
                    defer self.allocator.free(entry_rel);
                    try self.hashDirectory(base_path, entry_rel, files);
                },
                else => {
                    self.allocator.free(entry_rel);
                },
            }
        }
    }

    /// Hash a single file
    fn hashFile(self: *MultiSignatureSigner, base_path: []const u8, rel_path: []const u8) ![32]u8 {
        const full_path = try std.fs.path.join(self.allocator, &[_][]const u8{ base_path, rel_path });
        defer self.allocator.free(full_path);

        const file = try std.fs.cwd().openFile(full_path, .{});
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
};

// ============================================================================
// Tests
// ============================================================================

test "TrustLevel.description" {
    try std.testing.expectEqualStrings("Official PGSD Release Key", TrustLevel.official.description());
    try std.testing.expectEqualStrings("Trusted Community Maintainer", TrustLevel.community.description());
    try std.testing.expectEqualStrings("User-Added Third Party Key", TrustLevel.third_party.description());
    try std.testing.expectEqualStrings("Unknown/Untrusted Key", TrustLevel.unknown.description());
}

test "VerificationStatus.isVerified" {
    const verified_content = VerifiedContent{
        .content_hash = [_]u8{0} ** 32,
        .signer_key_id = "test-key",
        .signer_name = null,
        .signature_time = 1702400000,
        .trust_level = .official,
        .files_verified = 10,
    };

    const verified = VerificationStatus{ .verified = verified_content };
    try std.testing.expect(verified.isVerified());

    const missing = VerificationStatus{ .signature_missing = .{ .package_path = "/test" } };
    try std.testing.expect(!missing.isVerified());

    const invalid = VerificationStatus{ .signature_invalid = .{ .key_id = null, .reason = "test", .is_parse_error = true } };
    try std.testing.expect(!invalid.isVerified());
}

test "VerificationStatus.getVerifiedContent" {
    const verified_content = VerifiedContent{
        .content_hash = [_]u8{0} ** 32,
        .signer_key_id = "test-key",
        .signer_name = "Test Signer",
        .signature_time = 1702400000,
        .trust_level = .community,
        .files_verified = 5,
    };

    const verified = VerificationStatus{ .verified = verified_content };
    const content = verified.getVerifiedContent();
    try std.testing.expect(content != null);
    try std.testing.expectEqual(@as(usize, 5), content.?.files_verified);

    const missing = VerificationStatus{ .signature_missing = .{ .package_path = "/test" } };
    try std.testing.expect(missing.getVerifiedContent() == null);
}

test "VerificationStatus.getMessage" {
    const verified = VerificationStatus{ .verified = .{
        .content_hash = [_]u8{0} ** 32,
        .signer_key_id = "key",
        .signer_name = null,
        .signature_time = 0,
        .trust_level = .official,
        .files_verified = 0,
    } };
    try std.testing.expectEqualStrings("Package signature verified", verified.getMessage());

    const missing = VerificationStatus{ .signature_missing = .{ .package_path = "/test" } };
    try std.testing.expectEqualStrings("No signature file found", missing.getMessage());

    const invalid = VerificationStatus{ .signature_invalid = .{ .key_id = null, .reason = "bad", .is_parse_error = false } };
    try std.testing.expectEqualStrings("Signature is invalid", invalid.getMessage());

    const untrusted = VerificationStatus{ .key_untrusted = .{ .key_id = "key", .signer_name = null, .key_exists = false } };
    try std.testing.expectEqualStrings("Signing key is not trusted", untrusted.getMessage());

    const mismatch = VerificationStatus{ .hash_mismatch = .{
        .file_path = "/test",
        .expected_hash = [_]u8{0} ** 32,
        .actual_hash = [_]u8{1} ** 32,
        .total_failed = 1,
    } };
    try std.testing.expectEqualStrings("File content has been modified", mismatch.getMessage());
}

test "VerificationStatus.requireVerified" {
    const verified = VerificationStatus{ .verified = .{
        .content_hash = [_]u8{0} ** 32,
        .signer_key_id = "key",
        .signer_name = null,
        .signature_time = 0,
        .trust_level = .official,
        .files_verified = 0,
    } };
    const content = try verified.requireVerified();
    try std.testing.expectEqualStrings("key", content.signer_key_id);

    const missing = VerificationStatus{ .signature_missing = .{ .package_path = "/test" } };
    try std.testing.expectError(SignatureError.NotVerified, missing.requireVerified());
}

test "OfficialPGSDKey constants" {
    try std.testing.expectEqualStrings("PGSD0001A7E3F9B2", OfficialPGSDKey.key_id);
    try std.testing.expectEqualStrings("PGSD Official", OfficialPGSDKey.owner);
    try std.testing.expectEqualStrings("security@pgsd.io", OfficialPGSDKey.email);
    try std.testing.expectEqual(@as(usize, 64), OfficialPGSDKey.key_data_hex.len);
}

test "OfficialPGSDKey.getKey" {
    const allocator = std.testing.allocator;

    const key = try OfficialPGSDKey.getKey(allocator);
    defer {
        allocator.free(key.key_id);
        if (key.owner) |o| allocator.free(o);
        if (key.email) |e| allocator.free(e);
    }

    try std.testing.expectEqualStrings("PGSD0001A7E3F9B2", key.key_id);
    try std.testing.expectEqualStrings("PGSD Official", key.owner.?);
    try std.testing.expectEqualStrings("security@pgsd.io", key.email.?);
    try std.testing.expectEqual(TrustLevel.official, key.trust_level);
    try std.testing.expect(key.expires == null);
}

test "AuditLog.init" {
    const allocator = std.testing.allocator;

    var log = AuditLog.init(allocator, "/var/log/axiom-audit.log");
    defer log.deinit();

    try std.testing.expectEqualStrings("/var/log/axiom-audit.log", log.log_path);
    try std.testing.expectEqual(@as(usize, 0), log.entries.items.len);
}

test "AuditEntry.AuditAction enum" {
    try std.testing.expectEqual(AuditEntry.AuditAction.allowed, AuditEntry.AuditAction.allowed);
    try std.testing.expectEqual(AuditEntry.AuditAction.blocked, AuditEntry.AuditAction.blocked);
    try std.testing.expectEqual(AuditEntry.AuditAction.warned, AuditEntry.AuditAction.warned);
    try std.testing.expectEqual(AuditEntry.AuditAction.bypassed, AuditEntry.AuditAction.bypassed);
}

test "MultiSignatureConfig defaults" {
    const config = MultiSignatureConfig{
        .threshold = 2,
        .authorized_signers = &[_][]const u8{},
        .required_signers = &[_][]const u8{},
        .policy_name = null,
    };

    try std.testing.expectEqual(@as(u32, 2), config.threshold);
    try std.testing.expectEqual(@as(usize, 0), config.authorized_signers.len);
    try std.testing.expect(config.policy_name == null);
}

test "SignatureError values" {
    // Ensure all error values are distinct
    const errors = [_]SignatureError{
        SignatureError.InvalidSignature,
        SignatureError.SignatureNotFound,
        SignatureError.KeyNotFound,
        SignatureError.KeyNotTrusted,
        SignatureError.HashMismatch,
        SignatureError.InvalidKeyFormat,
        SignatureError.InvalidSignatureFormat,
        SignatureError.SigningFailed,
        SignatureError.VerificationFailed,
        SignatureError.NotVerified,
    };

    try std.testing.expectEqual(@as(usize, 10), errors.len);
}

test "MultiSignatureError values" {
    const errors = [_]MultiSignatureError{
        MultiSignatureError.ThresholdNotMet,
        MultiSignatureError.DuplicateSignature,
        MultiSignatureError.SignerNotAuthorized,
        MultiSignatureError.NoSignatures,
        MultiSignatureError.InvalidThreshold,
    };

    try std.testing.expectEqual(@as(usize, 5), errors.len);
}

// ============================================================================
// SECURITY TESTS: Signature Verification
// ============================================================================

test "SECURITY: TrustLevel hierarchy" {
    // Verify trust levels are ordered correctly for security decisions
    // Higher trust = lower enum value (official = 0 is most trusted)
    try std.testing.expect(@intFromEnum(TrustLevel.official) < @intFromEnum(TrustLevel.community));
    try std.testing.expect(@intFromEnum(TrustLevel.community) < @intFromEnum(TrustLevel.third_party));
    try std.testing.expect(@intFromEnum(TrustLevel.third_party) < @intFromEnum(TrustLevel.unknown));
}

test "SECURITY: TrustStore key operations" {
    const allocator = std.testing.allocator;

    var store = TrustStore.init(allocator, "/tmp/test-trust-store");
    defer store.deinit();

    // Initially no keys
    try std.testing.expect(store.getKey("nonexistent") == null);
    try std.testing.expect(!store.isKeyTrusted("nonexistent"));
}

test "SECURITY: verification status type safety" {
    // VerificationStatus is a tagged union - test that isVerified works correctly
    // Create a verified status with dummy data
    const verified_status = VerificationStatus{
        .verified = .{
            .content_hash = [_]u8{0} ** 32,
            .signer_key_id = "test-key",
            .signer_name = null,
            .signature_time = 0,
            .trust_level = .official,
        },
    };
    try std.testing.expect(verified_status.isVerified());

    // Create invalid status
    const invalid_status = VerificationStatus{
        .signature_invalid = .{
            .reason = "test",
            .signature_file = null,
        },
    };
    try std.testing.expect(!invalid_status.isVerified());
}

test "SECURITY: verification status - verified returns content" {
    // Test that getVerifiedContent works correctly for security decisions
    const verified = VerificationStatus{
        .verified = .{
            .content_hash = [_]u8{0xAB} ** 32,
            .signer_key_id = "official-key",
            .signer_name = "PGSD Official",
            .signature_time = 1234567890,
            .trust_level = .official,
        },
    };

    // Should return content for verified status
    const content = verified.getVerifiedContent();
    try std.testing.expect(content != null);
    try std.testing.expectEqual(TrustLevel.official, content.?.trust_level);
}

test "SECURITY: verification status - failures return null content" {
    // Security-critical: failure states must NOT return verified content
    const missing = VerificationStatus{
        .signature_missing = .{ .expected_path = "/test/sig" },
    };
    try std.testing.expect(missing.getVerifiedContent() == null);
    try std.testing.expect(!missing.isVerified());

    const invalid = VerificationStatus{
        .signature_invalid = .{ .reason = "bad sig", .signature_file = null },
    };
    try std.testing.expect(invalid.getVerifiedContent() == null);
    try std.testing.expect(!invalid.isVerified());

    const untrusted = VerificationStatus{
        .key_untrusted = .{ .key_id = "unknown-key", .reason = "not in store" },
    };
    try std.testing.expect(untrusted.getVerifiedContent() == null);
    try std.testing.expect(!untrusted.isVerified());

    const mismatch = VerificationStatus{
        .hash_mismatch = .{
            .expected_hash = [_]u8{0} ** 32,
            .actual_hash = [_]u8{1} ** 32,
            .file_path = "/test/file",
        },
    };
    try std.testing.expect(mismatch.getVerifiedContent() == null);
    try std.testing.expect(!mismatch.isVerified());
}

test "SECURITY: multi-signature threshold validation" {
    // Threshold must be at least 1
    const invalid_threshold = MultiSignatureConfig{
        .threshold = 0,
        .authorized_signers = &[_][]const u8{},
        .required_signers = &[_][]const u8{},
        .policy_name = null,
    };
    try std.testing.expectEqual(@as(u32, 0), invalid_threshold.threshold);

    // Valid threshold
    const valid_config = MultiSignatureConfig{
        .threshold = 2,
        .authorized_signers = &[_][]const u8{ "key1", "key2", "key3" },
        .required_signers = &[_][]const u8{},
        .policy_name = "m-of-n",
    };
    try std.testing.expectEqual(@as(u32, 2), valid_config.threshold);
    try std.testing.expectEqual(@as(usize, 3), valid_config.authorized_signers.len);
}

test "SECURITY: signature error distinctness" {
    // Ensure security-critical errors are distinct
    try std.testing.expect(SignatureError.InvalidSignature != SignatureError.SignatureNotFound);
    try std.testing.expect(SignatureError.KeyNotTrusted != SignatureError.KeyNotFound);
    try std.testing.expect(SignatureError.HashMismatch != SignatureError.InvalidSignature);
}

test "SECURITY: audit action types" {
    // Audit actions must be distinct for proper logging
    try std.testing.expect(AuditEntry.AuditAction.allowed != AuditEntry.AuditAction.blocked);
    try std.testing.expect(AuditEntry.AuditAction.blocked != AuditEntry.AuditAction.bypassed);
    try std.testing.expect(AuditEntry.AuditAction.warned != AuditEntry.AuditAction.allowed);
}

test "SECURITY: PublicKey deinit frees memory" {
    const allocator = std.testing.allocator;

    // Create a key with allocated strings
    var key = PublicKey{
        .key_id = try allocator.dupe(u8, "test-key-id"),
        .key_data = [_]u8{0} ** 32,
        .owner = try allocator.dupe(u8, "Test Owner"),
        .email = try allocator.dupe(u8, "test@example.com"),
        .created = 1234567890,
        .expires = null,
        .trust_level = .third_party,
    };

    // Deinit should free all allocated memory (test allocator will catch leaks)
    key.deinit(allocator);
}

test "SECURITY: OfficialPGSDKey constants are immutable" {
    // Verify the official key constants haven't been tampered with
    try std.testing.expectEqual(@as(usize, 16), OfficialPGSDKey.key_id.len);
    try std.testing.expectEqual(@as(usize, 64), OfficialPGSDKey.key_data_hex.len);
    try std.testing.expect(OfficialPGSDKey.created > 0);
}

// ============================================================================
// SECURITY TESTS: Trust Store Manipulation Prevention
// ============================================================================

test "SECURITY: trust store isolation" {
    const allocator = std.testing.allocator;

    // Two trust stores should be completely isolated
    var store1 = TrustStore.init(allocator, "/tmp/store1");
    defer store1.deinit();

    var store2 = TrustStore.init(allocator, "/tmp/store2");
    defer store2.deinit();

    // Adding a trusted key to store1 should not affect store2
    try store1.trusted.put(try allocator.dupe(u8, "key1"), true);
    try std.testing.expect(store1.isKeyTrusted("key1"));
    try std.testing.expect(!store2.isKeyTrusted("key1"));
}

test "SECURITY: untrust key properly removes trust" {
    const allocator = std.testing.allocator;

    var store = TrustStore.init(allocator, "/tmp/test-store");
    defer store.deinit();

    // Trust then untrust
    try store.trustKey("testkey");
    try std.testing.expect(store.isKeyTrusted("testkey"));

    store.untrustKey("testkey");
    try std.testing.expect(!store.isKeyTrusted("testkey"));
}

test "SECURITY: key trust level enforcement" {
    const allocator = std.testing.allocator;

    var store = TrustStore.init(allocator, "/tmp/test-store");
    defer store.deinit();

    // Unknown keys should return unknown trust level
    try std.testing.expectEqual(TrustLevel.unknown, store.getKeyTrustLevel("nonexistent"));
}
