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
            .entries = std.ArrayList(AuditEntry).init(allocator),
        };
    }

    pub fn deinit(self: *AuditLog) void {
        self.entries.deinit();
    }

    /// Record a verification event
    pub fn record(
        self: *AuditLog,
        package_path: []const u8,
        key_id: ?[]const u8,
        status: VerificationStatus,
        action: AuditEntry.AuditAction,
    ) !void {
        try self.entries.append(.{
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
        const writer = file.writer();

        for (self.entries.items) |entry| {
            try writer.print("{d}|{s}|{s}|{s}|{s}\n", .{
                entry.timestamp,
                entry.package_path,
                entry.key_id orelse "none",
                entry.status.getMessage(),
                @tagName(entry.action_taken),
            });
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
        return std.fmt.allocPrint(allocator, "{s}", .{
            std.fmt.fmtSliceHexUpper(self.public_key[0..8]),
        });
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
        var result = std.ArrayList(u8).init(allocator);
        defer result.deinit();
        const writer = result.writer();

        try writer.writeAll("# Axiom Package Signature\n");
        try writer.print("version: {d}\n", .{self.version});
        try writer.print("algorithm: {s}\n", .{self.algorithm});
        try writer.print("key_id: {s}\n", .{self.key_id});
        if (self.signer) |s| {
            try writer.print("signer: \"{s}\"\n", .{s});
        }
        try writer.print("timestamp: {d}\n", .{self.timestamp});
        try writer.print("signature: {s}\n", .{std.fmt.fmtSliceHexLower(&self.signature)});
        try writer.writeAll("files:\n");
        for (self.files) |f| {
            try writer.print("  - path: \"{s}\"\n", .{f.path});
            try writer.print("    sha256: {s}\n", .{std.fmt.fmtSliceHexLower(&f.hash)});
        }

        return result.toOwnedSlice();
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

        var files = std.ArrayList(FileHash).init(allocator);
        defer files.deinit();

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
                        try files.append(.{
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

        sig.files = try files.toOwnedSlice();
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
        var list = std.ArrayList(PublicKey).init(allocator);
        defer list.deinit();

        var iter = self.keys.valueIterator();
        while (iter.next()) |key| {
            try list.append(key.*);
        }

        return list.toOwnedSlice();
    }

    /// Save trust store to disk
    pub fn save(self: *TrustStore) !void {
        // Create directory if needed
        if (std.fs.path.dirname(self.store_path)) |dir| {
            std.fs.cwd().makePath(dir) catch {};
        }

        const file = try std.fs.cwd().createFile(self.store_path, .{});
        defer file.close();

        const writer = file.writer();
        try writer.writeAll("# Axiom Trust Store\n\n");

        var iter = self.keys.iterator();
        while (iter.next()) |entry| {
            const key = entry.value_ptr.*;
            try writer.print("[[key]]\n", .{});
            try writer.print("key_id = \"{s}\"\n", .{key.key_id});
            try writer.print("key_data = \"{s}\"\n", .{std.fmt.fmtSliceHexLower(&key.key_data)});
            if (key.owner) |o| try writer.print("owner = \"{s}\"\n", .{o});
            if (key.email) |e| try writer.print("email = \"{s}\"\n", .{e});
            try writer.print("created = {d}\n", .{key.created});
            if (key.expires) |exp| try writer.print("expires = {d}\n", .{exp});
            const trusted = self.trusted.get(key.key_id) orelse false;
            try writer.print("trusted = {}\n", .{trusted});
            try writer.writeAll("\n");
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
        var files = std.ArrayList(FileHash).init(self.allocator);
        defer files.deinit();

        try self.hashDirectory(pkg_path, "", &files);

        std.debug.print("  Hashed {d} files\n", .{files.items.len});

        // Build message to sign (concatenated hashes)
        var message = std.ArrayList(u8).init(self.allocator);
        defer message.deinit();

        for (files.items) |f| {
            try message.appendSlice(&f.hash);
            try message.appendSlice(f.path);
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
            .files = try files.toOwnedSlice(),
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
                    try files.append(.{
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
        std.debug.print("  Key trusted: {}\n", .{key_trusted});

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
        var message = std.ArrayList(u8).init(self.allocator);
        defer message.deinit();

        for (signature.files) |f| {
            try message.appendSlice(&f.hash);
            try message.appendSlice(f.path);
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

        std.debug.print("  Signature valid: {}\n", .{valid});

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
        var message = std.ArrayList(u8).init(self.allocator);
        defer message.deinit();

        for (signature.files) |f| {
            message.appendSlice(&f.hash) catch {};
            message.appendSlice(f.path) catch {};
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

    const writer = file.writer();
    try writer.writeAll("# Axiom Public Key\n");
    try writer.print("key_id: {s}\n", .{key.key_id});
    try writer.print("key_data: {s}\n", .{std.fmt.fmtSliceHexLower(&key.key_data)});
    if (key.owner) |o| try writer.print("owner: \"{s}\"\n", .{o});
    if (key.email) |e| try writer.print("email: \"{s}\"\n", .{e});
    try writer.print("created: {d}\n", .{key.created});
    if (key.expires) |exp| try writer.print("expires: {d}\n", .{exp});

    _ = allocator;
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
