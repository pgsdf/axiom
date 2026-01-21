const std = @import("std");
const Allocator = std.mem.Allocator;

const lockbox = @import("lockbox.zig");
const canonical_json = @import("canonical_json.zig");
const lockbox_types = @import("lockbox_types.zig");
const signature = @import("signature.zig");

pub const LockboxSpec = lockbox.LockboxSpec;
pub const LockboxParser = lockbox.LockboxParser;
pub const LockboxEmitter = lockbox.LockboxEmitter;
pub const CanonicalJson = canonical_json.CanonicalJson;

// ============================================================================
// Lockbox Canonicalization Boundary
// ============================================================================
//
// This module provides the single entry point for Lockbox canonicalization.
// It is intentionally kept separate from Axiom's existing YAML pipeline
// to avoid conflicts with package manifest processing.
//
// The canonicalization boundary enforces the principle:
//   "YAML for human authoring, Canonical JSON for machine verification"
//
// All content IDs, hashes, and signatures are derived ONLY from:
//   1. The canonical JSON representation
//   2. The Merkle root of the artifact filesystem manifest
//
// ============================================================================

/// Input format detection
pub const InputFormat = enum {
    yaml,
    json,
    unknown,

    /// Detect format from file extension
    pub fn fromPath(path: []const u8) InputFormat {
        if (std.mem.endsWith(u8, path, ".yaml") or std.mem.endsWith(u8, path, ".yml")) {
            return .yaml;
        } else if (std.mem.endsWith(u8, path, ".json")) {
            return .json;
        }
        return .unknown;
    }

    /// Detect format from content (heuristic)
    pub fn fromContent(content: []const u8) InputFormat {
        const trimmed = std.mem.trim(u8, content, " \t\r\n");
        if (trimmed.len == 0) return .unknown;

        // JSON starts with { or [
        if (trimmed[0] == '{' or trimmed[0] == '[') {
            return .json;
        }

        // YAML typically has key: value or starts with ---
        if (std.mem.startsWith(u8, trimmed, "---") or
            std.mem.indexOf(u8, trimmed, ":") != null)
        {
            return .yaml;
        }

        return .unknown;
    }
};

/// Result of canonicalization
pub const CanonicalResult = struct {
    /// The parsed specification
    spec: LockboxSpec,
    /// Canonical JSON bytes (deterministic, sorted keys, no whitespace)
    canonical_bytes: []u8,
    /// SHA-256 content hash of canonical JSON
    content_hash: [64]u8, // hex-encoded
    /// SHA-256 hash bytes (raw)
    content_hash_bytes: [32]u8,
    /// Merkle root of filesystem (if filesystem manifest present)
    merkle_root: ?[64]u8, // hex-encoded
    /// Combined content ID (hash of canonical JSON + merkle root)
    content_id: [64]u8, // hex-encoded

    allocator: Allocator,

    pub fn deinit(self: *CanonicalResult) void {
        self.spec.deinit(self.allocator);
        self.allocator.free(self.canonical_bytes);
    }
};

/// Signed canonical result
pub const SignedResult = struct {
    /// The canonical result
    canonical: CanonicalResult,
    /// Ed25519 signature over content_id
    signature_bytes: [64]u8,
    /// Signer key ID
    signer_key_id: []const u8,
    /// Signer name (optional)
    signer_name: ?[]const u8,
    /// Timestamp of signing
    timestamp: i64,

    allocator: Allocator,

    pub fn deinit(self: *SignedResult) void {
        self.canonical.deinit();
        self.allocator.free(self.signer_key_id);
        if (self.signer_name) |name| self.allocator.free(name);
    }

    /// Serialize signature to detached format
    pub fn toDetachedSignature(self: *const SignedResult, allocator: Allocator) ![]u8 {
        var buffer: std.ArrayList(u8) = .empty;
        errdefer buffer.deinit(allocator);

        const writer = buffer.writer(allocator);

        try writer.writeAll("# Lockbox Detached Signature\n");
        try writer.writeAll("format: lockbox-signature-v1\n");
        try writer.print("content_id: {s}\n", .{self.canonical.content_id});
        try writer.print("key_id: {s}\n", .{self.signer_key_id});
        if (self.signer_name) |name| {
            try writer.print("signer: {s}\n", .{name});
        }
        try writer.print("timestamp: {d}\n", .{self.timestamp});
        try writer.print("signature: {x}\n", .{self.signature_bytes});

        return buffer.toOwnedSlice(allocator);
    }
};

/// Canonicalization error types
pub const CanonError = error{
    /// Input format could not be determined
    UnknownFormat,
    /// YAML parsing failed
    YamlParseError,
    /// JSON parsing failed
    JsonParseError,
    /// Specification validation failed
    ValidationError,
    /// Canonicalization failed
    CanonicalizationError,
    /// Signing failed
    SigningError,
    /// File read error
    FileReadError,
    /// Allocation failed
    OutOfMemory,
};

/// Lockbox Canonicalization Boundary
///
/// This is the single entry point for all Lockbox canonicalization operations.
/// It accepts either YAML or JSON input and produces deterministic output.
pub const LockboxCanon = struct {
    allocator: Allocator,
    parser: LockboxParser,
    emitter: LockboxEmitter,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return .{
            .allocator = allocator,
            .parser = LockboxParser.init(allocator),
            .emitter = LockboxEmitter.init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        self.parser.deinit();
    }

    // ========================================================================
    // Core Canonicalization API
    // ========================================================================

    /// Canonicalize from file path
    ///
    /// Reads the file, detects format, parses, validates, and produces
    /// canonical output with content hashes.
    pub fn canonicalizeFile(self: *Self, path: []const u8) CanonError!CanonicalResult {
        // Read file content
        const content = std.fs.cwd().readFileAlloc(self.allocator, path, 10 * 1024 * 1024) catch {
            return CanonError.FileReadError;
        };
        defer self.allocator.free(content);

        // Detect format from path, fall back to content detection
        var format = InputFormat.fromPath(path);
        if (format == .unknown) {
            format = InputFormat.fromContent(content);
        }

        return self.canonicalizeContent(content, format);
    }

    /// Canonicalize from content bytes
    ///
    /// Parses content in the specified format, validates, and produces
    /// canonical output with content hashes.
    pub fn canonicalizeContent(self: *Self, content: []const u8, format: InputFormat) CanonError!CanonicalResult {
        // Parse based on format
        const spec = switch (format) {
            .yaml => self.parser.parseYaml(content) catch {
                return CanonError.YamlParseError;
            },
            .json => self.parser.parseJson(content) catch {
                return CanonError.JsonParseError;
            },
            .unknown => {
                // Try YAML first, then JSON
                self.parser.parseYaml(content) catch {
                    return self.parser.parseJson(content) catch {
                        return CanonError.UnknownFormat;
                    };
                };
            },
        };
        errdefer {
            var mut_spec = spec;
            mut_spec.deinit(self.allocator);
        }

        return self.canonicalizeSpec(spec);
    }

    /// Canonicalize from a parsed specification
    ///
    /// Takes an already-parsed spec and produces canonical output.
    pub fn canonicalizeSpec(self: *Self, spec: LockboxSpec) CanonError!CanonicalResult {
        // Emit canonical JSON
        const canonical_bytes = self.emitter.emitCanonicalJson(&spec) catch {
            return CanonError.CanonicalizationError;
        };
        errdefer self.allocator.free(canonical_bytes);

        // Compute content hash (SHA-256 of canonical JSON)
        var content_hash_bytes: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(canonical_bytes, &content_hash_bytes, .{});

        // Hex-encode the content hash
        var content_hash: [64]u8 = undefined;
        _ = std.fmt.bufPrint(&content_hash, "{x}", .{content_hash_bytes}) catch unreachable;

        // Compute merkle root if filesystem manifest present
        var merkle_root: ?[64]u8 = null;
        if (spec.filesystem) |fs| {
            var merkle_bytes: [32]u8 = undefined;
            fs.computeMerkleRoot(&merkle_bytes);
            var merkle_hex: [64]u8 = undefined;
            _ = std.fmt.bufPrint(&merkle_hex, "{x}", .{merkle_bytes}) catch unreachable;
            merkle_root = merkle_hex;
        }

        // Compute combined content ID
        var content_id: [64]u8 = undefined;
        var id_hasher = std.crypto.hash.sha2.Sha256.init(.{});
        id_hasher.update(&content_hash_bytes);
        if (merkle_root) |mr| {
            var mr_bytes: [32]u8 = undefined;
            _ = std.fmt.hexToBytes(&mr_bytes, &mr) catch {};
            id_hasher.update(&mr_bytes);
        }
        var id_bytes: [32]u8 = undefined;
        id_hasher.final(&id_bytes);
        _ = std.fmt.bufPrint(&content_id, "{x}", .{id_bytes}) catch unreachable;

        return CanonicalResult{
            .spec = spec,
            .canonical_bytes = canonical_bytes,
            .content_hash = content_hash,
            .content_hash_bytes = content_hash_bytes,
            .merkle_root = merkle_root,
            .content_id = content_id,
            .allocator = self.allocator,
        };
    }

    // ========================================================================
    // Signing API
    // ========================================================================

    /// Canonicalize and sign
    ///
    /// Performs canonicalization and signs the content ID with the provided key.
    pub fn canonicalizeAndSign(
        self: *Self,
        content: []const u8,
        format: InputFormat,
        key_pair: signature.KeyPair,
        key_id: []const u8,
        signer_name: ?[]const u8,
    ) CanonError!SignedResult {
        // First canonicalize
        var canonical = try self.canonicalizeContent(content, format);
        errdefer canonical.deinit();

        // Sign the content ID
        const secret_key = std.crypto.sign.Ed25519.SecretKey.fromBytes(key_pair.secret_key) catch {
            return CanonError.SigningError;
        };
        const ed_key_pair = std.crypto.sign.Ed25519.KeyPair.fromSecretKey(secret_key) catch {
            return CanonError.SigningError;
        };

        const sig = ed_key_pair.sign(&canonical.content_id, null) catch {
            return CanonError.SigningError;
        };

        return SignedResult{
            .canonical = canonical,
            .signature_bytes = sig.toBytes(),
            .signer_key_id = self.allocator.dupe(u8, key_id) catch return CanonError.OutOfMemory,
            .signer_name = if (signer_name) |name|
                (self.allocator.dupe(u8, name) catch return CanonError.OutOfMemory)
            else
                null,
            .timestamp = std.time.timestamp(),
            .allocator = self.allocator,
        };
    }

    /// Verify a signature against canonical content
    pub fn verifySignature(
        self: *Self,
        canonical: *const CanonicalResult,
        signature_bytes: [64]u8,
        public_key: [32]u8,
    ) bool {
        _ = self;
        const pub_key = std.crypto.sign.Ed25519.PublicKey.fromBytes(public_key) catch {
            return false;
        };
        const sig = std.crypto.sign.Ed25519.Signature.fromBytes(signature_bytes);

        sig.verify(&canonical.content_id, pub_key) catch {
            return false;
        };

        return true;
    }

    // ========================================================================
    // Utility Functions
    // ========================================================================

    /// Write canonical JSON to file
    pub fn writeCanonicalToFile(self: *Self, result: *const CanonicalResult, path: []const u8) !void {
        _ = self;
        const file = try std.fs.cwd().createFile(path, .{});
        defer file.close();
        try file.writeAll(result.canonical_bytes);
    }

    /// Write detached signature to file
    pub fn writeSignatureToFile(self: *Self, result: *const SignedResult, path: []const u8) !void {
        const sig_content = try result.toDetachedSignature(self.allocator);
        defer self.allocator.free(sig_content);

        const file = try std.fs.cwd().createFile(path, .{});
        defer file.close();
        try file.writeAll(sig_content);
    }

    /// Get parser errors (if any)
    pub fn getErrors(self: *const Self) []const []const u8 {
        return self.parser.errors.items;
    }
};

// ============================================================================
// Convenience Functions
// ============================================================================

/// Canonicalize a lockbox file and return the canonical JSON bytes
pub fn canonicalizeFile(allocator: Allocator, path: []const u8) ![]u8 {
    var canon = LockboxCanon.init(allocator);
    defer canon.deinit();

    var result = try canon.canonicalizeFile(path);
    defer result.deinit();

    // Return a copy of the canonical bytes (caller owns)
    return allocator.dupe(u8, result.canonical_bytes);
}

/// Compute content ID for a lockbox file
pub fn computeContentId(allocator: Allocator, path: []const u8) ![64]u8 {
    var canon = LockboxCanon.init(allocator);
    defer canon.deinit();

    var result = try canon.canonicalizeFile(path);
    defer result.deinit();

    return result.content_id;
}

/// Verify that two lockbox files are semantically equivalent
pub fn areEquivalent(allocator: Allocator, path1: []const u8, path2: []const u8) !bool {
    const id1 = try computeContentId(allocator, path1);
    const id2 = try computeContentId(allocator, path2);
    return std.mem.eql(u8, &id1, &id2);
}

// ============================================================================
// Tests
// ============================================================================

test "format detection from path" {
    try std.testing.expectEqual(InputFormat.yaml, InputFormat.fromPath("lockbox.yaml"));
    try std.testing.expectEqual(InputFormat.yaml, InputFormat.fromPath("lockbox.yml"));
    try std.testing.expectEqual(InputFormat.json, InputFormat.fromPath("lockbox.json"));
    try std.testing.expectEqual(InputFormat.json, InputFormat.fromPath("lockbox.canonical.json"));
    try std.testing.expectEqual(InputFormat.unknown, InputFormat.fromPath("lockbox.txt"));
}

test "format detection from content" {
    try std.testing.expectEqual(InputFormat.json, InputFormat.fromContent("{\"key\": \"value\"}"));
    try std.testing.expectEqual(InputFormat.json, InputFormat.fromContent("[1, 2, 3]"));
    try std.testing.expectEqual(InputFormat.yaml, InputFormat.fromContent("key: value"));
    try std.testing.expectEqual(InputFormat.yaml, InputFormat.fromContent("---\nkey: value"));
    try std.testing.expectEqual(InputFormat.unknown, InputFormat.fromContent(""));
}
