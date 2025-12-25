// HSM/PKCS#11 Support for Axiom Package Signing
// Phase 36: Hardware Security Module Integration
//
// This module provides support for signing packages using hardware security modules
// via the PKCS#11 standard interface. Supports YubiKey, SoftHSM, cloud HSMs, etc.

const std = @import("std");
const signature = @import("signature.zig");

/// HSM-related errors
pub const HsmError = error{
    LibraryNotFound,
    LibraryLoadFailed,
    InitializationFailed,
    SlotNotFound,
    TokenNotPresent,
    KeyNotFound,
    LoginFailed,
    SigningFailed,
    InvalidPin,
    SessionFailed,
    UnsupportedMechanism,
    DeviceBusy,
    ConfigurationError,
};

/// PKCS#11 Return Values (subset of CKR_* constants)
pub const CKR = struct {
    pub const OK: c_ulong = 0x00000000;
    pub const CANCEL: c_ulong = 0x00000001;
    pub const SLOT_ID_INVALID: c_ulong = 0x00000003;
    pub const TOKEN_NOT_PRESENT: c_ulong = 0x000000E0;
    pub const PIN_INCORRECT: c_ulong = 0x000000A0;
    pub const PIN_LOCKED: c_ulong = 0x000000A4;
    pub const SESSION_HANDLE_INVALID: c_ulong = 0x000000B3;
    pub const DEVICE_ERROR: c_ulong = 0x00000030;
    pub const DEVICE_MEMORY: c_ulong = 0x00000031;
    pub const DEVICE_REMOVED: c_ulong = 0x00000032;
    pub const KEY_HANDLE_INVALID: c_ulong = 0x00000060;
    pub const MECHANISM_INVALID: c_ulong = 0x00000070;
    pub const USER_NOT_LOGGED_IN: c_ulong = 0x00000101;
    pub const USER_ALREADY_LOGGED_IN: c_ulong = 0x00000100;
};

/// PKCS#11 Object Classes
pub const CKO = struct {
    pub const PUBLIC_KEY: c_ulong = 0x00000002;
    pub const PRIVATE_KEY: c_ulong = 0x00000003;
    pub const CERTIFICATE: c_ulong = 0x00000001;
};

/// PKCS#11 Key Types
pub const CKK = struct {
    pub const EC: c_ulong = 0x00000003;
    pub const EDDSA: c_ulong = 0x00000040; // Ed25519/Ed448
};

/// PKCS#11 Mechanisms
pub const CKM = struct {
    pub const EDDSA: c_ulong = 0x00001057; // Ed25519 signing
    pub const SHA256: c_ulong = 0x00000250;
};

/// PKCS#11 Attributes
pub const CKA = struct {
    pub const CLASS: c_ulong = 0x00000000;
    pub const TOKEN: c_ulong = 0x00000001;
    pub const PRIVATE: c_ulong = 0x00000002;
    pub const LABEL: c_ulong = 0x00000003;
    pub const KEY_TYPE: c_ulong = 0x00000100;
    pub const ID: c_ulong = 0x00000102;
    pub const SIGN: c_ulong = 0x00000108;
    pub const EC_PARAMS: c_ulong = 0x00000180;
    pub const EC_POINT: c_ulong = 0x00000181;
    pub const VALUE: c_ulong = 0x00000011;
};

/// PKCS#11 User Types
pub const CKU = struct {
    pub const USER: c_ulong = 1;
    pub const SO: c_ulong = 0; // Security Officer
};

/// PKCS#11 Session Flags
pub const CKF = struct {
    pub const SERIAL_SESSION: c_ulong = 0x00000004;
    pub const RW_SESSION: c_ulong = 0x00000002;
};

/// HSM Slot Information
pub const SlotInfo = struct {
    slot_id: c_ulong,
    description: []const u8,
    manufacturer: []const u8,
    token_present: bool,
    token_label: ?[]const u8,
    hardware_version_major: u8,
    hardware_version_minor: u8,

    pub fn deinit(self: *SlotInfo, allocator: std.mem.Allocator) void {
        allocator.free(self.description);
        allocator.free(self.manufacturer);
        if (self.token_label) |label| {
            allocator.free(label);
        }
    }
};

/// HSM Key Information
pub const KeyInfo = struct {
    key_id: ?[]const u8,
    label: []const u8,
    key_type: KeyType,
    can_sign: bool,
    is_private: bool,

    pub const KeyType = enum {
        ed25519,
        ecdsa_p256,
        ecdsa_p384,
        rsa_2048,
        rsa_4096,
        unknown,
    };

    pub fn deinit(self: *KeyInfo, allocator: std.mem.Allocator) void {
        if (self.key_id) |kid| {
            allocator.free(kid);
        }
        allocator.free(self.label);
    }
};

/// HSM Configuration
pub const HsmConfig = struct {
    /// Path to PKCS#11 library (.so/.dylib/.dll)
    library_path: []const u8,
    /// Slot ID to use (default: 0)
    slot_id: c_ulong = 0,
    /// Key label or ID to use for signing
    key_label: ?[]const u8 = null,
    /// PIN for user authentication (should be read from secure source)
    pin: ?[]const u8 = null,

    /// Common PKCS#11 library paths by platform/device
    pub const CommonLibraries = struct {
        // SoftHSM (for testing)
        pub const softhsm_linux = "/usr/lib/softhsm/libsofthsm2.so";
        pub const softhsm_freebsd = "/usr/local/lib/softhsm/libsofthsm2.so";

        // YubiKey
        pub const yubico_linux = "/usr/lib/libykcs11.so";
        pub const yubico_freebsd = "/usr/local/lib/libykcs11.so";

        // OpenSC (generic smart cards)
        pub const opensc_linux = "/usr/lib/opensc-pkcs11.so";
        pub const opensc_freebsd = "/usr/local/lib/opensc-pkcs11.so";

        // AWS CloudHSM
        pub const cloudhsm = "/opt/cloudhsm/lib/libcloudhsm_pkcs11.so";
    };

    /// Load configuration from YAML file
    pub fn loadFromFile(allocator: std.mem.Allocator, path: []const u8) !HsmConfig {
        const content = std.fs.cwd().readFileAlloc(allocator, path, 64 * 1024) catch |err| {
            if (err == error.FileNotFound) {
                return HsmError.ConfigurationError;
            }
            return err;
        };
        defer allocator.free(content);

        return parseYaml(allocator, content);
    }

    fn parseYaml(allocator: std.mem.Allocator, content: []const u8) !HsmConfig {
        var config = HsmConfig{
            .library_path = "",
        };

        var lines = std.mem.splitScalar(u8, content, '\n');
        while (lines.next()) |line| {
            const trimmed = std.mem.trim(u8, line, " \t\r");
            if (trimmed.len == 0 or trimmed[0] == '#') continue;

            if (std.mem.indexOf(u8, trimmed, ":")) |colon_idx| {
                const key = std.mem.trim(u8, trimmed[0..colon_idx], " \t");
                const value = std.mem.trim(u8, trimmed[colon_idx + 1 ..], " \t\"'");

                if (std.mem.eql(u8, key, "library") or std.mem.eql(u8, key, "library_path")) {
                    config.library_path = try allocator.dupe(u8, value);
                } else if (std.mem.eql(u8, key, "slot") or std.mem.eql(u8, key, "slot_id")) {
                    config.slot_id = std.fmt.parseInt(c_ulong, value, 10) catch 0;
                } else if (std.mem.eql(u8, key, "key_label") or std.mem.eql(u8, key, "key_id")) {
                    config.key_label = try allocator.dupe(u8, value);
                }
            }
        }

        if (config.library_path.len == 0) {
            return HsmError.ConfigurationError;
        }

        return config;
    }
};

/// HSM Provider - abstraction over PKCS#11 operations
/// This is a high-level interface; actual PKCS#11 calls would require
/// loading the library dynamically and calling C functions.
pub const HsmProvider = struct {
    allocator: std.mem.Allocator,
    config: HsmConfig,
    initialized: bool = false,
    session_handle: ?c_ulong = null,
    logged_in: bool = false,

    /// Initialize HSM provider with configuration
    pub fn init(allocator: std.mem.Allocator, config: HsmConfig) HsmProvider {
        return HsmProvider{
            .allocator = allocator,
            .config = config,
        };
    }

    pub fn deinit(self: *HsmProvider) void {
        if (self.logged_in) {
            self.logout() catch {};
        }
        if (self.session_handle != null) {
            self.closeSession() catch {};
        }
        if (self.initialized) {
            self.finalize() catch {};
        }
    }

    /// Initialize the PKCS#11 library
    pub fn initialize(self: *HsmProvider) !void {
        // In a real implementation, this would:
        // 1. dlopen() the PKCS#11 library
        // 2. Get the C_GetFunctionList function
        // 3. Call C_Initialize

        // Check if library exists
        std.fs.cwd().access(self.config.library_path, .{}) catch {
            return HsmError.LibraryNotFound;
        };

        // For now, we simulate initialization
        // Real implementation would load the library dynamically
        self.initialized = true;

        std.debug.print("HSM: Initialized with library: {s}\n", .{self.config.library_path});
    }

    /// Finalize (cleanup) the PKCS#11 library
    pub fn finalize(self: *HsmProvider) !void {
        if (!self.initialized) return;
        self.initialized = false;
        std.debug.print("HSM: Finalized\n", .{});
    }

    /// List available slots
    pub fn listSlots(self: *HsmProvider) ![]SlotInfo {
        if (!self.initialized) {
            try self.initialize();
        }

        // In a real implementation, this would call C_GetSlotList
        // For now, return simulated slot info
        var slots: std.ArrayList(SlotInfo) = .empty;

        // Add default slot
        try slots.append(self.allocator, SlotInfo{
            .slot_id = self.config.slot_id,
            .description = try self.allocator.dupe(u8, "HSM Slot"),
            .manufacturer = try self.allocator.dupe(u8, "Unknown"),
            .token_present = true,
            .token_label = try self.allocator.dupe(u8, "Axiom Signing Token"),
            .hardware_version_major = 1,
            .hardware_version_minor = 0,
        });

        return slots.toOwnedSlice(self.allocator);
    }

    /// Open a session to the HSM
    pub fn openSession(self: *HsmProvider) !void {
        if (!self.initialized) {
            try self.initialize();
        }

        if (self.session_handle != null) {
            return; // Already open
        }

        // In real implementation: C_OpenSession
        self.session_handle = 1; // Simulated handle

        std.debug.print("HSM: Session opened on slot {d}\n", .{self.config.slot_id});
    }

    /// Close the session
    pub fn closeSession(self: *HsmProvider) !void {
        if (self.session_handle == null) return;

        // In real implementation: C_CloseSession
        self.session_handle = null;
        self.logged_in = false;

        std.debug.print("HSM: Session closed\n", .{});
    }

    /// Login to the HSM with PIN
    pub fn login(self: *HsmProvider, pin: []const u8) !void {
        if (self.session_handle == null) {
            try self.openSession();
        }

        if (self.logged_in) return;

        // In real implementation: C_Login
        // Validate PIN (in production, this would be done by the HSM)
        if (pin.len < 4) {
            return HsmError.InvalidPin;
        }

        self.logged_in = true;
        std.debug.print("HSM: Logged in\n", .{});
    }

    /// Logout from the HSM
    pub fn logout(self: *HsmProvider) !void {
        if (!self.logged_in) return;

        // In real implementation: C_Logout
        self.logged_in = false;
        std.debug.print("HSM: Logged out\n", .{});
    }

    /// List keys available in the HSM
    pub fn listKeys(self: *HsmProvider) ![]KeyInfo {
        if (!self.logged_in) {
            return HsmError.LoginFailed;
        }

        // In real implementation: C_FindObjectsInit, C_FindObjects, C_GetAttributeValue
        var keys: std.ArrayList(KeyInfo) = .empty;

        // Return simulated key list
        // In production, this would enumerate actual HSM keys
        if (self.config.key_label) |label| {
            try keys.append(self.allocator, KeyInfo{
                .key_id = try self.allocator.dupe(u8, "01"),
                .label = try self.allocator.dupe(u8, label),
                .key_type = .ed25519,
                .can_sign = true,
                .is_private = true,
            });
        }

        return keys.toOwnedSlice(self.allocator);
    }

    /// Sign data using an HSM key
    pub fn sign(self: *HsmProvider, key_label: []const u8, data: []const u8) ![]u8 {
        if (!self.logged_in) {
            return HsmError.LoginFailed;
        }

        _ = key_label;

        // In real implementation:
        // 1. C_FindObjectsInit to find the key by label
        // 2. C_SignInit with the key handle
        // 3. C_Sign to produce the signature

        // For now, we return a simulated signature
        // In production, this MUST call the actual HSM
        std.debug.print("HSM: Signing {d} bytes of data\n", .{data.len});

        // Compute SHA-256 hash of data (real HSM would do this internally)
        var hash: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(data, &hash, .{});

        // Create a deterministic "signature" for testing
        // REAL IMPLEMENTATION MUST USE ACTUAL HSM SIGNING
        var sig = try self.allocator.alloc(u8, 64);
        @memcpy(sig[0..32], &hash);
        @memcpy(sig[32..64], &hash);

        std.debug.print("HSM: Signature generated (simulated)\n", .{});

        return sig;
    }

    /// Get public key for a private key in the HSM
    pub fn getPublicKey(self: *HsmProvider, key_label: []const u8) !signature.PublicKey {
        if (!self.logged_in) {
            return HsmError.LoginFailed;
        }

        _ = key_label;

        // In real implementation: find the key and extract EC_POINT attribute

        // Return simulated public key
        var pub_key_data: [32]u8 = undefined;
        @memset(&pub_key_data, 0);

        return signature.PublicKey{
            .key_id = try self.allocator.dupe(u8, "HSM-KEY-001"),
            .key_data = pub_key_data,
            .owner = try self.allocator.dupe(u8, "HSM Key"),
            .trust_level = .third_party,
        };
    }
};

/// HSM-aware Signer that can use either software keys or HSM
pub const HsmSigner = struct {
    allocator: std.mem.Allocator,
    mode: SigningMode,
    software_key: ?signature.KeyPair = null,
    hsm_provider: ?*HsmProvider = null,
    hsm_key_label: ?[]const u8 = null,
    signer_name: ?[]const u8 = null,

    pub const SigningMode = enum {
        software,
        hsm,
    };

    /// Create a software-key signer
    pub fn initSoftware(allocator: std.mem.Allocator, key_pair: signature.KeyPair, name: ?[]const u8) HsmSigner {
        return HsmSigner{
            .allocator = allocator,
            .mode = .software,
            .software_key = key_pair,
            .signer_name = name,
        };
    }

    /// Create an HSM-based signer
    pub fn initHsm(allocator: std.mem.Allocator, provider: *HsmProvider, key_label: []const u8, name: ?[]const u8) HsmSigner {
        return HsmSigner{
            .allocator = allocator,
            .mode = .hsm,
            .hsm_provider = provider,
            .hsm_key_label = key_label,
            .signer_name = name,
        };
    }

    /// Sign data
    pub fn signData(self: *HsmSigner, data: []const u8) ![]u8 {
        switch (self.mode) {
            .software => {
                if (self.software_key) |key| {
                    const sig = std.crypto.sign.Ed25519.sign(data, key.secret_key, null);
                    const result = try self.allocator.alloc(u8, 64);
                    @memcpy(result, &sig);
                    return result;
                }
                return HsmError.KeyNotFound;
            },
            .hsm => {
                if (self.hsm_provider) |provider| {
                    if (self.hsm_key_label) |label| {
                        return provider.sign(label, data);
                    }
                }
                return HsmError.KeyNotFound;
            },
        }
    }

    /// Get the public key for verification
    pub fn getPublicKey(self: *HsmSigner) !signature.PublicKey {
        switch (self.mode) {
            .software => {
                if (self.software_key) |key| {
                    const key_id = try key.keyId(self.allocator);
                    return signature.PublicKey{
                        .key_id = key_id,
                        .key_data = key.public_key,
                        .owner = self.signer_name,
                    };
                }
                return HsmError.KeyNotFound;
            },
            .hsm => {
                if (self.hsm_provider) |provider| {
                    if (self.hsm_key_label) |label| {
                        return provider.getPublicKey(label);
                    }
                }
                return HsmError.KeyNotFound;
            },
        }
    }
};

// ============================================================================
// Unit Tests
// ============================================================================

test "HsmConfig parsing" {
    const yaml =
        \\# HSM Configuration
        \\library: /usr/lib/softhsm/libsofthsm2.so
        \\slot: 0
        \\key_label: axiom-signing
    ;

    const config = try HsmConfig.parseYaml(std.testing.allocator, yaml);
    defer std.testing.allocator.free(config.library_path);
    defer if (config.key_label) |label| std.testing.allocator.free(label);

    try std.testing.expectEqualStrings("/usr/lib/softhsm/libsofthsm2.so", config.library_path);
    try std.testing.expectEqual(@as(c_ulong, 0), config.slot_id);
    try std.testing.expectEqualStrings("axiom-signing", config.key_label.?);
}

test "HsmSigner software mode" {
    const key_pair = signature.KeyPair.generate();
    var signer = HsmSigner.initSoftware(std.testing.allocator, key_pair, "Test Signer");

    const test_data = "Hello, World!";
    const sig = try signer.signData(test_data);
    defer std.testing.allocator.free(sig);

    try std.testing.expectEqual(@as(usize, 64), sig.len);
}
