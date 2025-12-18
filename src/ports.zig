// ports.zig - FreeBSD Ports Migration Tool
//
// Converts FreeBSD ports metadata into Axiom package manifests,
// enabling rapid ecosystem bootstrapping from the existing ports tree.
//
// Phase 1: Metadata extraction and manifest generation
// Phase 2: Happy-path builds for clean ports
// Phase 3: Options and variants mapping
//
// THREAD SAFETY WARNING:
// ----------------------
// PortsMigrator is NOT thread-safe. Each PortsMigrator instance should only
// be used from a single thread. The following operations are particularly
// sensitive to concurrent modifications:
//
// - findAllPackageRootsInStore(): Iterates filesystem directories that may
//   change if packages are added/removed concurrently
// - findPackageRootInStore(): Same issue as above
// - resolveDependencyTree(): Uses internal hashmaps for tracking visited nodes
// - getBuildEnvironment(): Creates symlinks that could conflict if called
//   concurrently for the same dependencies
//
// If concurrent ports operations are needed, create separate PortsMigrator
// instances for each thread, or serialize access with an external mutex.

const std = @import("std");
const manifest_pkg = @import("manifest.zig");
const types = @import("types.zig");
const store_pkg = @import("store.zig");
const build_pkg = @import("build.zig");
const errors = @import("errors.zig");

/// Progress indicator for long-running operations
/// Prints dots periodically to show activity
const ProgressIndicator = struct {
    thread: ?std.Thread = null,
    stop_flag: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    interval_ms: u64 = 5000, // Print a dot every 5 seconds
    prefix: []const u8 = "",

    /// Start the progress indicator in a background thread
    pub fn start(self: *ProgressIndicator) void {
        self.stop_flag.store(false, .release);
        self.thread = std.Thread.spawn(.{}, progressThread, .{self}) catch null;
    }

    /// Stop the progress indicator and wait for thread to finish
    pub fn stop(self: *ProgressIndicator) void {
        self.stop_flag.store(true, .release);
        if (self.thread) |t| {
            t.join();
            self.thread = null;
        }
        // Print newline after dots
        std.debug.print("\n", .{});
    }

    fn progressThread(self: *ProgressIndicator) void {
        var elapsed: u64 = 0;
        while (!self.stop_flag.load(.acquire)) {
            std.time.sleep(1000 * std.time.ns_per_ms); // Sleep 1 second
            elapsed += 1000;
            if (elapsed >= self.interval_ms) {
                std.debug.print(".", .{});
                elapsed = 0;
            }
        }
    }
};
const import_pkg = @import("import.zig");
const zfs = @import("zfs.zig");
const bootstrap_pkg = @import("bootstrap.zig");
const config = @import("config.zig");
const signature = @import("signature.zig");

const ZfsHandle = zfs.ZfsHandle;
const PackageStore = store_pkg.PackageStore;
const Builder = build_pkg.Builder;
const Importer = import_pkg.Importer;
const PackageId = types.PackageId;
const Signer = signature.Signer;
const KeyPair = signature.KeyPair;
const TrustStore = signature.TrustStore;
const PublicKey = signature.PublicKey;
const TrustLevel = signature.TrustLevel;

pub const PortsError = error{
    PortNotFound,
    MakefileParseError,
    DependencyParseError,
    UnsupportedPortFeature,
    BuildFailed,
    ImportFailed,
    InvalidPortsTree,
    MissingRequiredField,
    MissingDependencies,
    OutOfMemory,
    ProcessSpawnError,
};

/// Parsed port origin with optional flavor
/// e.g., "devel/py-setuptools@py311" -> path="devel/py-setuptools", flavor="py311"
pub const ParsedOrigin = struct {
    path: []const u8,
    flavor: ?[]const u8,

    /// Parse an origin string that may contain a @flavor suffix
    pub fn parse(origin: []const u8) ParsedOrigin {
        if (std.mem.indexOf(u8, origin, "@")) |at_pos| {
            return .{
                .path = origin[0..at_pos],
                .flavor = origin[at_pos + 1 ..],
            };
        }
        return .{
            .path = origin,
            .flavor = null,
        };
    }
};

/// FreeBSD port metadata extracted from Makefile
pub const PortMetadata = struct {
    // Identity
    name: []const u8,
    version: []const u8,
    revision: u32,
    epoch: u32,
    categories: []const []const u8,

    // Descriptive
    comment: []const u8,
    description: []const u8,
    maintainer: []const u8,
    www: []const u8,
    license: []const u8,

    // Source
    master_sites: []const []const u8,
    distfiles: []const []const u8,
    distinfo_sha256: []const u8,

    // Dependencies
    build_depends: []const PortDependency,
    lib_depends: []const PortDependency,
    run_depends: []const PortDependency,
    test_depends: []const PortDependency,

    // Build configuration
    uses: []const []const u8,
    options: []const PortOption,
    flavors: []const []const u8,
    conflicts: []const []const u8,

    // Build hints
    configure_style: ConfigureStyle,
    make_jobs_unsafe: bool,
    no_arch: bool,

    allocator: std.mem.Allocator,

    pub fn deinit(self: *PortMetadata) void {
        self.allocator.free(self.name);
        self.allocator.free(self.version);
        for (self.categories) |cat| self.allocator.free(cat);
        self.allocator.free(self.categories);
        self.allocator.free(self.comment);
        self.allocator.free(self.description);
        self.allocator.free(self.maintainer);
        self.allocator.free(self.www);
        self.allocator.free(self.license);
        for (self.master_sites) |site| self.allocator.free(site);
        self.allocator.free(self.master_sites);
        for (self.distfiles) |df| self.allocator.free(df);
        self.allocator.free(self.distfiles);
        self.allocator.free(self.distinfo_sha256);
        for (self.build_depends) |dep| dep.deinit(self.allocator);
        self.allocator.free(self.build_depends);
        for (self.lib_depends) |dep| dep.deinit(self.allocator);
        self.allocator.free(self.lib_depends);
        for (self.run_depends) |dep| dep.deinit(self.allocator);
        self.allocator.free(self.run_depends);
        for (self.test_depends) |dep| dep.deinit(self.allocator);
        self.allocator.free(self.test_depends);
        for (self.uses) |u| self.allocator.free(u);
        self.allocator.free(self.uses);
        for (self.options) |opt| opt.deinit(self.allocator);
        self.allocator.free(self.options);
        for (self.flavors) |f| self.allocator.free(f);
        self.allocator.free(self.flavors);
        for (self.conflicts) |c| self.allocator.free(c);
        self.allocator.free(self.conflicts);
    }
};

/// Port dependency specification
pub const PortDependency = struct {
    origin: []const u8, // e.g., "devel/gmake"
    package: []const u8, // e.g., "gmake"
    version: ?[]const u8, // Optional version constraint
    file_or_lib: ?[]const u8, // The file/lib that triggers the dep

    pub fn deinit(self: PortDependency, allocator: std.mem.Allocator) void {
        allocator.free(self.origin);
        allocator.free(self.package);
        if (self.version) |v| allocator.free(v);
        if (self.file_or_lib) |f| allocator.free(f);
    }
};

/// Port option (from OPTIONS framework)
pub const PortOption = struct {
    name: []const u8,
    description: []const u8,
    default: bool,
    group: ?[]const u8,

    pub fn deinit(self: PortOption, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.description);
        if (self.group) |g| allocator.free(g);
    }
};

/// Configure style detected from USES
pub const ConfigureStyle = enum {
    none,
    gnu_configure,
    cmake,
    meson,
    cargo,
    go,
    python,
    perl,
    ruby,
    qmake,
    scons,
    waf,
    custom,
};

/// Mapping configuration for port-to-axiom name translation
pub const NameMapping = struct {
    port_origin: []const u8,
    axiom_name: []const u8,
    notes: ?[]const u8,
};

/// Migration options
pub const MigrateOptions = struct {
    ports_tree: []const u8 = "/usr/ports",
    output_dir: []const u8 = "./generated/axiom-ports",
    build_after_generate: bool = false,
    import_after_build: bool = false,
    dry_run: bool = false,
    verbose: bool = false,
    name_mappings: []const NameMapping = &[_]NameMapping{},
    skip_options: bool = false,
    default_options_only: bool = true,

    // Dependency resolution
    auto_deps: bool = true, // Automatically build dependencies first
    continue_on_failure: bool = false, // Continue building other ports if one fails

    // Build system dependencies (required if build_after_generate or import_after_build is true)
    zfs_handle: ?*ZfsHandle = null,
    store: ?*PackageStore = null,
    importer: ?*Importer = null,

    // Build options
    build_jobs: u32 = 4,
    keep_sandbox: bool = false,

    // Workaround options
    use_system_tools: bool = false, // Skip sysroot creation, use /usr/local directly

    // Package signing options
    sign_packages: bool = true, // Sign packages after import (default: true)
    signing_key_path: ?[]const u8 = null, // Path to signing key, or null for auto-generated local key
};

/// Ports migration tool
/// WARNING: NOT thread-safe. See module-level documentation for details.
/// Each instance should only be accessed from a single thread.
pub const PortsMigrator = struct {
    allocator: std.mem.Allocator,
    options: MigrateOptions,

    pub fn init(allocator: std.mem.Allocator, options: MigrateOptions) PortsMigrator {
        return .{
            .allocator = allocator,
            .options = options,
        };
    }

    /// Default path for local signing key
    const LOCAL_KEY_DIR = config.DEFAULT_CONFIG_DIR ++ "/keys";
    const LOCAL_SECRET_KEY_PATH = LOCAL_KEY_DIR ++ "/local-signing.key";
    const LOCAL_PUBLIC_KEY_PATH = LOCAL_KEY_DIR ++ "/local-signing.pub";
    const TRUST_STORE_PATH = config.DEFAULT_CONFIG_DIR ++ "/trust.yaml";

    /// Ports that should be skipped during migration
    /// These are either replaced by Axiom itself or incompatible with Axiom's model
    const SKIP_PORTS = [_][]const u8{
        "ports-mgmt/pkg", // Axiom replaces pkg
    };

    /// Infrastructure ports that should always be included in the sysroot
    /// These provide tools that the ports framework itself needs (not just build dependencies)
    const INFRA_PORTS = [_][]const u8{
        "sysutils/coreutils", // Provides md5sum, sha256sum, etc. needed by ports framework
    };

    /// Get or create a local signing key for this machine
    /// Returns a KeyPair for signing packages built locally
    fn getOrCreateLocalSigningKey(self: *PortsMigrator) !KeyPair {
        // Check if user specified a custom key path
        if (self.options.signing_key_path) |custom_path| {
            return self.loadSigningKey(custom_path);
        }

        // Try to load existing local key
        if (self.loadSigningKey(LOCAL_SECRET_KEY_PATH)) |key| {
            // Ensure existing key is in trust store
            self.ensureKeyInTrustStore(key) catch |err| {
                errors.logTrustStoreOp(@src(), err, "ensure key in trust store");
            };
            return key;
        } else |_| {
            // Key doesn't exist - generate a new one
            std.debug.print("Generating local signing key...\n", .{});

            // Create key directory if needed
            std.fs.cwd().makePath(LOCAL_KEY_DIR) catch |err| {
                std.debug.print("Warning: Failed to create key directory: {s}\n", .{@errorName(err)});
                return err;
            };

            // Generate new key pair
            const key_pair = KeyPair.generate();
            const key_id = try key_pair.keyId(self.allocator);
            defer self.allocator.free(key_id);

            // Get hostname for owner field
            var hostname_buf: [255]u8 = undefined;
            const hostname = std.posix.gethostname(&hostname_buf) catch "localhost";

            // Save secret key
            {
                const file = try std.fs.cwd().createFile(LOCAL_SECRET_KEY_PATH, .{ .mode = 0o600 });
                defer file.close();
                const writer = file.writer();
                try writer.writeAll("# Axiom Local Signing Key (SECRET - keep private!)\n");
                try writer.writeAll("# Generated automatically for signing locally-built packages\n");
                try writer.print("key_id: {s}\n", .{key_id});
                try writer.print("secret_key: {s}\n", .{std.fmt.fmtSliceHexLower(&key_pair.secret_key)});
            }

            // Save public key (can be shared)
            {
                const file = try std.fs.cwd().createFile(LOCAL_PUBLIC_KEY_PATH, .{ .mode = 0o644 });
                defer file.close();
                const writer = file.writer();
                try writer.writeAll("# Axiom Local Signing Key (PUBLIC)\n");
                try writer.writeAll("# This key is used to verify packages built on this machine\n");
                try writer.print("key_id: {s}\n", .{key_id});
                try writer.print("key_data: {s}\n", .{std.fmt.fmtSliceHexLower(&key_pair.public_key)});
                try writer.print("owner: \"Local Build ({s})\"\n", .{hostname});
                try writer.print("created: {d}\n", .{std.time.timestamp()});
            }

            // Add public key to trust store so verification passes
            {
                var trust_store = TrustStore.init(self.allocator, TRUST_STORE_PATH);
                defer trust_store.deinit();

                // Try to load existing trust store (ignore errors for new store)
                trust_store.load() catch |err| {
                    errors.logConfigLoadOptional(@src(), err, TRUST_STORE_PATH);
                };

                // Create owner string for the key
                const owner = try std.fmt.allocPrint(self.allocator, "Local Build ({s})", .{hostname});
                defer self.allocator.free(owner);

                // Add the public key with third_party trust (local builds)
                const pub_key = PublicKey{
                    .key_id = key_id,
                    .key_data = key_pair.public_key,
                    .owner = owner,
                    .created = std.time.timestamp(),
                    .expires = null,
                    .trust_level = .third_party,
                };

                trust_store.addKeyWithTrust(pub_key, .third_party) catch |err| {
                    std.debug.print("Warning: Could not add key to trust store: {s}\n", .{@errorName(err)});
                };

                trust_store.save() catch |err| {
                    std.debug.print("Warning: Could not save trust store: {s}\n", .{@errorName(err)});
                };

                std.debug.print("  Key added to trust store: {s}\n", .{TRUST_STORE_PATH});
            }

            std.debug.print("  Key ID: {s}\n", .{key_id});
            std.debug.print("  Secret key saved to: {s}\n", .{LOCAL_SECRET_KEY_PATH});
            std.debug.print("  Public key saved to: {s}\n", .{LOCAL_PUBLIC_KEY_PATH});

            return key_pair;
        }
    }

    /// Load a signing key from file
    fn loadSigningKey(self: *PortsMigrator, path: []const u8) !KeyPair {
        const file = try std.fs.cwd().openFile(path, .{});
        defer file.close();

        const content = try file.readToEndAlloc(self.allocator, 1024 * 1024);
        defer self.allocator.free(content);

        var secret_key: [64]u8 = undefined;
        var found_key = false;

        var lines = std.mem.splitSequence(u8, content, "\n");
        while (lines.next()) |line| {
            const trimmed = std.mem.trim(u8, line, " \t");
            if (std.mem.startsWith(u8, trimmed, "secret_key:")) {
                const value = std.mem.trim(u8, trimmed[11..], " \t");
                if (value.len == 128) {
                    _ = std.fmt.hexToBytes(&secret_key, value) catch {
                        return error.InvalidKeyFormat;
                    };
                    found_key = true;
                }
            }
        }

        if (!found_key) {
            return error.InvalidKeyFormat;
        }

        // Reconstruct key pair from secret key
        const ed_secret = std.crypto.sign.Ed25519.SecretKey.fromBytes(secret_key) catch {
            return error.InvalidKeyFormat;
        };
        const ed_pair = std.crypto.sign.Ed25519.KeyPair.fromSecretKey(ed_secret) catch {
            return error.InvalidKeyFormat;
        };

        return KeyPair{
            .public_key = ed_pair.public_key.bytes,
            .secret_key = secret_key,
        };
    }

    /// Ensure a key is in the trust store (for existing keys that predate trust store integration)
    fn ensureKeyInTrustStore(self: *PortsMigrator, key_pair: KeyPair) !void {
        const key_id = try key_pair.keyId(self.allocator);
        defer self.allocator.free(key_id);

        var trust_store = TrustStore.init(self.allocator, TRUST_STORE_PATH);
        defer trust_store.deinit();

        // Try to load existing trust store
        trust_store.load() catch |err| {
            errors.logConfigLoadOptional(@src(), err, TRUST_STORE_PATH);
        };

        // Check if key is already trusted
        if (trust_store.isKeyTrusted(key_id)) {
            // Key exists - but check if trust_level needs to be upgraded from .unknown
            const current_level = trust_store.getKeyTrustLevel(key_id);
            if (current_level == .unknown) {
                // Upgrade trust level for existing key (from pre-trust_level trust store)
                trust_store.setKeyTrustLevel(key_id, .third_party) catch |err| {
                    errors.logTrustStoreOp(@src(), err, "set key trust level");
                };
                trust_store.save() catch |err| {
                    errors.logTrustStoreOp(@src(), err, "save trust store");
                };
            }
            return;
        }

        // Key not in trust store - add it
        std.debug.print("Adding local signing key to trust store...\n", .{});

        var hostname_buf: [255]u8 = undefined;
        const hostname = std.posix.gethostname(&hostname_buf) catch "localhost";
        const owner = try std.fmt.allocPrint(self.allocator, "Local Build ({s})", .{hostname});
        defer self.allocator.free(owner);

        const pub_key = PublicKey{
            .key_id = key_id,
            .key_data = key_pair.public_key,
            .owner = owner,
            .created = std.time.timestamp(),
            .expires = null,
            .trust_level = .third_party,
        };

        try trust_store.addKeyWithTrust(pub_key, .third_party);
        try trust_store.save();

        std.debug.print("  Key {s} added to trust store\n", .{key_id});
    }

    /// Sign a source directory before import
    /// Creates manifest.sig in the directory which will be copied to the store
    fn signSourceDirectory(self: *PortsMigrator, pkg_dir: []const u8, pkg_name: []const u8) !void {
        // Get the signing key
        const key_pair = self.getOrCreateLocalSigningKey() catch |err| {
            std.debug.print("Warning: Could not get signing key: {s}\n", .{@errorName(err)});
            std.debug.print("  Package will remain unsigned\n", .{});
            return;
        };

        // Get hostname for signer name
        var hostname_buf: [255]u8 = undefined;
        const hostname = std.posix.gethostname(&hostname_buf) catch "localhost";
        const signer_name = try std.fmt.allocPrint(self.allocator, "Local Build ({s})", .{hostname});
        defer self.allocator.free(signer_name);

        std.debug.print("Signing package: {s}\n", .{pkg_name});

        // Create signer and sign the package directory
        var signer = Signer.init(self.allocator, key_pair, signer_name);
        var sig = signer.signPackage(pkg_dir) catch |err| {
            std.debug.print("Warning: Failed to sign package: {s}\n", .{@errorName(err)});
            return;
        };
        defer sig.deinit(self.allocator);

        // Save signature
        const sig_yaml = try sig.toYaml(self.allocator);
        defer self.allocator.free(sig_yaml);

        const sig_path = try std.fs.path.join(self.allocator, &[_][]const u8{ pkg_dir, "manifest.sig" });
        defer self.allocator.free(sig_path);

        {
            const sig_file = std.fs.cwd().createFile(sig_path, .{}) catch |err| {
                std.debug.print("Warning: Failed to create signature file: {s}\n", .{@errorName(err)});
                return;
            };
            defer sig_file.close();
            sig_file.writeAll(sig_yaml) catch |err| {
                std.debug.print("Warning: Failed to write signature: {s}\n", .{@errorName(err)});
                return;
            };
        }

        const key_id = key_pair.keyId(self.allocator) catch "unknown";
        defer if (!std.mem.eql(u8, key_id, "unknown")) self.allocator.free(key_id);

        std.debug.print("  ✓ Package signed (key: {s})\n", .{key_id});
    }

    /// Check if minimal bootstrap packages are available and warn if not
    pub fn checkBootstrapStatus(self: *PortsMigrator) !void {
        var missing_minimal = std.ArrayList([]const u8).init(self.allocator);
        defer missing_minimal.deinit();

        // Check for minimal bootstrap packages
        for (bootstrap_pkg.MINIMAL_BOOTSTRAP_PACKAGES) |pkg_name| {
            const pkg_path = try std.fmt.allocPrint(self.allocator, config.DEFAULT_MOUNTPOINT ++ "/store/pkg/{s}", .{pkg_name});
            defer self.allocator.free(pkg_path);

            var dir = std.fs.openDirAbsolute(pkg_path, .{}) catch {
                try missing_minimal.append(pkg_name);
                continue;
            };
            dir.close();
        }

        if (missing_minimal.items.len > 0) {
            std.debug.print("\n", .{});
            std.debug.print("╔══════════════════════════════════════════════════════════════╗\n", .{});
            std.debug.print("║                    BOOTSTRAP WARNING                         ║\n", .{});
            std.debug.print("╠══════════════════════════════════════════════════════════════╣\n", .{});
            std.debug.print("║ Some bootstrap packages are missing from the Axiom store.    ║\n", .{});
            std.debug.print("║ Building may fail if these tools are not available.          ║\n", .{});
            std.debug.print("║                                                              ║\n", .{});
            std.debug.print("║ Missing packages:                                            ║\n", .{});
            for (missing_minimal.items) |pkg| {
                std.debug.print("║   - {s:<54} ║\n", .{pkg});
            }
            std.debug.print("║                                                              ║\n", .{});
            std.debug.print("║ To bootstrap without pkg:                                    ║\n", .{});
            std.debug.print("║   axiom bootstrap-import axiom-bootstrap-14.2-amd64.tar.zst  ║\n", .{});
            std.debug.print("║                                                              ║\n", .{});
            std.debug.print("║ Or build the minimal packages first:                         ║\n", .{});
            std.debug.print("║   axiom ports-import devel/gmake                             ║\n", .{});
            std.debug.print("║   axiom ports-import devel/m4                                ║\n", .{});
            std.debug.print("╚══════════════════════════════════════════════════════════════╝\n", .{});
            std.debug.print("\n", .{});
        }
    }

    /// Extract metadata from a port
    pub fn extractMetadata(self: *PortsMigrator, origin: []const u8) !PortMetadata {
        // Parse origin to extract optional flavor (e.g., "devel/py-setuptools@py311")
        const parsed = ParsedOrigin.parse(origin);

        const port_path = try std.fs.path.join(self.allocator, &[_][]const u8{
            self.options.ports_tree,
            parsed.path, // Use path without @flavor suffix
        });
        defer self.allocator.free(port_path);

        // Verify port exists
        std.fs.cwd().access(port_path, .{}) catch {
            return PortsError.PortNotFound;
        };

        // Extract variables using make -V (pass flavor if specified)
        const flavor = parsed.flavor;
        var metadata: PortMetadata = undefined;
        metadata.allocator = self.allocator;

        // Core identity
        metadata.name = try self.makeVarWithFlavor(port_path, "PORTNAME", flavor);
        metadata.version = try self.makeVarWithFlavor(port_path, "PORTVERSION", flavor);

        // Parse revision (free the string after parsing)
        const revision_str = try self.makeVarOptionalWithFlavor(port_path, "PORTREVISION", flavor);
        if (revision_str) |rev| {
            metadata.revision = std.fmt.parseInt(u32, rev, 10) catch 0;
            self.allocator.free(rev);
        } else {
            metadata.revision = 0;
        }

        // Parse epoch (free the string after parsing)
        const epoch_str = try self.makeVarOptionalWithFlavor(port_path, "PORTEPOCH", flavor);
        if (epoch_str) |ep| {
            metadata.epoch = std.fmt.parseInt(u32, ep, 10) catch 0;
            self.allocator.free(ep);
        } else {
            metadata.epoch = 0;
        }

        // Categories
        const cats_str = try self.makeVarWithFlavor(port_path, "CATEGORIES", flavor);
        metadata.categories = try self.splitWhitespace(cats_str);
        self.allocator.free(cats_str);

        // Descriptive
        metadata.comment = try self.makeVarOptionalWithFlavor(port_path, "COMMENT", flavor) orelse try self.allocator.dupe(u8, "");
        metadata.description = try self.readPkgDescr(port_path);
        metadata.maintainer = try self.makeVarOptionalWithFlavor(port_path, "MAINTAINER", flavor) orelse try self.allocator.dupe(u8, "ports@FreeBSD.org");
        metadata.www = try self.makeVarOptionalWithFlavor(port_path, "WWW", flavor) orelse try self.allocator.dupe(u8, "");
        metadata.license = try self.makeVarOptionalWithFlavor(port_path, "LICENSE", flavor) orelse try self.allocator.dupe(u8, "");

        // Source
        const sites_str = try self.makeVarOptionalWithFlavor(port_path, "MASTER_SITES", flavor) orelse try self.allocator.dupe(u8, "");
        metadata.master_sites = try self.splitWhitespace(sites_str);
        self.allocator.free(sites_str);

        const distfiles_str = try self.makeVarOptionalWithFlavor(port_path, "DISTFILES", flavor) orelse try self.allocator.dupe(u8, "");
        metadata.distfiles = try self.splitWhitespace(distfiles_str);
        self.allocator.free(distfiles_str);

        metadata.distinfo_sha256 = try self.readDistinfoSha256(port_path);

        // Dependencies (these also need flavor for correct resolution)
        metadata.build_depends = try self.parseDependenciesWithFlavor(port_path, "BUILD_DEPENDS", flavor);
        metadata.lib_depends = try self.parseDependenciesWithFlavor(port_path, "LIB_DEPENDS", flavor);
        metadata.run_depends = try self.parseDependenciesWithFlavor(port_path, "RUN_DEPENDS", flavor);
        metadata.test_depends = try self.parseDependenciesWithFlavor(port_path, "TEST_DEPENDS", flavor);

        // Build configuration
        const uses_str = try self.makeVarOptionalWithFlavor(port_path, "USES", flavor) orelse try self.allocator.dupe(u8, "");
        metadata.uses = try self.splitWhitespace(uses_str);
        self.allocator.free(uses_str);

        metadata.options = try self.parseOptionsWithFlavor(port_path, flavor);

        const flavors_str = try self.makeVarOptionalWithFlavor(port_path, "FLAVORS", flavor) orelse try self.allocator.dupe(u8, "");
        metadata.flavors = try self.splitWhitespace(flavors_str);
        self.allocator.free(flavors_str);

        const conflicts_str = try self.makeVarOptionalWithFlavor(port_path, "CONFLICTS", flavor) orelse try self.allocator.dupe(u8, "");
        metadata.conflicts = try self.splitWhitespace(conflicts_str);
        self.allocator.free(conflicts_str);

        // Detect configure style
        metadata.configure_style = self.detectConfigureStyle(metadata.uses);
        metadata.make_jobs_unsafe = try self.hasMakeVarWithFlavor(port_path, "MAKE_JOBS_UNSAFE", flavor);
        metadata.no_arch = try self.hasMakeVarWithFlavor(port_path, "NO_ARCH", flavor);

        return metadata;
    }

    /// Generate Axiom manifest from port metadata
    /// Uses origin to correctly handle Python package naming (e.g., py-flit-core@py311 → py311-flit-core)
    pub fn generateManifest(self: *PortsMigrator, meta: *const PortMetadata, origin: []const u8) !manifest_pkg.Manifest {
        var manifest: manifest_pkg.Manifest = undefined;

        // Use mapPortNameAlloc to get correct package name (handles Python flavors)
        manifest.name = try self.mapPortNameAlloc(origin);
        manifest.version = try types.Version.parse(meta.version);
        manifest.revision = meta.revision;
        manifest.description = try self.allocator.dupe(u8, meta.comment);
        manifest.license = try self.allocator.dupe(u8, meta.license);
        manifest.homepage = try self.allocator.dupe(u8, meta.www);

        // Map provides (the port provides itself as a virtual package)
        var provides = std.ArrayList([]const u8).init(self.allocator);
        try provides.append(try self.allocator.dupe(u8, meta.name));
        manifest.provides = try provides.toOwnedSlice();

        // Map conflicts
        var conflicts = std.ArrayList([]const u8).init(self.allocator);
        for (meta.conflicts) |c| {
            try conflicts.append(try self.allocator.dupe(u8, c));
        }
        manifest.conflicts = try conflicts.toOwnedSlice();

        manifest.replaces = &[_][]const u8{};

        return manifest;
    }

    /// Generate deps.yaml content from port metadata
    pub fn generateDepsYaml(self: *PortsMigrator, meta: *const PortMetadata) ![]const u8 {
        var output = std.ArrayList(u8).init(self.allocator);
        const writer = output.writer();

        try writer.writeAll("# Generated from FreeBSD port: ");
        try writer.writeAll(meta.name);
        try writer.writeAll("\n# Original categories: ");
        for (meta.categories, 0..) |cat, i| {
            if (i > 0) try writer.writeAll(", ");
            try writer.writeAll(cat);
        }
        try writer.writeAll("\n\n");

        // Build dependencies
        if (meta.build_depends.len > 0) {
            try writer.writeAll("build:\n");
            for (meta.build_depends) |dep| {
                try writer.writeAll("  - name: ");
                try writer.writeAll(self.mapPortName(dep.package));
                try writer.writeAll("\n");
                if (dep.version) |v| {
                    try writer.writeAll("    constraint: \"");
                    try writer.writeAll(v);
                    try writer.writeAll("\"\n");
                }
                try writer.writeAll("    # origin: ");
                try writer.writeAll(dep.origin);
                try writer.writeAll("\n");
            }
            try writer.writeAll("\n");
        }

        // Runtime dependencies (lib + run)
        const has_runtime = meta.lib_depends.len > 0 or meta.run_depends.len > 0;
        if (has_runtime) {
            try writer.writeAll("runtime:\n");
            for (meta.lib_depends) |dep| {
                try writer.writeAll("  - name: ");
                try writer.writeAll(self.mapPortName(dep.package));
                try writer.writeAll("\n");
                if (dep.file_or_lib) |lib| {
                    try writer.writeAll("    # lib: ");
                    try writer.writeAll(lib);
                    try writer.writeAll("\n");
                }
                try writer.writeAll("    # origin: ");
                try writer.writeAll(dep.origin);
                try writer.writeAll("\n");
            }
            for (meta.run_depends) |dep| {
                try writer.writeAll("  - name: ");
                try writer.writeAll(self.mapPortName(dep.package));
                try writer.writeAll("\n");
                try writer.writeAll("    # origin: ");
                try writer.writeAll(dep.origin);
                try writer.writeAll("\n");
            }
        }

        return output.toOwnedSlice();
    }

    /// Generate build.yaml recipe from port metadata
    pub fn generateBuildYaml(self: *PortsMigrator, meta: *const PortMetadata) ![]const u8 {
        var output = std.ArrayList(u8).init(self.allocator);
        const writer = output.writer();

        try writer.writeAll("# Generated from FreeBSD port\n");
        try writer.writeAll("# Manual review recommended before building\n\n");

        try writer.writeAll("name: ");
        try writer.writeAll(self.mapPortName(meta.name));
        try writer.writeAll("\n");

        try writer.writeAll("version: \"");
        try writer.writeAll(meta.version);
        try writer.writeAll("\"\n");

        try writer.writeAll("description: ");
        try writer.writeAll(meta.comment);
        try writer.writeAll("\n\n");

        // Source
        try writer.writeAll("source:\n");
        if (meta.master_sites.len > 0 and meta.distfiles.len > 0) {
            try writer.writeAll("  url: ");
            try writer.writeAll(meta.master_sites[0]);
            try writer.writeAll(meta.distfiles[0]);
            try writer.writeAll("\n");
        } else {
            try writer.writeAll("  url: # FIXME: determine source URL\n");
        }
        if (meta.distinfo_sha256.len > 0) {
            try writer.writeAll("  sha256: ");
            try writer.writeAll(meta.distinfo_sha256);
            try writer.writeAll("\n");
        }
        try writer.writeAll("\n");

        // USES hints
        if (meta.uses.len > 0) {
            try writer.writeAll("# FreeBSD USES: ");
            for (meta.uses, 0..) |u, i| {
                if (i > 0) try writer.writeAll(" ");
                try writer.writeAll(u);
            }
            try writer.writeAll("\n\n");
        }

        // Build phases based on configure style
        try writer.writeAll("phases:\n");

        switch (meta.configure_style) {
            .gnu_configure => {
                try writer.writeAll("  configure: |\n");
                try writer.writeAll("    ./configure --prefix=$PREFIX\n");
                try writer.writeAll("  build: |\n");
                if (meta.make_jobs_unsafe) {
                    try writer.writeAll("    make\n");
                } else {
                    try writer.writeAll("    make -j$JOBS\n");
                }
                try writer.writeAll("  install: |\n");
                try writer.writeAll("    make install DESTDIR=$DESTDIR\n");
            },
            .cmake => {
                try writer.writeAll("  configure: |\n");
                try writer.writeAll("    cmake -B build -DCMAKE_INSTALL_PREFIX=$PREFIX\n");
                try writer.writeAll("  build: |\n");
                try writer.writeAll("    cmake --build build -j$JOBS\n");
                try writer.writeAll("  install: |\n");
                try writer.writeAll("    DESTDIR=$DESTDIR cmake --install build\n");
            },
            .meson => {
                try writer.writeAll("  configure: |\n");
                try writer.writeAll("    meson setup build --prefix=$PREFIX\n");
                try writer.writeAll("  build: |\n");
                try writer.writeAll("    meson compile -C build\n");
                try writer.writeAll("  install: |\n");
                try writer.writeAll("    DESTDIR=$DESTDIR meson install -C build\n");
            },
            .cargo => {
                try writer.writeAll("  build: |\n");
                try writer.writeAll("    cargo build --release\n");
                try writer.writeAll("  install: |\n");
                try writer.writeAll("    install -d $DESTDIR$PREFIX/bin\n");
                try writer.writeAll("    install -m 755 target/release/* $DESTDIR$PREFIX/bin/\n");
            },
            .go => {
                try writer.writeAll("  build: |\n");
                try writer.writeAll("    go build -o build/\n");
                try writer.writeAll("  install: |\n");
                try writer.writeAll("    install -d $DESTDIR$PREFIX/bin\n");
                try writer.writeAll("    install -m 755 build/* $DESTDIR$PREFIX/bin/\n");
            },
            .python => {
                try writer.writeAll("  build: |\n");
                try writer.writeAll("    python setup.py build\n");
                try writer.writeAll("  install: |\n");
                try writer.writeAll("    python setup.py install --prefix=$PREFIX --root=$DESTDIR\n");
            },
            else => {
                try writer.writeAll("  # FIXME: determine build steps from USES\n");
                try writer.writeAll("  configure: |\n");
                try writer.writeAll("    # Configure step\n");
                try writer.writeAll("  build: |\n");
                if (meta.make_jobs_unsafe) {
                    try writer.writeAll("    make\n");
                } else {
                    try writer.writeAll("    make -j$JOBS\n");
                }
                try writer.writeAll("  install: |\n");
                try writer.writeAll("    make install DESTDIR=$DESTDIR\n");
            },
        }

        try writer.writeAll("\npost_process:\n");
        try writer.writeAll("  strip: true\n");
        try writer.writeAll("  compress_man: true\n");

        return output.toOwnedSlice();
    }

    /// Write generated files to output directory
    pub fn writeGeneratedFiles(
        self: *PortsMigrator,
        origin: []const u8,
        manifest_yaml: []const u8,
        deps_yaml: []const u8,
        build_yaml: []const u8,
    ) !void {
        // Create output directory: output_dir/category/portname/
        const out_path = try std.fs.path.join(self.allocator, &[_][]const u8{
            self.options.output_dir,
            origin,
        });
        defer self.allocator.free(out_path);

        // Create parent directories
        const parent = std.fs.path.dirname(out_path) orelse ".";
        std.fs.cwd().makePath(parent) catch |err| {
            errors.logMkdirBestEffort(@src(), err, parent);
        };
        std.fs.cwd().makePath(out_path) catch |err| {
            errors.logMkdirBestEffort(@src(), err, out_path);
        };

        // Write manifest.yaml
        const manifest_path = try std.fs.path.join(self.allocator, &[_][]const u8{
            out_path,
            "manifest.yaml",
        });
        defer self.allocator.free(manifest_path);

        const manifest_file = try std.fs.cwd().createFile(manifest_path, .{});
        defer manifest_file.close();
        try manifest_file.writeAll(manifest_yaml);

        // Write deps.yaml
        const deps_path = try std.fs.path.join(self.allocator, &[_][]const u8{
            out_path,
            "deps.yaml",
        });
        defer self.allocator.free(deps_path);

        const deps_file = try std.fs.cwd().createFile(deps_path, .{});
        defer deps_file.close();
        try deps_file.writeAll(deps_yaml);

        // Write build.yaml
        const build_path = try std.fs.path.join(self.allocator, &[_][]const u8{
            out_path,
            "build.yaml",
        });
        defer self.allocator.free(build_path);

        const build_file = try std.fs.cwd().createFile(build_path, .{});
        defer build_file.close();
        try build_file.writeAll(build_yaml);
    }

    /// Full migration: extract, generate, optionally build and import
    pub fn migrate(self: *PortsMigrator, origin: []const u8) !MigrationResult {
        // Duplicate origin so MigrationResult owns its copy
        // (caller's origin may be freed, e.g., from dep_tree in migrateWithDependencies)
        const owned_origin = try self.allocator.dupe(u8, origin);
        errdefer self.allocator.free(owned_origin);

        var result: MigrationResult = .{
            .origin = owned_origin,
            .status = .pending,
            .manifest_path = null,
            .axiom_package = null,
            .warnings = std.ArrayList([]const u8).init(self.allocator),
            .errors = std.ArrayList([]const u8).init(self.allocator),
        };

        // Check if port should be skipped (e.g., ports-mgmt/pkg is replaced by Axiom)
        for (SKIP_PORTS) |skip_origin| {
            if (std.mem.eql(u8, origin, skip_origin)) {
                std.debug.print("  ⊘ Skipping {s} (replaced by Axiom)\n", .{origin});
                result.status = .skipped;
                result.skip_reason = .replaced_by_axiom;
                return result;
            }
        }

        // Phase 1: Extract metadata
        var metadata = self.extractMetadata(origin) catch |err| {
            result.status = .failed;
            try result.errors.append(try std.fmt.allocPrint(
                self.allocator,
                "Failed to extract metadata: {s}",
                .{@errorName(err)},
            ));
            return result;
        };
        defer metadata.deinit();

        // Check if package already exists in store (skip only if same origin)
        if (self.options.store) |store| {
            // Use mapPortNameAlloc to get correct package name (handles Python flavors)
            const pkg_name = try self.mapPortNameAlloc(origin);
            defer self.allocator.free(pkg_name);

            const exists = store.packageNameExists(pkg_name) catch false;
            if (exists) {
                // Check if the existing package has the same origin
                const existing_origin = store.getPackageOriginByName(pkg_name) catch null;
                defer if (existing_origin) |o| self.allocator.free(o);

                const should_skip = if (existing_origin) |existing|
                    std.mem.eql(u8, existing, origin)
                else
                    // No origin recorded - legacy package built before origin tracking
                    // Proceed with build to replace it with properly tracked package
                    false;

                if (should_skip) {
                    std.debug.print("  ✓ Package '{s}' already in store (same origin: {s}), skipping\n", .{ pkg_name, origin });
                    result.status = .skipped;
                    result.skip_reason = .already_in_store;
                    result.axiom_package = try std.fmt.allocPrint(
                        self.allocator,
                        "{s} (existing)",
                        .{pkg_name},
                    );
                    return result;
                } else if (existing_origin) |existing| {
                    // Different origin - warn and proceed
                    std.debug.print("  ⚠ Package '{s}' exists from different origin ({s}), building from {s}\n", .{
                        pkg_name,
                        existing,
                        origin,
                    });
                } else {
                    // Legacy package with no origin - will be replaced
                    std.debug.print("  ⚠ Package '{s}' exists (no origin recorded), rebuilding from {s}\n", .{
                        pkg_name,
                        origin,
                    });
                }
            }
        }

        // Check for unsupported features
        if (metadata.flavors.len > 0 and !self.options.skip_options) {
            try result.warnings.append(try self.allocator.dupe(u8, "Port has FLAVORS - only default flavor generated"));
        }
        if (metadata.options.len > 0 and !self.options.skip_options) {
            try result.warnings.append(try std.fmt.allocPrint(
                self.allocator,
                "Port has {d} OPTIONS - only default options used",
                .{metadata.options.len},
            ));
        }

        // Generate YAML files
        const manifest_yaml = try self.generateManifestYaml(&metadata, origin);
        defer self.allocator.free(manifest_yaml);

        const deps_yaml = try self.generateDepsYaml(&metadata);
        defer self.allocator.free(deps_yaml);

        const build_yaml = try self.generateBuildYaml(&metadata);
        defer self.allocator.free(build_yaml);

        // Write files
        if (!self.options.dry_run) {
            try self.writeGeneratedFiles(origin, manifest_yaml, deps_yaml, build_yaml);

            const out_path = try std.fs.path.join(self.allocator, &[_][]const u8{
                self.options.output_dir,
                origin,
            });
            result.manifest_path = out_path;
        }

        result.status = .generated;

        // Phase 2: Build (optional)
        if (self.options.build_after_generate and !self.options.dry_run) {
            const build_result = self.buildPort(origin, &metadata, result.manifest_path) catch |err| {
                try result.errors.append(try std.fmt.allocPrint(
                    self.allocator,
                    "Build failed: {s}",
                    .{@errorName(err)},
                ));
                result.status = .failed;
                return result;
            };

            result.status = .built;

            // Phase 3: Import (optional)
            if (self.options.import_after_build) {
                // Get the mapped package name before import (importPort's copy is freed on return)
                const display_name = try self.mapPortNameAlloc(origin);
                defer self.allocator.free(display_name);

                const pkg_id = self.importPort(&metadata, build_result.output_dir, origin) catch |err| {
                    try result.errors.append(try std.fmt.allocPrint(
                        self.allocator,
                        "Import failed: {s}",
                        .{@errorName(err)},
                    ));
                    result.status = .failed;
                    // Clean up build output before returning
                    if (!self.options.keep_sandbox) {
                        std.fs.cwd().deleteTree(build_result.output_dir) catch |cleanup_err| {
                            errors.logFileCleanup(@src(), cleanup_err, build_result.output_dir);
                        };
                    }
                    self.allocator.free(build_result.output_dir);
                    return result;
                };

                result.status = .imported;
                // Use display_name instead of pkg_id.name (which points to freed memory)
                result.axiom_package = try std.fmt.allocPrint(
                    self.allocator,
                    "{s}@{}.{}.{}-r{d}",
                    .{ display_name, pkg_id.version.major, pkg_id.version.minor, pkg_id.version.patch, pkg_id.revision },
                );

                // Free the build_id that was allocated during import
                // (ports import always generates a build_id, so it's always allocated)
                self.allocator.free(pkg_id.build_id);
            }

            // Clean up build output if we're not keeping the sandbox
            if (!self.options.keep_sandbox) {
                std.fs.cwd().deleteTree(build_result.output_dir) catch |err| {
                    errors.logFileCleanup(@src(), err, build_result.output_dir);
                };
            }
            self.allocator.free(build_result.output_dir);
        }

        return result;
    }

    /// Build result from port build
    const PortBuildResult = struct {
        output_dir: []const u8,
        success: bool,
    };

    /// Build environment with sysroot containing symlinked dependencies
    /// The sysroot approach merges all dependency packages into a single directory tree,
    /// allowing wrapper scripts (like autoconf-switch) to find related binaries.
    const BuildEnvironment = struct {
        /// Path to the sysroot directory (e.g., /tmp/axiom-sysroot-XXXX/usr/local)
        /// All dependency binaries, libraries, headers are symlinked here
        sysroot: []const u8,
        /// PATH with sysroot bin/ first, then system paths
        path: []const u8,
        /// LD_LIBRARY_PATH with sysroot lib/ first
        ld_library_path: []const u8,
        /// LDFLAGS pointing to sysroot lib/
        ldflags: []const u8,
        /// CPPFLAGS pointing to sysroot include/
        cppflags: []const u8,
        /// PYTHONPATH for Python packages in sysroot lib/python*/site-packages
        pythonpath: []const u8,
        /// PERL5LIB for Perl modules in sysroot lib/perl5/site_perl
        perl5lib: []const u8,
        /// Path to gmake binary in sysroot (for GMAKE override)
        /// FreeBSD ports use GMAKE variable which defaults to /usr/local/bin/gmake
        gmake_path: []const u8,
        /// Path to cmake binary in sysroot (for CMAKE override)
        /// FreeBSD ports use CMAKE variable which defaults to /usr/local/bin/cmake
        cmake_path: []const u8,
        allocator: std.mem.Allocator,

        pub fn deinit(self: *BuildEnvironment) void {
            // Clean up the sysroot directory
            if (self.sysroot.len > 0) {
                // Get parent of sysroot (the temp directory)
                if (std.fs.path.dirname(self.sysroot)) |sysroot_parent| {
                    if (std.fs.path.dirname(sysroot_parent)) |temp_dir| {
                        std.fs.cwd().deleteTree(temp_dir) catch |err| {
                            errors.logFileCleanup(@src(), err, temp_dir);
                        };
                    }
                }
            }
            self.allocator.free(self.sysroot);
            self.allocator.free(self.path);
            self.allocator.free(self.ld_library_path);
            self.allocator.free(self.ldflags);
            self.allocator.free(self.cppflags);
            if (self.pythonpath.len > 0) self.allocator.free(self.pythonpath);
            if (self.perl5lib.len > 0) self.allocator.free(self.perl5lib);
            if (self.gmake_path.len > 0) self.allocator.free(self.gmake_path);
            if (self.cmake_path.len > 0) self.allocator.free(self.cmake_path);
        }
    };

    /// Create a sysroot directory with symlinks to all dependency package files
    /// This merges all packages into a single directory tree, solving the problem where
    /// wrapper scripts (like autoconf-switch) need to find related binaries in the same directory.
    ///
    /// Structure created:
    ///   /tmp/axiom-sysroot-XXXX/usr/local/
    ///     ├── bin/      (symlinks to all dependency bin files)
    ///     ├── lib/      (symlinks to all dependency lib files)
    ///     ├── include/  (symlinks to all dependency include files)
    ///     ├── share/    (symlinks to all dependency share files)
    ///     └── libexec/  (symlinks to all dependency libexec files)
    fn createBuildSysroot(self: *PortsMigrator, package_roots: []const []const u8) ![]const u8 {
        // Generate unique sysroot path
        const timestamp = std.time.timestamp();
        var random_bytes: [4]u8 = undefined;
        std.crypto.random.bytes(&random_bytes);

        // sysroot_root is the base directory (e.g., /tmp/axiom-sysroot-XXX)
        // Packages are linked here, preserving their usr/local structure
        const sysroot_root = try std.fmt.allocPrint(
            self.allocator,
            "/tmp/axiom-sysroot-{d}-{x:0>2}{x:0>2}{x:0>2}{x:0>2}",
            .{ timestamp, random_bytes[0], random_bytes[1], random_bytes[2], random_bytes[3] },
        );
        // sysroot_root is only needed during setup; free it when function exits
        // (sysroot_localbase contains the full path that will be returned to caller)
        defer self.allocator.free(sysroot_root);

        // sysroot_localbase is the path that will be used for search paths (PATH, LDFLAGS, CPPFLAGS)
        // Note: LOCALBASE for ports is always /usr/local (the install prefix), NOT the sysroot
        const sysroot_localbase = try std.fs.path.join(self.allocator, &[_][]const u8{
            sysroot_root,
            "usr/local",
        });
        errdefer self.allocator.free(sysroot_localbase);

        // Create the sysroot_localbase directory structure
        const subdirs = [_][]const u8{ "bin", "lib", "include", "share", "libexec", "lib/perl5", "share/aclocal" };
        for (subdirs) |subdir| {
            const full_path = try std.fs.path.join(self.allocator, &[_][]const u8{ sysroot_localbase, subdir });
            defer self.allocator.free(full_path);
            try std.fs.cwd().makePath(full_path);
        }

        std.debug.print("    [SYSROOT] Creating sysroot at: {s}\n", .{sysroot_root});
        std.debug.print("    [SYSROOT] Sysroot localbase: {s}\n", .{sysroot_localbase});

        // Link files from each package root into the sysroot
        // Detect package layout and link appropriately:
        // - If package has usr/local/ structure, link root/* to sysroot_root/*
        // - If package has direct layout (bin/, lib/), link root/* to sysroot_root/usr/local/*
        for (package_roots) |root| {
            std.debug.print("    [SYSROOT]   Linking from: {s}\n", .{root});

            // First, check for broken layout (root/tmp/axiom-sysroot-*/usr/local)
            // This happens when packages were built with LOCALBASE set to the sysroot path
            const broken_content_path = try self.findBrokenLayoutContent(root);
            if (broken_content_path) |content_path| {
                defer self.allocator.free(content_path);
                std.debug.print("    [SYSROOT]     Layout: BROKEN (found content at {s})\n", .{content_path});
                std.debug.print("    [SYSROOT]     WARNING: Package has broken layout, linking from nested path\n", .{});
                try self.linkTreeContents(content_path, sysroot_localbase);
                continue;
            }

            // Check if this package uses usr/local layout or direct layout
            const usr_local_path = try std.fs.path.join(self.allocator, &[_][]const u8{ root, "usr/local" });
            defer self.allocator.free(usr_local_path);

            const has_usr_local = blk: {
                std.fs.cwd().access(usr_local_path, .{}) catch {
                    break :blk false;
                };
                break :blk true;
            };

            if (has_usr_local) {
                // Package uses usr/local layout (e.g., from broken LOCALBASE builds)
                // Link root/* to sysroot_root/* to preserve the usr/local structure
                std.debug.print("    [SYSROOT]     Layout: usr/local (preserving structure)\n", .{});
                try self.linkTreeContents(root, sysroot_root);
            } else {
                // Package uses direct layout (bin/, lib/, share/ directly under root)
                // Link root/* to sysroot_root/usr/local/* to match LOCALBASE
                std.debug.print("    [SYSROOT]     Layout: direct (linking to usr/local)\n", .{});
                try self.linkTreeContents(root, sysroot_localbase);
            }
        }

        // Return sysroot_localbase (sysroot_root/usr/local) as that's what callers expect
        // for building search paths (PATH, LDFLAGS, CPPFLAGS)
        // Note: sysroot_root is freed by defer above; sysroot_localbase ownership transfers to caller
        return sysroot_localbase;
    }

    /// Recursively link/copy contents of a source directory tree into a destination
    /// Preserves the directory structure from source
    fn linkTreeContents(self: *PortsMigrator, src_root: []const u8, dst_root: []const u8) !void {
        var src_dir = std.fs.cwd().openDir(src_root, .{ .iterate = true }) catch |err| {
            std.debug.print("    [SYSROOT] Warning: could not open {s}: {}\n", .{ src_root, err });
            return; // Source doesn't exist, skip
        };
        defer src_dir.close();

        var walker = src_dir.walk(self.allocator) catch |err| {
            std.debug.print("    [SYSROOT] Warning: could not walk {s}: {}\n", .{ src_root, err });
            return;
        };
        defer walker.deinit();

        var file_count: usize = 0;
        while (walker.next() catch null) |entry| {
            const src_path = try std.fs.path.join(self.allocator, &[_][]const u8{ src_root, entry.path });
            defer self.allocator.free(src_path);

            const dst_path = try std.fs.path.join(self.allocator, &[_][]const u8{ dst_root, entry.path });
            defer self.allocator.free(dst_path);

            switch (entry.kind) {
                .directory => {
                    std.fs.cwd().makePath(dst_path) catch |err| {
                        errors.logMkdirBestEffort(@src(), err, dst_path);
                    };
                },
                .file => {
                    // Ensure parent directory exists
                    if (std.fs.path.dirname(dst_path)) |parent| {
                        std.fs.cwd().makePath(parent) catch |err| {
                            errors.logMkdirBestEffort(@src(), err, parent);
                        };
                    }

                    // Check if destination already exists
                    std.fs.cwd().access(dst_path, .{}) catch {
                        // Doesn't exist - check if this is a bin/ file (copy) or other (symlink)
                        const is_bin = std.mem.indexOf(u8, entry.path, "bin/") != null or
                            std.mem.indexOf(u8, entry.path, "libexec/") != null;

                        if (is_bin) {
                            // Copy executables so $0 points to sysroot path
                            std.fs.copyFileAbsolute(src_path, dst_path, .{}) catch |err| {
                                std.debug.print("    [SYSROOT] Warning: could not copy {s}: {}\n", .{ entry.path, err });
                            };
                            file_count += 1;
                        } else {
                            // Symlink libraries and other files
                            std.fs.cwd().symLink(src_path, dst_path, .{}) catch |err| {
                                if (self.options.verbose) {
                                    std.debug.print("    [SYSROOT] Warning: could not symlink {s}: {}\n", .{ entry.path, err });
                                }
                            };
                            file_count += 1;
                        }
                    };
                },
                .sym_link => {
                    // Preserve symlinks
                    std.fs.cwd().access(dst_path, .{}) catch {
                        var target_buf: [std.fs.max_path_bytes]u8 = undefined;
                        const target = std.fs.cwd().readLink(src_path, &target_buf) catch continue;
                        std.fs.cwd().symLink(target, dst_path, .{}) catch |err| {
                            errors.logNonCriticalWithCategory(@src(), err, .io, "create symlink", dst_path);
                        };
                        file_count += 1;
                    };
                },
                else => {},
            }
        }

        if (file_count == 0) {
            std.debug.print("    [SYSROOT] Warning: no files linked from {s}\n", .{src_root});
        }
    }

    /// Detect and return the content path for packages with broken layout
    /// Broken packages have structure: root/tmp/axiom-sysroot-*/usr/local/...
    /// This happens when LOCALBASE was incorrectly set to the sysroot path during build
    fn findBrokenLayoutContent(self: *PortsMigrator, root: []const u8) !?[]const u8 {
        // Check if root/tmp exists
        const tmp_path = try std.fs.path.join(self.allocator, &[_][]const u8{ root, "tmp" });
        defer self.allocator.free(tmp_path);

        var tmp_dir = std.fs.cwd().openDir(tmp_path, .{ .iterate = true }) catch {
            return null; // No tmp directory, not a broken layout
        };
        defer tmp_dir.close();

        // Look for axiom-sysroot-* directories
        var iter = tmp_dir.iterate();
        while (iter.next() catch null) |entry| {
            if (entry.kind != .directory) continue;
            if (!std.mem.startsWith(u8, entry.name, "axiom-sysroot-")) continue;

            // Found a sysroot directory, check for usr/local inside
            const sysroot_path = try std.fs.path.join(self.allocator, &[_][]const u8{
                tmp_path,
                entry.name,
                "usr/local",
            });

            // Check if this path exists and has content
            std.fs.cwd().access(sysroot_path, .{}) catch {
                self.allocator.free(sysroot_path);
                continue;
            };

            // Found valid content path
            return sysroot_path;
        }

        return null;
    }

    /// Scan the package store for packages with broken layout
    /// Returns a list of (package_name, origin) tuples for packages that need rebuilding
    pub fn findBrokenPackages(self: *PortsMigrator) !std.ArrayList(BrokenPackage) {
        var broken = std.ArrayList(BrokenPackage).init(self.allocator);
        errdefer {
            for (broken.items) |b| b.deinit(self.allocator);
            broken.deinit();
        }

        // Require store to be configured
        _ = self.options.store orelse return broken;
        const store_path = "/axiom/store/pkg";

        var store_dir = std.fs.cwd().openDir(store_path, .{ .iterate = true }) catch {
            return broken;
        };
        defer store_dir.close();

        // Iterate over package names
        var pkg_iter = store_dir.iterate();
        while (pkg_iter.next() catch null) |pkg_entry| {
            if (pkg_entry.kind != .directory) continue;

            // Find latest version of this package
            const pkg_path = try std.fs.path.join(self.allocator, &[_][]const u8{ store_path, pkg_entry.name });
            defer self.allocator.free(pkg_path);

            var pkg_dir = std.fs.cwd().openDir(pkg_path, .{ .iterate = true }) catch continue;
            defer pkg_dir.close();

            // Iterate versions to find root paths
            var ver_iter = pkg_dir.iterate();
            while (ver_iter.next() catch null) |ver_entry| {
                if (ver_entry.kind != .directory) continue;

                const ver_path = try std.fs.path.join(self.allocator, &[_][]const u8{ pkg_path, ver_entry.name });
                defer self.allocator.free(ver_path);

                var ver_dir = std.fs.cwd().openDir(ver_path, .{ .iterate = true }) catch continue;
                defer ver_dir.close();

                // Iterate revisions
                var rev_iter = ver_dir.iterate();
                while (rev_iter.next() catch null) |rev_entry| {
                    if (rev_entry.kind != .directory) continue;

                    const rev_path = try std.fs.path.join(self.allocator, &[_][]const u8{ ver_path, rev_entry.name });
                    defer self.allocator.free(rev_path);

                    var rev_dir = std.fs.cwd().openDir(rev_path, .{ .iterate = true }) catch continue;
                    defer rev_dir.close();

                    // Iterate build IDs
                    var build_iter = rev_dir.iterate();
                    while (build_iter.next() catch null) |build_entry| {
                        if (build_entry.kind != .directory) continue;

                        const root_path = try std.fs.path.join(self.allocator, &[_][]const u8{
                            rev_path, build_entry.name, "root",
                        });
                        defer self.allocator.free(root_path);

                        // Check if this package has broken layout
                        const broken_content = try self.findBrokenLayoutContent(root_path);
                        if (broken_content != null) {
                            self.allocator.free(broken_content.?);

                            // Try to get origin from manifest
                            const manifest_path = try std.fs.path.join(self.allocator, &[_][]const u8{
                                rev_path, build_entry.name, "manifest.yaml",
                            });
                            defer self.allocator.free(manifest_path);

                            const origin = self.readOriginFromManifest(manifest_path) catch null;

                            try broken.append(.{
                                .name = try self.allocator.dupe(u8, pkg_entry.name),
                                .origin = origin,
                                .path = try self.allocator.dupe(u8, rev_path),
                            });
                        }
                    }
                }
            }
        }

        return broken;
    }

    /// Read origin field from a manifest.yaml file
    fn readOriginFromManifest(self: *PortsMigrator, path: []const u8) ![]const u8 {
        const file = try std.fs.cwd().openFile(path, .{});
        defer file.close();

        const content = try file.readToEndAlloc(self.allocator, 1024 * 1024);
        defer self.allocator.free(content);

        // Simple parsing: look for "origin: " line
        var lines = std.mem.splitScalar(u8, content, '\n');
        while (lines.next()) |line| {
            if (std.mem.startsWith(u8, line, "origin: ")) {
                const origin = std.mem.trim(u8, line["origin: ".len..], " \t\r");
                return try self.allocator.dupe(u8, origin);
            }
        }

        return error.OriginNotFound;
    }

    /// Guess the origin for a package by searching the ports tree
    /// Maps package name back to category/portname format
    fn guessOriginFromName(self: *PortsMigrator, pkg_name: []const u8) !?[]const u8 {
        // Common package name to origin mappings
        // These handle cases where the package name differs from the port name
        const mappings = [_]struct { pkg: []const u8, origin: []const u8 }{
            .{ .pkg = "make", .origin = "devel/gmake" },
            .{ .pkg = "perl", .origin = "lang/perl5.36" },
            .{ .pkg = "python", .origin = "lang/python311" },
            .{ .pkg = "Locale-gettext", .origin = "misc/p5-Locale-gettext" },
            .{ .pkg = "Locale-libintl", .origin = "misc/p5-Locale-libintl" },
            .{ .pkg = "Unicode-EastAsianWidth", .origin = "textproc/p5-Unicode-EastAsianWidth" },
            .{ .pkg = "Text-Unidecode", .origin = "converters/p5-Text-Unidecode" },
        };

        // Check hardcoded mappings first
        for (mappings) |m| {
            if (std.mem.eql(u8, pkg_name, m.pkg)) {
                return try self.allocator.dupe(u8, m.origin);
            }
        }

        // Search common categories for a matching port
        const categories = [_][]const u8{
            "devel", "lang", "print", "misc", "textproc", "converters",
            "sysutils", "security", "net", "www", "databases", "editors",
        };

        for (categories) |category| {
            // Try exact match: category/pkg_name
            const origin = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ category, pkg_name });
            defer self.allocator.free(origin);

            const port_path = try std.fs.path.join(self.allocator, &[_][]const u8{
                self.options.ports_tree, category, pkg_name,
            });
            defer self.allocator.free(port_path);

            // Check if this port exists
            if (std.fs.cwd().access(port_path, .{})) |_| {
                return try self.allocator.dupe(u8, origin);
            } else |_| {}
        }

        // Try searching for PORTNAME match in common categories
        for (categories) |category| {
            const cat_path = try std.fs.path.join(self.allocator, &[_][]const u8{
                self.options.ports_tree, category,
            });
            defer self.allocator.free(cat_path);

            var cat_dir = std.fs.cwd().openDir(cat_path, .{ .iterate = true }) catch continue;
            defer cat_dir.close();

            var iter = cat_dir.iterate();
            while (iter.next() catch null) |entry| {
                if (entry.kind != .directory) continue;

                // Check if the Makefile's PORTNAME matches our package name
                const makefile_path = try std.fs.path.join(self.allocator, &[_][]const u8{
                    cat_path, entry.name, "Makefile",
                });
                defer self.allocator.free(makefile_path);

                const file = std.fs.cwd().openFile(makefile_path, .{}) catch continue;
                defer file.close();

                const content = file.readToEndAlloc(self.allocator, 64 * 1024) catch continue;
                defer self.allocator.free(content);

                // Look for PORTNAME= line
                var lines = std.mem.splitScalar(u8, content, '\n');
                while (lines.next()) |line| {
                    if (std.mem.startsWith(u8, line, "PORTNAME=")) {
                        const portname = std.mem.trim(u8, line["PORTNAME=".len..], " \t");
                        if (std.mem.eql(u8, portname, pkg_name)) {
                            return try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ category, entry.name });
                        }
                        break; // Only check first PORTNAME
                    }
                }
            }
        }

        return null;
    }

    /// Fix broken packages by destroying and rebuilding them
    pub fn fixBrokenPackages(self: *PortsMigrator) !usize {
        const broken = try self.findBrokenPackages();
        defer {
            for (broken.items) |b| b.deinit(self.allocator);
            broken.deinit();
        }

        if (broken.items.len == 0) {
            std.debug.print("No broken packages found.\n", .{});
            return 0;
        }

        // Deduplicate by package name - we destroy entire ZFS datasets so only need to process once
        var unique_packages = std.StringHashMap(BrokenPackage).init(self.allocator);
        defer unique_packages.deinit();

        for (broken.items) |b| {
            if (!unique_packages.contains(b.name)) {
                try unique_packages.put(b.name, b);
            }
        }

        const unique_count = unique_packages.count();
        std.debug.print("\nFound {d} broken build(s) across {d} unique package(s):\n", .{ broken.items.len, unique_count });

        var iter = unique_packages.iterator();
        while (iter.next()) |entry| {
            const b = entry.value_ptr.*;
            std.debug.print("  - {s}", .{b.name});
            if (b.origin) |o| {
                std.debug.print(" (origin: {s})", .{o});
            }
            std.debug.print("\n", .{});
        }
        std.debug.print("\n", .{});

        var fixed: usize = 0;
        var pkg_iter = unique_packages.iterator();
        while (pkg_iter.next()) |entry| {
            const b = entry.value_ptr.*;
            // Try to get origin from manifest, or guess it from package name
            const origin = b.origin orelse blk: {
                const guessed = self.guessOriginFromName(b.name) catch null;
                if (guessed) |g| {
                    std.debug.print("Guessed origin for {s}: {s}\n", .{ b.name, g });
                    break :blk g;
                }
                std.debug.print("Skipping {s}: no origin recorded and couldn't guess\n", .{b.name});
                continue;
            };
            defer if (b.origin == null) self.allocator.free(origin);

            std.debug.print("Fixing {s} from {s}...\n", .{ b.name, origin });

            // Destroy the broken package using direct zfs command with -Rf
            // -R = recursive including clones, -f = force unmount
            const dataset = try std.fmt.allocPrint(self.allocator, "zroot/axiom/store/pkg/{s}", .{b.name});
            defer self.allocator.free(dataset);

            const destroy_cmd = try std.fmt.allocPrint(self.allocator, "zfs destroy -Rf {s} 2>&1", .{dataset});
            defer self.allocator.free(destroy_cmd);

            var child = std.process.Child.init(&[_][]const u8{ "sh", "-c", destroy_cmd }, self.allocator);
            child.stdout_behavior = .Pipe;
            child.stderr_behavior = .Pipe;

            child.spawn() catch |err| {
                std.debug.print("  Failed to spawn destroy command: {s}\n", .{@errorName(err)});
                continue;
            };

            const stdout = child.stdout.?.reader().readAllAlloc(self.allocator, 4096) catch "";
            defer if (stdout.len > 0) self.allocator.free(stdout);

            const term = child.wait() catch {
                std.debug.print("  Failed to wait for destroy command\n", .{});
                continue;
            };

            if (term.Exited != 0) {
                std.debug.print("  Failed to destroy {s}: {s}\n", .{ dataset, stdout });
                continue;
            }
            std.debug.print("  Destroyed {s}\n", .{dataset});

            // Rebuild the package
            var result = self.migrate(origin) catch |err| {
                std.debug.print("  Rebuild failed: {s}\n", .{@errorName(err)});
                continue;
            };
            defer result.deinit(self.allocator);

            if (result.status == .imported) {
                std.debug.print("  ✓ Rebuilt successfully\n", .{});
                fixed += 1;
            } else {
                std.debug.print("  Rebuild status: {s}\n", .{@tagName(result.status)});
            }
        }

        std.debug.print("\nFixed {d} of {d} broken packages.\n", .{ fixed, unique_count });
        return fixed;
    }

    /// Recursively link/copy contents of a directory into the sysroot
    /// For bin/ directories, we COPY files instead of symlinking because:
    /// - When kernel executes a symlinked script, it passes the RESOLVED path to the interpreter
    /// - This makes $0 point to the original package directory, not the sysroot
    /// - Wrapper scripts like autoconf-switch use $0 to find related binaries
    /// - By copying, $0 becomes the sysroot path, so ls -d "$0"[0-9]* works correctly
    fn symlinkOrCopyDirectoryContents(
        self: *PortsMigrator,
        source_base: []const u8,
        dest_base: []const u8,
        subdir: []const u8,
        copy_mode: bool, // true for bin/ directories, false for others
    ) !void {
        const source_dir_path = try std.fs.path.join(self.allocator, &[_][]const u8{ source_base, subdir });
        defer self.allocator.free(source_dir_path);

        const dest_dir_path = try std.fs.path.join(self.allocator, &[_][]const u8{ dest_base, subdir });
        defer self.allocator.free(dest_dir_path);

        var source_dir = std.fs.cwd().openDir(source_dir_path, .{ .iterate = true }) catch {
            // Source directory doesn't exist, skip
            return;
        };
        defer source_dir.close();

        // Ensure destination directory exists
        std.fs.cwd().makePath(dest_dir_path) catch |err| {
            errors.logMkdirBestEffort(@src(), err, dest_dir_path);
        };

        var iter = source_dir.iterate();
        while (try iter.next()) |entry| {
            const source_path = try std.fs.path.join(self.allocator, &[_][]const u8{ source_dir_path, entry.name });
            defer self.allocator.free(source_path);

            const dest_path = try std.fs.path.join(self.allocator, &[_][]const u8{ dest_dir_path, entry.name });
            defer self.allocator.free(dest_path);

            if (entry.kind == .directory) {
                // Recursively handle subdirectories (keep same copy_mode for nested bin/ dirs)
                const sub_subdir = try std.fs.path.join(self.allocator, &[_][]const u8{ subdir, entry.name });
                defer self.allocator.free(sub_subdir);
                try self.symlinkOrCopyDirectoryContents(source_base, dest_base, sub_subdir, copy_mode);
            } else if (entry.kind == .sym_link) {
                // Handle symlinks: read the link target and create a new symlink
                // This preserves symlinks as symlinks rather than copying their content
                std.fs.cwd().access(dest_path, .{}) catch {
                    // Read the symlink target
                    var target_buf: [std.fs.max_path_bytes]u8 = undefined;
                    const target = std.fs.cwd().readLink(source_path, &target_buf) catch |err| {
                        std.debug.print("    [SYSROOT] Warning: could not read symlink {s}: {}\n", .{ entry.name, err });
                        continue;
                    };

                    // Create symlink with same target
                    std.fs.cwd().symLink(target, dest_path, .{}) catch |err| {
                        std.debug.print("    [SYSROOT] Warning: could not create symlink {s}: {}\n", .{ entry.name, err });
                    };
                };
            } else {
                // Regular files
                std.fs.cwd().access(dest_path, .{}) catch {
                    // Doesn't exist, create link or copy
                    if (copy_mode) {
                        // Copy file for bin/ directories (preserves executable permissions)
                        std.fs.copyFileAbsolute(source_path, dest_path, .{}) catch |err| {
                            std.debug.print("    [SYSROOT] Warning: could not copy {s}: {}\n", .{ entry.name, err });
                        };
                    } else {
                        // Symlink for lib/, include/, share/, etc.
                        std.fs.cwd().symLink(source_path, dest_path, .{}) catch |err| {
                            if (self.options.verbose) {
                                std.debug.print("    [SYSROOT] Warning: could not symlink {s}: {}\n", .{ entry.name, err });
                            }
                        };
                    }
                };
            }
        }
    }

    /// Create binary aliases in the sysroot for scripts that expect unprefixed GNU tool names.
    ///
    /// On FreeBSD, GNU tools are installed with 'g' prefix (gmake, gsed, gtar, ggrep, gawk)
    /// because BSD has its own make/sed/tar/grep/awk. Some build scripts expect the
    /// unprefixed names, so we create aliases.
    ///
    /// For example:
    /// - devel/gmake: The GNU make package installs 'gmake', we create 'make' alias
    /// - devel/gsed: The GNU sed package installs 'gsed', we create 'sed' alias
    ///
    /// This creates symlinks in sysroot/bin/ from the alias name to the actual binary.
    fn createBinaryAliases(self: *PortsMigrator, sysroot: []const u8, dep_origins: []const []const u8) !void {
        // Map of port origin -> (alias_name, target_name)
        // alias_name is what we create, target_name is what the package actually installs
        const BinaryAlias = struct {
            alias: []const u8,
            target: []const u8,
        };

        const alias_map = std.StaticStringMap(BinaryAlias).initComptime(.{
            // GNU make: package installs 'gmake', create 'make' alias for scripts expecting 'make'
            .{ "devel/gmake", BinaryAlias{ .alias = "make", .target = "gmake" } },
            // GNU sed: package installs 'gsed', create 'sed' alias
            .{ "devel/gsed", BinaryAlias{ .alias = "sed", .target = "gsed" } },
            // GNU tar: package installs 'gtar', create 'tar' alias
            .{ "archivers/gtar", BinaryAlias{ .alias = "tar", .target = "gtar" } },
            // GNU grep: package installs 'ggrep', create 'grep' alias
            .{ "textproc/gnugrep", BinaryAlias{ .alias = "grep", .target = "ggrep" } },
            // GNU awk: package installs 'gawk', create 'awk' alias
            .{ "lang/gawk", BinaryAlias{ .alias = "awk", .target = "gawk" } },
        });

        const bin_dir = try std.fs.path.join(self.allocator, &[_][]const u8{ sysroot, "bin" });
        defer self.allocator.free(bin_dir);

        std.debug.print("    [DEBUG] createBinaryAliases: checking {d} origins, bin_dir={s}\n", .{ dep_origins.len, bin_dir });

        for (dep_origins) |origin| {
            if (alias_map.get(origin)) |alias_info| {
                std.debug.print("    [DEBUG] Found alias mapping for {s}: {s} -> {s}\n", .{ origin, alias_info.alias, alias_info.target });

                const target_path = try std.fs.path.join(self.allocator, &[_][]const u8{ bin_dir, alias_info.target });
                defer self.allocator.free(target_path);

                const alias_path = try std.fs.path.join(self.allocator, &[_][]const u8{ bin_dir, alias_info.alias });
                defer self.allocator.free(alias_path);

                // Check if target binary exists
                std.fs.cwd().access(target_path, .{}) catch {
                    // Target doesn't exist, skip
                    std.debug.print("    [DEBUG] Target {s} does not exist, skipping\n", .{target_path});
                    continue;
                };

                std.debug.print("    [DEBUG] Target {s} exists\n", .{target_path});

                // Check if alias already exists
                std.fs.cwd().access(alias_path, .{}) catch {
                    // Alias doesn't exist, create symlink
                    // Use relative symlink so it works regardless of sysroot location
                    std.fs.cwd().symLink(alias_info.target, alias_path, .{}) catch |err| {
                        std.debug.print("    [SYSROOT] Warning: could not create alias {s} -> {s}: {}\n", .{ alias_info.alias, alias_info.target, err });
                        continue;
                    };
                    std.debug.print("    [SYSROOT] Created alias: {s} -> {s}\n", .{ alias_info.alias, alias_info.target });
                };
            }
        }
    }

    /// Create unversioned wrapper symlinks for autotools in the sysroot.
    ///
    /// FreeBSD's devel/autoconf installs versioned binaries like:
    ///   autoconf-2.72, autoheader-2.72, autoreconf-2.72, etc.
    ///
    /// But other ports (like automake) expect unversioned 'autoconf' on PATH.
    /// Normally devel/autoconf-switch provides these wrappers via pkg.
    ///
    /// This function scans the sysroot bin directory for versioned autotools
    /// and creates symlinks from the unversioned names to the highest version found.
    fn createAutotoolsWrappers(self: *PortsMigrator, sysroot: []const u8) !void {
        const bin_dir = try std.fs.path.join(self.allocator, &[_][]const u8{ sysroot, "bin" });
        defer self.allocator.free(bin_dir);

        std.debug.print("    [DEBUG] createAutotoolsWrappers: scanning {s}\n", .{bin_dir});

        // Autotools that need unversioned wrappers
        const autotools = [_][]const u8{
            "autoconf",
            "autoheader",
            "autoreconf",
            "autom4te",
            "autoscan",
            "autoupdate",
            "ifnames",
        };

        var dir = std.fs.cwd().openDir(bin_dir, .{ .iterate = true }) catch |err| {
            std.debug.print("    [DEBUG] createAutotoolsWrappers: could not open bin dir: {}\n", .{err});
            return; // bin dir doesn't exist, nothing to do
        };
        defer dir.close();

        // First, list what's in the bin directory
        var count: usize = 0;
        var list_iter = dir.iterate();
        while (list_iter.next() catch null) |entry| {
            if (std.mem.startsWith(u8, entry.name, "auto")) {
                std.debug.print("    [DEBUG] Found in bin: {s}\n", .{entry.name});
            }
            count += 1;
        }
        std.debug.print("    [DEBUG] Total files in bin dir: {d}\n", .{count});

        for (autotools) |tool| {
            // Check if unversioned wrapper already exists
            const wrapper_path = try std.fs.path.join(self.allocator, &[_][]const u8{ bin_dir, tool });
            defer self.allocator.free(wrapper_path);

            std.fs.cwd().access(wrapper_path, .{}) catch {
                // Wrapper doesn't exist, try to find a versioned binary
                // FreeBSD autoconf installs as "autoconf2.72" (no hyphen)
                // Some other systems use "autoconf-2.72" (with hyphen)
                var best_version: ?[]const u8 = null;
                var best_target: ?[]const u8 = null;

                var iter = dir.iterate();
                while (iter.next() catch null) |entry| {
                    if (entry.kind != .file and entry.kind != .sym_link) continue;

                    // Check if this is a versioned variant of the tool
                    // Patterns: "autoconf2.72" (FreeBSD) or "autoconf-2.72" (some Linux)
                    if (entry.name.len > tool.len and
                        std.mem.startsWith(u8, entry.name, tool))
                    {
                        const suffix = entry.name[tool.len..];
                        // Check if suffix starts with a digit (e.g., "2.72") or hyphen+digit
                        const version_start: usize = if (suffix.len > 0 and suffix[0] == '-') 1 else 0;
                        if (suffix.len > version_start and
                            suffix[version_start] >= '0' and suffix[version_start] <= '9')
                        {
                            const version = suffix[version_start..];
                            // Simple version comparison: prefer higher versions
                            if (best_version == null or
                                std.mem.order(u8, version, best_version.?) == .gt)
                            {
                                if (best_target) |old| self.allocator.free(old);
                                best_version = version;
                                best_target = try self.allocator.dupe(u8, entry.name);
                            }
                        }
                    }
                }

                if (best_target) |target| {
                    defer self.allocator.free(target);

                    // Create symlink: autoconf -> autoconf-2.72
                    std.fs.cwd().symLink(target, wrapper_path, .{}) catch |err| {
                        std.debug.print("    [SYSROOT] Warning: could not create autotools wrapper {s} -> {s}: {}\n", .{ tool, target, err });
                        continue;
                    };
                    std.debug.print("    [SYSROOT] Created autotools wrapper: {s} -> {s}\n", .{ tool, target });
                }

                continue; // Move to next tool
            };
            // Wrapper already exists, nothing to do
        }
    }

    /// Find ALL root paths for a package in the Axiom store by name
    /// Returns paths to all versions' root/ directories (important for packages like autoconf
    /// where autoconf-switch and autoconf both provide different binaries under the same package name)
    fn findAllPackageRootsInStore(self: *PortsMigrator, pkg_name: []const u8) !std.ArrayList([]const u8) {
        var roots = std.ArrayList([]const u8).init(self.allocator);
        errdefer {
            for (roots.items) |r| self.allocator.free(r);
            roots.deinit();
        }

        const store = self.options.store orelse return roots;

        const store_mountpoint = store.zfs_handle.getMountpoint(self.allocator, store.paths.store_root) catch {
            return roots;
        };
        defer self.allocator.free(store_mountpoint);

        const pkg_dir_path = std.fs.path.join(self.allocator, &[_][]const u8{
            store_mountpoint,
            pkg_name,
        }) catch return roots;
        defer self.allocator.free(pkg_dir_path);

        var pkg_dir = std.fs.cwd().openDir(pkg_dir_path, .{ .iterate = true }) catch {
            return roots;
        };
        defer pkg_dir.close();

        // Iterate through ALL versions
        var version_iter = pkg_dir.iterate();
        while (version_iter.next() catch null) |version_entry| {
            if (version_entry.kind != .directory) continue;

            const version_path = std.fs.path.join(self.allocator, &[_][]const u8{
                pkg_dir_path,
                version_entry.name,
            }) catch continue;
            defer self.allocator.free(version_path);

            var version_dir = std.fs.cwd().openDir(version_path, .{ .iterate = true }) catch continue;
            defer version_dir.close();

            // First revision
            var revision_iter = version_dir.iterate();
            const revision_entry = (revision_iter.next() catch continue) orelse continue;
            if (revision_entry.kind != .directory) continue;

            const revision_path = std.fs.path.join(self.allocator, &[_][]const u8{
                version_path,
                revision_entry.name,
            }) catch continue;
            defer self.allocator.free(revision_path);

            var revision_dir = std.fs.cwd().openDir(revision_path, .{ .iterate = true }) catch continue;
            defer revision_dir.close();

            // First build-id
            var build_iter = revision_dir.iterate();
            const build_entry = (build_iter.next() catch continue) orelse continue;
            if (build_entry.kind != .directory) continue;

            const root_path = std.fs.path.join(self.allocator, &[_][]const u8{
                revision_path,
                build_entry.name,
                "root",
            }) catch continue;
            errdefer self.allocator.free(root_path);

            // Verify root directory exists
            std.fs.cwd().access(root_path, .{}) catch {
                self.allocator.free(root_path);
                continue;
            };

            roots.append(root_path) catch {
                self.allocator.free(root_path);
                continue;
            };
        }

        return roots;
    }

    /// Find the root path for a package in the Axiom store by name
    /// Returns the path to the package's root/ directory, or null if not found
    fn findPackageRootInStore(self: *PortsMigrator, pkg_name: []const u8) ?[]const u8 {
        // Axiom store structure: ZFS dataset at {store_root}/{name}/{version}/{revision}/{build-id}
        // with files in the root/ subdirectory of the mountpoint
        // We need to find any version of this package and return its root path

        // Use ZFS to get proper mountpoint if store is available
        const store = self.options.store orelse {
            std.debug.print("      [DEBUG findPkg] store is null\n", .{});
            return null;
        };

        // Get the ROOT store mountpoint (e.g., zroot/axiom/store/pkg -> /axiom/store/pkg)
        // This is more reliable than querying child datasets which may not have explicit mountpoints
        const store_mountpoint = store.zfs_handle.getMountpoint(self.allocator, store.paths.store_root) catch |err| {
            std.debug.print("      [DEBUG findPkg] getMountpoint for store root failed: {}\n", .{err});
            return null;
        };
        defer self.allocator.free(store_mountpoint);

        std.debug.print("      [DEBUG findPkg] Store mountpoint: {s}\n", .{store_mountpoint});

        // Construct the package directory path under the store
        const pkg_dir_path = std.fs.path.join(self.allocator, &[_][]const u8{
            store_mountpoint,
            pkg_name,
        }) catch return null;
        defer self.allocator.free(pkg_dir_path);

        std.debug.print("      [DEBUG findPkg] Looking for package at: {s}\n", .{pkg_dir_path});

        // Open the package name directory
        var pkg_dir = std.fs.cwd().openDir(pkg_dir_path, .{ .iterate = true }) catch |err| {
            std.debug.print("      [DEBUG findPkg] openDir failed: {}\n", .{err});
            return null;
        };
        defer pkg_dir.close();

        // Find first version directory
        var version_iter = pkg_dir.iterate();
        const version_entry = (version_iter.next() catch return null) orelse return null;
        if (version_entry.kind != .directory) return null;

        const version_path = std.fs.path.join(self.allocator, &[_][]const u8{
            pkg_dir_path,
            version_entry.name,
        }) catch return null;
        defer self.allocator.free(version_path);

        // Find first revision directory
        var version_dir = std.fs.cwd().openDir(version_path, .{ .iterate = true }) catch return null;
        defer version_dir.close();

        var revision_iter = version_dir.iterate();
        const revision_entry = (revision_iter.next() catch return null) orelse return null;
        if (revision_entry.kind != .directory) return null;

        const revision_path = std.fs.path.join(self.allocator, &[_][]const u8{
            version_path,
            revision_entry.name,
        }) catch return null;
        defer self.allocator.free(revision_path);

        // Find first build-id directory
        var revision_dir = std.fs.cwd().openDir(revision_path, .{ .iterate = true }) catch return null;
        defer revision_dir.close();

        var build_iter = revision_dir.iterate();
        const build_entry = (build_iter.next() catch return null) orelse return null;
        if (build_entry.kind != .directory) return null;

        // Return path to root/ directory
        const root_path = std.fs.path.join(self.allocator, &[_][]const u8{
            revision_path,
            build_entry.name,
            "root",
        }) catch return null;

        // Verify root directory exists
        std.fs.cwd().access(root_path, .{}) catch {
            self.allocator.free(root_path);
            return null;
        };

        return root_path;
    }

    /// Build environment using sysroot approach
    /// Creates a unified sysroot directory where all dependency packages are symlinked together.
    /// This solves the autoconf-switch problem where wrapper scripts need to find related binaries
    /// in the same directory (e.g., autoconf wrapper looking for autoconf2.72 via ls -d "$0"[0-9]*).
    fn getBuildEnvironment(self: *PortsMigrator, origin: []const u8) !BuildEnvironment {
        // If use_system_tools is enabled, skip sysroot creation and use /usr/local directly
        if (self.options.use_system_tools) {
            std.debug.print("    [SYSROOT] Using system tools (--use-system-tools)\n", .{});
            return BuildEnvironment{
                .sysroot = try self.allocator.dupe(u8, ""),
                .path = try self.allocator.dupe(u8, "/usr/local/bin:/usr/bin:/bin"),
                .ld_library_path = try self.allocator.dupe(u8, "/usr/local/lib:/usr/lib:/lib"),
                .ldflags = try self.allocator.dupe(u8, "-L/usr/local/lib"),
                .cppflags = try self.allocator.dupe(u8, "-I/usr/local/include"),
                .pythonpath = "",
                .perl5lib = "",
                .gmake_path = try self.allocator.dupe(u8, "/usr/local/bin/gmake"),
                .cmake_path = try self.allocator.dupe(u8, "/usr/local/bin/cmake"),
                .allocator = self.allocator,
            };
        }

        // Collect all package roots from dependencies
        var all_roots = std.ArrayList([]const u8).init(self.allocator);
        defer {
            for (all_roots.items) |r| self.allocator.free(r);
            all_roots.deinit();
        }

        // Get ALL transitive dependencies for this port (not just direct ones)
        // This is critical for cases like automake -> autoconf -> autoconf-switch
        var deps = self.resolveDependencyTree(origin) catch {
            // If we can't get dependencies, just return system defaults with empty sysroot
            std.debug.print("    [DEBUG] Failed to get dependencies for {s}, using system defaults\n", .{origin});
            return BuildEnvironment{
                .sysroot = try self.allocator.dupe(u8, ""),
                .path = try self.allocator.dupe(u8, "/usr/local/bin:/usr/bin:/bin"),
                .ld_library_path = try self.allocator.dupe(u8, "/usr/local/lib:/usr/lib:/lib"),
                .ldflags = try self.allocator.dupe(u8, "-L/usr/local/lib"),
                .cppflags = try self.allocator.dupe(u8, "-I/usr/local/include"),
                .pythonpath = "",
                .perl5lib = "",
                .gmake_path = try self.allocator.dupe(u8, "/usr/local/bin/gmake"),
                .cmake_path = try self.allocator.dupe(u8, "/usr/local/bin/cmake"),
                .allocator = self.allocator,
            };
        };
        defer {
            for (deps.items) |d| self.allocator.free(d);
            deps.deinit();
        }

        std.debug.print("    [DEBUG] Processing {d} transitive dependencies for sysroot\n", .{deps.items.len});

        // Detect if this is a Python bootstrap package BEFORE collecting dependencies
        // Bootstrap packages have chicken-and-egg problems and we bootstrap wheel ourselves
        const is_python_bootstrap = std.mem.startsWith(u8, origin, "devel/py-installer") or
            std.mem.startsWith(u8, origin, "devel/py-setuptools") or
            std.mem.startsWith(u8, origin, "devel/py-wheel") or
            std.mem.startsWith(u8, origin, "devel/py-flit") or
            std.mem.startsWith(u8, origin, "devel/py-build") or
            std.mem.startsWith(u8, origin, "devel/py-packaging");

        // For each dependency, collect ALL package roots from the Axiom store
        for (deps.items) |dep_origin| {
            // Skip the package itself
            if (std.mem.eql(u8, dep_origin, origin)) continue;

            // Skip ports that axiom replaces (e.g., ports-mgmt/pkg)
            var is_skipped = false;
            for (SKIP_PORTS) |skip_origin| {
                if (std.mem.eql(u8, dep_origin, skip_origin)) {
                    is_skipped = true;
                    break;
                }
            }
            if (is_skipped) {
                std.debug.print("    [DEBUG] Skipping {s} (replaced by axiom)\n", .{dep_origin});
                continue;
            }

            // Skip wheel packages for bootstrap builds - we bootstrap wheel 0.37.1 ourselves
            // to avoid version parsing issues in wheel 0.40+ when building setuptools
            if (is_python_bootstrap and std.mem.startsWith(u8, dep_origin, "devel/py-wheel")) {
                std.debug.print("    [DEBUG] Skipping {s} for bootstrap build (using bootstrapped wheel instead)\n", .{dep_origin});
                continue;
            }

            // Map port origin to Axiom package name
            // For Python packages: py-flit-core@py311 → py311-flit-core
            // For others: strips @flavor and applies standard mappings
            const pkg_name = try self.mapPortNameAlloc(dep_origin);
            defer self.allocator.free(pkg_name);
            if (!std.mem.eql(u8, pkg_name, dep_origin)) {
                std.debug.print("    [DEBUG] Mapped {s} → {s}\n", .{ dep_origin, pkg_name });
            }
            std.debug.print("    [DEBUG] Looking for {s} in store\n", .{pkg_name});

            // Find ALL versions of package in store
            var roots = self.findAllPackageRootsInStore(pkg_name) catch continue;
            defer {
                // Free all strings in roots before deiniting
                for (roots.items) |r| self.allocator.free(r);
                roots.deinit();
            }

            if (roots.items.len == 0) {
                std.debug.print("    [DEBUG] Package {s} NOT found in store\n", .{pkg_name});
                continue;
            }

            std.debug.print("    [DEBUG] Found {d} version(s) of {s}\n", .{ roots.items.len, pkg_name });

            // Add all roots (transfer ownership to all_roots)
            for (roots.items) |root| {
                // Dupe to transfer ownership since roots will be cleaned up
                const root_copy = self.allocator.dupe(u8, root) catch continue;
                all_roots.append(root_copy) catch {
                    self.allocator.free(root_copy);
                    continue;
                };
            }
        }

        // Always add infrastructure packages to sysroot (tools the ports framework needs)
        for (INFRA_PORTS) |infra_origin| {
            const pkg_name = try self.mapPortNameAlloc(infra_origin);
            defer self.allocator.free(pkg_name);

            std.debug.print("    [DEBUG] Adding infrastructure package: {s} → {s}\n", .{ infra_origin, pkg_name });

            var roots = self.findAllPackageRootsInStore(pkg_name) catch continue;
            defer {
                for (roots.items) |r| self.allocator.free(r);
                roots.deinit();
            }

            if (roots.items.len == 0) {
                std.debug.print("    [DEBUG] Infrastructure package {s} NOT found in store (build it first)\n", .{pkg_name});
                continue;
            }

            std.debug.print("    [DEBUG] Found {d} version(s) of infrastructure package {s}\n", .{ roots.items.len, pkg_name });

            for (roots.items) |root| {
                const root_copy = self.allocator.dupe(u8, root) catch continue;
                all_roots.append(root_copy) catch {
                    self.allocator.free(root_copy);
                    continue;
                };
            }
        }

        // If no dependencies found, return system defaults
        if (all_roots.items.len == 0) {
            std.debug.print("    [DEBUG] No dependencies found in store, using system defaults\n", .{});
            return BuildEnvironment{
                .sysroot = try self.allocator.dupe(u8, ""),
                .path = try self.allocator.dupe(u8, "/usr/local/bin:/usr/bin:/bin"),
                .ld_library_path = try self.allocator.dupe(u8, "/usr/local/lib:/usr/lib:/lib"),
                .ldflags = try self.allocator.dupe(u8, "-L/usr/local/lib"),
                .cppflags = try self.allocator.dupe(u8, "-I/usr/local/include"),
                .pythonpath = "",
                .perl5lib = "",
                .gmake_path = try self.allocator.dupe(u8, "/usr/local/bin/gmake"),
                .cmake_path = try self.allocator.dupe(u8, "/usr/local/bin/cmake"),
                .allocator = self.allocator,
            };
        }

        // Create sysroot with all package roots symlinked
        const sysroot = try self.createBuildSysroot(all_roots.items);
        errdefer self.allocator.free(sysroot);

        // Create binary aliases in sysroot for scripts expecting unprefixed GNU tool names
        // (e.g., gmake installs 'gmake' binary, we create 'make' alias for scripts expecting 'make')
        try self.createBinaryAliases(sysroot, deps.items);

        // Create unversioned wrappers for autotools (autoconf -> autoconf-2.72, etc.)
        // FreeBSD's devel/autoconf installs versioned binaries, but other ports expect 'autoconf'
        try self.createAutotoolsWrappers(sysroot);

        // Build paths using the sysroot
        const sysroot_bin = try std.fs.path.join(self.allocator, &[_][]const u8{ sysroot, "bin" });
        defer self.allocator.free(sysroot_bin);

        const sysroot_lib = try std.fs.path.join(self.allocator, &[_][]const u8{ sysroot, "lib" });
        defer self.allocator.free(sysroot_lib);

        const sysroot_include = try std.fs.path.join(self.allocator, &[_][]const u8{ sysroot, "include" });
        defer self.allocator.free(sysroot_include);

        // PATH: sysroot/bin first, then system paths
        const path = try std.fmt.allocPrint(
            self.allocator,
            "{s}:/usr/local/bin:/usr/bin:/bin",
            .{sysroot_bin},
        );

        // LD_LIBRARY_PATH: sysroot/lib first, then system paths
        const ld_library_path = try std.fmt.allocPrint(
            self.allocator,
            "{s}:/usr/local/lib:/usr/lib:/lib",
            .{sysroot_lib},
        );

        // LDFLAGS: -L pointing to sysroot/lib and /usr/local/lib
        const ldflags = try std.fmt.allocPrint(
            self.allocator,
            "-L{s} -L/usr/local/lib",
            .{sysroot_lib},
        );

        // CPPFLAGS: -I pointing to sysroot/include and /usr/local/include
        const cppflags = try std.fmt.allocPrint(
            self.allocator,
            "-I{s} -I/usr/local/include",
            .{sysroot_include},
        );

        // PYTHONPATH: scan sysroot/lib for python*/site-packages directories
        // Python packages (py-flit-core, py-setuptools, etc.) install to lib/pythonX.Y/site-packages
        var pythonpath = try self.buildPythonPath(sysroot_lib);

        // Bootstrap Python modules for Python bootstrap packages
        // These packages have chicken-and-egg problems where they need certain modules to build themselves
        // We bootstrap: installer (needed by py-installer), wheel (needed by py-setuptools, py-wheel)
        // Note: is_python_bootstrap was already detected above to skip wheel packages from sysroot
        if (is_python_bootstrap) {
            std.debug.print("    [BOOTSTRAP] Detected Python bootstrap package: {s}\n", .{origin});
            if (try self.bootstrapPythonModules(sysroot_lib)) |bootstrap_path| {
                // Prepend bootstrap path to PYTHONPATH
                if (pythonpath.len > 0) {
                    const new_pythonpath = try std.fmt.allocPrint(
                        self.allocator,
                        "{s}:{s}",
                        .{ bootstrap_path, pythonpath },
                    );
                    self.allocator.free(pythonpath);
                    self.allocator.free(bootstrap_path);
                    pythonpath = new_pythonpath;
                } else {
                    pythonpath = bootstrap_path;
                }
            }
        }

        // PERL5LIB: scan sysroot/lib for perl5/site_perl directories
        // Perl modules (p5-Locale-gettext, etc.) install to lib/perl5/site_perl/X.YZ
        const perl5lib = try self.buildPerl5Lib(sysroot_lib);

        // GMAKE: Check if gmake exists in sysroot, otherwise fall back to system path
        // FreeBSD ports framework uses GMAKE variable (defaults to /usr/local/bin/gmake)
        // We override this to point to sysroot gmake when available
        const gmake_in_sysroot = try std.fs.path.join(self.allocator, &[_][]const u8{ sysroot_bin, "gmake" });
        errdefer self.allocator.free(gmake_in_sysroot);

        const gmake_path = blk: {
            // Check if gmake exists in sysroot
            std.fs.cwd().access(gmake_in_sysroot, .{}) catch {
                // gmake not in sysroot, fall back to system path
                self.allocator.free(gmake_in_sysroot);
                break :blk try self.allocator.dupe(u8, "/usr/local/bin/gmake");
            };
            // gmake found in sysroot
            break :blk gmake_in_sysroot;
        };

        // CMAKE: Check if cmake exists in sysroot, otherwise fall back to system path
        // FreeBSD ports framework uses CMAKE variable (defaults to /usr/local/bin/cmake)
        // We override this to point to sysroot cmake when available
        const cmake_in_sysroot = try std.fs.path.join(self.allocator, &[_][]const u8{ sysroot_bin, "cmake" });
        errdefer self.allocator.free(cmake_in_sysroot);

        const cmake_path = blk: {
            // Check if cmake exists in sysroot
            std.fs.cwd().access(cmake_in_sysroot, .{}) catch {
                // cmake not in sysroot, fall back to system path
                self.allocator.free(cmake_in_sysroot);
                break :blk try self.allocator.dupe(u8, "/usr/local/bin/cmake");
            };
            // cmake found in sysroot
            break :blk cmake_in_sysroot;
        };

        std.debug.print("    [DEBUG] Sysroot created: {s}\n", .{sysroot});
        std.debug.print("    [DEBUG] Final PATH: {s}\n", .{path});
        std.debug.print("    [DEBUG] Final LDFLAGS: {s}\n", .{ldflags});
        std.debug.print("    [DEBUG] Final GMAKE: {s}\n", .{gmake_path});
        std.debug.print("    [DEBUG] Final CMAKE: {s}\n", .{cmake_path});
        if (pythonpath.len > 0) {
            std.debug.print("    [DEBUG] Final PYTHONPATH: {s}\n", .{pythonpath});
        }
        if (perl5lib.len > 0) {
            std.debug.print("    [DEBUG] Final PERL5LIB: {s}\n", .{perl5lib});
        }

        return BuildEnvironment{
            .sysroot = sysroot,
            .path = path,
            .ld_library_path = ld_library_path,
            .ldflags = ldflags,
            .cppflags = cppflags,
            .pythonpath = pythonpath,
            .perl5lib = perl5lib,
            .gmake_path = gmake_path,
            .cmake_path = cmake_path,
            .allocator = self.allocator,
        };
    }

    /// Build PYTHONPATH by scanning lib directories for python*/site-packages
    /// Scans sysroot first, then system paths as fallback
    /// This allows bootstrap Python packages (like py-installer) to use system modules
    fn buildPythonPath(self: *PortsMigrator, lib_dir: []const u8) ![]const u8 {
        var paths = std.ArrayList([]const u8).init(self.allocator);
        defer {
            for (paths.items) |p| self.allocator.free(p);
            paths.deinit();
        }

        // Directories to scan: sysroot first, then system fallbacks
        // Include /root/.local/lib for user-installed packages (when running as root)
        // Include /usr/lib for system Python packages
        const lib_dirs = [_][]const u8{ lib_dir, "/usr/local/lib", "/usr/lib", "/root/.local/lib" };

        // Package directory names: site-packages (FreeBSD), dist-packages (Debian/Ubuntu)
        const pkg_dirs = [_][]const u8{ "site-packages", "dist-packages" };


        for (lib_dirs) |search_dir| {
            // Open lib directory and scan for python* subdirectories
            std.debug.print("    [DEBUG] buildPythonPath: scanning {s}\n", .{search_dir});
            var dir = std.fs.cwd().openDir(search_dir, .{ .iterate = true }) catch |err| {
                std.debug.print("    [DEBUG] buildPythonPath: {s} error: {}\n", .{ search_dir, err });
                if (err == error.FileNotFound) continue;
                if (err == error.AccessDenied) continue;
                return err;
            };
            defer dir.close();

            var iter = dir.iterate();
            while (try iter.next()) |entry| {
                // Look for directories starting with "python"
                if (entry.kind != .directory) continue;
                if (!std.mem.startsWith(u8, entry.name, "python")) continue;

                // Check for both site-packages and dist-packages
                for (pkg_dirs) |pkg_dir| {
                    const packages_path = try std.fs.path.join(self.allocator, &[_][]const u8{
                        search_dir,
                        entry.name,
                        pkg_dir,
                    });

                    // Verify it exists
                    std.fs.cwd().access(packages_path, .{}) catch {
                        self.allocator.free(packages_path);
                        continue;
                    };

                    std.debug.print("    [DEBUG] buildPythonPath: found {s}\n", .{packages_path});

                    // Check if this path is already in the list (avoid duplicates)
                    var already_added = false;
                    for (paths.items) |existing| {
                        if (std.mem.eql(u8, existing, packages_path)) {
                            already_added = true;
                            break;
                        }
                    }
                    if (already_added) {
                        self.allocator.free(packages_path);
                        continue;
                    }

                    try paths.append(packages_path);
                }
            }
        }

        if (paths.items.len == 0) return "";

        // Join all paths with ":"
        var total_len: usize = 0;
        for (paths.items, 0..) |p, i| {
            total_len += p.len;
            if (i < paths.items.len - 1) total_len += 1; // for ':'
        }

        const result = try self.allocator.alloc(u8, total_len);
        var pos: usize = 0;
        for (paths.items, 0..) |p, i| {
            @memcpy(result[pos..][0..p.len], p);
            pos += p.len;
            if (i < paths.items.len - 1) {
                result[pos] = ':';
                pos += 1;
            }
        }

        return result;
    }

    /// Bootstrap essential Python modules (installer, wheel) by downloading and extracting wheels
    /// This solves chicken-and-egg problems where Python bootstrap packages need these modules
    /// Returns the path to add to PYTHONPATH, or null if bootstrap fails
    fn bootstrapPythonModules(self: *PortsMigrator, lib_dir: []const u8) !?[]const u8 {
        // Create bootstrap directory under lib_dir
        const bootstrap_dir = try std.fs.path.join(self.allocator, &[_][]const u8{ lib_dir, "python-bootstrap" });
        defer self.allocator.free(bootstrap_dir);

        // Create bootstrap directory
        std.fs.cwd().makePath(bootstrap_dir) catch |err| {
            std.debug.print("    [BOOTSTRAP] Failed to create bootstrap dir: {}\n", .{err});
            return null;
        };

        // Bootstrap modules: installer and wheel
        // These are the core modules needed to build Python packages
        const modules = [_]struct { name: []const u8, url: []const u8, filename: []const u8 }{
            .{
                .name = "installer",
                .url = "https://files.pythonhosted.org/packages/py3/i/installer/installer-0.7.0-py3-none-any.whl",
                .filename = "installer-0.7.0-py3-none-any.whl",
            },
            .{
                // Using wheel 0.42.0 instead of 0.44.0 to avoid version parsing issue
                // wheel 0.44.0 has code that tries to parse setuptools.__version__ which
                // returns 'unknown' when building setuptools from source
                .name = "wheel",
                .url = "https://files.pythonhosted.org/packages/py3/w/wheel/wheel-0.42.0-py3-none-any.whl",
                .filename = "wheel-0.42.0-py3-none-any.whl",
            },
        };

        for (modules) |mod| {
            // Always download fresh - remove any existing module directory
            // This ensures we get the correct version even if something else created the dir
            const mod_check = try std.fs.path.join(self.allocator, &[_][]const u8{ bootstrap_dir, mod.name });
            defer self.allocator.free(mod_check);

            // Remove existing directory to ensure we use the correct version
            std.fs.cwd().deleteTree(mod_check) catch {};

            // Download wheel from PyPI
            const wheel_path = try std.fs.path.join(self.allocator, &[_][]const u8{ bootstrap_dir, mod.filename });
            defer self.allocator.free(wheel_path);

            std.debug.print("    [BOOTSTRAP] Downloading {s} from {s}...\n", .{ mod.name, mod.url });

            // Use fetch (FreeBSD) or curl to download
            const download_ok = blk: {
                // Try fetch first (FreeBSD native)
                if (std.process.Child.run(.{
                    .allocator = self.allocator,
                    .argv = &[_][]const u8{ "fetch", "-o", wheel_path, mod.url },
                })) |result| {
                    defer self.allocator.free(result.stdout);
                    defer self.allocator.free(result.stderr);
                    if (result.term.Exited == 0) break :blk true;
                } else |_| {}

                // Try curl as fallback
                if (std.process.Child.run(.{
                    .allocator = self.allocator,
                    .argv = &[_][]const u8{ "curl", "-sL", "-o", wheel_path, mod.url },
                })) |result| {
                    defer self.allocator.free(result.stdout);
                    defer self.allocator.free(result.stderr);
                    if (result.term.Exited == 0) break :blk true;
                } else |_| {}

                break :blk false;
            };

            if (!download_ok) {
                std.debug.print("    [BOOTSTRAP] Failed to download {s}\n", .{mod.name});
                continue;
            }

            // Extract wheel (wheels are zip files)
            std.debug.print("    [BOOTSTRAP] Extracting {s}...\n", .{mod.name});
            const unzip_result = std.process.Child.run(.{
                .allocator = self.allocator,
                .argv = &[_][]const u8{ "unzip", "-o", "-q", wheel_path, "-d", bootstrap_dir },
            }) catch |err| {
                std.debug.print("    [BOOTSTRAP] unzip failed for {s}: {}\n", .{ mod.name, err });
                continue;
            };
            defer self.allocator.free(unzip_result.stdout);
            defer self.allocator.free(unzip_result.stderr);

            if (unzip_result.term.Exited != 0) {
                std.debug.print("    [BOOTSTRAP] unzip failed for {s}: {s}\n", .{ mod.name, unzip_result.stderr });
                continue;
            }

            std.debug.print("    [BOOTSTRAP] Successfully bootstrapped {s}\n", .{mod.name});
        }

        // Return bootstrap dir if at least one module was bootstrapped
        const installer_check = try std.fs.path.join(self.allocator, &[_][]const u8{ bootstrap_dir, "installer" });
        defer self.allocator.free(installer_check);
        const wheel_check = try std.fs.path.join(self.allocator, &[_][]const u8{ bootstrap_dir, "wheel" });
        defer self.allocator.free(wheel_check);

        const has_installer = if (std.fs.cwd().access(installer_check, .{})) |_| true else |_| false;
        const has_wheel = if (std.fs.cwd().access(wheel_check, .{})) |_| true else |_| false;

        if (has_installer or has_wheel) {
            return try self.allocator.dupe(u8, bootstrap_dir);
        }

        return null;
    }

    /// Build PERL5LIB by scanning lib directory for perl5/site_perl directories
    fn buildPerl5Lib(self: *PortsMigrator, lib_dir: []const u8) ![]const u8 {
        var paths = std.ArrayList([]const u8).init(self.allocator);
        defer {
            for (paths.items) |p| self.allocator.free(p);
            paths.deinit();
        }

        // Perl modules are in lib/perl5/site_perl and lib/perl5/X.YZ
        const perl5_dir = try std.fs.path.join(self.allocator, &[_][]const u8{ lib_dir, "perl5" });
        defer self.allocator.free(perl5_dir);

        // First check if perl5 directory exists
        var dir = std.fs.cwd().openDir(perl5_dir, .{ .iterate = true }) catch |err| {
            if (err == error.FileNotFound) return "";
            return err;
        };
        defer dir.close();

        // Add site_perl directories (where p5-* packages install)
        // FreeBSD perl modules install to:
        //   site_perl/5.XX/ - pure Perl modules
        //   site_perl/5.XX/amd64-freebsd/ - architecture-specific XS modules
        //   site_perl/ - some modules install directly here
        const site_perl_dir = try std.fs.path.join(self.allocator, &[_][]const u8{ perl5_dir, "site_perl" });
        defer self.allocator.free(site_perl_dir);

        // Try to open site_perl and add it plus subdirectories
        if (std.fs.cwd().openDir(site_perl_dir, .{ .iterate = true })) |sd| {
            var site_dir = sd;
            defer site_dir.close();

            // Add site_perl itself first (some modules install directly here)
            const site_perl_copy = try self.allocator.dupe(u8, site_perl_dir);
            try paths.append(site_perl_copy);

            // Scan site_perl for both version dirs (5.XX) and arch dirs (amd64-freebsd)
            // FreeBSD installs p5-* modules to various patterns:
            //   site_perl/5.42/ - version-specific
            //   site_perl/mach/ - architecture-specific
            //   site_perl/mach/5.42/ - arch then version (p5-Locale-gettext uses this!)
            // Note: Also include symlinks since 'mach' is often a symlink
            var site_iter = site_dir.iterate();
            while (try site_iter.next()) |entry| {
                // Include directories AND symlinks (mach is often a symlink)
                if (entry.kind != .directory and entry.kind != .sym_link) continue;
                // Skip special directories that aren't module paths
                if (std.mem.eql(u8, entry.name, "auto")) continue;
                if (std.mem.eql(u8, entry.name, "man")) continue;

                const subdir_path = try std.fs.path.join(self.allocator, &[_][]const u8{
                    site_perl_dir,
                    entry.name,
                });
                try paths.append(subdir_path);

                // Scan ALL subdirs (not just version dirs) for nested directories
                // This handles site_perl/mach/5.42/ pattern used by p5-Locale-gettext
                if (std.fs.cwd().openDir(subdir_path, .{ .iterate = true })) |vd| {
                    var ver_dir = vd;
                    defer ver_dir.close();
                    var ver_iter = ver_dir.iterate();
                    while (try ver_iter.next()) |sub_entry| {
                        // Include directories AND symlinks
                        if (sub_entry.kind != .directory and sub_entry.kind != .sym_link) continue;
                        if (std.mem.eql(u8, sub_entry.name, "auto")) continue;
                        if (std.mem.eql(u8, sub_entry.name, "man")) continue;
                        // Add subdirs like site_perl/mach/5.42 or site_perl/5.42/amd64-freebsd
                        const sub_path = try std.fs.path.join(self.allocator, &[_][]const u8{
                            subdir_path,
                            sub_entry.name,
                        });
                        try paths.append(sub_path);
                    }
                } else |_| {}
            }
        } else |_| {
            // site_perl doesn't exist, continue to check other locations
        }

        // Scan for versioned directories directly under perl5 (like 5.42)
        // Also add the corresponding site_perl/<version> paths
        var perl5_iter = dir.iterate();
        while (try perl5_iter.next()) |entry| {
            // Include directories AND symlinks
            if (entry.kind != .directory and entry.kind != .sym_link) continue;
            if (std.mem.eql(u8, entry.name, "site_perl")) continue; // Already handled
            // Only add version directories (start with digit)
            if (entry.name.len == 0 or !std.ascii.isDigit(entry.name[0])) continue;

            // Add perl5/<version>
            const version_path = try std.fs.path.join(self.allocator, &[_][]const u8{
                perl5_dir,
                entry.name,
            });
            try paths.append(version_path);

            // Also add site_perl/<version> if it exists (p5-* packages install here)
            const site_version_path = try std.fs.path.join(self.allocator, &[_][]const u8{
                site_perl_dir,
                entry.name,
            });
            // Check if it exists and add it
            std.fs.cwd().access(site_version_path, .{}) catch {
                self.allocator.free(site_version_path);
                continue;
            };
            try paths.append(site_version_path);

            // Also scan for arch subdirs under site_perl/<version>
            if (std.fs.cwd().openDir(site_version_path, .{ .iterate = true })) |svd| {
                var sv_dir = svd;
                defer sv_dir.close();
                var sv_iter = sv_dir.iterate();
                while (try sv_iter.next()) |arch_entry| {
                    // Include directories AND symlinks
                    if (arch_entry.kind != .directory and arch_entry.kind != .sym_link) continue;
                    if (std.mem.eql(u8, arch_entry.name, "auto")) continue;
                    if (std.mem.eql(u8, arch_entry.name, "man")) continue;
                    const arch_path = try std.fs.path.join(self.allocator, &[_][]const u8{
                        site_version_path,
                        arch_entry.name,
                    });
                    try paths.append(arch_path);
                }
            } else |_| {}
        }

        if (paths.items.len == 0) return "";

        // Join all paths with ":"
        var total_len: usize = 0;
        for (paths.items, 0..) |p, i| {
            total_len += p.len;
            if (i < paths.items.len - 1) total_len += 1; // for ':'
        }

        const result = try self.allocator.alloc(u8, total_len);
        var pos: usize = 0;
        for (paths.items, 0..) |p, i| {
            @memcpy(result[pos..][0..p.len], p);
            pos += p.len;
            if (i < paths.items.len - 1) {
                result[pos] = ':';
                pos += 1;
            }
        }

        return result;
    }

    /// Build a port using the FreeBSD ports build system
    fn buildPort(
        self: *PortsMigrator,
        origin: []const u8,
        metadata: *const PortMetadata,
        manifest_path: ?[]const u8,
    ) !PortBuildResult {
        _ = manifest_path; // May be used in future for dependency resolution

        // Parse origin to extract optional flavor (e.g., "devel/py-setuptools@py311")
        const parsed = ParsedOrigin.parse(origin);

        std.debug.print("\n=== Building port: {s} ===\n", .{origin});

        const port_path = try std.fs.path.join(self.allocator, &[_][]const u8{
            self.options.ports_tree,
            parsed.path, // Use path without @flavor suffix
        });
        defer self.allocator.free(port_path);

        // Create a temporary output directory for the staged installation
        const timestamp = std.time.timestamp();
        var random_bytes: [4]u8 = undefined;
        std.crypto.random.bytes(&random_bytes);

        const stage_dir = try std.fmt.allocPrint(
            self.allocator,
            "/tmp/axiom-ports-stage-{s}-{d}-{x:0>2}{x:0>2}{x:0>2}{x:0>2}",
            .{ metadata.name, timestamp, random_bytes[0], random_bytes[1], random_bytes[2], random_bytes[3] },
        );
        errdefer self.allocator.free(stage_dir);

        try std.fs.cwd().makePath(stage_dir);

        // Build using FreeBSD ports make with DESTDIR
        std.debug.print("Building in: {s}\n", .{port_path});
        std.debug.print("Staging to: {s}\n", .{stage_dir});

        // Step 1: Clean any previous build
        std.debug.print("  Cleaning...\n", .{});
        var clean_result = try self.runMakeTarget(port_path, "clean", null);
        clean_result.deinit(self.allocator);

        // Step 2: Check and display required dependencies
        // (User must build these first via separate ports-import calls)
        try self.displayDependencies(port_path);

        // Step 3: Set up build environment with Axiom store paths
        // This allows built dependencies to be found by configure scripts and compilers
        std.debug.print("  Setting up build environment...\n", .{});
        var build_env = try self.getBuildEnvironment(origin);
        defer build_env.deinit();

        if (self.options.verbose) {
            std.debug.print("  Axiom store dependencies added to PATH\n", .{});
        }

        // Step 4: Build the port with NO_DEPENDS (skip ports dependency machinery)
        // Dependencies are now available via PATH from Axiom store
        std.debug.print("  Building (may take a while)", .{});

        // Start progress indicator for long-running build
        var build_progress = ProgressIndicator{ .interval_ms = 10000 }; // Dot every 10 seconds
        build_progress.start();

        var build_result = try self.runMakeTargetNoDeps(port_path, "build", null, &build_env, origin);

        build_progress.stop();

        if (build_result.exit_code != 0) {
            std.debug.print("  Build FAILED (exit code: {d})\n", .{build_result.exit_code});
            // Show the last part of stdout (compiler errors are in stdout)
            if (build_result.stdout) |stdout| {
                // Show last 4KB of output to catch the actual error
                const start = if (stdout.len > 4096) stdout.len - 4096 else 0;
                std.debug.print("\n--- Build output (last 4KB) ---\n{s}\n", .{stdout[start..]});
            }
            if (build_result.stderr) |stderr| {
                std.debug.print("--- stderr ---\n{s}\n", .{stderr});
            }
            std.debug.print("-------------------------------\n", .{});
            build_result.deinit(self.allocator);
            return PortsError.BuildFailed;
        }
        std.debug.print("  Build OK\n", .{});
        build_result.deinit(self.allocator);

        // Step 5: Stage the port (uses internal staging in work/stage)
        std.debug.print("  Staging", .{});

        // Start progress indicator for staging phase
        var stage_progress = ProgressIndicator{ .interval_ms = 5000 }; // Dot every 5 seconds
        stage_progress.start();

        var stage_result = try self.runMakeTargetNoDeps(port_path, "stage", null, &build_env, origin);

        stage_progress.stop();

        if (stage_result.exit_code != 0) {
            std.debug.print("  Stage FAILED (exit code: {d})\n", .{stage_result.exit_code});
            if (stage_result.stdout) |stdout| {
                const start = if (stdout.len > 4096) stdout.len - 4096 else 0;
                std.debug.print("\n--- Stage output (last 4KB) ---\n{s}\n", .{stdout[start..]});
            }
            if (stage_result.stderr) |stderr| {
                std.debug.print("--- stderr ---\n{s}\n", .{stderr});
            }
            std.debug.print("-------------------------------\n", .{});
            stage_result.deinit(self.allocator);
            return PortsError.BuildFailed;
        }
        std.debug.print("  Stage OK\n", .{});
        stage_result.deinit(self.allocator);

        // Step 6: Copy staged files from STAGEDIR to our staging directory
        // Query the actual STAGEDIR from the port - this handles flavored ports
        // (e.g., vim uses work-default/stage instead of work/stage)
        std.debug.print("  Copying staged files...\n", .{});
        const work_stage = try self.makeVar(port_path, "STAGEDIR");
        defer self.allocator.free(work_stage);

        // Use cp -a to preserve attributes and copy recursively
        var cp_args = [_][]const u8{
            "cp",
            "-a",
            work_stage,
            stage_dir,
        };

        var cp_child = std.process.Child.init(&cp_args, self.allocator);
        cp_child.stdout_behavior = .Ignore;
        cp_child.stderr_behavior = .Pipe;
        try cp_child.spawn();

        var cp_stderr: ?[]const u8 = null;
        if (cp_child.stderr) |stderr_pipe| {
            cp_stderr = stderr_pipe.readToEndAlloc(self.allocator, 1024 * 1024) catch null;
        }
        defer if (cp_stderr) |s| self.allocator.free(s);

        const cp_term = try cp_child.wait();
        if (cp_term.Exited != 0) {
            std.debug.print("  Copy failed with exit code: {d}\n", .{cp_term.Exited});
            if (cp_stderr) |stderr| {
                std.debug.print("  stderr: {s}\n", .{stderr});
            }
            return PortsError.BuildFailed;
        }

        std.debug.print("  Build completed successfully\n", .{});

        // Return path to the copied stage directory
        const final_stage = try std.fs.path.join(self.allocator, &[_][]const u8{
            stage_dir,
            "stage",
        });
        self.allocator.free(stage_dir);

        return PortBuildResult{
            .output_dir = final_stage,
            .success = true,
        };
    }

    /// Result from running a make target
    const MakeResult = struct {
        exit_code: u8,
        stdout: ?[]const u8,
        stderr: ?[]const u8,

        pub fn deinit(self: *MakeResult, allocator: std.mem.Allocator) void {
            if (self.stdout) |s| allocator.free(s);
            if (self.stderr) |s| allocator.free(s);
        }
    };

    /// Run a make target in the port directory
    fn runMakeTarget(
        self: *PortsMigrator,
        port_path: []const u8,
        target: []const u8,
        destdir: ?[]const u8,
    ) !MakeResult {
        var args = std.ArrayList([]const u8).init(self.allocator);
        defer args.deinit();

        // Track allocated strings to free after process completes
        var destdir_arg: ?[]const u8 = null;
        defer if (destdir_arg) |d| self.allocator.free(d);

        var jobs_arg: ?[]const u8 = null;
        defer if (jobs_arg) |j| self.allocator.free(j);

        try args.append("make");
        try args.append("-C");
        try args.append(port_path);

        // Add BATCH=yes to prevent interactive prompts
        try args.append("BATCH=yes");

        // Disable interactive dialogs
        try args.append("DISABLE_VULNERABILITIES=yes");

        // Add DESTDIR if provided
        if (destdir) |dir| {
            destdir_arg = try std.fmt.allocPrint(self.allocator, "DESTDIR={s}", .{dir});
            try args.append(destdir_arg.?);
        }

        // Add job count for parallel builds
        jobs_arg = try std.fmt.allocPrint(self.allocator, "-j{d}", .{self.options.build_jobs});
        try args.append(jobs_arg.?);

        try args.append(target);

        var child = std.process.Child.init(args.items, self.allocator);

        // Always capture both stdout and stderr so we can show errors
        // (compiler errors go to stdout, make errors go to stderr)
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Pipe;

        try child.spawn();

        // Read stdout and stderr concurrently to avoid pipe deadlock
        // If we read sequentially, the child can fill the stderr buffer while we're
        // blocked reading stdout, causing deadlock (common with large builds like Python)
        const output = try collectOutputConcurrently(self.allocator, &child);

        const term = try child.wait();

        // In verbose mode, show stdout
        if (self.options.verbose) {
            if (output.stdout) |out| {
                std.debug.print("{s}", .{out});
            }
        }

        return MakeResult{
            .exit_code = term.Exited,
            .stdout = output.stdout,
            .stderr = output.stderr,
        };
    }

    /// Helper to collect stdout and stderr concurrently using a thread
    /// This prevents pipe deadlock when subprocess produces lots of output
    const CollectedOutput = struct {
        stdout: ?[]const u8,
        stderr: ?[]const u8,
    };

    fn collectOutputConcurrently(allocator: std.mem.Allocator, child: *std.process.Child) !CollectedOutput {
        var stdout_output: ?[]const u8 = null;
        var stderr_output: ?[]const u8 = null;

        // Context for stderr reader thread
        const StderrReader = struct {
            alloc: std.mem.Allocator,
            pipe: *std.fs.File,
            result: ?[]const u8 = null,

            fn run(self: *@This()) void {
                self.result = self.pipe.readToEndAlloc(self.alloc, 1024 * 1024) catch null;
            }
        };

        var stderr_reader: ?StderrReader = null;
        var stderr_thread: ?std.Thread = null;

        // Spawn thread to read stderr
        if (child.stderr) |*stderr_pipe| {
            stderr_reader = StderrReader{
                .alloc = allocator,
                .pipe = stderr_pipe,
            };
            stderr_thread = std.Thread.spawn(.{}, StderrReader.run, .{&stderr_reader.?}) catch null;
        }

        // Read stdout in main thread
        if (child.stdout) |stdout_pipe| {
            const stdout_content = stdout_pipe.readToEndAlloc(allocator, 10 * 1024 * 1024) catch null;
            if (stdout_content) |content| {
                if (content.len > 0) {
                    stdout_output = content;
                } else {
                    allocator.free(content);
                }
            }
        }

        // Wait for stderr thread to complete
        if (stderr_thread) |t| {
            t.join();
            if (stderr_reader) |reader| {
                if (reader.result) |content| {
                    if (content.len > 0) {
                        stderr_output = content;
                    } else {
                        allocator.free(content);
                    }
                }
            }
        }

        return CollectedOutput{
            .stdout = stdout_output,
            .stderr = stderr_output,
        };
    }

    /// Run a make target with NO_DEPENDS to skip port-based dependency building
    /// (assumes dependencies were pre-installed from packages or are in Axiom store)
    fn runMakeTargetNoDeps(
        self: *PortsMigrator,
        port_path: []const u8,
        target: []const u8,
        destdir: ?[]const u8,
        build_env: ?*const BuildEnvironment,
        origin: []const u8,
    ) !MakeResult {
        var args = std.ArrayList([]const u8).init(self.allocator);
        defer args.deinit();

        // Track allocated strings to free after process completes
        var destdir_arg: ?[]const u8 = null;
        defer if (destdir_arg) |d| self.allocator.free(d);

        var jobs_arg: ?[]const u8 = null;
        defer if (jobs_arg) |j| self.allocator.free(j);

        // These are passed as make variables so ports framework respects them
        var make_env_arg: ?[]const u8 = null;
        defer if (make_env_arg) |m| self.allocator.free(m);

        var configure_env_arg: ?[]const u8 = null;
        defer if (configure_env_arg) |c| self.allocator.free(c);

        // CPPFLAGS and LDFLAGS must be passed as make variables
        // Setting them in child process environment is not enough - they don't propagate
        // to configure subprocesses. The ports framework needs them as make variable overrides.
        var cppflags_arg: ?[]const u8 = null;
        defer if (cppflags_arg) |f| self.allocator.free(f);

        var ldflags_arg: ?[]const u8 = null;
        defer if (ldflags_arg) |f| self.allocator.free(f);

        // Additional CONFIGURE_ENV and MAKE_ENV for CPPFLAGS/LDFLAGS
        // These must be passed separately with shell quoting for values with spaces
        var configure_cppflags_arg: ?[]const u8 = null;
        defer if (configure_cppflags_arg) |f| self.allocator.free(f);

        var configure_ldflags_arg: ?[]const u8 = null;
        defer if (configure_ldflags_arg) |f| self.allocator.free(f);

        var make_cppflags_arg: ?[]const u8 = null;
        defer if (make_cppflags_arg) |f| self.allocator.free(f);

        var make_ldflags_arg: ?[]const u8 = null;
        defer if (make_ldflags_arg) |f| self.allocator.free(f);

        // PYTHONPATH for Python package builds
        var make_pythonpath_arg: ?[]const u8 = null;
        defer if (make_pythonpath_arg) |f| self.allocator.free(f);

        var configure_pythonpath_arg: ?[]const u8 = null;
        defer if (configure_pythonpath_arg) |f| self.allocator.free(f);

        // PERL5LIB for Perl module builds
        var make_perl5lib_arg: ?[]const u8 = null;
        defer if (make_perl5lib_arg) |f| self.allocator.free(f);

        var configure_perl5lib_arg: ?[]const u8 = null;
        defer if (configure_perl5lib_arg) |f| self.allocator.free(f);

        // LD_LIBRARY_PATH for loading shared libraries (needed for XS modules)
        var make_ld_library_path_arg: ?[]const u8 = null;
        defer if (make_ld_library_path_arg) |f| self.allocator.free(f);

        var configure_ld_library_path_arg: ?[]const u8 = null;

        // GMAKE: Override path to GNU make for ports that use GMAKE variable
        var gmake_arg: ?[]const u8 = null;
        defer if (gmake_arg) |f| self.allocator.free(f);
        defer if (configure_ld_library_path_arg) |f| self.allocator.free(f);

        // CMAKE: Override path to cmake for ports that use CMAKE variable
        var cmake_arg: ?[]const u8 = null;
        defer if (cmake_arg) |f| self.allocator.free(f);

        // CMAKE_PREFIX_PATH for cmake-based builds
        var cmake_prefix_arg: ?[]const u8 = null;
        defer if (cmake_prefix_arg) |f| self.allocator.free(f);

        var configure_cmake_prefix_arg: ?[]const u8 = null;
        defer if (configure_cmake_prefix_arg) |f| self.allocator.free(f);

        // FLAVOR argument for flavored ports (e.g., devel/py-setuptools@py311)
        var flavor_arg: ?[]const u8 = null;
        defer if (flavor_arg) |f| self.allocator.free(f);

        try args.append("make");
        try args.append("-C");
        try args.append(port_path);

        // Add BATCH=yes to prevent interactive prompts
        try args.append("BATCH=yes");

        // Parse origin to check for flavor suffix (e.g., @py311)
        const parsed = ParsedOrigin.parse(origin);
        if (parsed.flavor) |flavor| {
            flavor_arg = try std.fmt.allocPrint(self.allocator, "FLAVOR={s}", .{flavor});
            try args.append(flavor_arg.?);
        }

        // Disable interactive dialogs
        try args.append("DISABLE_VULNERABILITIES=yes");

        // Skip dependency building - we installed them from packages
        try args.append("NO_DEPENDS=yes");

        // Don't chroot during install (DESTDIR is empty staging dir without /bin/sh)
        try args.append("NO_INSTALL_CHROOT=yes");

        // Pass Axiom sysroot PATH through MAKE_ENV and CONFIGURE_ENV
        // This is critical: the ports framework (bsd.port.mk) uses these variables
        // to set up the environment for configure and build phases.
        //
        // The sysroot approach merges all dependency packages into a single directory,
        // allowing wrapper scripts (like autoconf-switch) to find related binaries.
        //
        // IMPORTANT:
        // - LOCALBASE must ALWAYS be /usr/local (the install prefix in the stage dir)
        // - Do NOT set LOCALBASE to the sysroot! That causes files to be installed
        //   under stage/tmp/axiom-sysroot-.../usr/local instead of stage/usr/local
        // - The sysroot only affects search paths (PATH, LDFLAGS, CPPFLAGS)
        //
        // IMPORTANT: Only pass variables WITHOUT SPACES via MAKE_ENV/CONFIGURE_ENV.
        // Variables with spaces (like LDFLAGS with multiple -L flags) get shell-split
        // when the ports framework runs: env ${MAKE_ENV} ./configure
        // Instead, LDFLAGS/CPPFLAGS are set in the child process env_map below.
        if (build_env) |env| {
            // LOCALBASE is always /usr/local - this is the install prefix
            // The sysroot is only used for search paths, not for installation
            const localbase = "/usr/local";

            // Only pass variables WITHOUT SPACES via MAKE_ENV/CONFIGURE_ENV
            // PATH includes sysroot/bin for finding dependency binaries
            // LOCALBASE is /usr/local for correct installation prefix
            make_env_arg = try std.fmt.allocPrint(
                self.allocator,
                "MAKE_ENV+=PATH={s} LOCALBASE={s}",
                .{ env.path, localbase },
            );
            try args.append(make_env_arg.?);

            configure_env_arg = try std.fmt.allocPrint(
                self.allocator,
                "CONFIGURE_ENV+=PATH={s} LOCALBASE={s} FORCE_UNSAFE_CONFIGURE=1",
                .{ env.path, localbase },
            );
            try args.append(configure_env_arg.?);

            // Pass CPPFLAGS and LDFLAGS as make variable overrides
            // Using += syntax ensures they're appended to existing values
            cppflags_arg = try std.fmt.allocPrint(
                self.allocator,
                "CPPFLAGS+={s}",
                .{env.cppflags},
            );
            try args.append(cppflags_arg.?);

            ldflags_arg = try std.fmt.allocPrint(
                self.allocator,
                "LDFLAGS+={s}",
                .{env.ldflags},
            );
            try args.append(ldflags_arg.?);

            // CRITICAL: Also pass CPPFLAGS and LDFLAGS via CONFIGURE_ENV and MAKE_ENV
            // The ports framework runs: env ${CONFIGURE_ENV} ./configure
            // Configure scripts read CPPFLAGS/LDFLAGS from environment to set up build
            // Without this, configure won't find headers/libs and the build will fail
            // Use shell quoting to protect values containing spaces
            configure_cppflags_arg = try std.fmt.allocPrint(
                self.allocator,
                "CONFIGURE_ENV+=CPPFLAGS=\"{s}\"",
                .{env.cppflags},
            );
            try args.append(configure_cppflags_arg.?);

            configure_ldflags_arg = try std.fmt.allocPrint(
                self.allocator,
                "CONFIGURE_ENV+=LDFLAGS=\"{s}\"",
                .{env.ldflags},
            );
            try args.append(configure_ldflags_arg.?);

            make_cppflags_arg = try std.fmt.allocPrint(
                self.allocator,
                "MAKE_ENV+=CPPFLAGS=\"{s}\"",
                .{env.cppflags},
            );
            try args.append(make_cppflags_arg.?);

            make_ldflags_arg = try std.fmt.allocPrint(
                self.allocator,
                "MAKE_ENV+=LDFLAGS=\"{s}\"",
                .{env.ldflags},
            );
            try args.append(make_ldflags_arg.?);

            // PYTHONPATH for Python package builds (flit_core, setuptools, etc.)
            // Only set if we found Python site-packages in the sysroot
            if (env.pythonpath.len > 0) {
                make_pythonpath_arg = try std.fmt.allocPrint(
                    self.allocator,
                    "MAKE_ENV+=PYTHONPATH=\"{s}\"",
                    .{env.pythonpath},
                );
                try args.append(make_pythonpath_arg.?);

                configure_pythonpath_arg = try std.fmt.allocPrint(
                    self.allocator,
                    "CONFIGURE_ENV+=PYTHONPATH=\"{s}\"",
                    .{env.pythonpath},
                );
                try args.append(configure_pythonpath_arg.?);
            }

            // PERL5LIB for Perl module builds (p5-Locale-gettext, etc.)
            // Only set if we found Perl modules in the sysroot
            if (env.perl5lib.len > 0) {
                make_perl5lib_arg = try std.fmt.allocPrint(
                    self.allocator,
                    "MAKE_ENV+=PERL5LIB=\"{s}\"",
                    .{env.perl5lib},
                );
                try args.append(make_perl5lib_arg.?);

                configure_perl5lib_arg = try std.fmt.allocPrint(
                    self.allocator,
                    "CONFIGURE_ENV+=PERL5LIB=\"{s}\"",
                    .{env.perl5lib},
                );
                try args.append(configure_perl5lib_arg.?);
            }

            // LD_LIBRARY_PATH for loading shared libraries during configure
            // This is needed for Perl XS modules (like Locale::gettext) that load .so files
            if (env.ld_library_path.len > 0) {
                make_ld_library_path_arg = try std.fmt.allocPrint(
                    self.allocator,
                    "MAKE_ENV+=LD_LIBRARY_PATH=\"{s}\"",
                    .{env.ld_library_path},
                );
                try args.append(make_ld_library_path_arg.?);

                configure_ld_library_path_arg = try std.fmt.allocPrint(
                    self.allocator,
                    "CONFIGURE_ENV+=LD_LIBRARY_PATH=\"{s}\"",
                    .{env.ld_library_path},
                );
                try args.append(configure_ld_library_path_arg.?);
            }

            // GMAKE: Override the path to GNU make
            // FreeBSD ports framework uses GMAKE variable which defaults to /usr/local/bin/gmake
            // We override this to point to the sysroot or system gmake
            if (env.gmake_path.len > 0) {
                gmake_arg = try std.fmt.allocPrint(
                    self.allocator,
                    "GMAKE={s}",
                    .{env.gmake_path},
                );
                try args.append(gmake_arg.?);
            }

            // CMAKE_BIN: Override the path to cmake binary
            // FreeBSD ports framework uses CMAKE_BIN variable which defaults to ${LOCALBASE}/bin/cmake
            // We override this to point to the sysroot cmake when available
            if (env.cmake_path.len > 0) {
                cmake_arg = try std.fmt.allocPrint(
                    self.allocator,
                    "CMAKE_BIN={s}",
                    .{env.cmake_path},
                );
                try args.append(cmake_arg.?);
            }

            // CMAKE_PREFIX_PATH for cmake-based builds (like cmake-core itself)
            // cmake's find_library/find_path doesn't use LDFLAGS/CPPFLAGS,
            // it needs CMAKE_PREFIX_PATH to find packages in the sysroot
            cmake_prefix_arg = try std.fmt.allocPrint(
                self.allocator,
                "CMAKE_PREFIX_PATH={s}",
                .{env.sysroot},
            );
            try args.append(cmake_prefix_arg.?);

            // Also pass via CONFIGURE_ENV for ports that run cmake in configure phase
            configure_cmake_prefix_arg = try std.fmt.allocPrint(
                self.allocator,
                "CONFIGURE_ENV+=CMAKE_PREFIX_PATH=\"{s}\"",
                .{env.sysroot},
            );
            try args.append(configure_cmake_prefix_arg.?);

            std.debug.print("    [DEBUG] Passing to ports framework:\n", .{});
            std.debug.print("    [DEBUG]   MAKE_ENV+=PATH={s} LOCALBASE={s}\n", .{ env.path, localbase });
            std.debug.print("    [DEBUG]   CONFIGURE_ENV+=PATH={s} LOCALBASE={s}\n", .{ env.path, localbase });
            std.debug.print("    [DEBUG]   CPPFLAGS+={s}\n", .{env.cppflags});
            std.debug.print("    [DEBUG]   LDFLAGS+={s}\n", .{env.ldflags});
            std.debug.print("    [DEBUG]   CONFIGURE_ENV+=CPPFLAGS=\"{s}\"\n", .{env.cppflags});
            std.debug.print("    [DEBUG]   CONFIGURE_ENV+=LDFLAGS=\"{s}\"\n", .{env.ldflags});
            if (env.pythonpath.len > 0) {
                std.debug.print("    [DEBUG]   MAKE_ENV+=PYTHONPATH=\"{s}\"\n", .{env.pythonpath});
                std.debug.print("    [DEBUG]   CONFIGURE_ENV+=PYTHONPATH=\"{s}\"\n", .{env.pythonpath});
            }
            if (env.perl5lib.len > 0) {
                std.debug.print("    [DEBUG]   MAKE_ENV+=PERL5LIB=\"{s}\"\n", .{env.perl5lib});
                std.debug.print("    [DEBUG]   CONFIGURE_ENV+=PERL5LIB=\"{s}\"\n", .{env.perl5lib});
            }
            if (env.ld_library_path.len > 0) {
                std.debug.print("    [DEBUG]   MAKE_ENV+=LD_LIBRARY_PATH=\"{s}\"\n", .{env.ld_library_path});
                std.debug.print("    [DEBUG]   CONFIGURE_ENV+=LD_LIBRARY_PATH=\"{s}\"\n", .{env.ld_library_path});
            }
            if (env.gmake_path.len > 0) {
                std.debug.print("    [DEBUG]   GMAKE={s}\n", .{env.gmake_path});
            }
            if (env.cmake_path.len > 0) {
                std.debug.print("    [DEBUG]   CMAKE_BIN={s}\n", .{env.cmake_path});
            }
            std.debug.print("    [DEBUG]   CMAKE_PREFIX_PATH={s}\n", .{env.sysroot});
        }

        // Add DESTDIR if provided
        if (destdir) |dir| {
            destdir_arg = try std.fmt.allocPrint(self.allocator, "DESTDIR={s}", .{dir});
            try args.append(destdir_arg.?);
        }

        // Add job count for parallel builds
        jobs_arg = try std.fmt.allocPrint(self.allocator, "-j{d}", .{self.options.build_jobs});
        try args.append(jobs_arg.?);

        try args.append(target);

        var child = std.process.Child.init(args.items, self.allocator);

        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Pipe;

        // Set up custom environment if provided (includes Axiom store paths)
        var env_map: ?std.process.EnvMap = null;
        defer if (env_map) |*em| em.deinit();

        if (build_env) |env| {
            // Create environment map with PATH and LD_LIBRARY_PATH from Axiom store
            env_map = std.process.EnvMap.init(self.allocator);

            // Copy important environment variables from parent process
            if (std.posix.getenv("HOME")) |home| {
                try env_map.?.put("HOME", home);
            }
            if (std.posix.getenv("USER")) |user| {
                try env_map.?.put("USER", user);
            }
            if (std.posix.getenv("SHELL")) |shell| {
                try env_map.?.put("SHELL", shell);
            }
            if (std.posix.getenv("TERM")) |term| {
                try env_map.?.put("TERM", term);
            }
            if (std.posix.getenv("LANG")) |lang| {
                try env_map.?.put("LANG", lang);
            }

            // LOCALBASE must ALWAYS be /usr/local - this is the install prefix
            // Do NOT set LOCALBASE to the sysroot! That would cause ports to install
            // files to the wrong location (stage/tmp/axiom-sysroot-.../usr/local)
            // The sysroot is only used for search paths (PATH, LDFLAGS, CPPFLAGS)
            try env_map.?.put("LOCALBASE", "/usr/local");

            // Set custom PATH with sysroot bin directory first
            try env_map.?.put("PATH", env.path);
            try env_map.?.put("LD_LIBRARY_PATH", env.ld_library_path);

            // Set PYTHONPATH for Python packages in sysroot (py-flit-core, py-setuptools, etc.)
            if (env.pythonpath.len > 0) {
                try env_map.?.put("PYTHONPATH", env.pythonpath);
            }

            // Set LDFLAGS and CPPFLAGS in environment for configure-time detection
            // This helps Perl Makefile.PL and other detection scripts find libraries
            // These MUST be set here (not via MAKE_ENV) because values contain spaces
            try env_map.?.put("LDFLAGS", env.ldflags);
            try env_map.?.put("CPPFLAGS", env.cppflags);

            // For Perl modules, also set LIBS and INC which ExtUtils::MakeMaker reads
            if (std.mem.indexOf(u8, origin, "/p5-") != null) {
                // LIBS needs -lintl for gettext support
                const libs_value = try std.fmt.allocPrint(
                    self.allocator,
                    "{s} -lintl",
                    .{env.ldflags},
                );
                defer self.allocator.free(libs_value);
                try env_map.?.put("LIBS", libs_value);
                try env_map.?.put("INC", env.cppflags);

                std.debug.print("    [DEBUG] Perl module env: LIBS={s}\n", .{libs_value});
                std.debug.print("    [DEBUG] Perl module env: INC={s}\n", .{env.cppflags});
            }

            // FreeBSD make needs these
            try env_map.?.put("MAKE", "make");
            try env_map.?.put("PORTSDIR", self.options.ports_tree);

            // Set the pointer on child
            child.env_map = &(env_map.?);

            if (self.options.verbose) {
                std.debug.print("  Build environment:\n", .{});
                std.debug.print("    LOCALBASE=/usr/local\n", .{});
                std.debug.print("    PATH={s}\n", .{env.path});
                std.debug.print("    LD_LIBRARY_PATH={s}\n", .{env.ld_library_path});
                if (env.pythonpath.len > 0) {
                    std.debug.print("    PYTHONPATH={s}\n", .{env.pythonpath});
                }
                if (env.perl5lib.len > 0) {
                    std.debug.print("    PERL5LIB={s}\n", .{env.perl5lib});
                }
            }
        }

        try child.spawn();

        // Read stdout and stderr concurrently to avoid pipe deadlock
        // If we read sequentially, the child can fill the stderr buffer while we're
        // blocked reading stdout, causing deadlock (common with large builds like Python)
        const output = try collectOutputConcurrently(self.allocator, &child);

        const term = try child.wait();

        // In verbose mode, show stdout
        if (self.options.verbose) {
            if (output.stdout) |out| {
                std.debug.print("{s}", .{out});
            }
        }

        return MakeResult{
            .exit_code = term.Exited,
            .stdout = output.stdout,
            .stderr = output.stderr,
        };
    }

    /// Display build dependencies (user must build these first via separate ports-import calls)
    fn displayDependencies(self: *PortsMigrator, port_path: []const u8) !void {
        // Get BUILD_DEPENDS, LIB_DEPENDS, and RUN_DEPENDS
        const dep_vars = [_][]const u8{ "BUILD_DEPENDS", "LIB_DEPENDS", "RUN_DEPENDS" };
        var all_deps: [3]?[]const u8 = .{ null, null, null };

        for (dep_vars, 0..) |dep_var, idx| {
            var args = [_][]const u8{ "make", "-C", port_path, "-V", dep_var };
            var child = std.process.Child.init(&args, self.allocator);
            child.stdout_behavior = .Pipe;
            child.stderr_behavior = .Ignore;
            try child.spawn();

            if (child.stdout) |stdout_pipe| {
                all_deps[idx] = stdout_pipe.readToEndAlloc(self.allocator, 1024 * 1024) catch null;
            }
            _ = try child.wait();
        }

        defer {
            for (&all_deps) |*dep| {
                if (dep.*) |d| self.allocator.free(d);
            }
        }

        const build_deps = all_deps[0];
        const lib_deps = all_deps[1];
        const run_deps = all_deps[2];

        // Parse dependencies and extract port origins (category/port format)
        var origins = std.ArrayList([]const u8).init(self.allocator);
        defer {
            for (origins.items) |o| self.allocator.free(o);
            origins.deinit();
        }

        // BUILD_DEPENDS format: "/path/to/file:category/port" or "command:category/port"
        if (build_deps) |deps| {
            const trimmed = std.mem.trim(u8, deps, " \t\n\r");
            if (trimmed.len > 0) {
                var dep_iter = std.mem.splitSequence(u8, trimmed, " ");
                while (dep_iter.next()) |dep| {
                    const dep_trimmed = std.mem.trim(u8, dep, " \t\n\r");
                    if (dep_trimmed.len == 0) continue;

                    if (std.mem.indexOf(u8, dep_trimmed, ":")) |colon_pos| {
                        const origin = dep_trimmed[colon_pos + 1 ..];
                        if (origin.len > 0 and std.mem.indexOf(u8, origin, "/") != null) {
                            // Check for duplicates
                            var found = false;
                            for (origins.items) |existing| {
                                if (std.mem.eql(u8, existing, origin)) {
                                    found = true;
                                    break;
                                }
                            }
                            if (!found) {
                                try origins.append(try self.allocator.dupe(u8, origin));
                            }
                        }
                    }
                }
            }
        }

        // LIB_DEPENDS and RUN_DEPENDS format: "libname.so:category/port" or "file:category/port"
        const remaining_deps = [_]?[]const u8{ lib_deps, run_deps };
        for (remaining_deps) |deps_opt| {
            if (deps_opt) |deps| {
                const trimmed = std.mem.trim(u8, deps, " \t\n\r");
                if (trimmed.len > 0) {
                    var dep_iter = std.mem.splitSequence(u8, trimmed, " ");
                    while (dep_iter.next()) |dep| {
                        const dep_trimmed = std.mem.trim(u8, dep, " \t\n\r");
                        if (dep_trimmed.len == 0) continue;

                        if (std.mem.indexOf(u8, dep_trimmed, ":")) |colon_pos| {
                            const origin = dep_trimmed[colon_pos + 1 ..];
                            if (origin.len > 0 and std.mem.indexOf(u8, origin, "/") != null) {
                                var found = false;
                                for (origins.items) |existing| {
                                    if (std.mem.eql(u8, existing, origin)) {
                                        found = true;
                                        break;
                                    }
                                }
                                if (!found) {
                                    try origins.append(try self.allocator.dupe(u8, origin));
                                }
                            }
                        }
                    }
                }
            }
        }

        if (origins.items.len == 0) {
            std.debug.print("  Dependencies: none\n", .{});
            return;
        }

        std.debug.print("  Dependencies ({d} ports):\n", .{origins.items.len});
        for (origins.items) |origin| {
            std.debug.print("    - {s}\n", .{origin});
        }

        // Check which dependencies are missing from the Axiom store
        var missing = std.ArrayList([]const u8).init(self.allocator);
        defer missing.deinit();
        // Note: we don't free the strings in missing since they're borrowed from origins

        for (origins.items) |dep_origin| {
            // Skip dependencies that are in SKIP_PORTS (e.g., ports-mgmt/pkg)
            var is_skipped = false;
            for (SKIP_PORTS) |skip_origin| {
                if (std.mem.eql(u8, dep_origin, skip_origin)) {
                    is_skipped = true;
                    break;
                }
            }
            if (is_skipped) continue;

            // Map port origin to package name (handles Python flavors, etc.)
            const pkg_name = try self.mapPortNameAlloc(dep_origin);
            defer self.allocator.free(pkg_name);

            // Check if package exists in store
            var roots = self.findAllPackageRootsInStore(pkg_name) catch {
                try missing.append(dep_origin);
                continue;
            };

            if (roots.items.len == 0) {
                try missing.append(dep_origin);
            }

            // Clean up roots
            for (roots.items) |r| self.allocator.free(r);
            roots.deinit();
        }

        if (missing.items.len > 0) {
            std.debug.print("\n  ERROR: Required dependencies not found in Axiom store:\n", .{});
            for (missing.items) |dep| {
                std.debug.print("    - {s}\n", .{dep});
            }
            std.debug.print("\n  Please build these dependencies first:\n", .{});
            for (missing.items) |dep| {
                std.debug.print("    axiom ports-import {s}\n", .{dep});
            }
            std.debug.print("\n", .{});
            return error.MissingDependencies;
        }

        std.debug.print("  Note: All dependencies found in store.\n", .{});
    }

    /// Get direct dependencies for a port (returns list of port origins)
    fn getPortDependencies(self: *PortsMigrator, origin: []const u8) !std.ArrayList([]const u8) {
        // Parse origin to extract flavor (e.g., "devel/py-wheel@py311" -> path="devel/py-wheel", flavor="py311")
        const parsed = ParsedOrigin.parse(origin);

        const port_path = try std.fs.path.join(self.allocator, &[_][]const u8{
            self.options.ports_tree,
            parsed.path, // Use path without @flavor suffix
        });
        defer self.allocator.free(port_path);

        var deps = std.ArrayList([]const u8).init(self.allocator);
        errdefer {
            for (deps.items) |d| self.allocator.free(d);
            deps.deinit();
        }

        // Get BUILD_DEPENDS, LIB_DEPENDS, RUN_DEPENDS
        const dep_vars = [_][]const u8{ "BUILD_DEPENDS", "LIB_DEPENDS", "RUN_DEPENDS" };

        // Build flavor argument if present
        var flavor_arg: ?[]const u8 = null;
        defer if (flavor_arg) |f| self.allocator.free(f);
        if (parsed.flavor) |flv| {
            flavor_arg = try std.fmt.allocPrint(self.allocator, "FLAVOR={s}", .{flv});
        }

        for (dep_vars) |dep_var| {
            // Build args list with optional flavor
            var args_list = std.ArrayList([]const u8).init(self.allocator);
            defer args_list.deinit();
            try args_list.append("make");
            try args_list.append("-C");
            try args_list.append(port_path);
            if (flavor_arg) |f| {
                try args_list.append(f);
            }
            try args_list.append("-V");
            try args_list.append(dep_var);

            var child = std.process.Child.init(args_list.items, self.allocator);
            child.stdout_behavior = .Pipe;
            child.stderr_behavior = .Ignore;

            child.spawn() catch continue;

            var dep_output: ?[]const u8 = null;
            if (child.stdout) |stdout_pipe| {
                dep_output = stdout_pipe.readToEndAlloc(self.allocator, 1024 * 1024) catch null;
            }
            _ = child.wait() catch continue;

            if (dep_output) |output| {
                defer self.allocator.free(output);
                const trimmed = std.mem.trim(u8, output, " \t\n\r");
                if (trimmed.len == 0) continue;

                var iter = std.mem.splitSequence(u8, trimmed, " ");
                while (iter.next()) |dep| {
                    const dep_trimmed = std.mem.trim(u8, dep, " \t\n\r");
                    if (dep_trimmed.len == 0) continue;

                    // Extract origin from "file:category/port" or "lib:category/port"
                    if (std.mem.indexOf(u8, dep_trimmed, ":")) |colon_pos| {
                        const dep_origin = dep_trimmed[colon_pos + 1 ..];
                        if (dep_origin.len > 0 and std.mem.indexOf(u8, dep_origin, "/") != null) {
                            // Check for duplicates
                            var found = false;
                            for (deps.items) |existing| {
                                if (std.mem.eql(u8, existing, dep_origin)) {
                                    found = true;
                                    break;
                                }
                            }
                            if (!found) {
                                try deps.append(try self.allocator.dupe(u8, dep_origin));
                            }
                        }
                    }
                }
            }
        }

        return deps;
    }

    /// Dependency graph node
    const DepNode = struct {
        origin: []const u8,
        deps: []const []const u8,
        depth: usize,
    };

    /// Build complete dependency tree for a port (recursive)
    /// Returns list of all dependencies in topological order (leaves first)
    pub fn resolveDependencyTree(self: *PortsMigrator, root_origin: []const u8) !std.ArrayList([]const u8) {
        // Use ArrayHashMap so we can iterate keys later to free them
        var visited = std.StringArrayHashMap(usize).init(self.allocator);
        defer {
            // Free all owned keys
            for (visited.keys()) |key| {
                self.allocator.free(key);
            }
            visited.deinit();
        }

        var result = std.ArrayList([]const u8).init(self.allocator);
        errdefer {
            for (result.items) |r| self.allocator.free(r);
            result.deinit();
        }

        // Track what we're currently visiting (for cycle detection)
        // Keys are borrowed from visited, so no need to free
        var visiting = std.StringHashMap(void).init(self.allocator);
        defer visiting.deinit();

        // Recursive depth-first traversal
        try self.visitDependency(root_origin, &visited, &visiting, &result, 0);

        // Sort by depth (deepest first = leaves first)
        const SortContext = struct {
            visited: *std.StringArrayHashMap(usize),
        };

        const ctx = SortContext{ .visited = &visited };
        std.mem.sort([]const u8, result.items, ctx, struct {
            fn lessThan(c: SortContext, a: []const u8, b: []const u8) bool {
                const depth_a = c.visited.get(a) orelse 0;
                const depth_b = c.visited.get(b) orelse 0;
                // Higher depth = deeper in tree = should come first (leaves)
                return depth_a > depth_b;
            }
        }.lessThan);

        return result;
    }

    /// Visit a dependency node (recursive DFS)
    fn visitDependency(
        self: *PortsMigrator,
        origin: []const u8,
        visited: *std.StringArrayHashMap(usize),
        visiting: *std.StringHashMap(void),
        result: *std.ArrayList([]const u8),
        depth: usize,
    ) !void {
        // Already fully visited?
        if (visited.get(origin)) |existing_depth| {
            // Update depth if we found a deeper path
            if (depth > existing_depth) {
                visited.putAssumeCapacity(origin, depth);
            }
            return;
        }

        // Currently visiting? (cycle detection)
        if (visiting.contains(origin)) {
            if (self.options.verbose) {
                std.debug.print("  Warning: Circular dependency detected at {s}, skipping\n", .{origin});
            }
            return;
        }

        // Dupe the origin string so we own it (for use as hashmap key)
        const owned_origin = try self.allocator.dupe(u8, origin);
        errdefer self.allocator.free(owned_origin);

        // Mark as currently visiting (borrow from owned_origin)
        try visiting.put(owned_origin, {});

        // Get direct dependencies
        var deps = self.getPortDependencies(origin) catch |err| {
            if (self.options.verbose) {
                std.debug.print("  Warning: Could not get dependencies for {s}: {s}\n", .{ origin, @errorName(err) });
            }
            _ = visiting.remove(owned_origin);
            self.allocator.free(owned_origin);
            return;
        };
        defer {
            for (deps.items) |d| self.allocator.free(d);
            deps.deinit();
        }

        // Visit each dependency first (depth-first)
        for (deps.items) |dep| {
            try self.visitDependency(dep, visited, visiting, result, depth + 1);
        }

        // Done visiting children
        _ = visiting.remove(owned_origin);

        // Mark as visited with depth (transfer ownership of owned_origin to visited map)
        try visited.put(owned_origin, depth);

        // Add to result (dupe again since result needs its own copy)
        try result.append(try self.allocator.dupe(u8, origin));
    }

    /// Migrate a port and all its dependencies
    /// Returns results for all ports in build order
    pub fn migrateWithDependencies(self: *PortsMigrator, origin: []const u8) !std.ArrayList(MigrationResult) {
        var results = std.ArrayList(MigrationResult).init(self.allocator);
        errdefer {
            for (results.items) |*r| r.deinit(self.allocator);
            results.deinit();
        }

        if (self.options.auto_deps) {
            // Resolve full dependency tree
            std.debug.print("Resolving dependency tree for {s}...\n", .{origin});

            var dep_tree = try self.resolveDependencyTree(origin);
            defer {
                for (dep_tree.items) |d| self.allocator.free(d);
                dep_tree.deinit();
            }

            if (dep_tree.items.len > 1) {
                std.debug.print("\nBuild order ({d} ports):\n", .{dep_tree.items.len});
                for (dep_tree.items, 0..) |dep, i| {
                    std.debug.print("  {d}. {s}\n", .{ i + 1, dep });
                }
                std.debug.print("\n", .{});
            }

            // Build each dependency in order
            for (dep_tree.items) |dep| {
                std.debug.print("\n" ++ "=" ** 60 ++ "\n", .{});
                std.debug.print("Processing: {s}\n", .{dep});
                std.debug.print("=" ** 60 ++ "\n", .{});

                // Temporarily disable auto_deps to avoid infinite recursion
                const saved_auto_deps = self.options.auto_deps;
                self.options.auto_deps = false;
                defer self.options.auto_deps = saved_auto_deps;

                const result = try self.migrate(dep);
                try results.append(result);

                // Stop on failure unless continue_on_failure is set
                if (result.status == .failed and !self.options.continue_on_failure) {
                    std.debug.print("Stopping due to failure in {s}\n", .{dep});
                    std.debug.print("  (use --continue-on-failure to continue building other ports)\n", .{});
                    break;
                }
            }
        } else {
            // Just migrate the single port (no dependency resolution)
            const result = try self.migrate(origin);
            try results.append(result);
        }

        return results;
    }

    /// Import a built port into the Axiom store
    fn importPort(
        self: *PortsMigrator,
        metadata: *const PortMetadata,
        stage_dir: []const u8,
        origin: []const u8,
    ) !PackageId {
        // Map the origin to the correct package name (handles Python flavors)
        // e.g., devel/py-flit-core@py311 → py311-flit-core
        const pkg_name = try self.mapPortNameAlloc(origin);
        defer self.allocator.free(pkg_name);

        std.debug.print("\n=== Importing to store: {s} ===\n", .{pkg_name});

        // Get the importer from options
        const importer = self.options.importer orelse {
            std.debug.print("Error: Importer not provided in options\n", .{});
            return PortsError.ImportFailed;
        };

        // Parse version
        const version = types.Version.parse(metadata.version) catch {
            std.debug.print("Error: Failed to parse version: {s}\n", .{metadata.version});
            return PortsError.ImportFailed;
        };

        // Create import options
        // Note: We sign packages locally but the key may not be in the trust store yet
        // Use warn mode so verification continues but doesn't fail on untrusted local keys
        const import_options = import_pkg.ImportOptions{
            .name = pkg_name,
            .version = version,
            .revision = metadata.revision,
            .description = metadata.comment,
            .license = if (metadata.license.len > 0) metadata.license else null,
            .origin = origin, // FreeBSD port origin for tracking
            .dry_run = false,
            .auto_detect = false,
            .security = .{
                .verification_mode = signature.VerificationMode.warn, // Don't fail on untrusted local signing keys
                .allow_unsigned = true, // Also allow unsigned packages (signing optional)
                .trust_store_path = TRUST_STORE_PATH, // Use same trust store as signing
            },
        };

        // Find the actual package files (usually in usr/local under stage_dir)
        const pkg_root = try self.findPackageRoot(stage_dir);
        defer if (pkg_root.ptr != stage_dir.ptr) self.allocator.free(pkg_root);

        std.debug.print("  Package root: {s}\n", .{pkg_root});

        // Sign the package BEFORE import (while the staging directory is still writable)
        // The manifest.sig will be copied to the store along with other files
        if (self.options.sign_packages) {
            self.signSourceDirectory(pkg_root, pkg_name) catch |err| {
                std.debug.print("Warning: Failed to sign package: {s}\n", .{@errorName(err)});
                // Don't fail the import if signing fails
            };
        }

        // Import the package
        const pkg_id = importer.import(
            import_pkg.ImportSource{ .directory = pkg_root },
            import_options,
        ) catch |err| {
            std.debug.print("Import error: {s}\n", .{@errorName(err)});
            return PortsError.ImportFailed;
        };

        std.debug.print("  ✓ Package imported: {s}@{}\n", .{ pkg_id.name, pkg_id.version });

        return pkg_id;
    }

    /// Find the actual package root directory (e.g., usr/local) in staged output
    fn findPackageRoot(self: *PortsMigrator, stage_dir: []const u8) ![]const u8 {
        // FreeBSD ports typically stage to DESTDIR/usr/local
        const usr_local = try std.fs.path.join(self.allocator, &[_][]const u8{ stage_dir, "usr", "local" });

        if (std.fs.cwd().access(usr_local, .{})) |_| {
            return usr_local;
        } else |_| {
            self.allocator.free(usr_local);
        }

        // Try just usr/
        const usr = try std.fs.path.join(self.allocator, &[_][]const u8{ stage_dir, "usr" });

        if (std.fs.cwd().access(usr, .{})) |_| {
            return usr;
        } else |_| {
            self.allocator.free(usr);
        }

        // Fall back to stage_dir itself
        return stage_dir;
    }

    /// Batch migrate multiple ports
    pub fn migrateMultiple(self: *PortsMigrator, origins: []const []const u8) ![]MigrationResult {
        var results = std.ArrayList(MigrationResult).init(self.allocator);

        for (origins) |origin| {
            const result = try self.migrate(origin);
            try results.append(result);
        }

        return results.toOwnedSlice();
    }

    /// Scan ports tree for all ports in a category
    pub fn scanCategory(self: *PortsMigrator, category: []const u8) ![][]const u8 {
        const cat_path = try std.fs.path.join(self.allocator, &[_][]const u8{
            self.options.ports_tree,
            category,
        });
        defer self.allocator.free(cat_path);

        var ports = std.ArrayList([]const u8).init(self.allocator);

        var dir = std.fs.cwd().openDir(cat_path, .{ .iterate = true }) catch {
            return ports.toOwnedSlice();
        };
        defer dir.close();

        var iter = dir.iterate();
        while (try iter.next()) |entry| {
            if (entry.kind == .directory and entry.name[0] != '.') {
                // Check if it's a valid port (has Makefile)
                const makefile_path = try std.fs.path.join(self.allocator, &[_][]const u8{
                    cat_path,
                    entry.name,
                    "Makefile",
                });
                defer self.allocator.free(makefile_path);

                if (std.fs.cwd().access(makefile_path, .{})) |_| {
                    const origin = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ category, entry.name });
                    try ports.append(origin);
                } else |_| {}
            }
        }

        return ports.toOwnedSlice();
    }

    // --- Internal helpers ---

    fn makeVar(self: *PortsMigrator, port_path: []const u8, varname: []const u8) ![]const u8 {
        const result = try self.makeVarOptionalWithFlavor(port_path, varname, null);
        return result orelse PortsError.MissingRequiredField;
    }

    fn makeVarWithFlavor(self: *PortsMigrator, port_path: []const u8, varname: []const u8, flavor: ?[]const u8) ![]const u8 {
        const result = try self.makeVarOptionalWithFlavor(port_path, varname, flavor);
        return result orelse PortsError.MissingRequiredField;
    }

    fn makeVarOptional(self: *PortsMigrator, port_path: []const u8, varname: []const u8) !?[]const u8 {
        return self.makeVarOptionalWithFlavor(port_path, varname, null);
    }

    fn makeVarOptionalWithFlavor(self: *PortsMigrator, port_path: []const u8, varname: []const u8, flavor: ?[]const u8) !?[]const u8 {
        var args = std.ArrayList([]const u8).init(self.allocator);
        defer args.deinit();

        try args.append("make");
        try args.append("-C");
        try args.append(port_path);

        // Add FLAVOR if specified (for flavored ports like py-setuptools@py311)
        var flavor_arg: ?[]const u8 = null;
        defer if (flavor_arg) |f| self.allocator.free(f);
        if (flavor) |flv| {
            flavor_arg = try std.fmt.allocPrint(self.allocator, "FLAVOR={s}", .{flv});
            try args.append(flavor_arg.?);
        }

        try args.append("-V");
        try args.append(varname);

        var child = std.process.Child.init(args.items, self.allocator);
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Ignore;

        try child.spawn();

        var stdout_buf: [8192]u8 = undefined;
        var total_read: usize = 0;

        if (child.stdout) |stdout| {
            while (true) {
                const n = stdout.read(stdout_buf[total_read..]) catch break;
                if (n == 0) break;
                total_read += n;
                if (total_read >= stdout_buf.len) break;
            }
        }

        _ = child.wait() catch |err| {
            errors.logProcessCleanup(@src(), err, "ports make target");
        };

        if (total_read == 0) return null;

        // Trim trailing newline
        var end = total_read;
        while (end > 0 and (stdout_buf[end - 1] == '\n' or stdout_buf[end - 1] == '\r')) {
            end -= 1;
        }

        if (end == 0) return null;

        return try self.allocator.dupe(u8, stdout_buf[0..end]);
    }

    fn hasMakeVar(self: *PortsMigrator, port_path: []const u8, varname: []const u8) !bool {
        return self.hasMakeVarWithFlavor(port_path, varname, null);
    }

    fn hasMakeVarWithFlavor(self: *PortsMigrator, port_path: []const u8, varname: []const u8, flavor: ?[]const u8) !bool {
        const result = try self.makeVarOptionalWithFlavor(port_path, varname, flavor);
        if (result) |r| {
            self.allocator.free(r);
            return true;
        }
        return false;
    }

    fn splitWhitespace(self: *PortsMigrator, input: []const u8) ![]const []const u8 {
        var parts = std.ArrayList([]const u8).init(self.allocator);
        var iter = std.mem.tokenizeAny(u8, input, " \t\n\r");
        while (iter.next()) |part| {
            try parts.append(try self.allocator.dupe(u8, part));
        }
        return parts.toOwnedSlice();
    }

    fn readPkgDescr(self: *PortsMigrator, port_path: []const u8) ![]const u8 {
        const descr_path = try std.fs.path.join(self.allocator, &[_][]const u8{
            port_path,
            "pkg-descr",
        });
        defer self.allocator.free(descr_path);

        const file = std.fs.cwd().openFile(descr_path, .{}) catch {
            return try self.allocator.dupe(u8, "");
        };
        defer file.close();

        return file.readToEndAlloc(self.allocator, 65536) catch {
            return try self.allocator.dupe(u8, "");
        };
    }

    fn readDistinfoSha256(self: *PortsMigrator, port_path: []const u8) ![]const u8 {
        const distinfo_path = try std.fs.path.join(self.allocator, &[_][]const u8{
            port_path,
            "distinfo",
        });
        defer self.allocator.free(distinfo_path);

        const file = std.fs.cwd().openFile(distinfo_path, .{}) catch {
            return try self.allocator.dupe(u8, "");
        };
        defer file.close();

        const content = file.readToEndAlloc(self.allocator, 65536) catch {
            return try self.allocator.dupe(u8, "");
        };
        defer self.allocator.free(content);

        // Parse SHA256 line: SHA256 (filename) = hash
        var lines = std.mem.tokenizeScalar(u8, content, '\n');
        while (lines.next()) |line| {
            if (std.mem.startsWith(u8, line, "SHA256")) {
                // Find the hash after " = "
                if (std.mem.indexOf(u8, line, " = ")) |idx| {
                    return try self.allocator.dupe(u8, line[idx + 3 ..]);
                }
            }
        }

        return try self.allocator.dupe(u8, "");
    }

    fn parseDependencies(self: *PortsMigrator, port_path: []const u8, depvar: []const u8) ![]const PortDependency {
        return self.parseDependenciesWithFlavor(port_path, depvar, null);
    }

    fn parseDependenciesWithFlavor(self: *PortsMigrator, port_path: []const u8, depvar: []const u8, flavor: ?[]const u8) ![]const PortDependency {
        const deps_str = try self.makeVarOptionalWithFlavor(port_path, depvar, flavor) orelse return &[_]PortDependency{};
        defer self.allocator.free(deps_str);

        var deps = std.ArrayList(PortDependency).init(self.allocator);

        // Format: file:origin or lib.so:origin or pkg>=version:origin
        var iter = std.mem.tokenizeAny(u8, deps_str, " \t\n\r");
        while (iter.next()) |dep_spec| {
            if (std.mem.indexOf(u8, dep_spec, ":")) |colon_idx| {
                const file_or_pkg = dep_spec[0..colon_idx];
                const origin = dep_spec[colon_idx + 1 ..];

                // Extract package name from origin (last component)
                const pkg_name = std.fs.path.basename(origin);

                try deps.append(.{
                    .origin = try self.allocator.dupe(u8, origin),
                    .package = try self.allocator.dupe(u8, pkg_name),
                    .version = null, // TODO: parse version from pkg>=version
                    .file_or_lib = try self.allocator.dupe(u8, file_or_pkg),
                });
            }
        }

        return deps.toOwnedSlice();
    }

    fn parseOptions(self: *PortsMigrator, port_path: []const u8) ![]const PortOption {
        return self.parseOptionsWithFlavor(port_path, null);
    }

    fn parseOptionsWithFlavor(self: *PortsMigrator, port_path: []const u8, flavor: ?[]const u8) ![]const PortOption {
        _ = self;
        _ = port_path;
        _ = flavor;
        // TODO: Parse OPTIONS_DEFINE, OPTIONS_DEFAULT, etc.
        return &[_]PortOption{};
    }

    fn detectConfigureStyle(self: *PortsMigrator, uses: []const []const u8) ConfigureStyle {
        _ = self;
        for (uses) |u| {
            if (std.mem.startsWith(u8, u, "cmake")) return .cmake;
            if (std.mem.startsWith(u8, u, "meson")) return .meson;
            if (std.mem.startsWith(u8, u, "cargo")) return .cargo;
            if (std.mem.startsWith(u8, u, "go:")) return .go;
            if (std.mem.startsWith(u8, u, "python")) return .python;
            if (std.mem.startsWith(u8, u, "perl")) return .perl;
            if (std.mem.startsWith(u8, u, "ruby")) return .ruby;
            if (std.mem.startsWith(u8, u, "qmake")) return .qmake;
            if (std.mem.startsWith(u8, u, "scons")) return .scons;
            if (std.mem.startsWith(u8, u, "waf")) return .waf;
            if (std.mem.startsWith(u8, u, "autoreconf") or
                std.mem.startsWith(u8, u, "gmake") or
                std.mem.startsWith(u8, u, "libtool"))
            {
                return .gnu_configure;
            }
        }
        return .gnu_configure; // Default assumption
    }

    /// Map a ports origin like "devel/p5-Locale-gettext" or "lang/perl5.42"
    /// to the canonical Axiom package name used in the store.
    ///
    /// Rules in order:
    /// 0. Strip @flavor suffix if present (e.g., py-setuptools@py311 → py-setuptools)
    /// 1. Exact origin overrides (lang/perl5.42 → perl, devel/autoconf-switch → autoconf)
    /// 2. Python packages with flavor: py-*@pyXXX → pyXXX-* (e.g., py-flit-core@py311 → py311-flit-core)
    /// 3. Perl core ports: perl5* → perl
    /// 4. Perl modules: p5-* → strip "p5-" prefix
    /// 5. Fallback: use the port name (last path component) as-is
    fn mapPortName(self: *PortsMigrator, origin: []const u8) []const u8 {
        _ = self; // May use self.options.name_mappings for additional overrides later

        // Extract flavor if present (e.g., "devel/py-setuptools@py311" → flavor="py311")
        var flavor: ?[]const u8 = null;
        const origin_without_flavor = if (std.mem.indexOfScalar(u8, origin, '@')) |at_pos| blk: {
            flavor = origin[at_pos + 1 ..];
            break :blk origin[0..at_pos];
        } else origin;

        // Compile-time map for exact origin overrides
        const overrides = std.StaticStringMap([]const u8).initComptime(.{
            // Perl core (explicit origins)
            .{ "lang/perl5.42", "perl" },
            .{ "lang/perl5.40", "perl" },
            .{ "lang/perl5.38", "perl" },
            .{ "lang/perl5.36", "perl" },

            // Autoconf switch installs tools under autoconf
            .{ "devel/autoconf-switch", "autoconf" },

            // gmake package - normalize to 'make' for Axiom store naming
            // (the binary is still 'gmake', this is just the package name)
            .{ "devel/gmake", "make" },
        });

        // 1. Check exact origin overrides (using origin without flavor)
        if (overrides.get(origin_without_flavor)) |name| {
            return name;
        }

        // 2. Extract last path component: "category/name" → "name"
        const port_name = blk: {
            if (std.mem.lastIndexOfScalar(u8, origin_without_flavor, '/')) |idx| {
                break :blk origin_without_flavor[idx + 1 ..];
            } else {
                break :blk origin_without_flavor;
            }
        };

        // 3. Perl core ports: perl5, perl5.42, perl5XX → "perl"
        if (std.mem.startsWith(u8, port_name, "perl5")) {
            return "perl";
        }

        // 4. Python interpreter: python311, python39, python3XX → "python"
        // FreeBSD python ports (lang/python311, lang/python39) all install as "python"
        if (std.mem.startsWith(u8, port_name, "python3") or std.mem.startsWith(u8, port_name, "python2")) {
            return "python";
        }

        // 5. Perl modules: p5-* → strip "p5-" prefix
        if (std.mem.startsWith(u8, port_name, "p5-") and port_name.len > 3) {
            return port_name[3..]; // Skip "p5-"
        }

        // 6. Fallback: use the port name as-is
        return port_name;
    }

    /// Map port origin to Axiom package name (allocating version)
    /// Handles Python packages: py-flit-core@py311 → py311-flit-core
    /// Returns an allocated string that the caller must free.
    fn mapPortNameAlloc(self: *PortsMigrator, origin: []const u8) ![]const u8 {
        // Extract flavor if present
        var flavor: ?[]const u8 = null;
        const origin_without_flavor = if (std.mem.indexOfScalar(u8, origin, '@')) |at_pos| blk: {
            flavor = origin[at_pos + 1 ..];
            break :blk origin[0..at_pos];
        } else origin;

        // Extract port name (last path component)
        const port_name = if (std.mem.lastIndexOfScalar(u8, origin_without_flavor, '/')) |idx|
            origin_without_flavor[idx + 1 ..]
        else
            origin_without_flavor;

        // Python packages with flavor: py-flit-core@py311 → py311-flit-core
        if (flavor) |flv| {
            if (std.mem.startsWith(u8, port_name, "py-") and port_name.len > 3) {
                // Construct: flavor + "-" + (port_name without "py-")
                // e.g., "py311" + "-" + "flit-core" = "py311-flit-core"
                const name_without_prefix = port_name[3..]; // Skip "py-"
                return try std.fmt.allocPrint(self.allocator, "{s}-{s}", .{ flv, name_without_prefix });
            }
        }

        // For non-Python packages, use the existing mapping and dupe
        const mapped = self.mapPortName(origin);
        return try self.allocator.dupe(u8, mapped);
    }

    /// Check if a port is a kernel module based on USES and categories
    fn isKernelModule(meta: *const PortMetadata) bool {
        // Check USES for kmod
        for (meta.uses) |u| {
            if (std.mem.eql(u8, u, "kmod") or std.mem.startsWith(u8, u, "kmod:")) {
                return true;
            }
        }

        // Check categories for kld (kernel loadable modules)
        for (meta.categories) |cat| {
            if (std.mem.eql(u8, cat, "kld")) {
                return true;
            }
        }

        return false;
    }

    /// Get current FreeBSD version for kernel compat (placeholder)
    fn getCurrentFreeBSDVersion(self: *PortsMigrator) u32 {
        _ = self;
        // In production, this would read from:
        // - make -V OSVERSION
        // - sysctl kern.osreldate
        // For now, return a placeholder value
        return 1502000; // FreeBSD 15.0-CURRENT
    }

    fn generateManifestYaml(self: *PortsMigrator, meta: *const PortMetadata, origin: []const u8) ![]const u8 {
        var output = std.ArrayList(u8).init(self.allocator);
        const writer = output.writer();

        // Use mapPortNameAlloc to get correct package name (handles Python flavors)
        // e.g., devel/py-flit-core@py311 → py311-flit-core
        const pkg_name = try self.mapPortNameAlloc(origin);
        defer self.allocator.free(pkg_name);

        try writer.writeAll("# Generated from FreeBSD port\n");
        try writer.writeAll("name: ");
        try writer.writeAll(pkg_name);
        try writer.writeAll("\n");

        try writer.writeAll("version: \"");
        try writer.writeAll(meta.version);
        try writer.writeAll("\"\n");

        try writer.writeAll("revision: ");
        try std.fmt.format(writer, "{d}\n", .{meta.revision});

        try writer.writeAll("description: ");
        try writer.writeAll(meta.comment);
        try writer.writeAll("\n");

        if (meta.license.len > 0) {
            try writer.writeAll("license: ");
            try writer.writeAll(meta.license);
            try writer.writeAll("\n");
        }

        if (meta.www.len > 0) {
            try writer.writeAll("homepage: ");
            try writer.writeAll(meta.www);
            try writer.writeAll("\n");
        }

        if (meta.maintainer.len > 0) {
            try writer.writeAll("maintainer: ");
            try writer.writeAll(meta.maintainer);
            try writer.writeAll("\n");
        }

        // Origin (port path) - used to distinguish packages with same name from different ports
        try writer.writeAll("origin: ");
        try writer.writeAll(origin);
        try writer.writeAll("\n");

        // Provides
        try writer.writeAll("\nprovides:\n");
        try writer.writeAll("  - ");
        try writer.writeAll(meta.name);
        try writer.writeAll("\n");

        // Conflicts
        if (meta.conflicts.len > 0) {
            try writer.writeAll("\nconflicts:\n");
            for (meta.conflicts) |c| {
                try writer.writeAll("  - ");
                try writer.writeAll(c);
                try writer.writeAll("\n");
            }
        }

        // Kernel compatibility (for kmod packages)
        if (isKernelModule(meta)) {
            const freebsd_version = self.getCurrentFreeBSDVersion();
            // Set version range for current major version (e.g., 1500000-1509999 for 15.x)
            const major_min = (freebsd_version / 100000) * 100000;
            const major_max = major_min + 99999;

            try writer.writeAll("\nkernel:\n");
            try writer.writeAll("  kmod: true\n");
            try std.fmt.format(writer, "  freebsd_version_min: {d}\n", .{major_min});
            try std.fmt.format(writer, "  freebsd_version_max: {d}\n", .{major_max});
            try writer.writeAll("  # Note: kernel_idents left empty - compatible with any ident\n");
            try writer.writeAll("  # Add specific kernel idents if this kmod requires them:\n");
            try writer.writeAll("  # kernel_idents:\n");
            try writer.writeAll("  #   - \"GENERIC\"\n");
            try writer.writeAll("  #   - \"PGSD-GENERIC\"\n");
            try writer.writeAll("  require_exact_ident: false\n");
            try writer.writeAll("  # kld_names populated from port's installed .ko files:\n");
            try writer.writeAll("  kld_names:\n");
            try std.fmt.format(writer, "    - \"{s}.ko\"\n", .{meta.name});
        }

        return output.toOwnedSlice();
    }
};

/// Information about a package with broken layout
pub const BrokenPackage = struct {
    name: []const u8,
    origin: ?[]const u8,
    path: []const u8,

    pub fn deinit(self: BrokenPackage, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        if (self.origin) |o| allocator.free(o);
        allocator.free(self.path);
    }
};

/// Result of a single port migration
pub const MigrationResult = struct {
    origin: []const u8,
    status: MigrationStatus,
    skip_reason: SkipReason = .none,
    manifest_path: ?[]const u8,
    axiom_package: ?[]const u8, // Package ID if imported
    warnings: std.ArrayList([]const u8),
    errors: std.ArrayList([]const u8),

    pub fn deinit(self: *MigrationResult, allocator: std.mem.Allocator) void {
        // origin is now owned (duplicated in migrate())
        allocator.free(self.origin);
        if (self.manifest_path) |p| allocator.free(p);
        if (self.axiom_package) |p| allocator.free(p);
        for (self.warnings.items) |w| allocator.free(w);
        self.warnings.deinit();
        for (self.errors.items) |e| allocator.free(e);
        self.errors.deinit();
    }
};

pub const MigrationStatus = enum {
    pending,
    generated,
    built,
    imported,
    failed,
    skipped,
};

/// Reason why a package was skipped during migration
pub const SkipReason = enum {
    none, // Not skipped
    already_in_store, // Package already exists with same origin
    replaced_by_axiom, // Port is in SKIP_PORTS (e.g., ports-mgmt/pkg)

    pub fn description(self: SkipReason) []const u8 {
        return switch (self) {
            .none => "not skipped",
            .already_in_store => "already in store",
            .replaced_by_axiom => "replaced by Axiom",
        };
    }
};

/// Generate a migration report
pub fn generateReport(allocator: std.mem.Allocator, results: []const MigrationResult) ![]const u8 {
    var output = std.ArrayList(u8).init(allocator);
    const writer = output.writer();

    var generated: u32 = 0;
    var built: u32 = 0;
    var imported: u32 = 0;
    var failed: u32 = 0;
    var skipped: u32 = 0;

    for (results) |r| {
        switch (r.status) {
            .generated => generated += 1,
            .built => built += 1,
            .imported => imported += 1,
            .failed => failed += 1,
            .skipped => skipped += 1,
            .pending => {},
        }
    }

    try writer.writeAll("Ports Migration Report\n");
    try writer.writeAll("======================\n\n");

    try std.fmt.format(writer, "Total ports processed: {d}\n", .{results.len});
    try std.fmt.format(writer, "  Generated: {d}\n", .{generated});
    try std.fmt.format(writer, "  Built: {d}\n", .{built});
    try std.fmt.format(writer, "  Imported: {d}\n", .{imported});
    try std.fmt.format(writer, "  Failed: {d}\n", .{failed});
    try std.fmt.format(writer, "  Skipped: {d}\n", .{skipped});

    if (failed > 0) {
        try writer.writeAll("\nFailed ports:\n");
        for (results) |r| {
            if (r.status == .failed) {
                try std.fmt.format(writer, "  - {s}\n", .{r.origin});
                for (r.errors.items) |err| {
                    try std.fmt.format(writer, "      Error: {s}\n", .{err});
                }
            }
        }
    }

    return output.toOwnedSlice();
}
