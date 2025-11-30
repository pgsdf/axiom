const std = @import("std");
const zfs = @import("zfs.zig");
const types = @import("types.zig");
const store = @import("store.zig");
const manifest = @import("manifest.zig");
const secure_tar = @import("secure_tar.zig");
const signature = @import("signature.zig");

const ZfsHandle = zfs.ZfsHandle;
const PackageId = types.PackageId;
const PackageStore = store.PackageStore;
const Version = types.Version;
const SecureTarExtractor = secure_tar.SecureTarExtractor;
const Verifier = signature.Verifier;
const TrustStore = signature.TrustStore;
const VerificationStatus = signature.VerificationStatus;
const VerificationMode = signature.VerificationMode;

/// Import errors
pub const ImportError = error{
    SourceNotFound,
    InvalidSource,
    ManifestRequired,
    ExtractionFailed,
    ImportFailed,
    UnsupportedFormat,
    // Security errors
    PathTraversal,
    SymlinkEscape,
    DeviceNodeRejected,
    FileTooLarge,
    InvalidArchive,
    // Signature verification errors (Phase 25)
    SignatureMissing,
    SignatureInvalid,
    KeyUntrusted,
    HashMismatch,
    VerificationFailed,
};

/// Source types for package import
pub const ImportSource = union(enum) {
    directory: []const u8,
    tarball: []const u8,
    zfs_stream: []const u8,

    pub fn getPath(self: ImportSource) []const u8 {
        return switch (self) {
            .directory => |p| p,
            .tarball => |p| p,
            .zfs_stream => |p| p,
        };
    }
};

/// Detected metadata from package contents
pub const DetectedMetadata = struct {
    name: ?[]const u8 = null,
    version: ?Version = null,
    description: ?[]const u8 = null,
    license: ?[]const u8 = null,
    homepage: ?[]const u8 = null,
    file_type: FileType = .unknown,
    has_binaries: bool = false,
    has_libraries: bool = false,
    has_headers: bool = false,
    has_man_pages: bool = false,

    pub const FileType = enum {
        binary,
        library,
        headers,
        data,
        mixed,
        unknown,
    };

    pub fn deinit(self: *DetectedMetadata, allocator: std.mem.Allocator) void {
        if (self.name) |n| allocator.free(n);
        if (self.description) |d| allocator.free(d);
        if (self.license) |l| allocator.free(l);
        if (self.homepage) |h| allocator.free(h);
    }
};

/// Import options
pub const ImportOptions = struct {
    name: ?[]const u8 = null,
    version: ?Version = null,
    revision: u32 = 1,
    description: ?[]const u8 = null,
    license: ?[]const u8 = null,
    manifest_path: ?[]const u8 = null,
    dry_run: bool = false,
    auto_detect: bool = true,
    build_id: ?[]const u8 = null,
    /// Security options for tarball extraction
    security: SecurityOptions = .{},
};

/// Security options for import operations
pub const SecurityOptions = struct {
    /// Use secure extraction (Phase 24 hardening)
    secure_extraction: bool = true,
    /// Allow symlinks in imported packages
    allow_symlinks: bool = true,
    /// Strip setuid/setgid bits
    strip_setuid: bool = true,
    /// Maximum file size (bytes)
    max_file_size: u64 = 1024 * 1024 * 1024, // 1GB
    /// Maximum total extraction size (bytes)
    max_total_size: u64 = 10 * 1024 * 1024 * 1024, // 10GB

    // Phase 25: Signature verification options
    /// Verification mode (strict, warn, disabled)
    verification_mode: VerificationMode = .strict,
    /// Allow import of unsigned packages (requires explicit flag)
    allow_unsigned: bool = false,
    /// Trust store path for key lookup
    trust_store_path: ?[]const u8 = null,
};

/// Package importer
pub const Importer = struct {
    allocator: std.mem.Allocator,
    zfs_handle: *ZfsHandle,
    store: *PackageStore,

    /// Initialize importer
    pub fn init(
        allocator: std.mem.Allocator,
        zfs_handle: *ZfsHandle,
        store_ptr: *PackageStore,
    ) Importer {
        return Importer{
            .allocator = allocator,
            .zfs_handle = zfs_handle,
            .store = store_ptr,
        };
    }

    /// Import a package from source
    pub fn import(self: *Importer, source: ImportSource, options: ImportOptions) !PackageId {
        std.debug.print("Importing package from: {s}\n", .{source.getPath()});

        // Verify source exists
        try self.verifySource(source);

        // Create temporary extraction directory if needed
        var extract_dir: ?[]const u8 = null;
        var cleanup_extract = false;
        defer {
            if (cleanup_extract) {
                if (extract_dir) |dir| {
                    std.fs.cwd().deleteTree(dir) catch {};
                    self.allocator.free(dir);
                }
            }
        }

        // Get the directory containing package files
        const pkg_dir: []const u8 = switch (source) {
            .directory => |dir| dir,
            .tarball => |path| blk: {
                extract_dir = try self.extractTarball(path, options.security);
                cleanup_extract = true;
                break :blk extract_dir.?;
            },
            .zfs_stream => {
                std.debug.print("ZFS stream import not yet implemented\n", .{});
                return ImportError.UnsupportedFormat;
            },
        };

        // Phase 25: Verify package signature before trusting content
        if (options.security.verification_mode != .disabled) {
            try self.verifyPackageSignature(pkg_dir, options.security);
        }

        // Detect or load metadata
        var metadata: DetectedMetadata = undefined;
        var cleanup_metadata = false;
        defer {
            if (cleanup_metadata) {
                metadata.deinit(self.allocator);
            }
        }

        if (options.manifest_path) |manifest_file| {
            // Load from provided manifest
            metadata = try self.loadManifestMetadata(manifest_file);
            cleanup_metadata = true;
        } else if (options.auto_detect) {
            // Auto-detect metadata
            metadata = try self.detectMetadata(pkg_dir);
            cleanup_metadata = true;
        } else {
            metadata = DetectedMetadata{};
        }

        // Build final package info, preferring explicit options over detected
        const pkg_name = options.name orelse metadata.name orelse {
            std.debug.print("Error: Package name required. Use --name or provide manifest.\n", .{});
            return ImportError.ManifestRequired;
        };

        const pkg_version = options.version orelse metadata.version orelse {
            std.debug.print("Error: Package version required. Use --version or provide manifest.\n", .{});
            return ImportError.ManifestRequired;
        };

        // Generate build ID if not provided
        const build_id = options.build_id orelse try self.generateBuildId();
        defer if (options.build_id == null) self.allocator.free(build_id);

        const pkg_id = PackageId{
            .name = pkg_name,
            .version = pkg_version,
            .revision = options.revision,
            .build_id = build_id,
        };

        std.debug.print("\nPackage Details:\n", .{});
        std.debug.print("  Name:     {s}\n", .{pkg_id.name});
        std.debug.print("  Version:  {}\n", .{pkg_id.version});
        std.debug.print("  Revision: {d}\n", .{pkg_id.revision});
        std.debug.print("  Build ID: {s}\n", .{pkg_id.build_id});

        if (options.dry_run) {
            std.debug.print("\nDRY RUN - Package would be imported\n", .{});
            return pkg_id;
        }

        // Create manifests
        const pkg_manifest = manifest.Manifest{
            .name = pkg_name,
            .version = pkg_version,
            .revision = options.revision,
            .description = if (options.description) |d| 
                try self.allocator.dupe(u8, d) 
            else if (metadata.description) |d| 
                try self.allocator.dupe(u8, d) 
            else 
                null,
            .license = if (options.license) |l| 
                try self.allocator.dupe(u8, l) 
            else if (metadata.license) |l| 
                try self.allocator.dupe(u8, l) 
            else 
                null,
            .homepage = if (metadata.homepage) |h| try self.allocator.dupe(u8, h) else null,
            .tags = &[_][]const u8{},
        };
        defer {
            if (pkg_manifest.description) |d| self.allocator.free(d);
            if (pkg_manifest.license) |l| self.allocator.free(l);
            if (pkg_manifest.homepage) |h| self.allocator.free(h);
        }

        const deps_manifest = manifest.DependencyManifest{
            .dependencies = &[_]types.Dependency{},
        };

        const prov = manifest.Provenance{
            .build_time = std.time.timestamp(),
            .builder = try self.allocator.dupe(u8, "axiom-import"),
            .source_url = try self.allocator.dupe(u8, source.getPath()),
            .build_flags = &[_][]const u8{},
        };
        defer {
            self.allocator.free(prov.builder);
            if (prov.source_url) |u| self.allocator.free(u);
        }

        // Add to store
        std.debug.print("\nAdding to package store...\n", .{});
        try self.store.addPackage(pkg_id, pkg_dir, pkg_manifest, deps_manifest, prov);

        std.debug.print("✓ Package imported successfully\n", .{});

        return pkg_id;
    }

    /// Verify source exists and is accessible
    fn verifySource(self: *Importer, source: ImportSource) !void {
        _ = self;
        const path = source.getPath();

        std.fs.cwd().access(path, .{}) catch {
            std.debug.print("Error: Source not found: {s}\n", .{path});
            return ImportError.SourceNotFound;
        };
    }

    // ========================================================================
    // Phase 25: Signature Verification
    // ========================================================================

    /// Verify package signature using type-safe VerificationStatus
    fn verifyPackageSignature(self: *Importer, pkg_path: []const u8, security: SecurityOptions) !void {
        std.debug.print("Verifying package signature...\n", .{});

        // Initialize trust store
        const trust_store_path = security.trust_store_path orelse "/var/axiom/trust/keys.toml";
        var trust_store = TrustStore.init(self.allocator, trust_store_path);
        defer trust_store.deinit();

        // Try to load existing trust store
        trust_store.load() catch {
            // Trust store doesn't exist yet - that's OK for new installations
            std.debug.print("  Note: Trust store not found at {s}\n", .{trust_store_path});
        };

        // Create verifier with configured mode
        var verifier = Verifier.init(self.allocator, &trust_store, security.verification_mode);

        // Perform type-safe verification
        var status = verifier.verifyPackageTypeSafe(pkg_path);
        defer status.deinit(self.allocator);

        // Handle verification result based on mode
        switch (status) {
            .verified => |v| {
                std.debug.print("  ✓ Package verified\n", .{});
                std.debug.print("    Signer: {s}\n", .{v.signer_name orelse "unknown"});
                std.debug.print("    Key ID: {s}\n", .{v.signer_key_id});
                std.debug.print("    Trust Level: {s}\n", .{v.trust_level.description()});
                std.debug.print("    Files verified: {d}\n", .{v.files_verified});
                // Verification passed - continue with import
            },
            .signature_missing => {
                if (security.verification_mode == .strict and !security.allow_unsigned) {
                    std.debug.print("  ✗ SECURITY ERROR: No signature found\n", .{});
                    std.debug.print("    Use --allow-unsigned to import unsigned packages\n", .{});
                    return ImportError.SignatureMissing;
                } else {
                    std.debug.print("  ⚠ WARNING: Package is not signed\n", .{});
                    // Continue with import in warn mode or if allow_unsigned
                }
            },
            .signature_invalid => |info| {
                if (security.verification_mode == .strict) {
                    std.debug.print("  ✗ SECURITY ERROR: Invalid signature\n", .{});
                    std.debug.print("    Reason: {s}\n", .{info.reason});
                    return ImportError.SignatureInvalid;
                } else {
                    std.debug.print("  ⚠ WARNING: Invalid signature - {s}\n", .{info.reason});
                }
            },
            .key_untrusted => |info| {
                if (security.verification_mode == .strict) {
                    std.debug.print("  ✗ SECURITY ERROR: Signing key is not trusted\n", .{});
                    std.debug.print("    Key ID: {s}\n", .{info.key_id});
                    if (info.signer_name) |name| {
                        std.debug.print("    Signer: {s}\n", .{name});
                    }
                    if (info.key_exists) {
                        std.debug.print("    Note: Key exists but is not marked as trusted\n", .{});
                        std.debug.print("    Run: axiom key-trust {s}\n", .{info.key_id});
                    } else {
                        std.debug.print("    Note: Key not found in trust store\n", .{});
                        std.debug.print("    Run: axiom key-add <key-file> to add the key\n", .{});
                    }
                    return ImportError.KeyUntrusted;
                } else {
                    std.debug.print("  ⚠ WARNING: Signing key {s} is not trusted\n", .{info.key_id});
                }
            },
            .hash_mismatch => |info| {
                std.debug.print("  ✗ SECURITY ERROR: Package content has been modified!\n", .{});
                std.debug.print("    File: {s}\n", .{info.file_path});
                std.debug.print("    Total files with mismatched hashes: {d}\n", .{info.total_failed});
                // Hash mismatch is always an error, even in warn mode
                return ImportError.HashMismatch;
            },
        }
    }

    /// Extract tarball to temporary directory using secure extraction
    fn extractTarball(self: *Importer, tarball_path: []const u8, security: SecurityOptions) ![]const u8 {
        std.debug.print("Extracting tarball: {s}\n", .{tarball_path});

        // Create temp directory with random component for security
        const timestamp = std.time.timestamp();
        var random_bytes: [4]u8 = undefined;
        std.crypto.random.bytes(&random_bytes);

        const temp_dir = try std.fmt.allocPrint(
            self.allocator,
            "/tmp/axiom-import-{d}-{x:0>2}{x:0>2}{x:0>2}{x:0>2}",
            .{ timestamp, random_bytes[0], random_bytes[1], random_bytes[2], random_bytes[3] },
        );
        errdefer self.allocator.free(temp_dir);

        try std.fs.cwd().makePath(temp_dir);

        // Use secure extraction by default
        if (security.secure_extraction) {
            std.debug.print("Using secure tar extraction (Phase 24 hardening)\n", .{});

            // Configure secure extraction options
            const extract_options = SecureTarExtractor.ExtractOptions{
                .allow_symlinks = security.allow_symlinks,
                .allow_absolute_paths = false, // Always reject absolute paths
                .allow_parent_refs = false, // Always reject path traversal
                .strip_setuid = security.strip_setuid,
                .strip_sticky = true,
                .max_file_size = security.max_file_size,
                .max_total_size = security.max_total_size,
            };

            var extractor = SecureTarExtractor.init(
                self.allocator,
                temp_dir,
                extract_options,
            );

            extractor.extractFromPath(tarball_path) catch |err| {
                // Map secure_tar errors to ImportError
                switch (err) {
                    SecureTarExtractor.ExtractionError.PathTraversal => {
                        std.debug.print("SECURITY: Path traversal attack detected in tarball!\n", .{});
                        return ImportError.PathTraversal;
                    },
                    SecureTarExtractor.ExtractionError.AbsolutePath => {
                        std.debug.print("SECURITY: Absolute path detected in tarball!\n", .{});
                        return ImportError.PathTraversal;
                    },
                    SecureTarExtractor.ExtractionError.SymlinkEscape => {
                        std.debug.print("SECURITY: Symlink escape detected in tarball!\n", .{});
                        return ImportError.SymlinkEscape;
                    },
                    SecureTarExtractor.ExtractionError.FileTooLarge,
                    SecureTarExtractor.ExtractionError.TotalSizeTooLarge,
                    => {
                        std.debug.print("SECURITY: Archive size limit exceeded!\n", .{});
                        return ImportError.FileTooLarge;
                    },
                    SecureTarExtractor.ExtractionError.MalformedArchive => {
                        std.debug.print("Error: Malformed archive\n", .{});
                        return ImportError.InvalidArchive;
                    },
                    else => {
                        std.debug.print("Error extracting tarball: {}\n", .{err});
                        return ImportError.ExtractionFailed;
                    },
                }
            };

            // Report extraction statistics
            const stats = extractor.getStats();
            std.debug.print("Extraction complete:\n", .{});
            std.debug.print("  Files: {d}\n", .{stats.files_extracted});
            std.debug.print("  Directories: {d}\n", .{stats.directories_created});
            std.debug.print("  Symlinks: {d}\n", .{stats.symlinks_created});
            std.debug.print("  Bytes: {d}\n", .{stats.bytes_extracted});
            if (stats.paths_rejected > 0) {
                std.debug.print("  Rejected paths: {d}\n", .{stats.paths_rejected});
            }
            if (stats.permissions_modified > 0) {
                std.debug.print("  Permissions modified: {d}\n", .{stats.permissions_modified});
            }
        } else {
            // Legacy extraction using system tar (insecure, for compatibility)
            std.debug.print("WARNING: Using legacy tar extraction (insecure)\n", .{});
            try self.extractTarballLegacy(tarball_path, temp_dir);
        }

        // Check if tarball extracted to a subdirectory
        var dir = try std.fs.cwd().openDir(temp_dir, .{ .iterate = true });
        defer dir.close();

        var iter = dir.iterate();
        var first_entry: ?[]const u8 = null;
        var entry_count: usize = 0;

        while (try iter.next()) |entry| {
            entry_count += 1;
            if (first_entry == null and entry.kind == .directory) {
                first_entry = try self.allocator.dupe(u8, entry.name);
            }
        }

        // If single directory, return that instead
        if (entry_count == 1 and first_entry != null) {
            const subdir = try std.fs.path.join(self.allocator, &[_][]const u8{ temp_dir, first_entry.? });
            self.allocator.free(first_entry.?);
            self.allocator.free(temp_dir);
            return subdir;
        }

        if (first_entry) |f| self.allocator.free(f);
        return temp_dir;
    }

    /// Legacy extraction using system tar command (kept for compatibility)
    fn extractTarballLegacy(self: *Importer, tarball_path: []const u8, temp_dir: []const u8) !void {
        // Determine compression based on extension
        var tar_args: []const []const u8 = undefined;

        if (std.mem.endsWith(u8, tarball_path, ".tar.gz") or
            std.mem.endsWith(u8, tarball_path, ".tgz"))
        {
            tar_args = &[_][]const u8{ "tar", "-xzf", tarball_path, "-C", temp_dir };
        } else if (std.mem.endsWith(u8, tarball_path, ".tar.xz") or
            std.mem.endsWith(u8, tarball_path, ".txz"))
        {
            tar_args = &[_][]const u8{ "tar", "-xJf", tarball_path, "-C", temp_dir };
        } else if (std.mem.endsWith(u8, tarball_path, ".tar.zst") or
            std.mem.endsWith(u8, tarball_path, ".tzst"))
        {
            tar_args = &[_][]const u8{ "tar", "--zstd", "-xf", tarball_path, "-C", temp_dir };
        } else if (std.mem.endsWith(u8, tarball_path, ".tar.bz2") or
            std.mem.endsWith(u8, tarball_path, ".tbz2"))
        {
            tar_args = &[_][]const u8{ "tar", "-xjf", tarball_path, "-C", temp_dir };
        } else if (std.mem.endsWith(u8, tarball_path, ".tar")) {
            tar_args = &[_][]const u8{ "tar", "-xf", tarball_path, "-C", temp_dir };
        } else {
            std.debug.print("Error: Unknown tarball format\n", .{});
            return ImportError.UnsupportedFormat;
        }

        var child = std.process.Child.init(tar_args, self.allocator);
        child.stderr_behavior = .Pipe;

        try child.spawn();
        const stderr = try child.stderr.?.readToEndAlloc(self.allocator, 1024 * 1024);
        defer self.allocator.free(stderr);

        const term = try child.wait();

        if (term.Exited != 0) {
            std.debug.print("Error extracting tarball: {s}\n", .{stderr});
            return ImportError.ExtractionFailed;
        }
    }

    /// Detect metadata from package directory contents
    fn detectMetadata(self: *Importer, pkg_dir: []const u8) !DetectedMetadata {
        std.debug.print("Auto-detecting package metadata...\n", .{});

        var metadata = DetectedMetadata{};

        // Check for standard directories
        metadata.has_binaries = self.dirExists(pkg_dir, "bin") or 
                                self.dirExists(pkg_dir, "sbin");
        metadata.has_libraries = self.dirExists(pkg_dir, "lib") or 
                                 self.dirExists(pkg_dir, "lib64");
        metadata.has_headers = self.dirExists(pkg_dir, "include");
        metadata.has_man_pages = self.dirExists(pkg_dir, "share/man") or 
                                 self.dirExists(pkg_dir, "man");

        // Determine file type
        if (metadata.has_binaries and metadata.has_libraries) {
            metadata.file_type = .mixed;
        } else if (metadata.has_binaries) {
            metadata.file_type = .binary;
        } else if (metadata.has_libraries) {
            metadata.file_type = .library;
        } else if (metadata.has_headers) {
            metadata.file_type = .headers;
        } else {
            metadata.file_type = .data;
        }

        // Try to detect from common metadata files
        try self.detectFromPackageJson(pkg_dir, &metadata);
        try self.detectFromCargoToml(pkg_dir, &metadata);
        try self.detectFromCMakeLists(pkg_dir, &metadata);
        try self.detectFromMakefile(pkg_dir, &metadata);
        try self.detectFromPkgInfo(pkg_dir, &metadata);

        // Report findings
        std.debug.print("  File type: {s}\n", .{@tagName(metadata.file_type)});
        if (metadata.name) |n| std.debug.print("  Detected name: {s}\n", .{n});
        if (metadata.version) |v| std.debug.print("  Detected version: {}\n", .{v});
        if (metadata.description) |d| std.debug.print("  Detected description: {s}\n", .{d});
        if (metadata.license) |l| std.debug.print("  Detected license: {s}\n", .{l});

        return metadata;
    }

    /// Check if subdirectory exists
    fn dirExists(self: *Importer, base: []const u8, subdir: []const u8) bool {
        _ = self;
        const path = std.fs.path.join(std.heap.page_allocator, &[_][]const u8{ base, subdir }) catch return false;
        defer std.heap.page_allocator.free(path);
        
        std.fs.cwd().access(path, .{}) catch return false;
        return true;
    }

    /// Try to detect metadata from package.json
    fn detectFromPackageJson(self: *Importer, pkg_dir: []const u8, metadata: *DetectedMetadata) !void {
        const path = try std.fs.path.join(self.allocator, &[_][]const u8{ pkg_dir, "package.json" });
        defer self.allocator.free(path);

        const file = std.fs.cwd().openFile(path, .{}) catch return;
        defer file.close();

        const content = file.readToEndAlloc(self.allocator, 1024 * 1024) catch return;
        defer self.allocator.free(content);

        // Simple JSON parsing for name and version
        if (self.extractJsonString(content, "\"name\"")) |name| {
            if (metadata.name == null) metadata.name = name;
        }
        if (self.extractJsonString(content, "\"description\"")) |desc| {
            if (metadata.description == null) metadata.description = desc;
        }
        if (self.extractJsonString(content, "\"license\"")) |lic| {
            if (metadata.license == null) metadata.license = lic;
        }
        if (self.extractJsonString(content, "\"version\"")) |ver_str| {
            defer self.allocator.free(ver_str);
            if (metadata.version == null) {
                metadata.version = Version.parse(ver_str) catch null;
            }
        }
    }

    /// Try to detect metadata from Cargo.toml
    fn detectFromCargoToml(self: *Importer, pkg_dir: []const u8, metadata: *DetectedMetadata) !void {
        const path = try std.fs.path.join(self.allocator, &[_][]const u8{ pkg_dir, "Cargo.toml" });
        defer self.allocator.free(path);

        const file = std.fs.cwd().openFile(path, .{}) catch return;
        defer file.close();

        const content = file.readToEndAlloc(self.allocator, 1024 * 1024) catch return;
        defer self.allocator.free(content);

        // Simple TOML parsing
        if (self.extractTomlString(content, "name")) |name| {
            if (metadata.name == null) metadata.name = name;
        }
        if (self.extractTomlString(content, "description")) |desc| {
            if (metadata.description == null) metadata.description = desc;
        }
        if (self.extractTomlString(content, "license")) |lic| {
            if (metadata.license == null) metadata.license = lic;
        }
        if (self.extractTomlString(content, "version")) |ver_str| {
            defer self.allocator.free(ver_str);
            if (metadata.version == null) {
                metadata.version = Version.parse(ver_str) catch null;
            }
        }
    }

    /// Try to detect from CMakeLists.txt
    fn detectFromCMakeLists(self: *Importer, pkg_dir: []const u8, metadata: *DetectedMetadata) !void {
        const path = try std.fs.path.join(self.allocator, &[_][]const u8{ pkg_dir, "CMakeLists.txt" });
        defer self.allocator.free(path);

        const file = std.fs.cwd().openFile(path, .{}) catch return;
        defer file.close();

        const content = file.readToEndAlloc(self.allocator, 1024 * 1024) catch return;
        defer self.allocator.free(content);

        // Look for project() command
        if (std.mem.indexOf(u8, content, "project(")) |start| {
            const rest = content[start + 8..];
            if (std.mem.indexOf(u8, rest, ")")) |end| {
                const project_args = rest[0..end];
                // First word is usually the project name
                var iter = std.mem.tokenizeAny(u8, project_args, " \t\n");
                if (iter.next()) |name| {
                    if (metadata.name == null) {
                        metadata.name = try self.allocator.dupe(u8, name);
                    }
                }
            }
        }
    }

    /// Try to detect from Makefile
    fn detectFromMakefile(self: *Importer, pkg_dir: []const u8, metadata: *DetectedMetadata) !void {
        const path = try std.fs.path.join(self.allocator, &[_][]const u8{ pkg_dir, "Makefile" });
        defer self.allocator.free(path);

        const file = std.fs.cwd().openFile(path, .{}) catch return;
        defer file.close();

        const content = file.readToEndAlloc(self.allocator, 1024 * 1024) catch return;
        defer self.allocator.free(content);

        // Look for PACKAGE_NAME or NAME variable
        var lines = std.mem.splitSequence(u8, content, "\n");
        while (lines.next()) |line| {
            const trimmed = std.mem.trim(u8, line, " \t");
            
            if (std.mem.startsWith(u8, trimmed, "PACKAGE_NAME") or
                std.mem.startsWith(u8, trimmed, "NAME")) {
                if (std.mem.indexOf(u8, trimmed, "=")) |eq| {
                    const value = std.mem.trim(u8, trimmed[eq + 1..], " \t");
                    if (value.len > 0 and metadata.name == null) {
                        metadata.name = try self.allocator.dupe(u8, value);
                    }
                }
            } else if (std.mem.startsWith(u8, trimmed, "VERSION")) {
                if (std.mem.indexOf(u8, trimmed, "=")) |eq| {
                    const value = std.mem.trim(u8, trimmed[eq + 1..], " \t");
                    if (value.len > 0 and metadata.version == null) {
                        metadata.version = Version.parse(value) catch null;
                    }
                }
            }
        }
    }

    /// Try to detect from +PKG_INFO (FreeBSD pkg format)
    fn detectFromPkgInfo(self: *Importer, pkg_dir: []const u8, metadata: *DetectedMetadata) !void {
        const path = try std.fs.path.join(self.allocator, &[_][]const u8{ pkg_dir, "+PKG_INFO" });
        defer self.allocator.free(path);

        const file = std.fs.cwd().openFile(path, .{}) catch return;
        defer file.close();

        const content = file.readToEndAlloc(self.allocator, 1024 * 1024) catch return;
        defer self.allocator.free(content);

        var lines = std.mem.splitSequence(u8, content, "\n");
        while (lines.next()) |line| {
            if (std.mem.startsWith(u8, line, "name:")) {
                const value = std.mem.trim(u8, line[5..], " \t");
                if (value.len > 0 and metadata.name == null) {
                    metadata.name = try self.allocator.dupe(u8, value);
                }
            } else if (std.mem.startsWith(u8, line, "version:")) {
                const value = std.mem.trim(u8, line[8..], " \t");
                if (value.len > 0 and metadata.version == null) {
                    metadata.version = Version.parse(value) catch null;
                }
            } else if (std.mem.startsWith(u8, line, "comment:")) {
                const value = std.mem.trim(u8, line[8..], " \t");
                if (value.len > 0 and metadata.description == null) {
                    metadata.description = try self.allocator.dupe(u8, value);
                }
            }
        }
    }

    /// Load metadata from existing manifest file
    fn loadManifestMetadata(self: *Importer, manifest_path: []const u8) !DetectedMetadata {
        std.debug.print("Loading manifest from: {s}\n", .{manifest_path});

        const file = try std.fs.cwd().openFile(manifest_path, .{});
        defer file.close();

        const content = try file.readToEndAlloc(self.allocator, 1024 * 1024);
        defer self.allocator.free(content);

        const parsed = try manifest.Manifest.parse(self.allocator, content);
        defer {
            // We need to copy the strings we want to keep
        }

        var metadata = DetectedMetadata{
            .name = try self.allocator.dupe(u8, parsed.name),
            .version = parsed.version,
        };

        if (parsed.description) |d| {
            metadata.description = try self.allocator.dupe(u8, d);
        }
        if (parsed.license) |l| {
            metadata.license = try self.allocator.dupe(u8, l);
        }
        if (parsed.homepage) |h| {
            metadata.homepage = try self.allocator.dupe(u8, h);
        }

        // Clean up parsed manifest (we've copied what we need)
        self.allocator.free(parsed.name);
        if (parsed.description) |d| self.allocator.free(d);
        if (parsed.license) |l| self.allocator.free(l);
        if (parsed.homepage) |h| self.allocator.free(h);
        if (parsed.maintainer) |m| self.allocator.free(m);
        for (parsed.tags) |t| self.allocator.free(t);
        self.allocator.free(parsed.tags);

        return metadata;
    }

    /// Generate a unique build ID
    fn generateBuildId(self: *Importer) ![]u8 {
        const timestamp = std.time.timestamp();
        var random_bytes: [4]u8 = undefined;
        std.crypto.random.bytes(&random_bytes);
        
        return std.fmt.allocPrint(self.allocator, "{x:0>8}{x:0>2}{x:0>2}{x:0>2}{x:0>2}", .{
            @as(u32, @truncate(@as(u64, @intCast(timestamp)))),
            random_bytes[0],
            random_bytes[1],
            random_bytes[2],
            random_bytes[3],
        });
    }

    /// Extract a string value from simple JSON
    fn extractJsonString(self: *Importer, json: []const u8, key: []const u8) ?[]const u8 {
        const key_pos = std.mem.indexOf(u8, json, key) orelse return null;
        const after_key = json[key_pos + key.len..];
        
        // Find the colon
        const colon = std.mem.indexOf(u8, after_key, ":") orelse return null;
        const after_colon = std.mem.trimLeft(u8, after_key[colon + 1..], " \t\n");
        
        // Check for string value
        if (after_colon.len == 0 or after_colon[0] != '"') return null;
        
        // Find closing quote
        const end_quote = std.mem.indexOf(u8, after_colon[1..], "\"") orelse return null;
        
        return self.allocator.dupe(u8, after_colon[1..][0..end_quote]) catch null;
    }

    /// Extract a string value from simple TOML
    fn extractTomlString(self: *Importer, toml: []const u8, key: []const u8) ?[]const u8 {
        var lines = std.mem.splitSequence(u8, toml, "\n");
        while (lines.next()) |line| {
            const trimmed = std.mem.trim(u8, line, " \t");
            if (std.mem.startsWith(u8, trimmed, key)) {
                const rest = trimmed[key.len..];
                const trimmed_rest = std.mem.trimLeft(u8, rest, " \t");
                if (trimmed_rest.len > 0 and trimmed_rest[0] == '=') {
                    const value_part = std.mem.trimLeft(u8, trimmed_rest[1..], " \t");
                    if (value_part.len > 0 and value_part[0] == '"') {
                        if (std.mem.indexOf(u8, value_part[1..], "\"")) |end| {
                            return self.allocator.dupe(u8, value_part[1..][0..end]) catch null;
                        }
                    }
                }
            }
        }
        return null;
    }
};
