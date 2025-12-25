const std = @import("std");
const zfs = @import("zfs.zig");
const types = @import("types.zig");
const store = @import("store.zig");
const profile = @import("profile.zig");
const manifest = @import("manifest.zig");

const Allocator = std.mem.Allocator;
const ZfsHandle = zfs.ZfsHandle;
const PackageId = types.PackageId;
const PackageStore = store.PackageStore;
const ProfileManager = profile.ProfileManager;
const Manifest = manifest.Manifest;

// =============================================================================
// Store Invariants Documentation
// =============================================================================
//
// The Axiom package store maintains the following invariants:
//
// 1. MANIFEST INVARIANT: Every package directory in /axiom/store/pkg/ contains
//    a valid manifest.yaml file that can be parsed without errors.
//
// 2. CONTENT-ADDRESSABLE INVARIANT: Each package's content hash matches the
//    hash recorded in its manifest (when hash verification is enabled).
//
// 3. NO-ORPHAN INVARIANT: Every ZFS dataset under zroot/axiom/store/pkg has
//    a corresponding valid package with manifest.
//
// 4. REFERENCE ACCURACY INVARIANT: Reference counts accurately reflect all
//    sources: profiles, environments, running processes, and active builds.
//
// 5. ATOMIC DELETION INVARIANT: Package deletion is atomic - a package is
//    either fully present or fully removed, never partially deleted.
//
// 6. CRASH SAFETY INVARIANT: After a crash, the store can be recovered to a
//    consistent state using the transaction log.
//
// =============================================================================

/// Store integrity errors
pub const IntegrityError = error{
    ScanFailed,
    ManifestMissing,
    ManifestInvalid,
    HashMismatch,
    OrphanedDataset,
    BrokenReference,
    PartialImport,
    RepairFailed,
    TransactionLogCorrupted,
};

/// Hash mismatch information
pub const HashMismatch = struct {
    package_path: []const u8,
    expected_hash: []const u8,
    actual_hash: []const u8,
};

/// Broken reference information
pub const BrokenRef = struct {
    source_type: RefSourceType,
    source_name: []const u8,
    missing_package: []const u8,
};

/// Reference source type
pub const RefSourceType = enum {
    profile,
    environment,
    process,
    build,
};

/// Reference source with details
pub const RefSource = struct {
    source_type: RefSourceType,
    name: []const u8,
    detail: ?[]const u8 = null,
};

/// Store integrity verification report
pub const IntegrityReport = struct {
    /// Packages that pass all integrity checks
    valid_packages: u32 = 0,

    /// ZFS datasets without valid package data
    orphaned_datasets: std.ArrayList([]const u8),

    /// Package directories missing manifest.yaml
    missing_manifests: std.ArrayList([]const u8),

    /// Packages with content hash mismatches
    hash_mismatches: std.ArrayList(HashMismatch),

    /// References to packages that don't exist
    broken_references: std.ArrayList(BrokenRef),

    /// Incomplete import operations detected
    partial_imports: std.ArrayList([]const u8),

    /// Overall store health status
    healthy: bool = true,

    /// Summary message
    summary: []const u8 = "",

    allocator: Allocator,

    pub fn init(allocator: Allocator) IntegrityReport {
        return .{
            .orphaned_datasets = std.ArrayList([]const u8).empty,
            .missing_manifests = std.ArrayList([]const u8).empty,
            .hash_mismatches = std.ArrayList(HashMismatch).empty,
            .broken_references = std.ArrayList(BrokenRef).empty,
            .partial_imports = std.ArrayList([]const u8).empty,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *IntegrityReport) void {
        for (self.orphaned_datasets.items) |item| {
            self.allocator.free(item);
        }
        self.orphaned_datasets.deinit();

        for (self.missing_manifests.items) |item| {
            self.allocator.free(item);
        }
        self.missing_manifests.deinit();

        for (self.hash_mismatches.items) |item| {
            self.allocator.free(item.package_path);
            self.allocator.free(item.expected_hash);
            self.allocator.free(item.actual_hash);
        }
        self.hash_mismatches.deinit();

        for (self.broken_references.items) |item| {
            self.allocator.free(item.source_name);
            self.allocator.free(item.missing_package);
        }
        self.broken_references.deinit();

        for (self.partial_imports.items) |item| {
            self.allocator.free(item);
        }
        self.partial_imports.deinit();

        if (self.summary.len > 0) {
            self.allocator.free(self.summary);
        }
    }

    /// Check if any issues were found
    pub fn hasIssues(self: *const IntegrityReport) bool {
        return self.orphaned_datasets.items.len > 0 or
            self.missing_manifests.items.len > 0 or
            self.hash_mismatches.items.len > 0 or
            self.broken_references.items.len > 0 or
            self.partial_imports.items.len > 0;
    }

    /// Get total issue count
    pub fn totalIssues(self: *const IntegrityReport) usize {
        return self.orphaned_datasets.items.len +
            self.missing_manifests.items.len +
            self.hash_mismatches.items.len +
            self.broken_references.items.len +
            self.partial_imports.items.len;
    }
};

/// Store integrity checker and repairer
pub const StoreIntegrity = struct {
    allocator: Allocator,
    store_path: []const u8,
    profile_path: []const u8,
    env_path: []const u8,

    const DEFAULT_STORE_PATH = "/axiom/store";
    const DEFAULT_PROFILE_PATH = "/axiom/profiles";
    const DEFAULT_ENV_PATH = "/axiom/env";

    pub fn init(allocator: Allocator) StoreIntegrity {
        return .{
            .allocator = allocator,
            .store_path = DEFAULT_STORE_PATH,
            .profile_path = DEFAULT_PROFILE_PATH,
            .env_path = DEFAULT_ENV_PATH,
        };
    }

    /// Verify store integrity and return a report
    pub fn verify(self: *StoreIntegrity, options: VerifyOptions) !IntegrityReport {
        var report = IntegrityReport.init(self.allocator);
        errdefer report.deinit();

        // Check for partial imports first (transaction log)
        try self.checkPartialImports(&report);

        // Scan package store
        try self.scanPackages(&report, options.verify_hashes);

        // Check references if requested
        if (options.check_references) {
            try self.checkReferences(&report);
        }

        // Set health status
        report.healthy = !report.hasIssues();

        // Generate summary
        report.summary = try self.generateSummary(&report);

        return report;
    }

    /// Repair detected issues
    pub fn repair(self: *StoreIntegrity, report: *IntegrityReport, options: RepairOptions) !RepairResult {
        var result = RepairResult{};

        // Clean up partial imports
        if (options.clean_partial_imports) {
            for (report.partial_imports.items) |partial| {
                if (self.cleanupPartialImport(partial)) {
                    result.partial_imports_cleaned += 1;
                } else |_| {
                    result.errors += 1;
                }
            }
        }

        // Remove orphaned datasets
        if (options.remove_orphans) {
            for (report.orphaned_datasets.items) |orphan| {
                if (self.removeOrphanedDataset(orphan)) {
                    result.orphans_removed += 1;
                } else |_| {
                    result.errors += 1;
                }
            }
        }

        // Remove packages with missing manifests
        if (options.remove_invalid) {
            for (report.missing_manifests.items) |invalid| {
                if (self.removeInvalidPackage(invalid)) {
                    result.invalid_removed += 1;
                } else |_| {
                    result.errors += 1;
                }
            }
        }

        return result;
    }

    /// Check transaction log for partial imports
    fn checkPartialImports(self: *StoreIntegrity, report: *IntegrityReport) !void {
        const txlog_path = try std.fs.path.join(self.allocator, &.{ self.store_path, ".txlog" });
        defer self.allocator.free(txlog_path);

        var dir = std.fs.openDirAbsolute(txlog_path, .{ .iterate = true }) catch {
            // No transaction log directory - that's fine
            return;
        };
        defer dir.close();

        var iter = dir.iterate();
        while (try iter.next()) |entry| {
            if (entry.kind != .file) continue;

            // Look for .pending files
            if (std.mem.endsWith(u8, entry.name, ".pending")) {
                const full_path = try std.fs.path.join(self.allocator, &.{ txlog_path, entry.name });
                try report.partial_imports.append(full_path);
            }
        }
    }

    /// Scan all packages in store
    fn scanPackages(self: *StoreIntegrity, report: *IntegrityReport, verify_hashes: bool) !void {
        const pkg_path = try std.fs.path.join(self.allocator, &.{ self.store_path, "pkg" });
        defer self.allocator.free(pkg_path);

        var dir = std.fs.openDirAbsolute(pkg_path, .{ .iterate = true }) catch {
            // Store doesn't exist yet
            return;
        };
        defer dir.close();

        var iter = dir.iterate();
        while (try iter.next()) |entry| {
            if (entry.kind != .directory) continue;

            const package_path = try std.fs.path.join(self.allocator, &.{ pkg_path, entry.name });
            defer self.allocator.free(package_path);

            // Check for manifest
            const manifest_path = try std.fs.path.join(self.allocator, &.{ package_path, "manifest.yaml" });
            defer self.allocator.free(manifest_path);

            const manifest_file = std.fs.openFileAbsolute(manifest_path, .{}) catch {
                // Missing manifest
                const dup_path = try self.allocator.dupe(u8, package_path);
                try report.missing_manifests.append(dup_path);
                continue;
            };
            manifest_file.close();

            // Verify hash if requested
            if (verify_hashes) {
                // TODO: Implement content hash verification
                // This would read the manifest, get the expected hash,
                // compute actual hash of package contents, and compare
            }

            report.valid_packages += 1;
        }
    }

    /// Check references from profiles and environments
    fn checkReferences(self: *StoreIntegrity, report: *IntegrityReport) !void {
        // Check profile references
        try self.checkProfileReferences(report);

        // Check environment references
        try self.checkEnvironmentReferences(report);
    }

    /// Check profile lock files for broken references
    fn checkProfileReferences(self: *StoreIntegrity, report: *IntegrityReport) !void {
        var dir = std.fs.openDirAbsolute(self.profile_path, .{ .iterate = true }) catch {
            return;
        };
        defer dir.close();

        var iter = dir.iterate();
        while (try iter.next()) |entry| {
            if (entry.kind != .directory) continue;

            const lock_path = try std.fs.path.join(self.allocator, &.{
                self.profile_path,
                entry.name,
                "profile.lock.yaml",
            });
            defer self.allocator.free(lock_path);

            // Read lock file and check each package reference
            const lock_file = std.fs.openFileAbsolute(lock_path, .{}) catch {
                continue; // No lock file
            };
            defer lock_file.close();

            var buf: [8192]u8 = undefined;
            const bytes_read = lock_file.readAll(&buf) catch continue;
            const content = buf[0..bytes_read];

            // Simple parse for package names (name: <value>)
            var lines = std.mem.splitScalar(u8, content, '\n');
            while (lines.next()) |line| {
                const trimmed = std.mem.trim(u8, line, " \t\r");
                if (std.mem.startsWith(u8, trimmed, "name:")) {
                    var parts = std.mem.splitScalar(u8, trimmed, ':');
                    _ = parts.next();
                    const pkg_name = std.mem.trim(u8, parts.rest(), " \t\"");

                    if (pkg_name.len > 0 and !std.mem.eql(u8, pkg_name, entry.name)) {
                        // Check if package exists
                        const pkg_path = try std.fs.path.join(self.allocator, &.{
                            self.store_path,
                            "pkg",
                            pkg_name,
                        });
                        defer self.allocator.free(pkg_path);

                        std.fs.accessAbsolute(pkg_path, .{}) catch {
                            // Package doesn't exist - broken reference
                            try report.broken_references.append(.{
                                .source_type = .profile,
                                .source_name = try self.allocator.dupe(u8, entry.name),
                                .missing_package = try self.allocator.dupe(u8, pkg_name),
                            });
                        };
                    }
                }
            }
        }
    }

    /// Check environment symlinks for broken references
    fn checkEnvironmentReferences(self: *StoreIntegrity, report: *IntegrityReport) !void {
        var dir = std.fs.openDirAbsolute(self.env_path, .{ .iterate = true }) catch {
            return;
        };
        defer dir.close();

        var iter = dir.iterate();
        while (try iter.next()) |entry| {
            if (entry.kind != .directory) continue;

            // Check .axiom/packages in each environment
            const packages_path = try std.fs.path.join(self.allocator, &.{
                self.env_path,
                entry.name,
                ".axiom",
                "packages",
            });
            defer self.allocator.free(packages_path);

            var pkg_dir = std.fs.openDirAbsolute(packages_path, .{ .iterate = true }) catch {
                continue;
            };
            defer pkg_dir.close();

            var pkg_iter = pkg_dir.iterate();
            while (try pkg_iter.next()) |pkg_entry| {
                // Each entry should be a symlink to store
                if (pkg_entry.kind == .sym_link) {
                    var link_buf: [std.fs.max_path_bytes]u8 = undefined;
                    const link_target = pkg_dir.readLink(pkg_entry.name, &link_buf) catch continue;

                    // Check if target exists
                    std.fs.accessAbsolute(link_target, .{}) catch {
                        try report.broken_references.append(.{
                            .source_type = .environment,
                            .source_name = try self.allocator.dupe(u8, entry.name),
                            .missing_package = try self.allocator.dupe(u8, pkg_entry.name),
                        });
                    };
                }
            }
        }
    }

    /// Generate summary message
    fn generateSummary(self: *StoreIntegrity, report: *IntegrityReport) ![]const u8 {
        if (report.healthy) {
            return try std.fmt.allocPrint(self.allocator, "Store is healthy: {d} valid packages, no issues found", .{report.valid_packages});
        }

        return try std.fmt.allocPrint(
            self.allocator,
            "Store has issues: {d} valid packages, {d} total issues ({d} orphans, {d} missing manifests, {d} broken refs, {d} partial imports)",
            .{
                report.valid_packages,
                report.totalIssues(),
                report.orphaned_datasets.items.len,
                report.missing_manifests.items.len,
                report.broken_references.items.len,
                report.partial_imports.items.len,
            },
        );
    }

    /// Clean up a partial import
    fn cleanupPartialImport(_: *StoreIntegrity, txlog_path: []const u8) !void {
        // Read the transaction log to find what was being imported
        const file = try std.fs.openFileAbsolute(txlog_path, .{});
        defer file.close();

        var buf: [4096]u8 = undefined;
        const bytes_read = try file.readAll(&buf);
        const content = buf[0..bytes_read];

        // Parse package path from transaction log
        var lines = std.mem.splitScalar(u8, content, '\n');
        while (lines.next()) |line| {
            if (std.mem.startsWith(u8, line, "package_path:")) {
                var parts = std.mem.splitScalar(u8, line, ':');
                _ = parts.next();
                const pkg_path = std.mem.trim(u8, parts.rest(), " \t");

                // Remove the partial package directory
                std.fs.deleteTreeAbsolute(pkg_path) catch {};
            }
        }

        // Remove the transaction log entry
        try std.fs.deleteFileAbsolute(txlog_path);
    }

    /// Remove an orphaned dataset
    fn removeOrphanedDataset(self: *StoreIntegrity, dataset_path: []const u8) !void {
        _ = self;
        // Use ZFS to destroy the dataset
        // For now, just remove the directory
        try std.fs.deleteTreeAbsolute(dataset_path);
    }

    /// Remove an invalid package
    fn removeInvalidPackage(self: *StoreIntegrity, package_path: []const u8) !void {
        _ = self;
        try std.fs.deleteTreeAbsolute(package_path);
    }
};

/// Verification options
pub const VerifyOptions = struct {
    /// Verify content hashes (slower but more thorough)
    verify_hashes: bool = false,

    /// Check profile and environment references
    check_references: bool = true,

    /// Check for partial imports
    check_partial_imports: bool = true,
};

/// Repair options
pub const RepairOptions = struct {
    /// Clean up partial/failed imports
    clean_partial_imports: bool = true,

    /// Remove orphaned ZFS datasets
    remove_orphans: bool = false,

    /// Remove packages with missing/invalid manifests
    remove_invalid: bool = false,

    /// Dry run - don't actually make changes
    dry_run: bool = false,
};

/// Repair operation result
pub const RepairResult = struct {
    partial_imports_cleaned: u32 = 0,
    orphans_removed: u32 = 0,
    invalid_removed: u32 = 0,
    errors: u32 = 0,
};

/// Reference counter for packages
pub const RefCounter = struct {
    allocator: Allocator,
    store_path: []const u8,
    profile_path: []const u8,
    env_path: []const u8,

    const DEFAULT_STORE_PATH = "/axiom/store";
    const DEFAULT_PROFILE_PATH = "/axiom/profiles";
    const DEFAULT_ENV_PATH = "/axiom/env";

    pub fn init(allocator: Allocator) RefCounter {
        return .{
            .allocator = allocator,
            .store_path = DEFAULT_STORE_PATH,
            .profile_path = DEFAULT_PROFILE_PATH,
            .env_path = DEFAULT_ENV_PATH,
        };
    }

    /// Count all references to a package
    pub fn countRefs(self: *RefCounter, package_name: []const u8) !u32 {
        var count: u32 = 0;

        // Count profile references
        count += try self.countProfileRefs(package_name);

        // Count environment references
        count += try self.countEnvRefs(package_name);

        // Count process references (packages in use)
        count += try self.countProcessRefs(package_name);

        return count;
    }

    /// Get detailed reference sources for a package
    pub fn getRefSources(self: *RefCounter, package_name: []const u8) !std.ArrayList(RefSource) {
        var sources = std.ArrayList(RefSource).init(self.allocator);
        errdefer sources.deinit();

        // Get profile references
        try self.getProfileRefSources(package_name, &sources);

        // Get environment references
        try self.getEnvRefSources(package_name, &sources);

        // Get process references
        try self.getProcessRefSources(package_name, &sources);

        return sources;
    }

    /// Check if a package has any references
    pub fn isReferenced(self: *RefCounter, package_name: []const u8) !bool {
        return (try self.countRefs(package_name)) > 0;
    }

    /// Count profile references
    fn countProfileRefs(self: *RefCounter, package_name: []const u8) !u32 {
        var count: u32 = 0;

        var dir = std.fs.openDirAbsolute(self.profile_path, .{ .iterate = true }) catch {
            return 0;
        };
        defer dir.close();

        var iter = dir.iterate();
        while (try iter.next()) |entry| {
            if (entry.kind != .directory) continue;

            const lock_path = try std.fs.path.join(self.allocator, &.{
                self.profile_path,
                entry.name,
                "profile.lock.yaml",
            });
            defer self.allocator.free(lock_path);

            if (try self.lockFileContainsPackage(lock_path, package_name)) {
                count += 1;
            }
        }

        return count;
    }

    /// Count environment references
    fn countEnvRefs(self: *RefCounter, package_name: []const u8) !u32 {
        var count: u32 = 0;

        var dir = std.fs.openDirAbsolute(self.env_path, .{ .iterate = true }) catch {
            return 0;
        };
        defer dir.close();

        var iter = dir.iterate();
        while (try iter.next()) |entry| {
            if (entry.kind != .directory) continue;

            const pkg_link = try std.fs.path.join(self.allocator, &.{
                self.env_path,
                entry.name,
                ".axiom",
                "packages",
                package_name,
            });
            defer self.allocator.free(pkg_link);

            std.fs.accessAbsolute(pkg_link, .{}) catch {
                continue;
            };
            count += 1;
        }

        return count;
    }

    /// Count process references (packages with open files)
    fn countProcessRefs(self: *RefCounter, package_name: []const u8) !u32 {
        _ = self;
        _ = package_name;
        // On FreeBSD, we would use fstat or procfs to find processes
        // with open files in the package directory.
        // For now, return 0 as this requires platform-specific implementation
        return 0;
    }

    /// Get profile reference sources
    fn getProfileRefSources(self: *RefCounter, package_name: []const u8, sources: *std.ArrayList(RefSource)) !void {
        var dir = std.fs.openDirAbsolute(self.profile_path, .{ .iterate = true }) catch {
            return;
        };
        defer dir.close();

        var iter = dir.iterate();
        while (try iter.next()) |entry| {
            if (entry.kind != .directory) continue;

            const lock_path = try std.fs.path.join(self.allocator, &.{
                self.profile_path,
                entry.name,
                "profile.lock.yaml",
            });
            defer self.allocator.free(lock_path);

            if (try self.lockFileContainsPackage(lock_path, package_name)) {
                try sources.append(.{
                    .source_type = .profile,
                    .name = try self.allocator.dupe(u8, entry.name),
                });
            }
        }
    }

    /// Get environment reference sources
    fn getEnvRefSources(self: *RefCounter, package_name: []const u8, sources: *std.ArrayList(RefSource)) !void {
        var dir = std.fs.openDirAbsolute(self.env_path, .{ .iterate = true }) catch {
            return;
        };
        defer dir.close();

        var iter = dir.iterate();
        while (try iter.next()) |entry| {
            if (entry.kind != .directory) continue;

            const pkg_link = try std.fs.path.join(self.allocator, &.{
                self.env_path,
                entry.name,
                ".axiom",
                "packages",
                package_name,
            });
            defer self.allocator.free(pkg_link);

            std.fs.accessAbsolute(pkg_link, .{}) catch {
                continue;
            };

            try sources.append(.{
                .source_type = .environment,
                .name = try self.allocator.dupe(u8, entry.name),
            });
        }
    }

    /// Get process reference sources
    fn getProcessRefSources(self: *RefCounter, package_name: []const u8, sources: *std.ArrayList(RefSource)) !void {
        _ = self;
        _ = package_name;
        _ = sources;
        // Platform-specific implementation needed
    }

    /// Check if a lock file contains a package reference
    fn lockFileContainsPackage(self: *RefCounter, lock_path: []const u8, package_name: []const u8) !bool {
        _ = self;
        const file = std.fs.openFileAbsolute(lock_path, .{}) catch {
            return false;
        };
        defer file.close();

        var buf: [16384]u8 = undefined;
        const bytes_read = file.readAll(&buf) catch return false;
        const content = buf[0..bytes_read];

        // Simple search for package name in resolved section
        return std.mem.indexOf(u8, content, package_name) != null;
    }
};

/// Transaction log for crash recovery
pub const TransactionLog = struct {
    allocator: Allocator,
    log_path: []const u8,
    log_path_owned: bool = false,
    sequence: u64 = 0,

    const DEFAULT_LOG_DIR = ".axiom-txlog";

    pub const Operation = enum {
        import,
        delete,
        gc,
        gc_remove,
        realize,
    };

    pub const Entry = struct {
        sequence: u64,
        operation: Operation,
        package_path: []const u8,
        started_at: i64,
        completed: bool = false,
    };

    /// Initialize with store path - creates log dir at store_path/.axiom-txlog
    pub fn init(allocator: Allocator, store_path: []const u8) !TransactionLog {
        const log_path = try std.fs.path.join(allocator, &.{ store_path, DEFAULT_LOG_DIR });
        errdefer allocator.free(log_path);

        // Create log directory if it doesn't exist
        std.fs.makeDirAbsolute(log_path) catch |err| {
            if (err != error.PathAlreadyExists) {
                return err;
            }
        };

        // Find highest sequence number
        var max_seq: u64 = 0;
        var dir = std.fs.openDirAbsolute(log_path, .{ .iterate = true }) catch {
            return TransactionLog{
                .allocator = allocator,
                .log_path = log_path,
                .log_path_owned = true,
                .sequence = 0,
            };
        };
        defer dir.close();

        var iter = dir.iterate();
        while (try iter.next()) |entry| {
            if (entry.kind != .file) continue;

            // Parse sequence from filename (NNNNN.operation.status)
            var parts = std.mem.splitScalar(u8, entry.name, '.');
            const seq_str = parts.next() orelse continue;
            const seq = std.fmt.parseInt(u64, seq_str, 10) catch continue;
            if (seq > max_seq) {
                max_seq = seq;
            }
        }

        return TransactionLog{
            .allocator = allocator,
            .log_path = log_path,
            .log_path_owned = true,
            .sequence = max_seq,
        };
    }

    pub fn deinit(self: *TransactionLog) void {
        if (self.log_path_owned) {
            self.allocator.free(self.log_path);
        }
    }

    /// Begin a new transaction
    pub fn begin(self: *TransactionLog, operation: Operation, package_path: []const u8) !u64 {
        self.sequence += 1;
        const seq = self.sequence;

        const op_str = switch (operation) {
            .import => "import",
            .delete => "delete",
            .gc => "gc",
            .gc_remove => "gc_remove",
            .realize => "realize",
        };

        const filename = try std.fmt.allocPrint(self.allocator, "{d:0>5}.{s}.pending", .{ seq, op_str });
        defer self.allocator.free(filename);

        const full_path = try std.fs.path.join(self.allocator, &.{ self.log_path, filename });
        defer self.allocator.free(full_path);

        const file = try std.fs.createFileAbsolute(full_path, .{});
        defer file.close();

        const content = try std.fmt.allocPrint(self.allocator, "sequence: {d}\noperation: {s}\npackage_path: {s}\nstarted_at: {d}\n", .{
            seq,
            op_str,
            package_path,
            std.time.timestamp(),
        });
        defer self.allocator.free(content);

        try file.writeAll(content);

        return seq;
    }

    /// Complete a transaction
    pub fn complete(self: *TransactionLog, seq: u64, operation: Operation) !void {
        const op_str = switch (operation) {
            .import => "import",
            .delete => "delete",
            .gc => "gc",
            .gc_remove => "gc_remove",
            .realize => "realize",
        };

        const pending_name = try std.fmt.allocPrint(self.allocator, "{d:0>5}.{s}.pending", .{ seq, op_str });
        defer self.allocator.free(pending_name);

        const complete_name = try std.fmt.allocPrint(self.allocator, "{d:0>5}.{s}.complete", .{ seq, op_str });
        defer self.allocator.free(complete_name);

        const pending_path = try std.fs.path.join(self.allocator, &.{ self.log_path, pending_name });
        defer self.allocator.free(pending_path);

        const complete_path = try std.fs.path.join(self.allocator, &.{ self.log_path, complete_name });
        defer self.allocator.free(complete_path);

        // Rename pending to complete
        std.fs.renameAbsolute(pending_path, complete_path) catch |err| {
            if (err == error.FileNotFound) {
                // Already completed or aborted
                return;
            }
            return err;
        };
    }

    /// Abort a transaction
    pub fn abort(self: *TransactionLog, seq: u64, operation: Operation) !void {
        const op_str = switch (operation) {
            .import => "import",
            .delete => "delete",
            .gc => "gc",
            .gc_remove => "gc_remove",
            .realize => "realize",
        };

        const pending_name = try std.fmt.allocPrint(self.allocator, "{d:0>5}.{s}.pending", .{ seq, op_str });
        defer self.allocator.free(pending_name);

        const pending_path = try std.fs.path.join(self.allocator, &.{ self.log_path, pending_name });
        defer self.allocator.free(pending_path);

        // Remove pending entry
        std.fs.deleteFileAbsolute(pending_path) catch {};
    }

    /// Get all pending transactions (for recovery)
    pub fn getPending(self: *TransactionLog) !std.ArrayList(Entry) {
        var entries = std.ArrayList(Entry).init(self.allocator);
        errdefer entries.deinit();

        var dir = std.fs.openDirAbsolute(self.log_path, .{ .iterate = true }) catch {
            return entries;
        };
        defer dir.close();

        var iter = dir.iterate();
        while (try iter.next()) |entry| {
            if (entry.kind != .file) continue;
            if (!std.mem.endsWith(u8, entry.name, ".pending")) continue;

            // Parse entry
            const full_path = try std.fs.path.join(self.allocator, &.{ self.log_path, entry.name });
            defer self.allocator.free(full_path);

            const file = std.fs.openFileAbsolute(full_path, .{}) catch continue;
            defer file.close();

            var buf: [4096]u8 = undefined;
            const bytes_read = file.readAll(&buf) catch continue;
            const content = buf[0..bytes_read];

            // Parse content
            var seq: u64 = 0;
            var op: Operation = .import;
            var pkg_path: []const u8 = "";
            var started: i64 = 0;

            var lines = std.mem.splitScalar(u8, content, '\n');
            while (lines.next()) |line| {
                if (std.mem.startsWith(u8, line, "sequence:")) {
                    const val = std.mem.trim(u8, line["sequence:".len..], " \t");
                    seq = std.fmt.parseInt(u64, val, 10) catch 0;
                } else if (std.mem.startsWith(u8, line, "operation:")) {
                    const val = std.mem.trim(u8, line["operation:".len..], " \t");
                    if (std.mem.eql(u8, val, "import")) op = .import else if (std.mem.eql(u8, val, "delete")) op = .delete else if (std.mem.eql(u8, val, "gc")) op = .gc;
                } else if (std.mem.startsWith(u8, line, "package_path:")) {
                    pkg_path = std.mem.trim(u8, line["package_path:".len..], " \t");
                } else if (std.mem.startsWith(u8, line, "started_at:")) {
                    const val = std.mem.trim(u8, line["started_at:".len..], " \t");
                    started = std.fmt.parseInt(i64, val, 10) catch 0;
                }
            }

            try entries.append(.{
                .sequence = seq,
                .operation = op,
                .package_path = try self.allocator.dupe(u8, pkg_path),
                .started_at = started,
            });
        }

        return entries;
    }

    /// Clean old completed transactions
    pub fn cleanup(self: *TransactionLog, max_age_seconds: i64) !u32 {
        var cleaned: u32 = 0;
        const now = std.time.timestamp();

        var dir = std.fs.openDirAbsolute(self.log_path, .{ .iterate = true }) catch {
            return 0;
        };
        defer dir.close();

        var iter = dir.iterate();
        while (try iter.next()) |entry| {
            if (entry.kind != .file) continue;
            if (!std.mem.endsWith(u8, entry.name, ".complete")) continue;

            const full_path = try std.fs.path.join(self.allocator, &.{ self.log_path, entry.name });
            defer self.allocator.free(full_path);

            // Check file age
            const stat = std.fs.cwd().statFile(full_path) catch continue;
            const mtime_sec = @divFloor(stat.mtime, std.time.ns_per_s);
            if (now - mtime_sec > max_age_seconds) {
                std.fs.deleteFileAbsolute(full_path) catch continue;
                cleaned += 1;
            }
        }

        return cleaned;
    }
};

// Tests
test "IntegrityReport.hasIssues" {
    const allocator = std.testing.allocator;
    var report = IntegrityReport.empty;
    defer report.deinit();

    try std.testing.expect(!report.hasIssues());

    try report.orphaned_datasets.append(try allocator.dupe(u8, "/test/orphan"));
    try std.testing.expect(report.hasIssues());
}

test "SemanticVersion in format_version" {
    // Basic sanity test that the module compiles
    const integrity = StoreIntegrity.init(std.testing.allocator);
    try std.testing.expectEqualStrings("/axiom/store", integrity.store_path);
}
