const std = @import("std");

const Allocator = std.mem.Allocator;

/// Unified Axiom error taxonomy
pub const AxiomError = error{
    // Store errors
    StoreCorrupted,
    StoreVersionMismatch,
    PackageNotFound,
    PackageCorrupted,
    ManifestInvalid,

    // Import errors
    ImportInterrupted,
    ImportHashMismatch,
    ImportSignatureInvalid,

    // Realization errors
    RealizationConflict,
    RealizationInterrupted,
    EnvironmentCorrupted,

    // Resolution errors
    DependencyConflict,
    UnsatisfiableDependency,
    CyclicDependency,

    // ZFS errors
    DatasetNotFound,
    DatasetExists,
    ZfsOperationFailed,
    PoolNotAvailable,

    // Network errors
    CacheUnreachable,
    FetchFailed,
    FetchTimeout,

    // Permission errors
    PermissionDenied,
    InsufficientPrivileges,
};

/// Error category for grouping related errors
pub const ErrorCategory = enum {
    store,
    import_op,
    realization,
    resolution,
    zfs,
    network,
    permission,

    pub fn toString(self: ErrorCategory) []const u8 {
        return switch (self) {
            .store => "Store Error",
            .import_op => "Import Error",
            .realization => "Realization Error",
            .resolution => "Resolution Error",
            .zfs => "ZFS Error",
            .network => "Network Error",
            .permission => "Permission Error",
        };
    }
};

/// Error severity level
pub const ErrorSeverity = enum {
    info,
    warning,
    err,
    critical,

    pub fn toString(self: ErrorSeverity) []const u8 {
        return switch (self) {
            .info => "INFO",
            .warning => "WARNING",
            .err => "ERROR",
            .critical => "CRITICAL",
        };
    }
};

/// Context information for errors
pub const ErrorContext = struct {
    category: ErrorCategory,
    severity: ErrorSeverity,
    operation: []const u8,
    resource: ?[]const u8,
    details: ?[]const u8,
    timestamp: i64,
    recoverable: bool,

    pub fn init(category: ErrorCategory, operation: []const u8) ErrorContext {
        return .{
            .category = category,
            .severity = .err,
            .operation = operation,
            .resource = null,
            .details = null,
            .timestamp = std.time.timestamp(),
            .recoverable = true,
        };
    }

    pub fn withResource(self: ErrorContext, resource: []const u8) ErrorContext {
        var ctx = self;
        ctx.resource = resource;
        return ctx;
    }

    pub fn withDetails(self: ErrorContext, details: []const u8) ErrorContext {
        var ctx = self;
        ctx.details = details;
        return ctx;
    }

    pub fn asCritical(self: ErrorContext) ErrorContext {
        var ctx = self;
        ctx.severity = .critical;
        ctx.recoverable = false;
        return ctx;
    }
};

/// Recovery action types
pub const RecoveryAction = enum {
    clean_partial,
    retry_operation,
    rollback_transaction,
    verify_integrity,
    refetch_package,
    rebuild_package,
    remove_orphan,
    repair_metadata,

    pub fn toString(self: RecoveryAction) []const u8 {
        return switch (self) {
            .clean_partial => "Clean partial data",
            .retry_operation => "Retry operation",
            .rollback_transaction => "Rollback transaction",
            .verify_integrity => "Verify integrity",
            .refetch_package => "Re-fetch package from cache",
            .rebuild_package => "Rebuild package from source",
            .remove_orphan => "Remove orphaned dataset",
            .repair_metadata => "Repair metadata",
        };
    }

    pub fn isAutomatic(self: RecoveryAction) bool {
        return switch (self) {
            .clean_partial => true,
            .retry_operation => true,
            .rollback_transaction => true,
            .verify_integrity => true,
            .remove_orphan => true,
            .repair_metadata => true,
            .refetch_package => false, // requires network
            .rebuild_package => false, // requires build
        };
    }
};

/// Import recovery information
pub const ImportRecovery = struct {
    package_name: []const u8,
    partial_path: []const u8,
    transaction_id: ?[]const u8,
    progress_percent: u8,
    actions: []const RecoveryAction,

    pub fn deinit(self: *ImportRecovery, allocator: Allocator) void {
        allocator.free(self.package_name);
        allocator.free(self.partial_path);
        if (self.transaction_id) |tid| {
            allocator.free(tid);
        }
        allocator.free(self.actions);
    }
};

/// Realization recovery information
pub const RealizationRecovery = struct {
    env_name: []const u8,
    profile_name: []const u8,
    partial_path: []const u8,
    completed_packages: usize,
    total_packages: usize,
    actions: []const RecoveryAction,

    pub fn deinit(self: *RealizationRecovery, allocator: Allocator) void {
        allocator.free(self.env_name);
        allocator.free(self.profile_name);
        allocator.free(self.partial_path);
        allocator.free(self.actions);
    }
};

/// Package recovery information
pub const PackageRecovery = struct {
    name: []const u8,
    version: []const u8,
    issue: []const u8,
    actions: []const RecoveryAction,

    pub fn deinit(self: *PackageRecovery, allocator: Allocator) void {
        allocator.free(self.name);
        allocator.free(self.version);
        allocator.free(self.issue);
        allocator.free(self.actions);
    }
};

/// Recovery mode
pub const RecoveryMode = enum {
    automatic, // Apply safe automatic fixes
    interactive, // Ask for each action
    dry_run, // Show plan only

    pub fn toString(self: RecoveryMode) []const u8 {
        return switch (self) {
            .automatic => "automatic",
            .interactive => "interactive",
            .dry_run => "dry-run",
        };
    }
};

/// Recovery plan containing all detected issues
pub const RecoveryPlan = struct {
    allocator: Allocator,
    interrupted_imports: std.ArrayList(ImportRecovery),
    interrupted_realizations: std.ArrayList(RealizationRecovery),
    orphaned_datasets: std.ArrayList([]const u8),
    corrupted_packages: std.ArrayList(PackageRecovery),
    scan_time: i64,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return .{
            .allocator = allocator,
            .interrupted_imports = std.ArrayList(ImportRecovery).init(allocator),
            .interrupted_realizations = std.ArrayList(RealizationRecovery).init(allocator),
            .orphaned_datasets = std.ArrayList([]const u8).init(allocator),
            .corrupted_packages = std.ArrayList(PackageRecovery).init(allocator),
            .scan_time = std.time.timestamp(),
        };
    }

    pub fn deinit(self: *Self) void {
        for (self.interrupted_imports.items) |*item| {
            item.deinit(self.allocator);
        }
        self.interrupted_imports.deinit();

        for (self.interrupted_realizations.items) |*item| {
            item.deinit(self.allocator);
        }
        self.interrupted_realizations.deinit();

        for (self.orphaned_datasets.items) |ds| {
            self.allocator.free(ds);
        }
        self.orphaned_datasets.deinit();

        for (self.corrupted_packages.items) |*item| {
            item.deinit(self.allocator);
        }
        self.corrupted_packages.deinit();
    }

    pub fn isEmpty(self: *const Self) bool {
        return self.interrupted_imports.items.len == 0 and
            self.interrupted_realizations.items.len == 0 and
            self.orphaned_datasets.items.len == 0 and
            self.corrupted_packages.items.len == 0;
    }

    pub fn totalIssues(self: *const Self) usize {
        return self.interrupted_imports.items.len +
            self.interrupted_realizations.items.len +
            self.orphaned_datasets.items.len +
            self.corrupted_packages.items.len;
    }

    pub fn automaticCount(self: *const Self) usize {
        var count: usize = 0;
        count += self.interrupted_imports.items.len;
        count += self.interrupted_realizations.items.len;
        count += self.orphaned_datasets.items.len;
        // corrupted packages may need manual intervention
        return count;
    }
};

/// Result of recovery execution
pub const RecoveryResult = struct {
    success: bool,
    actions_taken: usize,
    actions_failed: usize,
    actions_skipped: usize,
    messages: std.ArrayList([]const u8),

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return .{
            .success = true,
            .actions_taken = 0,
            .actions_failed = 0,
            .actions_skipped = 0,
            .messages = std.ArrayList([]const u8).init(allocator),
        };
    }

    pub fn deinit(self: *Self, allocator: Allocator) void {
        for (self.messages.items) |msg| {
            allocator.free(msg);
        }
        self.messages.deinit();
    }

    pub fn addMessage(self: *Self, allocator: Allocator, msg: []const u8) !void {
        try self.messages.append(try allocator.dupe(u8, msg));
    }
};

/// Verification status for a component
pub const VerificationStatus = enum {
    ok,
    warning,
    corrupted,
    missing,

    pub fn toString(self: VerificationStatus) []const u8 {
        return switch (self) {
            .ok => "OK",
            .warning => "WARNING",
            .corrupted => "CORRUPTED",
            .missing => "MISSING",
        };
    }

    pub fn symbol(self: VerificationStatus) []const u8 {
        return switch (self) {
            .ok => "✓",
            .warning => "⚠",
            .corrupted => "✗",
            .missing => "?",
        };
    }
};

/// Verification result for a component
pub const ComponentVerification = struct {
    name: []const u8,
    status: VerificationStatus,
    valid_count: usize,
    invalid_count: usize,
    details: ?[]const u8,

    pub fn deinit(self: *ComponentVerification, allocator: Allocator) void {
        allocator.free(self.name);
        if (self.details) |d| {
            allocator.free(d);
        }
    }
};

/// Full verification result
pub const VerificationResult = struct {
    allocator: Allocator,
    store: VerificationStatus,
    profiles: ComponentVerification,
    environments: ComponentVerification,
    packages: ComponentVerification,
    recommendations: std.ArrayList([]const u8),

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return .{
            .allocator = allocator,
            .store = .ok,
            .profiles = .{
                .name = "Profiles",
                .status = .ok,
                .valid_count = 0,
                .invalid_count = 0,
                .details = null,
            },
            .environments = .{
                .name = "Environments",
                .status = .ok,
                .valid_count = 0,
                .invalid_count = 0,
                .details = null,
            },
            .packages = .{
                .name = "Packages",
                .status = .ok,
                .valid_count = 0,
                .invalid_count = 0,
                .details = null,
            },
            .recommendations = std.ArrayList([]const u8).init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        for (self.recommendations.items) |rec| {
            self.allocator.free(rec);
        }
        self.recommendations.deinit();
    }

    pub fn overallStatus(self: *const Self) VerificationStatus {
        if (self.store == .corrupted or
            self.profiles.status == .corrupted or
            self.environments.status == .corrupted or
            self.packages.status == .corrupted)
        {
            return .corrupted;
        }
        if (self.store == .warning or
            self.profiles.status == .warning or
            self.environments.status == .warning or
            self.packages.status == .warning)
        {
            return .warning;
        }
        return .ok;
    }

    pub fn addRecommendation(self: *Self, rec: []const u8) !void {
        try self.recommendations.append(try self.allocator.dupe(u8, rec));
    }
};

/// Recovery Engine for scanning and executing recovery
pub const RecoveryEngine = struct {
    allocator: Allocator,
    store_path: []const u8,
    transaction_log_path: []const u8,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return .{
            .allocator = allocator,
            .store_path = "/axiom/store",
            .transaction_log_path = "/axiom/var/transactions",
        };
    }

    /// Scan for recoverable issues
    pub fn scan(self: *Self) !RecoveryPlan {
        var plan = RecoveryPlan.init(self.allocator);

        // Scan for interrupted imports
        try self.scanInterruptedImports(&plan);

        // Scan for interrupted realizations
        try self.scanInterruptedRealizations(&plan);

        // Scan for orphaned datasets
        try self.scanOrphanedDatasets(&plan);

        // Scan for corrupted packages
        try self.scanCorruptedPackages(&plan);

        return plan;
    }

    fn scanInterruptedImports(self: *Self, plan: *RecoveryPlan) !void {
        // Check transaction log for incomplete imports
        var tx_dir = std.fs.cwd().openDir(self.transaction_log_path, .{ .iterate = true }) catch {
            return; // No transaction log directory
        };
        defer tx_dir.close();

        var iter = tx_dir.iterate();
        while (try iter.next()) |entry| {
            if (std.mem.startsWith(u8, entry.name, "import-")) {
                // Found an import transaction - check if complete
                const recovery = ImportRecovery{
                    .package_name = try self.allocator.dupe(u8, entry.name[7..]),
                    .partial_path = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ self.transaction_log_path, entry.name }),
                    .transaction_id = try self.allocator.dupe(u8, entry.name),
                    .progress_percent = 0,
                    .actions = try self.allocator.dupe(RecoveryAction, &[_]RecoveryAction{
                        .clean_partial,
                        .retry_operation,
                    }),
                };
                try plan.interrupted_imports.append(recovery);
            }
        }
    }

    fn scanInterruptedRealizations(self: *Self, plan: *RecoveryPlan) !void {
        // Check for .partial directories in environments
        const env_path = "/axiom/env";
        var env_dir = std.fs.cwd().openDir(env_path, .{ .iterate = true }) catch {
            return; // No environments directory
        };
        defer env_dir.close();

        var iter = env_dir.iterate();
        while (try iter.next()) |entry| {
            if (std.mem.endsWith(u8, entry.name, ".partial")) {
                const env_name = entry.name[0 .. entry.name.len - 8];
                const recovery = RealizationRecovery{
                    .env_name = try self.allocator.dupe(u8, env_name),
                    .profile_name = try self.allocator.dupe(u8, "unknown"),
                    .partial_path = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ env_path, entry.name }),
                    .completed_packages = 0,
                    .total_packages = 0,
                    .actions = try self.allocator.dupe(RecoveryAction, &[_]RecoveryAction{
                        .clean_partial,
                        .retry_operation,
                    }),
                };
                try plan.interrupted_realizations.append(recovery);
            }
        }
    }

    fn scanOrphanedDatasets(self: *Self, plan: *RecoveryPlan) !void {
        _ = self;
        // In full implementation, would use ZFS to find orphaned datasets
        // For now, this is a placeholder
        _ = plan;
    }

    fn scanCorruptedPackages(self: *Self, plan: *RecoveryPlan) !void {
        _ = self;
        // In full implementation, would verify package hashes
        // For now, this is a placeholder
        _ = plan;
    }

    /// Execute recovery plan
    pub fn execute(self: *Self, plan: *RecoveryPlan, mode: RecoveryMode) !RecoveryResult {
        var result = RecoveryResult.init(self.allocator);

        if (mode == .dry_run) {
            try result.addMessage(self.allocator, "Dry run - no changes made");
            return result;
        }

        // Recover interrupted imports
        for (plan.interrupted_imports.items) |*import_rec| {
            const success = self.recoverImport(import_rec, mode) catch false;
            if (success) {
                result.actions_taken += 1;
                try result.addMessage(self.allocator, "Recovered interrupted import");
            } else {
                result.actions_failed += 1;
                result.success = false;
            }
        }

        // Recover interrupted realizations
        for (plan.interrupted_realizations.items) |*real_rec| {
            const success = self.recoverRealization(real_rec, mode) catch false;
            if (success) {
                result.actions_taken += 1;
                try result.addMessage(self.allocator, "Recovered interrupted realization");
            } else {
                result.actions_failed += 1;
                result.success = false;
            }
        }

        // Clean orphaned datasets
        for (plan.orphaned_datasets.items) |dataset| {
            if (mode == .automatic) {
                // Clean orphan
                result.actions_taken += 1;
                _ = dataset;
            } else {
                result.actions_skipped += 1;
            }
        }

        // Handle corrupted packages
        for (plan.corrupted_packages.items) |*pkg_rec| {
            _ = pkg_rec;
            if (mode == .automatic) {
                result.actions_skipped += 1; // Corrupted packages need manual intervention
            }
        }

        return result;
    }

    fn recoverImport(self: *Self, recovery: *ImportRecovery, mode: RecoveryMode) !bool {
        _ = mode;

        // Clean partial import data
        if (recovery.partial_path.len > 0) {
            std.fs.cwd().deleteTree(recovery.partial_path) catch {};
        }

        // Remove transaction log entry
        if (recovery.transaction_id) |tid| {
            const tx_path = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ self.transaction_log_path, tid });
            defer self.allocator.free(tx_path);
            std.fs.cwd().deleteFile(tx_path) catch {};
        }

        return true;
    }

    fn recoverRealization(self: *Self, recovery: *RealizationRecovery, mode: RecoveryMode) !bool {
        _ = self;
        _ = mode;

        // Clean partial realization
        if (recovery.partial_path.len > 0) {
            std.fs.cwd().deleteTree(recovery.partial_path) catch {};
        }

        return true;
    }

    /// Verify system integrity
    pub fn verify(self: *Self, quick: bool) !VerificationResult {
        var result = VerificationResult.init(self.allocator);

        // Verify store
        result.store = try self.verifyStore(quick);

        // Verify profiles
        result.profiles = try self.verifyProfiles(quick);

        // Verify environments
        result.environments = try self.verifyEnvironments(quick);

        // Verify packages (skip if quick mode)
        if (!quick) {
            result.packages = try self.verifyPackages();
        } else {
            result.packages = .{
                .name = "Packages",
                .status = .ok,
                .valid_count = 0,
                .invalid_count = 0,
                .details = try self.allocator.dupe(u8, "(skipped in quick mode)"),
            };
        }

        // Add recommendations based on findings
        if (result.environments.invalid_count > 0) {
            try result.addRecommendation("Run 'axiom recover' to fix environment issues");
        }
        if (result.packages.invalid_count > 0) {
            try result.addRecommendation("Run 'axiom store-repair' to fix package issues");
        }

        return result;
    }

    fn verifyStore(self: *Self, quick: bool) !VerificationStatus {
        _ = quick;

        // Check store directory exists
        std.fs.cwd().access(self.store_path, .{}) catch {
            return .missing;
        };

        // In full implementation, would check store metadata
        return .ok;
    }

    fn verifyProfiles(self: *Self, quick: bool) !ComponentVerification {
        _ = quick;

        var valid: usize = 0;
        var invalid: usize = 0;

        const profiles_path = "/axiom/profiles";
        var dir = std.fs.cwd().openDir(profiles_path, .{ .iterate = true }) catch {
            return .{
                .name = try self.allocator.dupe(u8, "Profiles"),
                .status = .missing,
                .valid_count = 0,
                .invalid_count = 0,
                .details = try self.allocator.dupe(u8, "Profiles directory not found"),
            };
        };
        defer dir.close();

        var iter = dir.iterate();
        while (try iter.next()) |entry| {
            if (entry.kind == .directory) {
                // Check if profile.json exists
                const profile_json = try std.fmt.allocPrint(self.allocator, "{s}/{s}/profile.json", .{ profiles_path, entry.name });
                defer self.allocator.free(profile_json);

                std.fs.cwd().access(profile_json, .{}) catch {
                    invalid += 1;
                    continue;
                };
                valid += 1;
            }
        }

        const status: VerificationStatus = if (invalid > 0) .warning else .ok;

        return .{
            .name = try self.allocator.dupe(u8, "Profiles"),
            .status = status,
            .valid_count = valid,
            .invalid_count = invalid,
            .details = null,
        };
    }

    fn verifyEnvironments(self: *Self, quick: bool) !ComponentVerification {
        _ = quick;

        var valid: usize = 0;
        var invalid: usize = 0;

        const env_path = "/axiom/env";
        var dir = std.fs.cwd().openDir(env_path, .{ .iterate = true }) catch {
            return .{
                .name = try self.allocator.dupe(u8, "Environments"),
                .status = .ok,
                .valid_count = 0,
                .invalid_count = 0,
                .details = try self.allocator.dupe(u8, "No environments"),
            };
        };
        defer dir.close();

        var iter = dir.iterate();
        while (try iter.next()) |entry| {
            if (std.mem.endsWith(u8, entry.name, ".partial")) {
                invalid += 1;
            } else if (entry.kind == .directory) {
                valid += 1;
            }
        }

        const status: VerificationStatus = if (invalid > 0) .warning else .ok;

        return .{
            .name = try self.allocator.dupe(u8, "Environments"),
            .status = status,
            .valid_count = valid,
            .invalid_count = invalid,
            .details = null,
        };
    }

    fn verifyPackages(self: *Self) !ComponentVerification {
        var valid: usize = 0;
        const invalid: usize = 0;

        const pkg_path = "/axiom/store/pkg";
        var dir = std.fs.cwd().openDir(pkg_path, .{ .iterate = true }) catch {
            return .{
                .name = try self.allocator.dupe(u8, "Packages"),
                .status = .ok,
                .valid_count = 0,
                .invalid_count = 0,
                .details = try self.allocator.dupe(u8, "No packages"),
            };
        };
        defer dir.close();

        var iter = dir.iterate();
        while (try iter.next()) |entry| {
            if (entry.kind == .directory) {
                // In full implementation, would verify hash
                valid += 1;
            }
        }

        const status: VerificationStatus = if (invalid > 0) .corrupted else .ok;

        return .{
            .name = try self.allocator.dupe(u8, "Packages"),
            .status = status,
            .valid_count = valid,
            .invalid_count = invalid,
            .details = null,
        };
    }
};

/// Error suggestion entry
pub const ErrorSuggestion = struct {
    error_name: []const u8,
    suggestion: []const u8,
};

/// Error Reporter for consistent error output and suggestions
pub const ErrorReporter = struct {
    allocator: Allocator,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return .{
            .allocator = allocator,
        };
    }

    /// Report an error with context
    pub fn report(self: *Self, err: anyerror, context: ErrorContext) void {
        std.debug.print("\n{s} [{s}]: {s}\n", .{
            context.severity.toString(),
            context.category.toString(),
            @errorName(err),
        });

        std.debug.print("  Operation: {s}\n", .{context.operation});

        if (context.resource) |res| {
            std.debug.print("  Resource: {s}\n", .{res});
        }

        if (context.details) |det| {
            std.debug.print("  Details: {s}\n", .{det});
        }

        if (self.suggest(err)) |suggestion| {
            std.debug.print("\n  Suggestion: {s}\n", .{suggestion});
        }

        std.debug.print("\n", .{});
    }

    /// Get recovery suggestion for an error
    pub fn suggest(self: *Self, err: anyerror) ?[]const u8 {
        _ = self;

        // Match against known errors and provide suggestions
        const err_name = @errorName(err);

        if (std.mem.eql(u8, err_name, "StoreCorrupted")) {
            return "Run 'axiom store-repair' to attempt automatic repair";
        } else if (std.mem.eql(u8, err_name, "PackageNotFound")) {
            return "Try 'axiom search <name>' to find the correct package name";
        } else if (std.mem.eql(u8, err_name, "ImportInterrupted")) {
            return "Run 'axiom import-recover' to clean up and retry";
        } else if (std.mem.eql(u8, err_name, "RealizationInterrupted")) {
            return "Run 'axiom env-recover <name>' to recover the environment";
        } else if (std.mem.eql(u8, err_name, "DependencyConflict")) {
            return "Run 'axiom deps-analyze <pkg>' to see conflict details";
        } else if (std.mem.eql(u8, err_name, "UnsatisfiableDependency")) {
            return "Check if required packages are available in the cache";
        } else if (std.mem.eql(u8, err_name, "CacheUnreachable")) {
            return "Check network connectivity and cache server status";
        } else if (std.mem.eql(u8, err_name, "PermissionDenied")) {
            return "Run with elevated privileges (sudo) for system operations";
        } else if (std.mem.eql(u8, err_name, "PoolNotAvailable")) {
            return "Ensure ZFS pool is imported: 'zpool import <pool>'";
        }

        return null;
    }

    /// Get all suggestions for errors
    pub fn getSuggestionTable() []const ErrorSuggestion {
        return &[_]ErrorSuggestion{
            .{ .error_name = "StoreCorrupted", .suggestion = "axiom store-repair" },
            .{ .error_name = "PackageNotFound", .suggestion = "axiom search <name>" },
            .{ .error_name = "ImportInterrupted", .suggestion = "axiom import-recover" },
            .{ .error_name = "RealizationInterrupted", .suggestion = "axiom env-recover <name>" },
            .{ .error_name = "DependencyConflict", .suggestion = "axiom deps-analyze <pkg>" },
            .{ .error_name = "CacheUnreachable", .suggestion = "Check network connectivity" },
            .{ .error_name = "PermissionDenied", .suggestion = "Run with sudo" },
            .{ .error_name = "PoolNotAvailable", .suggestion = "zpool import <pool>" },
        };
    }
};

/// Transaction log entry for tracking operations
pub const TransactionEntry = struct {
    id: []const u8,
    operation: []const u8,
    started_at: i64,
    completed_at: ?i64,
    status: TransactionStatus,
    resource: []const u8,

    pub const TransactionStatus = enum {
        in_progress,
        completed,
        failed,
        rolled_back,
    };

    pub fn deinit(self: *TransactionEntry, allocator: Allocator) void {
        allocator.free(self.id);
        allocator.free(self.operation);
        allocator.free(self.resource);
    }
};

/// Transaction logger for crash recovery
pub const TransactionLog = struct {
    allocator: Allocator,
    log_path: []const u8,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return .{
            .allocator = allocator,
            .log_path = "/axiom/var/transactions",
        };
    }

    /// Start a new transaction
    pub fn begin(self: *Self, operation: []const u8, resource: []const u8) ![]const u8 {
        const id = try std.fmt.allocPrint(self.allocator, "{s}-{d}", .{ operation, std.time.timestamp() });

        // Write transaction file
        const tx_path = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ self.log_path, id });
        defer self.allocator.free(tx_path);

        // Ensure directory exists
        std.fs.cwd().makePath(self.log_path) catch {};

        const file = try std.fs.cwd().createFile(tx_path, .{});
        defer file.close();

        try file.writeAll(resource);

        return id;
    }

    /// Complete a transaction
    pub fn commit(self: *Self, id: []const u8) !void {
        const tx_path = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ self.log_path, id });
        defer self.allocator.free(tx_path);

        // Remove transaction file (marks as complete)
        std.fs.cwd().deleteFile(tx_path) catch {};
    }

    /// Rollback a transaction
    pub fn rollback(self: *Self, id: []const u8) !void {
        // Same as commit - just remove the marker
        try self.commit(id);
    }

    /// Check for incomplete transactions
    pub fn getIncomplete(self: *Self) !std.ArrayList(TransactionEntry) {
        var entries = std.ArrayList(TransactionEntry).init(self.allocator);

        var dir = std.fs.cwd().openDir(self.log_path, .{ .iterate = true }) catch {
            return entries;
        };
        defer dir.close();

        var iter = dir.iterate();
        while (try iter.next()) |entry| {
            if (entry.kind == .file) {
                const tx_entry = TransactionEntry{
                    .id = try self.allocator.dupe(u8, entry.name),
                    .operation = try self.allocator.dupe(u8, "unknown"),
                    .started_at = 0,
                    .completed_at = null,
                    .status = .in_progress,
                    .resource = try self.allocator.dupe(u8, "unknown"),
                };
                try entries.append(tx_entry);
            }
        }

        return entries;
    }
};

// Tests
test "RecoveryPlan.isEmpty" {
    const allocator = std.testing.allocator;
    var plan = RecoveryPlan.init(allocator);
    defer plan.deinit();

    try std.testing.expect(plan.isEmpty());
}

test "VerificationResult.overallStatus" {
    const allocator = std.testing.allocator;
    var result = VerificationResult.init(allocator);
    defer result.deinit();

    try std.testing.expectEqual(VerificationStatus.ok, result.overallStatus());

    result.store = .corrupted;
    try std.testing.expectEqual(VerificationStatus.corrupted, result.overallStatus());
}

test "ErrorContext.init" {
    const ctx = ErrorContext.init(.store, "test_operation");
    try std.testing.expectEqual(ErrorCategory.store, ctx.category);
    try std.testing.expectEqual(ErrorSeverity.err, ctx.severity);
    try std.testing.expect(ctx.recoverable);
}

test "RecoveryAction.isAutomatic" {
    try std.testing.expect(RecoveryAction.clean_partial.isAutomatic());
    try std.testing.expect(!RecoveryAction.refetch_package.isAutomatic());
}
