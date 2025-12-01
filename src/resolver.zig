const std = @import("std");
const types = @import("types.zig");
const store = @import("store.zig");
const profile = @import("profile.zig");
const manifest_mod = @import("manifest.zig");
const sat_resolver = @import("sat_resolver.zig");

const Version = types.Version;
const VersionConstraint = types.VersionConstraint;
const Dependency = types.Dependency;
const PackageId = types.PackageId;
const PackageStore = store.PackageStore;
const Profile = profile.Profile;
const ProfileLock = profile.ProfileLock;
const ResolvedPackage = profile.ResolvedPackage;
const PackageRequest = profile.PackageRequest;
const Manifest = manifest_mod.Manifest;
const VirtualPackage = manifest_mod.VirtualPackage;
const KernelCompat = manifest_mod.KernelCompat;
const SATResolver = sat_resolver.SATResolver;

/// Context about the running kernel for compatibility checks
pub const KernelContext = struct {
    /// FreeBSD version from sysctl kern.osreldate (e.g., 1502000)
    freebsd_version: u32,

    /// Kernel identifier from sysctl kern.ident (e.g., "PGSD-GENERIC")
    kernel_ident: []const u8,

    /// Initialize from system values (for use on FreeBSD)
    pub fn initFromSystem(allocator: std.mem.Allocator) !KernelContext {
        // Default values for non-FreeBSD systems or when sysctl fails
        // Try to read kern.osreldate
        // In production, this would use sysctl
        // For now, use placeholder that can be overridden
        _ = allocator;

        return KernelContext{
            .freebsd_version = 0,
            .kernel_ident = "",
        };
    }

    /// Create a mock context for testing
    pub fn initMock(freebsd_version: u32, kernel_ident: []const u8) KernelContext {
        return KernelContext{
            .freebsd_version = freebsd_version,
            .kernel_ident = kernel_ident,
        };
    }
};

/// Reason for kernel incompatibility
pub const KernelIncompatReason = enum {
    none,
    version_below_minimum,
    version_above_maximum,
    ident_mismatch,

    pub fn message(self: KernelIncompatReason) []const u8 {
        return switch (self) {
            .none => "",
            .version_below_minimum => "running kernel version is below minimum required",
            .version_above_maximum => "running kernel version exceeds maximum supported",
            .ident_mismatch => "running kernel ident not in allowed list",
        };
    }
};

/// Result of kernel compatibility check with detailed diagnostics
pub const KernelCompatResult = struct {
    compatible: bool,
    reason: KernelIncompatReason = .none,
    /// Running kernel version (for diagnostics)
    running_version: u32 = 0,
    /// Required minimum version (if failed due to version)
    required_min: ?u32 = null,
    /// Required maximum version (if failed due to version)
    required_max: ?u32 = null,
    /// Running kernel ident (for diagnostics)
    running_ident: []const u8 = "",

    /// Get human-readable reason message
    pub fn getMessage(self: KernelCompatResult) []const u8 {
        return self.reason.message();
    }
};

/// Check if a package's kernel requirements are compatible with running kernel
pub fn kernelIsCompatible(
    kernel_ctx: *const KernelContext,
    compat: *const KernelCompat,
) KernelCompatResult {
    // If not a kernel module, always compatible
    if (!compat.kmod) {
        return .{ .compatible = true };
    }

    const fv = kernel_ctx.freebsd_version;

    // Check minimum version
    if (compat.freebsd_version_min) |minv| {
        if (fv < minv) {
            return .{
                .compatible = false,
                .reason = .version_below_minimum,
                .running_version = fv,
                .required_min = minv,
                .running_ident = kernel_ctx.kernel_ident,
            };
        }
    }

    // Check maximum version
    if (compat.freebsd_version_max) |maxv| {
        if (fv > maxv) {
            return .{
                .compatible = false,
                .reason = .version_above_maximum,
                .running_version = fv,
                .required_max = maxv,
                .running_ident = kernel_ctx.kernel_ident,
            };
        }
    }

    // Check kernel ident if required
    if (compat.require_exact_ident and compat.kernel_idents.len > 0) {
        var matched = false;
        for (compat.kernel_idents) |ident| {
            if (std.mem.eql(u8, ident, kernel_ctx.kernel_ident)) {
                matched = true;
                break;
            }
        }
        if (!matched) {
            return .{
                .compatible = false,
                .reason = .ident_mismatch,
                .running_version = fv,
                .running_ident = kernel_ctx.kernel_ident,
            };
        }
    }

    return .{ .compatible = true, .running_version = fv, .running_ident = kernel_ctx.kernel_ident };
}

/// Errors that can occur during resolution
pub const ResolverError = error{
    NoSolution,
    ConflictingConstraints,
    PackageNotFound,
    CircularDependency,
    ConflictingPackages,
    VirtualPackageAmbiguous,
    KernelIncompatible,
    // Phase 29: Resource limit errors
    ResolutionTimeout,
    MemoryLimitExceeded,
    DepthLimitExceeded,
    CandidateLimitExceeded,
    ComplexityLimitExceeded,
};

// ============================================================================
// Phase 29: Resolver Resource Limits
// ============================================================================

/// Resource limits for dependency resolution
/// Prevents DoS through malicious manifests with exponential complexity
pub const ResourceLimits = struct {
    /// Maximum resolution time in milliseconds (default: 30 seconds)
    max_resolution_time_ms: u64 = 30_000,

    /// Maximum memory usage in bytes (default: 256 MB)
    max_memory_bytes: usize = 256 * 1024 * 1024,

    /// Maximum dependency depth (default: 100)
    max_dependency_depth: u32 = 100,

    /// Maximum candidate versions per package (default: 1000)
    max_candidates_per_package: u32 = 1000,

    /// Maximum total candidates examined (default: 100,000)
    max_total_candidates: u32 = 100_000,

    /// Maximum SAT variables (default: 100,000)
    max_sat_variables: u32 = 100_000,

    /// Maximum SAT clauses (default: 1,000,000)
    max_sat_clauses: u32 = 1_000_000,

    /// Create unlimited configuration (for testing)
    pub fn unlimited() ResourceLimits {
        return .{
            .max_resolution_time_ms = std.math.maxInt(u64),
            .max_memory_bytes = std.math.maxInt(usize),
            .max_dependency_depth = std.math.maxInt(u32),
            .max_candidates_per_package = std.math.maxInt(u32),
            .max_total_candidates = std.math.maxInt(u32),
            .max_sat_variables = std.math.maxInt(u32),
            .max_sat_clauses = std.math.maxInt(u32),
        };
    }

    /// Create strict limits for untrusted inputs
    pub fn strict() ResourceLimits {
        return .{
            .max_resolution_time_ms = 10_000, // 10 seconds
            .max_memory_bytes = 64 * 1024 * 1024, // 64 MB
            .max_dependency_depth = 50,
            .max_candidates_per_package = 100,
            .max_total_candidates = 10_000,
            .max_sat_variables = 10_000,
            .max_sat_clauses = 100_000,
        };
    }
};

/// Statistics collected during resolution
pub const ResourceStats = struct {
    /// Resolution start time (milliseconds since epoch)
    start_time_ms: i64 = 0,

    /// Peak memory usage in bytes
    peak_memory_bytes: usize = 0,

    /// Current estimated memory usage
    current_memory_bytes: usize = 0,

    /// Maximum dependency depth reached
    max_depth_reached: u32 = 0,

    /// Total candidates examined
    candidates_examined: u32 = 0,

    /// Candidates examined per package (for diagnostics)
    candidates_per_package: std.StringHashMap(u32) = undefined,

    /// SAT variables created
    sat_variables: u32 = 0,

    /// SAT clauses created
    sat_clauses: u32 = 0,

    /// Number of packages resolved
    packages_resolved: u32 = 0,

    /// Whether limits were hit (and which one)
    limit_hit: ?LimitType = null,

    pub const LimitType = enum {
        time,
        memory,
        depth,
        candidates_per_package,
        total_candidates,
        sat_variables,
        sat_clauses,

        pub fn message(self: LimitType) []const u8 {
            return switch (self) {
                .time => "resolution timeout exceeded",
                .memory => "memory limit exceeded",
                .depth => "dependency depth limit exceeded",
                .candidates_per_package => "too many candidate versions for package",
                .total_candidates => "total candidates limit exceeded",
                .sat_variables => "SAT solver variable limit exceeded",
                .sat_clauses => "SAT solver clause limit exceeded",
            };
        }
    };

    pub fn init(allocator: std.mem.Allocator) ResourceStats {
        return .{
            .start_time_ms = std.time.milliTimestamp(),
            .candidates_per_package = std.StringHashMap(u32).init(allocator),
        };
    }

    pub fn deinit(self: *ResourceStats) void {
        self.candidates_per_package.deinit();
    }

    /// Get elapsed time in milliseconds
    pub fn elapsedMs(self: *const ResourceStats) i64 {
        return std.time.milliTimestamp() - self.start_time_ms;
    }

    /// Get elapsed time in seconds (for display)
    pub fn elapsedSeconds(self: *const ResourceStats) f64 {
        return @as(f64, @floatFromInt(self.elapsedMs())) / 1000.0;
    }

    /// Record a candidate examination
    pub fn recordCandidate(self: *ResourceStats, package_name: []const u8) !void {
        self.candidates_examined += 1;
        const entry = try self.candidates_per_package.getOrPut(package_name);
        if (entry.found_existing) {
            entry.value_ptr.* += 1;
        } else {
            entry.value_ptr.* = 1;
        }
    }

    /// Record memory allocation
    pub fn recordMemory(self: *ResourceStats, bytes: usize) void {
        self.current_memory_bytes += bytes;
        if (self.current_memory_bytes > self.peak_memory_bytes) {
            self.peak_memory_bytes = self.current_memory_bytes;
        }
    }

    /// Record memory deallocation
    pub fn releaseMemory(self: *ResourceStats, bytes: usize) void {
        if (bytes <= self.current_memory_bytes) {
            self.current_memory_bytes -= bytes;
        } else {
            self.current_memory_bytes = 0;
        }
    }

    /// Update depth tracking
    pub fn recordDepth(self: *ResourceStats, depth: u32) void {
        if (depth > self.max_depth_reached) {
            self.max_depth_reached = depth;
        }
    }

    /// Format stats for display
    pub fn format(
        self: *const ResourceStats,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        try writer.print(
            "Resolution completed in {d:.2}s\n" ++
                "  Memory used: {d} MB (peak: {d} MB)\n" ++
                "  Candidates examined: {d}\n" ++
                "  Packages resolved: {d}\n" ++
                "  Maximum depth: {d}\n",
            .{
                self.elapsedSeconds(),
                self.current_memory_bytes / (1024 * 1024),
                self.peak_memory_bytes / (1024 * 1024),
                self.candidates_examined,
                self.packages_resolved,
                self.max_depth_reached,
            },
        );
        if (self.sat_variables > 0 or self.sat_clauses > 0) {
            try writer.print(
                "  SAT variables: {d}\n" ++
                    "  SAT clauses: {d}\n",
                .{ self.sat_variables, self.sat_clauses },
            );
        }
        if (self.limit_hit) |limit| {
            try writer.print("  Limit hit: {s}\n", .{limit.message()});
        }
    }
};

/// Resource limit checker - used during resolution
pub const ResourceChecker = struct {
    limits: ResourceLimits,
    stats: *ResourceStats,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, limits: ResourceLimits, stats: *ResourceStats) ResourceChecker {
        return .{
            .limits = limits,
            .stats = stats,
            .allocator = allocator,
        };
    }

    /// Check if time limit has been exceeded
    pub fn checkTime(self: *ResourceChecker) ResolverError!void {
        const elapsed: u64 = @intCast(@max(0, self.stats.elapsedMs()));
        if (elapsed > self.limits.max_resolution_time_ms) {
            self.stats.limit_hit = .time;
            return ResolverError.ResolutionTimeout;
        }
    }

    /// Check if memory limit has been exceeded
    pub fn checkMemory(self: *ResourceChecker, additional_bytes: usize) ResolverError!void {
        const total = self.stats.current_memory_bytes + additional_bytes;
        if (total > self.limits.max_memory_bytes) {
            self.stats.limit_hit = .memory;
            return ResolverError.MemoryLimitExceeded;
        }
        self.stats.recordMemory(additional_bytes);
    }

    /// Check if depth limit has been exceeded
    pub fn checkDepth(self: *ResourceChecker, depth: u32) ResolverError!void {
        self.stats.recordDepth(depth);
        if (depth > self.limits.max_dependency_depth) {
            self.stats.limit_hit = .depth;
            return ResolverError.DepthLimitExceeded;
        }
    }

    /// Check and record candidate examination
    pub fn checkCandidate(self: *ResourceChecker, package_name: []const u8) ResolverError!void {
        try self.checkTime(); // Also check time on each candidate

        self.stats.recordCandidate(package_name) catch {};

        // Check total candidates
        if (self.stats.candidates_examined > self.limits.max_total_candidates) {
            self.stats.limit_hit = .total_candidates;
            return ResolverError.CandidateLimitExceeded;
        }

        // Check per-package candidates
        if (self.stats.candidates_per_package.get(package_name)) |count| {
            if (count > self.limits.max_candidates_per_package) {
                self.stats.limit_hit = .candidates_per_package;
                return ResolverError.CandidateLimitExceeded;
            }
        }
    }

    /// Check SAT variable limit
    pub fn checkSatVariable(self: *ResourceChecker) ResolverError!void {
        self.stats.sat_variables += 1;
        if (self.stats.sat_variables > self.limits.max_sat_variables) {
            self.stats.limit_hit = .sat_variables;
            return ResolverError.ComplexityLimitExceeded;
        }
    }

    /// Check SAT clause limit
    pub fn checkSatClause(self: *ResourceChecker) ResolverError!void {
        self.stats.sat_clauses += 1;
        if (self.stats.sat_clauses > self.limits.max_sat_clauses) {
            self.stats.limit_hit = .sat_clauses;
            return ResolverError.ComplexityLimitExceeded;
        }
    }

    /// Record a package resolution
    pub fn recordResolution(self: *ResourceChecker) void {
        self.stats.packages_resolved += 1;
    }
};

/// A candidate package version available in the store
pub const Candidate = struct {
    id: PackageId,
    dependencies: []Dependency,
    /// Virtual packages this candidate provides
    provides: [][]const u8 = &[_][]const u8{},
    /// Packages this candidate conflicts with
    conflicts: []VirtualPackage = &[_]VirtualPackage{},
    /// Packages this candidate replaces
    replaces: []VirtualPackage = &[_]VirtualPackage{},
    /// Kernel compatibility info (null for userland packages)
    kernel_compat: ?KernelCompat = null,
};

/// Tracks a conflict between two packages
pub const ConflictInfo = struct {
    package_a: []const u8,
    package_b: []const u8,
    reason: []const u8,
};

/// Maps virtual package names to packages that provide them
pub const VirtualPackageIndex = struct {
    allocator: std.mem.Allocator,
    /// Virtual name -> list of real package names that provide it
    providers: std.StringHashMap(std.ArrayList([]const u8)),

    pub fn init(allocator: std.mem.Allocator) VirtualPackageIndex {
        return VirtualPackageIndex{
            .allocator = allocator,
            .providers = std.StringHashMap(std.ArrayList([]const u8)).init(allocator),
        };
    }

    pub fn deinit(self: *VirtualPackageIndex) void {
        var iter = self.providers.iterator();
        while (iter.next()) |entry| {
            entry.value_ptr.deinit();
        }
        self.providers.deinit();
    }

    /// Register a package as a provider of a virtual package
    pub fn addProvider(self: *VirtualPackageIndex, virtual_name: []const u8, real_name: []const u8) !void {
        const entry = try self.providers.getOrPut(virtual_name);
        if (!entry.found_existing) {
            entry.value_ptr.* = std.ArrayList([]const u8).init(self.allocator);
        }
        try entry.value_ptr.append(real_name);
    }

    /// Get all packages that provide a virtual package
    pub fn getProviders(self: *VirtualPackageIndex, virtual_name: []const u8) ?[][]const u8 {
        if (self.providers.get(virtual_name)) |list| {
            return list.items;
        }
        return null;
    }

    /// Check if a name is a virtual package
    pub fn isVirtual(self: *VirtualPackageIndex, name: []const u8) bool {
        return self.providers.contains(name);
    }
};

/// Resolution context tracking state during dependency resolution
pub const ResolutionContext = struct {
    allocator: std.mem.Allocator,
    store: *PackageStore,

    /// Packages we're trying to resolve (name -> constraints)
    constraints: std.StringHashMap(std.ArrayList(VersionConstraint)),

    /// Resolved packages (name -> PackageId)
    resolved: std.StringHashMap(PackageId),

    /// Packages directly requested (not dependencies)
    requested: std.StringHashMap(bool),

    /// Packages currently being resolved (for cycle detection)
    resolving: std.StringHashMap(bool),

    /// Virtual package index for this resolution
    virtual_index: VirtualPackageIndex,

    /// Detected conflicts during resolution
    conflicts: std.ArrayList(ConflictInfo),

    /// Candidates for resolved packages (for conflict checking)
    resolved_candidates: std.StringHashMap(Candidate),

    pub fn init(allocator: std.mem.Allocator, store_ptr: *PackageStore) ResolutionContext {
        return ResolutionContext{
            .allocator = allocator,
            .store = store_ptr,
            .constraints = std.StringHashMap(std.ArrayList(VersionConstraint)).init(allocator),
            .resolved = std.StringHashMap(PackageId).init(allocator),
            .requested = std.StringHashMap(bool).init(allocator),
            .resolving = std.StringHashMap(bool).init(allocator),
            .virtual_index = VirtualPackageIndex.init(allocator),
            .conflicts = std.ArrayList(ConflictInfo).init(allocator),
            .resolved_candidates = std.StringHashMap(Candidate).init(allocator),
        };
    }

    pub fn deinit(self: *ResolutionContext) void {
        var constraint_iter = self.constraints.iterator();
        while (constraint_iter.next()) |entry| {
            entry.value_ptr.deinit();
        }
        self.constraints.deinit();
        self.resolved.deinit();
        self.requested.deinit();
        self.resolving.deinit();
        self.virtual_index.deinit();
        self.conflicts.deinit();
        self.resolved_candidates.deinit();
    }

    /// Check if adding a package would create a conflict with already resolved packages
    pub fn checkConflicts(self: *ResolutionContext, candidate: Candidate) !bool {
        // Check if the candidate conflicts with any resolved package
        for (candidate.conflicts) |conflict| {
            if (self.resolved.get(conflict.name)) |resolved_id| {
                // Check version constraint if present
                if (conflict.constraint) |constraint| {
                    if (constraint.satisfies(resolved_id.version)) {
                        try self.conflicts.append(.{
                            .package_a = candidate.id.name,
                            .package_b = conflict.name,
                            .reason = "explicit conflict declaration",
                        });
                        return true;
                    }
                } else {
                    try self.conflicts.append(.{
                        .package_a = candidate.id.name,
                        .package_b = conflict.name,
                        .reason = "explicit conflict declaration",
                    });
                    return true;
                }
            }
        }

        // Check if any resolved package conflicts with this candidate
        var iter = self.resolved_candidates.iterator();
        while (iter.next()) |entry| {
            const resolved_candidate = entry.value_ptr.*;
            for (resolved_candidate.conflicts) |conflict| {
                if (std.mem.eql(u8, conflict.name, candidate.id.name)) {
                    if (conflict.constraint) |constraint| {
                        if (constraint.satisfies(candidate.id.version)) {
                            try self.conflicts.append(.{
                                .package_a = resolved_candidate.id.name,
                                .package_b = candidate.id.name,
                                .reason = "explicit conflict declaration",
                            });
                            return true;
                        }
                    } else {
                        try self.conflicts.append(.{
                            .package_a = resolved_candidate.id.name,
                            .package_b = candidate.id.name,
                            .reason = "explicit conflict declaration",
                        });
                        return true;
                    }
                }
            }
        }

        return false;
    }

    /// Check if a candidate replaces a package that's already resolved
    pub fn checkReplaces(self: *ResolutionContext, candidate: Candidate) ?[]const u8 {
        for (candidate.replaces) |replace| {
            if (self.resolved.contains(replace.name)) {
                // Check version constraint if present
                if (replace.constraint) |constraint| {
                    if (self.resolved.get(replace.name)) |resolved_id| {
                        if (constraint.satisfies(resolved_id.version)) {
                            return replace.name;
                        }
                    }
                } else {
                    return replace.name;
                }
            }
        }
        return null;
    }
};

/// Resolution strategy
pub const ResolutionStrategy = enum {
    /// Fast greedy algorithm - picks newest satisfying version
    greedy,
    /// SAT solver - finds optimal solution, handles complex constraints
    sat,
    /// Try greedy first, fall back to SAT on failure
    greedy_with_sat_fallback,
};

/// Dependency resolver with greedy and SAT solving capabilities
pub const Resolver = struct {
    allocator: std.mem.Allocator,
    store: *PackageStore,
    strategy: ResolutionStrategy,
    /// Kernel context for kmod compatibility checks
    kernel_ctx: KernelContext,
    /// Last resolution failure details (for diagnostics)
    last_failure: ?sat_resolver.ResolutionFailure = null,
    /// Phase 29: Resource limits for resolution
    resource_limits: ResourceLimits = .{},
    /// Phase 29: Last resolution statistics
    last_stats: ?ResourceStats = null,
    /// Phase 29: Whether to show stats after resolution
    show_stats: bool = false,

    /// Initialize resolver with default greedy strategy
    pub fn init(allocator: std.mem.Allocator, store_ptr: *PackageStore) Resolver {
        return Resolver{
            .allocator = allocator,
            .store = store_ptr,
            .strategy = .greedy_with_sat_fallback,
            .kernel_ctx = KernelContext.initMock(0, ""),
        };
    }

    /// Initialize resolver with kernel context
    pub fn initWithKernel(
        allocator: std.mem.Allocator,
        store_ptr: *PackageStore,
        kernel_ctx: KernelContext,
    ) Resolver {
        return Resolver{
            .allocator = allocator,
            .store = store_ptr,
            .strategy = .greedy_with_sat_fallback,
            .kernel_ctx = kernel_ctx,
        };
    }

    /// Set kernel context
    pub fn setKernelContext(self: *Resolver, kernel_ctx: KernelContext) void {
        self.kernel_ctx = kernel_ctx;
    }

    /// Set resolution strategy
    pub fn setStrategy(self: *Resolver, strategy: ResolutionStrategy) void {
        self.strategy = strategy;
    }

    /// Phase 29: Set resource limits
    pub fn setResourceLimits(self: *Resolver, limits: ResourceLimits) void {
        self.resource_limits = limits;
    }

    /// Phase 29: Enable/disable stats display
    pub fn setShowStats(self: *Resolver, show: bool) void {
        self.show_stats = show;
    }

    /// Phase 29: Get last resolution statistics
    pub fn getLastStats(self: *Resolver) ?*const ResourceStats {
        if (self.last_stats) |*stats| {
            return stats;
        }
        return null;
    }

    /// Phase 29: Clean up last stats
    pub fn clearLastStats(self: *Resolver) void {
        if (self.last_stats) |*stats| {
            stats.deinit();
            self.last_stats = null;
        }
    }

    /// Get last resolution failure details
    pub fn getLastFailure(self: *Resolver) ?*sat_resolver.ResolutionFailure {
        if (self.last_failure) |*failure| {
            return failure;
        }
        return null;
    }

    /// Clear last failure
    pub fn clearLastFailure(self: *Resolver) void {
        if (self.last_failure) |*failure| {
            failure.deinit();
            self.last_failure = null;
        }
    }

    /// Resolve a profile to a lock file
    pub fn resolve(
        self: *Resolver,
        prof: Profile,
    ) !ProfileLock {
        std.debug.print("Resolving profile: {s}\n", .{prof.name});

        // Clear any previous failure and stats
        self.clearLastFailure();
        self.clearLastStats();

        // Phase 29: Initialize resource stats
        self.last_stats = ResourceStats.init(self.allocator);

        const result = switch (self.strategy) {
            .greedy => self.resolveGreedy(prof),
            .sat => self.resolveSAT(prof),
            .greedy_with_sat_fallback => self.resolveWithFallback(prof),
        };

        // Phase 29: Show stats if enabled
        if (self.show_stats) {
            if (self.last_stats) |stats| {
                std.debug.print("\n{}\n", .{stats});
            }
        }

        return result;
    }

    /// Resolve using greedy algorithm
    fn resolveGreedy(self: *Resolver, prof: Profile) !ProfileLock {
        var ctx = ResolutionContext.init(self.allocator, self.store);
        defer ctx.deinit();

        // Add all requested packages to constraints
        for (prof.packages) |pkg_req| {
            std.debug.print("  Request: {s} ", .{pkg_req.name});
            self.printConstraint(pkg_req.constraint);
            std.debug.print("\n", .{});

            try self.addConstraint(&ctx, pkg_req.name, pkg_req.constraint);
            try ctx.requested.put(pkg_req.name, true);
        }

        // Resolve all packages
        var constraint_iter = ctx.constraints.iterator();
        while (constraint_iter.next()) |entry| {
            const pkg_name = entry.key_ptr.*;
            if (!ctx.resolved.contains(pkg_name)) {
                try self.resolvePackage(&ctx, pkg_name);
            }
        }

        // Build result
        var resolved_packages = std.ArrayList(ResolvedPackage).init(self.allocator);
        defer resolved_packages.deinit();

        var resolved_iter = ctx.resolved.iterator();
        while (resolved_iter.next()) |entry| {
            const is_requested = ctx.requested.get(entry.key_ptr.*) orelse false;
            try resolved_packages.append(.{
                .id = .{
                    .name = try self.allocator.dupe(u8, entry.value_ptr.name),
                    .version = entry.value_ptr.version,
                    .revision = entry.value_ptr.revision,
                    .build_id = try self.allocator.dupe(u8, entry.value_ptr.build_id),
                },
                .requested = is_requested,
            });
        }

        std.debug.print("✓ Resolved {d} packages ({d} requested, {d} dependencies)\n", .{
            resolved_packages.items.len,
            prof.packages.len,
            resolved_packages.items.len - prof.packages.len,
        });

        return ProfileLock{
            .profile_name = try self.allocator.dupe(u8, prof.name),
            .lock_version = 1,
            .resolved = try resolved_packages.toOwnedSlice(),
        };
    }

    /// Resolve using SAT solver
    fn resolveSAT(self: *Resolver, prof: Profile) !ProfileLock {
        std.debug.print("  Using SAT solver for dependency resolution...\n", .{});

        var sat = SATResolver.init(self.allocator);
        defer sat.deinit();

        // Build SAT resolver from store
        // Register all available packages
        const packages = try self.store.listPackages();
        // Note: listPackages returns static/internal data, no need to free

        for (packages) |pkg_id| {
            // Load package metadata for dependencies and conflicts
            var pkg_meta = self.store.getPackage(pkg_id) catch continue;
            defer {
                // Clean up allocated fields in PackageMetadata
                pkg_meta.manifest.deinit(self.allocator);
                self.allocator.free(pkg_meta.dataset_path);
                for (pkg_meta.dependencies) |dep| {
                    self.allocator.free(dep.name);
                }
                self.allocator.free(pkg_meta.dependencies);
            }

            // Convert dependencies
            var deps = std.ArrayList(sat_resolver.PackageCandidate.Dependency).init(self.allocator);
            defer deps.deinit();

            for (pkg_meta.dependencies) |dep| {
                try deps.append(.{
                    .name = dep.name,
                    .constraint = dep.constraint,
                });
            }

            // Convert conflicts
            var conflicts = std.ArrayList([]const u8).init(self.allocator);
            defer conflicts.deinit();

            for (pkg_meta.manifest.conflicts) |conflict| {
                try conflicts.append(conflict.name);
            }

            try sat.registerPackage(pkg_id, deps.items, conflicts.items);
        }

        // Convert profile requests to SAT requests
        var requests = try self.allocator.alloc(sat_resolver.PackageRequest, prof.packages.len);
        defer self.allocator.free(requests);

        for (prof.packages, 0..) |pkg_req, i| {
            requests[i] = .{
                .name = pkg_req.name,
                .constraint = pkg_req.constraint,
                .requested = true,
            };
        }

        // Solve
        const result = try sat.resolve(requests);

        switch (result) {
            .success => |resolved_ids| {
                defer self.allocator.free(resolved_ids);

                var resolved_packages = std.ArrayList(ResolvedPackage).init(self.allocator);
                defer resolved_packages.deinit();

                for (resolved_ids) |pkg_id| {
                    // Check if this was directly requested
                    var is_requested = false;
                    for (prof.packages) |req| {
                        if (std.mem.eql(u8, req.name, pkg_id.name)) {
                            is_requested = true;
                            break;
                        }
                    }

                    try resolved_packages.append(.{
                        .id = .{
                            .name = try self.allocator.dupe(u8, pkg_id.name),
                            .version = pkg_id.version,
                            .revision = pkg_id.revision,
                            .build_id = try self.allocator.dupe(u8, pkg_id.build_id),
                        },
                        .requested = is_requested,
                    });
                }

                std.debug.print("✓ SAT solver found solution with {d} packages\n", .{resolved_packages.items.len});

                return ProfileLock{
                    .profile_name = try self.allocator.dupe(u8, prof.name),
                    .lock_version = 1,
                    .resolved = try resolved_packages.toOwnedSlice(),
                };
            },
            .failure => |failure| {
                std.debug.print("✗ SAT solver found no solution\n", .{});

                // Store failure for diagnostics
                self.last_failure = failure;

                // Print suggestions
                for (failure.suggestions) |suggestion| {
                    std.debug.print("  Suggestion: {s}\n", .{suggestion});
                }

                return ResolverError.NoSolution;
            },
        }
    }

    /// Try greedy first, fall back to SAT on failure
    fn resolveWithFallback(self: *Resolver, prof: Profile) !ProfileLock {
        // Try greedy first
        return self.resolveGreedy(prof) catch |err| {
            switch (err) {
                ResolverError.NoSolution,
                ResolverError.ConflictingConstraints,
                ResolverError.ConflictingPackages,
                => {
                    std.debug.print("  Greedy resolution failed, trying SAT solver...\n", .{});
                    return self.resolveSAT(prof);
                },
                else => return err,
            }
        };
    }

    /// Add a constraint for a package
    fn addConstraint(
        self: *Resolver,
        ctx: *ResolutionContext,
        pkg_name: []const u8,
        constraint: VersionConstraint,
    ) !void {
        const entry = try ctx.constraints.getOrPut(pkg_name);
        if (!entry.found_existing) {
            entry.value_ptr.* = std.ArrayList(VersionConstraint).init(self.allocator);
        }
        try entry.value_ptr.append(constraint);
    }

    /// Resolve a single package and its dependencies
    fn resolvePackage(
        self: *Resolver,
        ctx: *ResolutionContext,
        pkg_name: []const u8,
    ) !void {
        // Check for circular dependency
        if (ctx.resolving.contains(pkg_name)) {
            std.debug.print("  ✗ Circular dependency detected: {s}\n", .{pkg_name});
            return ResolverError.CircularDependency;
        }

        try ctx.resolving.put(pkg_name, true);
        defer _ = ctx.resolving.remove(pkg_name);

        // Check if this is a virtual package request
        if (ctx.virtual_index.isVirtual(pkg_name)) {
            // Get providers and resolve one of them
            if (ctx.virtual_index.getProviders(pkg_name)) |providers| {
                if (providers.len == 1) {
                    // Only one provider, resolve it directly
                    std.debug.print("  → Virtual package {s} provided by {s}\n", .{ pkg_name, providers[0] });
                    try self.resolvePackage(ctx, providers[0]);
                    return;
                } else if (providers.len > 1) {
                    // Multiple providers - for now, pick the first one
                    // Future: Could use heuristics or user preference
                    std.debug.print("  → Virtual package {s} has {d} providers, selecting {s}\n", .{
                        pkg_name,
                        providers.len,
                        providers[0],
                    });
                    try self.resolvePackage(ctx, providers[0]);
                    return;
                }
            }
        }

        // Get all constraints for this package
        const constraints = ctx.constraints.get(pkg_name) orelse {
            std.debug.print("  ✗ No constraints for: {s}\n", .{pkg_name});
            return ResolverError.PackageNotFound;
        };

        // Find candidates that satisfy all constraints
        const candidates = try self.findCandidates(ctx, pkg_name, constraints.items);
        defer self.allocator.free(candidates);

        if (candidates.len == 0) {
            std.debug.print("  ✗ No candidates found for: {s}\n", .{pkg_name});
            return ResolverError.NoSolution;
        }

        // Pick the best candidate that doesn't conflict
        var chosen: ?Candidate = null;
        var kernel_rejected_count: usize = 0;
        for (candidates) |candidate| {
            // Check for conflicts
            const has_conflict = try ctx.checkConflicts(candidate);
            if (has_conflict) {
                std.debug.print("  ⚠ Skipping {s}@{} due to conflict\n", .{ pkg_name, candidate.id.version });
                continue;
            }

            // Check kernel compatibility for kernel-bound packages
            if (candidate.kernel_compat) |kc| {
                const compat_result = kernelIsCompatible(&self.kernel_ctx, &kc);
                if (!compat_result.compatible) {
                    std.debug.print("  ⚠ Skipping {s}@{} - {s}", .{
                        pkg_name,
                        candidate.id.version,
                        compat_result.getMessage(),
                    });
                    // Print version details for version-related errors
                    switch (compat_result.reason) {
                        .version_below_minimum => {
                            if (compat_result.required_min) |min| {
                                std.debug.print(" (running: {d}, required: >={d})", .{
                                    compat_result.running_version,
                                    min,
                                });
                            }
                        },
                        .version_above_maximum => {
                            if (compat_result.required_max) |max| {
                                std.debug.print(" (running: {d}, required: <={d})", .{
                                    compat_result.running_version,
                                    max,
                                });
                            }
                        },
                        .ident_mismatch => {
                            std.debug.print(" (running: \"{s}\")", .{compat_result.running_ident});
                        },
                        .none => {},
                    }
                    std.debug.print("\n", .{});
                    kernel_rejected_count += 1;
                    continue;
                }
            }

            // Check if this candidate replaces an already resolved package
            if (ctx.checkReplaces(candidate)) |replaced| {
                std.debug.print("  → {s}@{} replaces {s}\n", .{ pkg_name, candidate.id.version, replaced });
                // Remove the replaced package from resolved set
                _ = ctx.resolved.remove(replaced);
                _ = ctx.resolved_candidates.remove(replaced);
            }

            if (chosen == null or candidate.id.version.greaterThan(chosen.?.id.version)) {
                chosen = candidate;
            }
        }

        // Report if all candidates were rejected due to kernel incompatibility
        if (chosen == null and kernel_rejected_count == candidates.len) {
            std.debug.print("  ✗ All candidates for {s} are incompatible with running kernel\n", .{pkg_name});
            return ResolverError.KernelIncompatible;
        }

        if (chosen == null) {
            std.debug.print("  ✗ All candidates for {s} have conflicts\n", .{pkg_name});
            return ResolverError.ConflictingPackages;
        }

        const final_choice = chosen.?;
        std.debug.print("  → Resolved {s} to {}\n", .{ pkg_name, final_choice.id.version });

        // Add to resolved set
        try ctx.resolved.put(pkg_name, final_choice.id);
        try ctx.resolved_candidates.put(pkg_name, final_choice);

        // Register virtual packages this candidate provides
        for (final_choice.provides) |virtual_name| {
            try ctx.virtual_index.addProvider(virtual_name, pkg_name);
        }

        // Recursively resolve dependencies
        for (final_choice.dependencies) |dep| {
            if (!ctx.resolved.contains(dep.name)) {
                try self.addConstraint(ctx, dep.name, dep.constraint);
                try self.resolvePackage(ctx, dep.name);
            }
        }
    }

    /// Find all package versions that satisfy the given constraints
    fn findCandidates(
        self: *Resolver,
        ctx: *ResolutionContext,
        pkg_name: []const u8,
        constraints: []VersionConstraint,
    ) ![]Candidate {
        _ = ctx;
        
        // For now, we'll simulate finding candidates
        // In a real implementation, this would query the package store index
        
        // TODO: Query store.listPackages() filtered by name
        // For demonstration, we'll create mock candidates
        
        var candidates = std.ArrayList(Candidate).init(self.allocator);
        defer candidates.deinit();

        // Mock: Create a few versions that might satisfy constraints
        const test_versions = [_]Version{
            Version{ .major = 5, .minor = 2, .patch = 0 },
            Version{ .major = 5, .minor = 1, .patch = 0 },
            Version{ .major = 5, .minor = 0, .patch = 0 },
            Version{ .major = 4, .minor = 9, .patch = 0 },
        };

        for (test_versions) |ver| {
            var satisfies_all = true;
            for (constraints) |constraint| {
                if (!constraint.satisfies(ver)) {
                    satisfies_all = false;
                    break;
                }
            }

            if (satisfies_all) {
                // Create mock package ID
                const build_id = try std.fmt.allocPrint(
                    self.allocator,
                    "mock{d}{d}{d}",
                    .{ ver.major, ver.minor, ver.patch },
                );
                
                try candidates.append(.{
                    .id = .{
                        .name = try self.allocator.dupe(u8, pkg_name),
                        .version = ver,
                        .revision = 1,
                        .build_id = build_id,
                    },
                    .dependencies = &[_]Dependency{},
                });
            }
        }

        return candidates.toOwnedSlice();
    }

    /// Pick the best candidate from available options
    /// Current strategy: newest version
    fn pickBest(self: *Resolver, candidates: []Candidate) Candidate {
        _ = self;
        
        var best = candidates[0];
        for (candidates[1..]) |candidate| {
            if (candidate.id.version.greaterThan(best.id.version)) {
                best = candidate;
            }
        }
        return best;
    }

    /// Print a constraint for debugging
    fn printConstraint(self: *Resolver, constraint: VersionConstraint) void {
        _ = self;
        switch (constraint) {
            .exact => |v| std.debug.print("={}", .{v}),
            .tilde => |v| std.debug.print("~{}", .{v}),
            .caret => |v| std.debug.print("^{}", .{v}),
            .any => std.debug.print("*", .{}),
            .range => |r| {
                if (r.min) |min| {
                    std.debug.print("{s}{}", .{ if (r.min_inclusive) ">=" else ">", min });
                }
                if (r.max) |max| {
                    if (r.min != null) std.debug.print(",", .{});
                    std.debug.print("{s}{}", .{ if (r.max_inclusive) "<=" else "<", max });
                }
            },
        }
    }

    /// Build a virtual package index from all packages in the store
    /// Returns a mapping of virtual names to providers
    pub fn buildVirtualIndex(self: *Resolver) !VirtualPackageIndex {
        const index = VirtualPackageIndex.init(self.allocator);

        // TODO: Query store for all packages and their manifests
        // For now, we'll need the caller to register providers manually
        // or integrate with the package store's manifest loading

        return index;
    }

    /// Query packages that provide a virtual package
    pub fn findProviders(
        self: *Resolver,
        virtual_index: *VirtualPackageIndex,
        virtual_name: []const u8,
    ) ?[][]const u8 {
        _ = self;
        return virtual_index.getProviders(virtual_name);
    }

    /// Check if two packages conflict
    pub fn checkPackageConflict(
        self: *Resolver,
        pkg_a: Candidate,
        pkg_b: Candidate,
    ) bool {
        _ = self;
        // Check if A conflicts with B
        for (pkg_a.conflicts) |conflict| {
            if (std.mem.eql(u8, conflict.name, pkg_b.id.name)) {
                if (conflict.constraint) |constraint| {
                    if (constraint.satisfies(pkg_b.id.version)) {
                        return true;
                    }
                } else {
                    return true;
                }
            }
        }

        // Check if B conflicts with A
        for (pkg_b.conflicts) |conflict| {
            if (std.mem.eql(u8, conflict.name, pkg_a.id.name)) {
                if (conflict.constraint) |constraint| {
                    if (constraint.satisfies(pkg_a.id.version)) {
                        return true;
                    }
                } else {
                    return true;
                }
            }
        }

        return false;
    }

    /// Get list of conflicts detected during resolution
    pub fn getConflicts(self: *Resolver, ctx: *ResolutionContext) []ConflictInfo {
        _ = self;
        return ctx.conflicts.items;
    }
};

// Tests
test "Resolver.constraint_satisfaction" {
    const allocator = std.testing.allocator;

    // Test exact constraint
    const exact = VersionConstraint{ .exact = Version{ .major = 1, .minor = 2, .patch = 3 } };
    try std.testing.expect(exact.satisfies(Version{ .major = 1, .minor = 2, .patch = 3 }));
    try std.testing.expect(!exact.satisfies(Version{ .major = 1, .minor = 2, .patch = 4 }));

    // Test tilde constraint
    const tilde = VersionConstraint{ .tilde = Version{ .major = 1, .minor = 2, .patch = 0 } };
    try std.testing.expect(tilde.satisfies(Version{ .major = 1, .minor = 2, .patch = 0 }));
    try std.testing.expect(tilde.satisfies(Version{ .major = 1, .minor = 2, .patch = 5 }));
    try std.testing.expect(!tilde.satisfies(Version{ .major = 1, .minor = 3, .patch = 0 }));

    // Test caret constraint
    const caret = VersionConstraint{ .caret = Version{ .major = 1, .minor = 2, .patch = 0 } };
    try std.testing.expect(caret.satisfies(Version{ .major = 1, .minor = 2, .patch = 0 }));
    try std.testing.expect(caret.satisfies(Version{ .major = 1, .minor = 5, .patch = 0 }));
    try std.testing.expect(!caret.satisfies(Version{ .major = 2, .minor = 0, .patch = 0 }));

    _ = allocator;
}

test "Resolver.version_comparison" {
    const v1 = Version{ .major = 1, .minor = 2, .patch = 3 };
    const v2 = Version{ .major = 1, .minor = 2, .patch = 4 };
    const v3 = Version{ .major = 1, .minor = 3, .patch = 0 };
    const v4 = Version{ .major = 2, .minor = 0, .patch = 0 };

    try std.testing.expect(v1.lessThan(v2));
    try std.testing.expect(v2.lessThan(v3));
    try std.testing.expect(v3.lessThan(v4));
    try std.testing.expect(v4.greaterThan(v1));
}

test "VirtualPackageIndex.basic_operations" {
    const allocator = std.testing.allocator;

    var index = VirtualPackageIndex.init(allocator);
    defer index.deinit();

    // Add providers for virtual packages
    try index.addProvider("shell", "bash");
    try index.addProvider("shell", "zsh");
    try index.addProvider("shell", "fish");
    try index.addProvider("http-client", "curl");
    try index.addProvider("http-client", "wget");

    // Check that shell is virtual
    try std.testing.expect(index.isVirtual("shell"));
    try std.testing.expect(index.isVirtual("http-client"));
    try std.testing.expect(!index.isVirtual("bash"));

    // Get providers
    const shell_providers = index.getProviders("shell").?;
    try std.testing.expectEqual(@as(usize, 3), shell_providers.len);
    try std.testing.expectEqualStrings("bash", shell_providers[0]);
    try std.testing.expectEqualStrings("zsh", shell_providers[1]);
    try std.testing.expectEqualStrings("fish", shell_providers[2]);

    const http_providers = index.getProviders("http-client").?;
    try std.testing.expectEqual(@as(usize, 2), http_providers.len);

    // Non-existent virtual package
    try std.testing.expect(index.getProviders("nonexistent") == null);
}

test "ResolutionContext.conflict_detection" {
    const allocator = std.testing.allocator;

    // Create a mock store (we won't actually use it for this test)
    var ctx = ResolutionContext.init(allocator, undefined);
    defer ctx.deinit();

    // Add a resolved package
    const bash_id = PackageId{
        .name = "bash",
        .version = Version{ .major = 5, .minor = 2, .patch = 0 },
        .revision = 1,
        .build_id = "abc123",
    };
    try ctx.resolved.put("bash", bash_id);
    try ctx.resolved_candidates.put("bash", Candidate{
        .id = bash_id,
        .dependencies = &[_]Dependency{},
        .conflicts = &[_]VirtualPackage{
            .{ .name = "csh", .constraint = null },
        },
    });

    // Try to add a package that conflicts with bash
    const csh_candidate = Candidate{
        .id = .{
            .name = "csh",
            .version = Version{ .major = 1, .minor = 0, .patch = 0 },
            .revision = 1,
            .build_id = "def456",
        },
        .dependencies = &[_]Dependency{},
    };

    // Check if csh conflicts with resolved packages
    const has_conflict = try ctx.checkConflicts(csh_candidate);
    try std.testing.expect(has_conflict);
    try std.testing.expectEqual(@as(usize, 1), ctx.conflicts.items.len);
}

test "ResolutionContext.replaces_detection" {
    const allocator = std.testing.allocator;

    var ctx = ResolutionContext.init(allocator, undefined);
    defer ctx.deinit();

    // Add an old package that will be replaced
    const sh_id = PackageId{
        .name = "sh",
        .version = Version{ .major = 1, .minor = 0, .patch = 0 },
        .revision = 1,
        .build_id = "old123",
    };
    try ctx.resolved.put("sh", sh_id);

    // Create a candidate that replaces sh
    const bash_candidate = Candidate{
        .id = .{
            .name = "bash",
            .version = Version{ .major = 5, .minor = 2, .patch = 0 },
            .revision = 1,
            .build_id = "new456",
        },
        .dependencies = &[_]Dependency{},
        .replaces = &[_]VirtualPackage{
            .{ .name = "sh", .constraint = null },
        },
    };

    // Check if bash replaces anything
    const replaced = ctx.checkReplaces(bash_candidate);
    try std.testing.expect(replaced != null);
    try std.testing.expectEqualStrings("sh", replaced.?);
}

test "kernelIsCompatible.basic_checks" {
    // Test userland package (kmod = false) is always compatible
    const userland_compat = KernelCompat{ .kmod = false };
    const kernel_ctx = KernelContext.initMock(1502000, "PGSD-GENERIC");

    const userland_result = kernelIsCompatible(&kernel_ctx, &userland_compat);
    try std.testing.expect(userland_result.compatible);

    // Test kmod within version range
    const kmod_compat_ok = KernelCompat{
        .kmod = true,
        .freebsd_version_min = 1500000,
        .freebsd_version_max = 1509999,
    };
    const kmod_result_ok = kernelIsCompatible(&kernel_ctx, &kmod_compat_ok);
    try std.testing.expect(kmod_result_ok.compatible);

    // Test kmod below version range (running 1502000 < min 1600000)
    const kmod_compat_new = KernelCompat{
        .kmod = true,
        .freebsd_version_min = 1600000,
        .freebsd_version_max = 1609999,
    };
    const kmod_result_new = kernelIsCompatible(&kernel_ctx, &kmod_compat_new);
    try std.testing.expect(!kmod_result_new.compatible);
    try std.testing.expectEqual(KernelIncompatReason.version_below_minimum, kmod_result_new.reason);
    try std.testing.expectEqual(@as(u32, 1502000), kmod_result_new.running_version);
    try std.testing.expectEqual(@as(?u32, 1600000), kmod_result_new.required_min);

    // Test kmod above version range (running 1502000 > max 1499999)
    const kmod_compat_old = KernelCompat{
        .kmod = true,
        .freebsd_version_min = 1400000,
        .freebsd_version_max = 1499999,
    };
    const kmod_result_old = kernelIsCompatible(&kernel_ctx, &kmod_compat_old);
    try std.testing.expect(!kmod_result_old.compatible);
    try std.testing.expectEqual(KernelIncompatReason.version_above_maximum, kmod_result_old.reason);
    try std.testing.expectEqual(@as(u32, 1502000), kmod_result_old.running_version);
    try std.testing.expectEqual(@as(?u32, 1499999), kmod_result_old.required_max);
}

test "kernelIsCompatible.ident_matching" {
    const kernel_ctx = KernelContext.initMock(1502000, "PGSD-GENERIC");

    // Test exact ident required and matching
    const compat_match = KernelCompat{
        .kmod = true,
        .freebsd_version_min = 1500000,
        .freebsd_version_max = 1509999,
        .kernel_idents = &[_][]const u8{ "PGSD-GENERIC", "PGSD-LAPTOP" },
        .require_exact_ident = true,
    };
    const result_match = kernelIsCompatible(&kernel_ctx, &compat_match);
    try std.testing.expect(result_match.compatible);

    // Test exact ident required but not matching
    const compat_nomatch = KernelCompat{
        .kmod = true,
        .freebsd_version_min = 1500000,
        .freebsd_version_max = 1509999,
        .kernel_idents = &[_][]const u8{ "CUSTOM-KERNEL", "OTHER-KERNEL" },
        .require_exact_ident = true,
    };
    const result_nomatch = kernelIsCompatible(&kernel_ctx, &compat_nomatch);
    try std.testing.expect(!result_nomatch.compatible);
    try std.testing.expectEqual(KernelIncompatReason.ident_mismatch, result_nomatch.reason);
    try std.testing.expectEqualStrings("PGSD-GENERIC", result_nomatch.running_ident);
}
