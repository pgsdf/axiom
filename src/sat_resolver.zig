const std = @import("std");
const sat = @import("sat.zig");
const types = @import("types.zig");
const store = @import("store.zig");
const manifest = @import("manifest.zig");

const Solver = sat.Solver;
const Literal = sat.Literal;
const Optimizer = sat.Optimizer;
const PackageId = types.PackageId;
const Version = types.Version;
const VersionConstraint = types.VersionConstraint;
const PackageStore = store.PackageStore;

/// Package version candidate for SAT encoding
pub const PackageCandidate = struct {
    id: PackageId,
    variable: u32,
    dependencies: []Dependency,
    conflicts: [][]const u8,

    pub const Dependency = struct {
        name: []const u8,
        constraint: VersionConstraint,
    };
};

/// Conflict explanation for user feedback
pub const ConflictExplanation = struct {
    allocator: std.mem.Allocator,
    package_a: []const u8,
    version_a: Version,
    package_b: []const u8,
    version_b: Version,
    reason: Reason,

    pub const Reason = enum {
        version_conflict,
        dependency_conflict,
        mutual_exclusion,
        unsatisfiable_dependency,
    };

    pub fn format(self: ConflictExplanation, writer: anytype) !void {
        switch (self.reason) {
            .version_conflict => {
                try writer.print("Version conflict: {s} {} conflicts with {s} {}", .{
                    self.package_a,
                    self.version_a,
                    self.package_b,
                    self.version_b,
                });
            },
            .dependency_conflict => {
                try writer.print("Dependency conflict: {s} requires incompatible version of {s}", .{
                    self.package_a,
                    self.package_b,
                });
            },
            .mutual_exclusion => {
                try writer.print("Mutual exclusion: {s} and {s} cannot be installed together", .{
                    self.package_a,
                    self.package_b,
                });
            },
            .unsatisfiable_dependency => {
                try writer.print("Unsatisfiable: {s} requires {s} which has no valid version", .{
                    self.package_a,
                    self.package_b,
                });
            },
        }
    }

    pub fn deinit(self: *ConflictExplanation) void {
        self.allocator.free(self.package_a);
        self.allocator.free(self.package_b);
    }
};

/// Resolution result from SAT solver
pub const SATResolutionResult = union(enum) {
    success: []PackageId,
    failure: ResolutionFailure,
};

pub const ResolutionFailure = struct {
    allocator: std.mem.Allocator,
    explanations: []ConflictExplanation,
    suggestions: [][]const u8,

    pub fn deinit(self: *ResolutionFailure) void {
        for (self.explanations) |*exp| {
            exp.deinit();
        }
        self.allocator.free(self.explanations);

        for (self.suggestions) |sug| {
            self.allocator.free(sug);
        }
        self.allocator.free(self.suggestions);
    }
};

/// SAT-based dependency resolver
pub const SATResolver = struct {
    allocator: std.mem.Allocator,
    solver: Solver,
    optimizer: Optimizer,

    // Mappings between packages and SAT variables
    pkg_to_var: std.StringHashMap(std.ArrayList(PackageCandidate)),
    var_to_pkg: std.AutoHashMap(u32, PackageCandidate),

    // All available package versions
    available_packages: std.StringHashMap(std.ArrayList(PackageId)),

    // Preference weights for optimization
    const VERSION_WEIGHT_MAJOR: u32 = 1000;
    const VERSION_WEIGHT_MINOR: u32 = 100;
    const VERSION_WEIGHT_PATCH: u32 = 10;
    const DIRECT_DEPENDENCY_WEIGHT: u32 = 50;

    pub fn init(allocator: std.mem.Allocator) SATResolver {
        var solver = Solver.empty;
        return .{
            .allocator = allocator,
            .solver = solver,
            .optimizer = Optimizer.init(allocator, &solver),
            .pkg_to_var = std.StringHashMap(std.ArrayList(PackageCandidate)).empty,
            .var_to_pkg = std.AutoHashMap(u32, PackageCandidate).empty,
            .available_packages = std.StringHashMap(std.ArrayList(PackageId)).empty,
        };
    }

    pub fn deinit(self: *SATResolver) void {
        var pkg_iter = self.pkg_to_var.valueIterator();
        while (pkg_iter.next()) |list| {
            list.deinit();
        }
        self.pkg_to_var.deinit();
        self.var_to_pkg.deinit();

        var avail_iter = self.available_packages.valueIterator();
        while (avail_iter.next()) |list| {
            list.deinit();
        }
        self.available_packages.deinit();

        self.optimizer.deinit();
        self.solver.deinit();
    }

    /// Register an available package version
    pub fn registerPackage(
        self: *SATResolver,
        id: PackageId,
        dependencies: []const PackageCandidate.Dependency,
        conflicts: []const []const u8,
    ) !void {
        // Create SAT variable for this package version
        const variable = try self.solver.newVariable();

        // Store the candidate
        const candidate = PackageCandidate{
            .id = id,
            .variable = variable,
            .dependencies = try self.allocator.dupe(PackageCandidate.Dependency, dependencies),
            .conflicts = try self.allocator.dupe([]const u8, conflicts),
        };

        // Add to package -> candidates mapping
        const result = try self.pkg_to_var.getOrPut(id.name);
        if (!result.found_existing) {
            result.value_ptr.* = std.ArrayList(PackageCandidate).init(self.allocator);
        }
        try result.value_ptr.append(candidate);

        // Add to variable -> package mapping
        try self.var_to_pkg.put(variable, candidate);

        // Track available packages
        const avail_result = try self.available_packages.getOrPut(id.name);
        if (!avail_result.found_existing) {
            avail_result.value_ptr.* = std.ArrayList(PackageId).init(self.allocator);
        }
        try avail_result.value_ptr.append(id);

        // Add preference for newer versions (higher weight for newer)
        const version_weight = self.calculateVersionWeight(id.version);
        try self.optimizer.preferTrue(variable, version_weight);
    }

    /// Calculate weight for version preference (prefer newer versions)
    fn calculateVersionWeight(self: *SATResolver, version: Version) u32 {
        _ = self;
        return version.major * VERSION_WEIGHT_MAJOR +
            version.minor * VERSION_WEIGHT_MINOR +
            version.patch * VERSION_WEIGHT_PATCH;
    }

    /// Resolve dependencies for requested packages
    pub fn resolve(self: *SATResolver, requests: []const PackageRequest) !SATResolutionResult {
        // Add constraints for each request
        for (requests) |request| {
            try self.addRequestConstraints(request);
        }

        // Add version exclusivity constraints (at most one version per package)
        try self.addExclusivityConstraints();

        // Add dependency constraints
        try self.addDependencyConstraints();

        // Add conflict constraints
        try self.addConflictConstraints();

        // Solve
        const result = try self.solver.solve();

        switch (result) {
            .satisfiable => |solution| {
                defer self.allocator.free(solution);
                return .{ .success = try self.extractPackages(solution) };
            },
            .unsatisfiable => {
                return .{ .failure = try self.generateExplanation() };
            },
        }
    }

    /// Add constraints for a package request
    fn addRequestConstraints(self: *SATResolver, request: PackageRequest) !void {
        const candidates = self.pkg_to_var.get(request.name) orelse {
            // Package not found - will result in UNSAT
            return;
        };

        // Collect satisfying versions
        var satisfying = std.ArrayList(Literal).init(self.allocator);
        defer satisfying.deinit();

        for (candidates.items) |candidate| {
            if (request.constraint.satisfies(candidate.id.version)) {
                try satisfying.append(Literal.positive(candidate.variable));

                // Boost preference for directly requested packages
                try self.optimizer.preferTrue(candidate.variable, DIRECT_DEPENDENCY_WEIGHT);
            }
        }

        // At least one satisfying version must be selected
        if (satisfying.items.len > 0) {
            try self.solver.addAtLeastOne(satisfying.items);
        } else {
            // Add unsatisfiable clause
            try self.solver.addClause(&[_]Literal{});
        }
    }

    /// Add "at most one version per package" constraints
    fn addExclusivityConstraints(self: *SATResolver) !void {
        var iter = self.pkg_to_var.valueIterator();
        while (iter.next()) |candidates| {
            if (candidates.items.len > 1) {
                var variables = try self.allocator.alloc(u32, candidates.items.len);
                defer self.allocator.free(variables);

                for (candidates.items, 0..) |cand, i| {
                    variables[i] = cand.variable;
                }

                try self.solver.addAtMostOne(variables);
            }
        }
    }

    /// Add dependency implication constraints
    fn addDependencyConstraints(self: *SATResolver) !void {
        var iter = self.var_to_pkg.iterator();
        while (iter.next()) |entry| {
            const candidate = entry.value_ptr.*;

            for (candidate.dependencies) |dep| {
                // If this package is selected, at least one satisfying dep must be selected
                const dep_candidates = self.pkg_to_var.get(dep.name) orelse continue;

                var satisfying = std.ArrayList(Literal).init(self.allocator);
                defer satisfying.deinit();

                // NOT(this) is always an option (if we don't select this, constraint is satisfied)
                try satisfying.append(Literal.negative(candidate.variable));

                for (dep_candidates.items) |dep_cand| {
                    if (dep.constraint.satisfies(dep_cand.id.version)) {
                        try satisfying.append(Literal.positive(dep_cand.variable));
                    }
                }

                // Add clause: NOT(pkg) OR dep1 OR dep2 OR ...
                try self.solver.addClause(satisfying.items);
            }
        }
    }

    /// Add conflict constraints
    fn addConflictConstraints(self: *SATResolver) !void {
        var iter = self.var_to_pkg.iterator();
        while (iter.next()) |entry| {
            const candidate = entry.value_ptr.*;

            for (candidate.conflicts) |conflict_name| {
                const conflict_candidates = self.pkg_to_var.get(conflict_name) orelse continue;

                // Cannot select both this package and any version of the conflicting package
                for (conflict_candidates.items) |conflict_cand| {
                    try self.solver.addClause(&[_]Literal{
                        Literal.negative(candidate.variable),
                        Literal.negative(conflict_cand.variable),
                    });
                }
            }
        }
    }

    /// Extract selected packages from SAT solution
    fn extractPackages(self: *SATResolver, solution: []bool) ![]PackageId {
        var selected = std.ArrayList(PackageId).init(self.allocator);
        errdefer selected.deinit();

        var iter = self.var_to_pkg.iterator();
        while (iter.next()) |entry| {
            const variable = entry.key_ptr.*;
            if (variable < solution.len and solution[variable]) {
                const candidate = entry.value_ptr.*;
                try selected.append(candidate.id);
            }
        }

        return try selected.toOwnedSlice();
    }

    /// Generate human-readable explanation for UNSAT result
    fn generateExplanation(self: *SATResolver) !ResolutionFailure {
        var explanations = std.ArrayList(ConflictExplanation).init(self.allocator);
        var suggestions = std.ArrayList([]const u8).init(self.allocator);

        // Analyze the conflict (simplified - full UNSAT core would be more detailed)
        // For now, we provide general suggestions

        try suggestions.append(try self.allocator.dupe(u8, "Try relaxing version constraints"));
        try suggestions.append(try self.allocator.dupe(u8, "Check for conflicting packages in your profile"));
        try suggestions.append(try self.allocator.dupe(u8, "Ensure all required packages are available in the store"));

        return .{
            .allocator = self.allocator,
            .explanations = try explanations.toOwnedSlice(),
            .suggestions = try suggestions.toOwnedSlice(),
        };
    }
};

/// Package request from user
pub const PackageRequest = struct {
    name: []const u8,
    constraint: VersionConstraint,
    requested: bool = true,
};

/// Helper to build SAT resolver from package store
pub fn buildResolverFromStore(
    allocator: std.mem.Allocator,
    pkg_store: *PackageStore,
) !SATResolver {
    var resolver = SATResolver.empty;
    errdefer resolver.deinit();

    // Get all packages from store
    const packages = try pkg_store.listPackages(allocator);
    defer {
        for (packages) |pkg| {
            allocator.free(pkg.name);
            allocator.free(pkg.build_id);
        }
        allocator.free(packages);
    }

    // Register each package
    for (packages) |pkg_id| {
        // Load manifest to get dependencies and conflicts
        const pkg_manifest = pkg_store.loadManifest(allocator, pkg_id) catch continue;
        defer manifest.freeManifest(pkg_manifest, allocator);

        // Convert dependencies
        var deps = std.ArrayList(PackageCandidate.Dependency).empty;
        defer deps.deinit();

        for (pkg_manifest.dependencies) |dep| {
            try deps.append(.{
                .name = try allocator.dupe(u8, dep.name),
                .constraint = dep.version,
            });
        }

        // Convert conflicts
        var conflicts = std.ArrayList([]const u8).empty;
        defer conflicts.deinit();

        for (pkg_manifest.conflicts) |conflict| {
            try conflicts.append(try allocator.dupe(u8, conflict.name));
        }

        try resolver.registerPackage(
            pkg_id,
            deps.items,
            conflicts.items,
        );
    }

    return resolver;
}

// Tests
test "SATResolver basic resolution" {
    const allocator = std.testing.allocator;

    var resolver = SATResolver.empty;
    defer resolver.deinit();

    // Register package A version 1.0.0
    try resolver.registerPackage(
        .{
            .name = "pkg-a",
            .version = .{ .major = 1, .minor = 0, .patch = 0 },
            .revision = 1,
            .build_id = "abc",
        },
        &[_]PackageCandidate.Dependency{},
        &[_][]const u8{},
    );

    // Register package B version 2.0.0 that depends on A
    try resolver.registerPackage(
        .{
            .name = "pkg-b",
            .version = .{ .major = 2, .minor = 0, .patch = 0 },
            .revision = 1,
            .build_id = "def",
        },
        &[_]PackageCandidate.Dependency{
            .{ .name = "pkg-a", .constraint = .{ .kind = .any } },
        },
        &[_][]const u8{},
    );

    // Request package B
    const result = try resolver.resolve(&[_]PackageRequest{
        .{ .name = "pkg-b", .constraint = .{ .kind = .any } },
    });

    switch (result) {
        .success => |packages| {
            defer allocator.free(packages);
            // Should have both A and B
            try std.testing.expectEqual(@as(usize, 2), packages.len);
        },
        .failure => {
            try std.testing.expect(false);
        },
    }
}

test "SATResolver conflict detection" {
    const allocator = std.testing.allocator;

    var resolver = SATResolver.empty;
    defer resolver.deinit();

    // Register package A that conflicts with B
    try resolver.registerPackage(
        .{
            .name = "pkg-a",
            .version = .{ .major = 1, .minor = 0, .patch = 0 },
            .revision = 1,
            .build_id = "abc",
        },
        &[_]PackageCandidate.Dependency{},
        &[_][]const u8{"pkg-b"},
    );

    // Register package B
    try resolver.registerPackage(
        .{
            .name = "pkg-b",
            .version = .{ .major = 1, .minor = 0, .patch = 0 },
            .revision = 1,
            .build_id = "def",
        },
        &[_]PackageCandidate.Dependency{},
        &[_][]const u8{},
    );

    // Request both A and B - should fail
    const result = try resolver.resolve(&[_]PackageRequest{
        .{ .name = "pkg-a", .constraint = .{ .kind = .any } },
        .{ .name = "pkg-b", .constraint = .{ .kind = .any } },
    });

    switch (result) {
        .success => {
            try std.testing.expect(false);
        },
        .failure => |*failure| {
            defer failure.deinit();
            // Expected - conflict detected
        },
    }
}
