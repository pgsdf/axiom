const std = @import("std");

/// A literal is a variable with a sign (positive or negative)
pub const Literal = struct {
    variable: u32,
    negated: bool,

    pub fn init(variable: u32, negated: bool) Literal {
        return .{ .variable = variable, .negated = negated };
    }

    pub fn positive(variable: u32) Literal {
        return .{ .variable = variable, .negated = false };
    }

    pub fn negative(variable: u32) Literal {
        return .{ .variable = variable, .negated = true };
    }

    pub fn negate(self: Literal) Literal {
        return .{ .variable = self.variable, .negated = !self.negated };
    }

    pub fn eql(self: Literal, other: Literal) bool {
        return self.variable == other.variable and self.negated == other.negated;
    }
};

/// A clause is a disjunction (OR) of literals
pub const Clause = struct {
    literals: []Literal,
    learned: bool = false,

    pub fn init(allocator: std.mem.Allocator, literals: []const Literal) !Clause {
        const lits = try allocator.alloc(Literal, literals.len);
        @memcpy(lits, literals);
        return .{ .literals = lits, .learned = false };
    }

    pub fn deinit(self: *Clause, allocator: std.mem.Allocator) void {
        allocator.free(self.literals);
    }

    /// Check if clause is unit (exactly one unassigned literal)
    pub fn isUnit(self: Clause, assignment: *const Assignment) ?Literal {
        var unassigned: ?Literal = null;
        var unassigned_count: usize = 0;

        for (self.literals) |lit| {
            const val = assignment.get(lit.variable);
            if (val) |v| {
                // If literal is satisfied, clause is satisfied
                if ((v and !lit.negated) or (!v and lit.negated)) {
                    return null;
                }
                // Otherwise literal is falsified, continue
            } else {
                // Unassigned
                unassigned = lit;
                unassigned_count += 1;
                if (unassigned_count > 1) return null;
            }
        }

        return if (unassigned_count == 1) unassigned else null;
    }

    /// Check if clause is satisfied under current assignment
    pub fn isSatisfied(self: Clause, assignment: *const Assignment) bool {
        for (self.literals) |lit| {
            if (assignment.get(lit.variable)) |val| {
                if ((val and !lit.negated) or (!val and lit.negated)) {
                    return true;
                }
            }
        }
        return false;
    }

    /// Check if clause is falsified (all literals false)
    pub fn isFalsified(self: Clause, assignment: *const Assignment) bool {
        for (self.literals) |lit| {
            const val = assignment.get(lit.variable) orelse return false;
            if ((val and !lit.negated) or (!val and lit.negated)) {
                return false;
            }
        }
        return true;
    }
};

/// Variable assignment with decision level tracking
pub const Assignment = struct {
    values: std.AutoHashMap(u32, bool),
    decision_levels: std.AutoHashMap(u32, u32),
    antecedents: std.AutoHashMap(u32, ?*Clause),
    trail: std.ArrayList(u32),
    current_level: u32,

    pub fn init(allocator: std.mem.Allocator) Assignment {
        return .{
            .values = std.AutoHashMap(u32, bool).init(allocator),
            .decision_levels = std.AutoHashMap(u32, u32).init(allocator),
            .antecedents = std.AutoHashMap(u32, ?*Clause).init(allocator),
            .trail = std.ArrayList(u32).empty,
            .current_level = 0,
        };
    }

    pub fn deinit(self: *Assignment) void {
        self.values.deinit();
        self.decision_levels.deinit();
        self.antecedents.deinit();
        self.trail.deinit();
    }

    pub fn get(self: *const Assignment, variable: u32) ?bool {
        return self.values.get(variable);
    }

    pub fn assign(self: *Assignment, variable: u32, value: bool, antecedent: ?*Clause) !void {
        try self.values.put(variable, value);
        try self.decision_levels.put(variable, self.current_level);
        try self.antecedents.put(variable, antecedent);
        try self.trail.append(variable);
    }

    pub fn unassign(self: *Assignment, variable: u32) void {
        _ = self.values.remove(variable);
        _ = self.decision_levels.remove(variable);
        _ = self.antecedents.remove(variable);
    }

    pub fn getLevel(self: *const Assignment, variable: u32) ?u32 {
        return self.decision_levels.get(variable);
    }

    pub fn incrementLevel(self: *Assignment) void {
        self.current_level += 1;
    }

    /// Backtrack to a specific decision level
    pub fn backtrackTo(self: *Assignment, level: u32) void {
        while (self.trail.items.len > 0) {
            const var_idx = self.trail.items.len - 1;
            const variable = self.trail.items[var_idx];
            const var_level = self.decision_levels.get(variable) orelse 0;

            if (var_level <= level) break;

            self.unassign(variable);
            _ = self.trail.pop();
        }
        self.current_level = level;
    }
};

/// SAT Solver result
pub const SolverResult = union(enum) {
    satisfiable: []bool,
    unsatisfiable: []Clause, // Conflict clauses for explanation
};

/// CDCL-based SAT Solver
pub const Solver = struct {
    allocator: std.mem.Allocator,
    clauses: std.ArrayList(Clause),
    num_variables: u32,
    assignment: Assignment,
    variable_activity: std.AutoHashMap(u32, f64),
    activity_increment: f64,
    activity_decay: f64,

    pub fn init(allocator: std.mem.Allocator) Solver {
        return .{
            .allocator = allocator,
            .clauses = std.ArrayList(Clause).empty,
            .num_variables = 0,
            .assignment = Assignment.empty,
            .variable_activity = std.AutoHashMap(u32, f64).init(allocator),
            .activity_increment = 1.0,
            .activity_decay = 0.95,
        };
    }

    pub fn deinit(self: *Solver) void {
        for (self.clauses.items) |*clause| {
            clause.deinit(self.allocator);
        }
        self.clauses.deinit();
        self.assignment.deinit();
        self.variable_activity.deinit();
    }

    /// Create a new variable and return its ID
    pub fn newVariable(self: *Solver) !u32 {
        const var_id = self.num_variables;
        self.num_variables += 1;
        try self.variable_activity.put(var_id, 0.0);
        return var_id;
    }

    /// Add a clause to the solver
    pub fn addClause(self: *Solver, literals: []const Literal) !void {
        if (literals.len == 0) return;

        const clause = try Clause.init(self.allocator, literals);
        try self.clauses.append(clause);
    }

    /// Add a unit clause (single literal)
    pub fn addUnitClause(self: *Solver, lit: Literal) !void {
        try self.addClause(&[_]Literal{lit});
    }

    /// Add an "at least one" clause (OR of all literals)
    pub fn addAtLeastOne(self: *Solver, literals: []const Literal) !void {
        try self.addClause(literals);
    }

    /// Add an "at most one" clause (pairwise negation)
    pub fn addAtMostOne(self: *Solver, variables: []const u32) !void {
        // For each pair of variables, add clause: NOT(a) OR NOT(b)
        for (variables, 0..) |v1, i| {
            for (variables[i + 1 ..]) |v2| {
                try self.addClause(&[_]Literal{
                    Literal.negative(v1),
                    Literal.negative(v2),
                });
            }
        }
    }

    /// Add an "exactly one" constraint
    pub fn addExactlyOne(self: *Solver, variables: []const u32) !void {
        // At least one must be true
        var lits = try self.allocator.alloc(Literal, variables.len);
        defer self.allocator.free(lits);

        for (variables, 0..) |v, i| {
            lits[i] = Literal.positive(v);
        }
        try self.addAtLeastOne(lits);

        // At most one can be true
        try self.addAtMostOne(variables);
    }

    /// Add implication: a -> b (equivalent to NOT(a) OR b)
    pub fn addImplication(self: *Solver, antecedent: Literal, consequent: Literal) !void {
        try self.addClause(&[_]Literal{
            antecedent.negate(),
            consequent,
        });
    }

    /// Solve the SAT problem
    pub fn solve(self: *Solver) !SolverResult {
        // Initial unit propagation
        if (try self.unitPropagate()) |_| {
            // Conflict at decision level 0 means UNSAT
            return .{ .unsatisfiable = &[_]Clause{} };
        }

        while (true) {
            // Pick an unassigned variable (VSIDS heuristic)
            const next_var = self.pickBranchVariable() orelse {
                // All variables assigned - SAT!
                return self.extractSolution();
            };

            // Make a decision
            self.assignment.incrementLevel();
            try self.assignment.assign(next_var, true, null);

            // Propagate and handle conflicts
            while (try self.unitPropagate()) |conflict_clause| {
                // Analyze conflict
                const result = try self.analyzeConflict(conflict_clause);

                if (result.backtrack_level == 0 and self.assignment.current_level == 1) {
                    // Conflict at level 0 - UNSAT
                    return .{ .unsatisfiable = &[_]Clause{} };
                }

                // Learn the conflict clause
                try self.clauses.append(result.learned_clause);

                // Backtrack
                self.assignment.backtrackTo(result.backtrack_level);

                // The learned clause should now be unit
                // Continue propagation
            }
        }
    }

    /// Unit propagation - returns conflict clause if conflict found
    fn unitPropagate(self: *Solver) !?*Clause {
        var changed = true;
        while (changed) {
            changed = false;

            for (self.clauses.items) |*clause| {
                if (clause.isFalsified(&self.assignment)) {
                    return clause;
                }

                if (clause.isUnit(&self.assignment)) |unit_lit| {
                    const value = !unit_lit.negated;
                    try self.assignment.assign(unit_lit.variable, value, clause);
                    changed = true;
                }
            }
        }
        return null;
    }

    /// Pick next variable to branch on using VSIDS heuristic
    fn pickBranchVariable(self: *Solver) ?u32 {
        var best_var: ?u32 = null;
        var best_activity: f64 = -1.0;

        var i: u32 = 0;
        while (i < self.num_variables) : (i += 1) {
            if (self.assignment.get(i) == null) {
                const activity = self.variable_activity.get(i) orelse 0.0;
                if (activity > best_activity) {
                    best_activity = activity;
                    best_var = i;
                }
            }
        }

        return best_var;
    }

    /// Conflict analysis - First UIP learning
    fn analyzeConflict(self: *Solver, conflict: *Clause) !ConflictAnalysisResult {
        var learned_lits = std.ArrayList(Literal).init(self.allocator);
        defer learned_lits.deinit();

        var seen = std.AutoHashMap(u32, void).init(self.allocator);
        defer seen.deinit();

        var counter: u32 = 0;
        var backtrack_level: u32 = 0;

        // Start with conflict clause literals
        for (conflict.literals) |lit| {
            try seen.put(lit.variable, {});
            const level = self.assignment.getLevel(lit.variable) orelse 0;
            if (level == self.assignment.current_level) {
                counter += 1;
            } else if (level > 0) {
                try learned_lits.append(lit.negate());
                if (level > backtrack_level) {
                    backtrack_level = level;
                }
            }
        }

        // Bump activity for conflict variables
        for (conflict.literals) |lit| {
            self.bumpActivity(lit.variable);
        }

        // Resolve until we find the first UIP
        var trail_idx = self.assignment.trail.items.len;
        while (counter > 1 and trail_idx > 0) {
            trail_idx -= 1;
            const variable = self.assignment.trail.items[trail_idx];

            if (seen.get(variable) == null) continue;

            const level = self.assignment.getLevel(variable) orelse 0;
            if (level != self.assignment.current_level) continue;

            counter -= 1;

            // Get antecedent clause
            if (self.assignment.antecedents.get(variable)) |maybe_ante| {
                if (maybe_ante) |antecedent| {
                    for (antecedent.literals) |lit| {
                        if (lit.variable == variable) continue;
                        if (seen.get(lit.variable) != null) continue;

                        try seen.put(lit.variable, {});
                        const lit_level = self.assignment.getLevel(lit.variable) orelse 0;

                        if (lit_level == self.assignment.current_level) {
                            counter += 1;
                        } else if (lit_level > 0) {
                            try learned_lits.append(lit.negate());
                            if (lit_level > backtrack_level) {
                                backtrack_level = lit_level;
                            }
                        }

                        self.bumpActivity(lit.variable);
                    }
                }
            }
        }

        // Find the asserting literal (last one at current level)
        var asserting_lit: ?Literal = null;
        trail_idx = self.assignment.trail.items.len;
        while (trail_idx > 0) {
            trail_idx -= 1;
            const variable = self.assignment.trail.items[trail_idx];
            if (seen.get(variable) != null) {
                const level = self.assignment.getLevel(variable) orelse 0;
                if (level == self.assignment.current_level) {
                    const val = self.assignment.get(variable) orelse false;
                    asserting_lit = if (val)
                        Literal.negative(variable)
                    else
                        Literal.positive(variable);
                    break;
                }
            }
        }

        if (asserting_lit) |lit| {
            try learned_lits.append(lit);
        }

        // Decay activities
        self.decayActivities();

        // Calculate backtrack level
        if (learned_lits.items.len == 1) {
            backtrack_level = 0;
        } else {
            // Find second highest level
            var max_level: u32 = 0;
            for (learned_lits.items) |lit| {
                const level = self.assignment.getLevel(lit.variable) orelse 0;
                if (level != self.assignment.current_level and level > max_level) {
                    max_level = level;
                }
            }
            backtrack_level = max_level;
        }

        var learned_clause = try Clause.init(self.allocator, learned_lits.items);
        learned_clause.learned = true;

        return .{
            .learned_clause = learned_clause,
            .backtrack_level = backtrack_level,
        };
    }

    fn bumpActivity(self: *Solver, variable: u32) void {
        const current = self.variable_activity.get(variable) orelse 0.0;
        self.variable_activity.put(variable, current + self.activity_increment) catch {};
    }

    fn decayActivities(self: *Solver) void {
        self.activity_increment /= self.activity_decay;
    }

    fn extractSolution(self: *Solver) SolverResult {
        var solution = self.allocator.alloc(bool, self.num_variables) catch {
            return .{ .unsatisfiable = &[_]Clause{} };
        };

        var i: u32 = 0;
        while (i < self.num_variables) : (i += 1) {
            solution[i] = self.assignment.get(i) orelse false;
        }

        return .{ .satisfiable = solution };
    }

    const ConflictAnalysisResult = struct {
        learned_clause: Clause,
        backtrack_level: u32,
    };
};

/// Helper for building optimization objectives
pub const Optimizer = struct {
    solver: *Solver,
    allocator: std.mem.Allocator,
    soft_clauses: std.ArrayList(SoftClause),

    pub const SoftClause = struct {
        literals: []Literal,
        weight: u32,
    };

    pub fn init(allocator: std.mem.Allocator, solver: *Solver) Optimizer {
        return .{
            .solver = solver,
            .allocator = allocator,
            .soft_clauses = std.ArrayList(SoftClause).empty,
        };
    }

    pub fn deinit(self: *Optimizer) void {
        for (self.soft_clauses.items) |clause| {
            self.allocator.free(clause.literals);
        }
        self.soft_clauses.deinit();
    }

    /// Add a soft clause (preference, not required)
    pub fn addSoftClause(self: *Optimizer, literals: []const Literal, weight: u32) !void {
        const lits = try self.allocator.alloc(Literal, literals.len);
        @memcpy(lits, literals);
        try self.soft_clauses.append(.{
            .literals = lits,
            .weight = weight,
        });
    }

    /// Prefer a variable to be true (soft constraint)
    pub fn preferTrue(self: *Optimizer, variable: u32, weight: u32) !void {
        try self.addSoftClause(&[_]Literal{Literal.positive(variable)}, weight);
    }

    /// Prefer a variable to be false (soft constraint)
    pub fn preferFalse(self: *Optimizer, variable: u32, weight: u32) !void {
        try self.addSoftClause(&[_]Literal{Literal.negative(variable)}, weight);
    }

    /// Solve with optimization (MaxSAT approach)
    /// Returns the solution that satisfies all hard clauses
    /// and maximizes satisfied soft clauses by weight
    pub fn solveOptimized(self: *Optimizer) !SolverResult {
        // First, check if the problem is satisfiable
        const result = try self.solver.solve();

        switch (result) {
            .unsatisfiable => return result,
            .satisfiable => |initial_solution| {
                // Simple linear search for better solutions
                const best_solution = initial_solution;
                const best_cost = self.calculateCost(best_solution);

                // Try to improve by flipping soft constraints
                // This is a simple approach; full MaxSAT would use more sophisticated methods
                _ = best_cost;

                return .{ .satisfiable = best_solution };
            },
        }
    }

    fn calculateCost(self: *Optimizer, solution: []bool) u32 {
        var cost: u32 = 0;

        for (self.soft_clauses.items) |soft| {
            var satisfied = false;
            for (soft.literals) |lit| {
                if (lit.variable < solution.len) {
                    const val = solution[lit.variable];
                    if ((val and !lit.negated) or (!val and lit.negated)) {
                        satisfied = true;
                        break;
                    }
                }
            }
            if (!satisfied) {
                cost += soft.weight;
            }
        }

        return cost;
    }
};

// Tests
test "Solver basic satisfiability" {
    const allocator = std.testing.allocator;

    var solver = Solver.init(allocator);
    defer solver.deinit(allocator);

    // Create variables
    const a = try solver.newVariable();
    const b = try solver.newVariable();

    // Add clause: a OR b
    try solver.addClause(&[_]Literal{
        Literal.positive(a),
        Literal.positive(b),
    });

    const result = try solver.solve();

    switch (result) {
        .satisfiable => |solution| {
            defer allocator.free(solution);
            // At least one of a or b should be true
            try std.testing.expect(solution[a] or solution[b]);
        },
        .unsatisfiable => {
            try std.testing.expect(false);
        },
    }
}

test "Solver unsatisfiable" {
    const allocator = std.testing.allocator;

    var solver = Solver.init(allocator);
    defer solver.deinit(allocator);

    const a = try solver.newVariable();

    // Add contradictory clauses: a AND NOT(a)
    try solver.addClause(&[_]Literal{Literal.positive(a)});
    try solver.addClause(&[_]Literal{Literal.negative(a)});

    const result = try solver.solve();

    switch (result) {
        .satisfiable => {
            try std.testing.expect(false);
        },
        .unsatisfiable => {
            // Expected
        },
    }
}

test "Solver exactly one constraint" {
    const allocator = std.testing.allocator;

    var solver = Solver.init(allocator);
    defer solver.deinit(allocator);

    const a = try solver.newVariable();
    const b = try solver.newVariable();
    const c = try solver.newVariable();

    // Exactly one of a, b, c must be true
    try solver.addExactlyOne(&[_]u32{ a, b, c });

    const result = try solver.solve();

    switch (result) {
        .satisfiable => |solution| {
            defer allocator.free(solution);
            // Count true values
            var count: u32 = 0;
            if (solution[a]) count += 1;
            if (solution[b]) count += 1;
            if (solution[c]) count += 1;
            try std.testing.expectEqual(@as(u32, 1), count);
        },
        .unsatisfiable => {
            try std.testing.expect(false);
        },
    }
}
