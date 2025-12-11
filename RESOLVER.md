# Axiom Dependency Resolver

## Overview

The dependency resolver is the algorithmic core of Axiom. It takes a profile (list of package requests with version constraints) and produces a lock file (specific package versions that satisfy all constraints).

## Problem Statement

Given:
- A set of package requests with version constraints
- A package store with available versions
- Dependency information for each package

Find:
- A specific version for each package that satisfies all constraints
- Include all transitive dependencies
- Detect conflicts and circular dependencies

## Algorithm

### Current Implementation: Greedy Resolution

The current resolver uses a simple greedy algorithm:

1. **Constraint Collection**: Gather all version constraints for each package
2. **Candidate Selection**: Find all versions that satisfy constraints
3. **Version Selection**: Pick the newest version (greedy choice)
4. **Recursive Resolution**: Resolve dependencies of chosen packages
5. **Conflict Detection**: Detect circular dependencies

### Algorithm Steps

```
function resolve(profile):
    context = new ResolutionContext()
    
    # Add all requested packages
    for request in profile.packages:
        add_constraint(context, request.name, request.constraint)
        mark_requested(context, request.name)
    
    # Resolve all packages
    for package in context.constraints:
        if not resolved(package):
            resolve_package(context, package)
    
    return build_lock_file(context)

function resolve_package(context, package_name):
    # Detect circular dependencies
    if is_resolving(package_name):
        error("Circular dependency")
    
    mark_resolving(package_name)
    
    # Get all constraints for this package
    constraints = get_constraints(context, package_name)
    
    # Find candidates
    candidates = find_versions_satisfying(constraints)
    
    if candidates.empty():
        error("No solution")
    
    # Pick best (newest version)
    chosen = pick_newest(candidates)
    mark_resolved(context, package_name, chosen)
    
    # Resolve dependencies
    for dependency in chosen.dependencies:
        add_constraint(context, dependency.name, dependency.constraint)
        resolve_package(context, dependency.name)
    
    unmark_resolving(package_name)
```

## Version Constraint Satisfaction

### Exact Version

```
constraint: = 1.2.3
satisfies: 1.2.3
rejects:   1.2.4, 1.3.0, 2.0.0
```

### Tilde Constraint (~)

Allows patch-level changes:

```
constraint: ~1.2.3
equivalent: >=1.2.3 AND <1.3.0
satisfies: 1.2.3, 1.2.4, 1.2.999
rejects:   1.3.0, 1.1.9, 2.0.0
```

### Caret Constraint (^)

Allows minor-level changes (SemVer compatible):

```
constraint: ^1.2.3
equivalent: >=1.2.3 AND <2.0.0
satisfies: 1.2.3, 1.3.0, 1.999.999
rejects:   2.0.0, 1.2.2, 0.9.0
```

### Range Constraint

Explicit bounds:

```
constraint: >=1.0.0,<2.0.0
satisfies: 1.0.0, 1.5.2, 1.999.999
rejects:   0.9.9, 2.0.0, 2.1.0
```

### Wildcard (*)

Accepts any version:

```
constraint: *
satisfies: any version
```

## Conflict Detection

### Conflicting Version Constraints

```
Package A requires: foo ^1.0.0
Package B requires: foo ~2.1.0

Result: No version of foo satisfies both constraints
Error: ConflictingConstraints
```

### Circular Dependencies

```
Package A depends on: B
Package B depends on: C
Package C depends on: A

Result: Cycle detected
Error: CircularDependency
```

## Resolution Context

The resolver maintains state during resolution:

```zig
ResolutionContext {
    // Package name -> list of constraints
    constraints: HashMap<String, List<VersionConstraint>>
    
    // Package name -> chosen version
    resolved: HashMap<String, PackageId>
    
    // Packages directly requested (not dependencies)
    requested: HashMap<String, bool>
    
    // Packages currently being resolved (cycle detection)
    resolving: HashMap<String, bool>
}
```

## Example Resolution

### Input Profile

```yaml
name: development
packages:
  - name: bash
    version: "^5.0.0"
    constraint: caret
  - name: git
    version: ">=2.40.0"
    constraint: range
```

### Resolution Process

```
1. Add constraints:
   bash: ^5.0.0
   git: >=2.40.0

2. Resolve bash:
   - Find candidates: [5.2.0, 5.1.0, 5.0.0]
   - Pick newest: 5.2.0
   - Dependencies: [readline ~8.2.0, ncurses ^6.0.0]
   - Add dependency constraints

3. Resolve git:
   - Find candidates: [2.43.0, 2.42.0, 2.41.0]
   - Pick newest: 2.43.0
   - Dependencies: [curl ^8.0.0, zlib *]
   - Add dependency constraints

4. Resolve readline:
   - Find candidates: [8.2.0]
   - Pick newest: 8.2.0
   - Dependencies: [ncurses ^6.0.0]

5. Resolve ncurses:
   - Constraints: ^6.0.0 (from bash), ^6.0.0 (from readline)
   - Find candidates: [6.4.0, 6.3.0]
   - Pick newest: 6.4.0
   - Dependencies: []

6. Resolve curl:
   - Find candidates: [8.5.0, 8.4.0]
   - Pick newest: 8.5.0
   - Dependencies: [zlib *, openssl ^3.0.0]

7. Resolve zlib:
   - Constraints: * (from git), * (from curl)
   - Find candidates: [1.3.0, 1.2.13]
   - Pick newest: 1.3.0
   - Dependencies: []

8. Resolve openssl:
   - Find candidates: [3.2.0, 3.1.0]
   - Pick newest: 3.2.0
   - Dependencies: []
```

### Output Lock File

```yaml
profile_name: development
lock_version: 1
resolved:
  - name: bash
    version: "5.2.0"
    revision: 1
    build_id: abc123
    requested: true
  - name: git
    version: "2.43.0"
    revision: 1
    build_id: def456
    requested: true
  - name: readline
    version: "8.2.0"
    revision: 1
    build_id: ghi789
    requested: false
  - name: ncurses
    version: "6.4.0"
    revision: 1
    build_id: jkl012
    requested: false
  - name: curl
    version: "8.5.0"
    revision: 1
    build_id: mno345
    requested: false
  - name: zlib
    version: "1.3.0"
    revision: 1
    build_id: pqr678
    requested: false
  - name: openssl
    version: "3.2.0"
    revision: 1
    build_id: stu901
    requested: false
```

## Resolution Strategies

Axiom supports multiple resolution strategies:

### Greedy (Default)

Fast algorithm that picks the newest satisfying version:
- Time complexity: O(P × V × D)
- Good for most use cases
- May fail on complex constraint graphs

```bash
axiom resolve myprofile --strategy greedy
```

### Greedy with Backtracking

For small graphs, tries alternative versions when conflicts are detected:
- Automatically falls back to SAT for large graphs (>20 packages)
- Configurable backtrack limits
- Better success rate than pure greedy

```bash
axiom resolve myprofile --strategy backtracking
```

### SAT Solver

Uses Boolean Satisfiability solving for complex graphs:
- Finds solutions when greedy fails
- Handles complex constraint interactions
- Higher computational cost

```bash
axiom resolve myprofile --strategy sat
```

### Greedy with SAT Fallback (Recommended)

Tries greedy first, falls back to SAT on failure:
- Best of both worlds
- Fast for simple cases, robust for complex ones

```bash
axiom resolve myprofile  # Default strategy
```

## Version Preferences

Control which versions are preferred when multiple satisfy constraints:

### Newest (Default)

Always picks the newest satisfying version:
```bash
axiom resolve myprofile --prefer newest
```

### Stable

Prefers older, more stable versions for production:
- Favors .0 patch releases (1.2.0 over 1.2.5)
- When equal stability, prefers older
- Good for production environments

```bash
axiom resolve myprofile --prefer stable
```

### Oldest

Picks the oldest satisfying version:
```bash
axiom resolve myprofile --prefer oldest
```

## Backtracking Configuration

For the backtracking strategy, you can configure limits:

```bash
# Maximum backtracks per package (default: 5)
axiom resolve myprofile --max-backtracks 10

# Maximum total backtracks (default: 50)
axiom resolve myprofile --total-backtracks 100

# Small graph threshold - above this, use SAT instead (default: 20)
axiom resolve myprofile --backtrack-threshold 30
```

Combined example for production use:
```bash
axiom resolve production --strategy backtracking --prefer stable --max-backtracks 10
```

## Package Pinning

Pin specific packages to exact versions:

```yaml
# profile.yaml
name: production
packages:
  - name: python
    version: "=3.11.0"  # Exact version pin
    constraint: exact
pins:
  - name: openssl
    version: "3.1.0"
    revision: 2
    build_id: xyz789
```

## Error Handling

### No Solution

**Cause**: No version satisfies all constraints

**Example**:
```
Package A requires: foo ^1.0.0
Package B requires: foo ^2.0.0
```

**Resolution**: Relax constraints or update packages

### Circular Dependency

**Cause**: Package dependency cycle

**Example**:
```
A → B → C → A
```

**Resolution**: Break cycle by making one dependency optional

### Package Not Found

**Cause**: Requested package not in store

**Resolution**: Add package to store or fix package name

## Resource Limits (Phase 29)

To prevent denial-of-service attacks and runaway resolution, the resolver enforces configurable resource limits.

### Available Limits

| Limit | Default | Description |
|-------|---------|-------------|
| `max_resolution_time_ms` | 30,000 | Maximum time for resolution (30 seconds) |
| `max_memory_bytes` | 256 MB | Maximum memory usage |
| `max_dependency_depth` | 100 | Maximum dependency chain depth |
| `max_candidates_per_package` | 1,000 | Maximum versions considered per package |
| `max_total_candidates` | 100,000 | Total candidates across all packages |
| `max_sat_variables` | 100,000 | SAT solver variable limit |
| `max_sat_clauses` | 1,000,000 | SAT solver clause limit |

### Limit Presets

**Default limits**: Balanced for typical workloads
```zig
ResourceLimits{}  // Uses defaults above
```

**Strict limits**: Tighter constraints for untrusted inputs
```zig
ResourceLimits.strict()
// 10 seconds, 64 MB, depth 50, 100 candidates/pkg
```

**Unlimited**: For benchmarking only (not recommended for production)
```zig
ResourceLimits.unlimited()
```

### CLI Options

```bash
# Set timeout (seconds, default: 30)
axiom resolve myprofile --timeout 60

# Set memory limit (MB, default: 256)
axiom resolve myprofile --max-memory 512

# Set maximum dependency depth (default: 100)
axiom resolve myprofile --max-depth 50

# Use strict preset (10s timeout, 64MB, depth 50)
axiom resolve myprofile --strict

# Show resolution statistics
axiom resolve myprofile --stats
```

Full example with all options:
```bash
axiom resolve production \
    --strategy backtracking \
    --prefer stable \
    --max-backtracks 10 \
    --timeout 120 \
    --max-memory 1024 \
    --stats
```

### Resource Statistics

When `--stats` is enabled, the resolver reports:

```
Resolution Statistics:
  Time elapsed: 1.23s
  Peak memory: 45 MB
  Candidates examined: 1,234
  Dependency depth reached: 12
  Packages resolved: 47
```

### Error Handling

When a limit is exceeded, the resolver returns a specific error:

| Error | Meaning |
|-------|---------|
| `ResolutionTimeout` | Exceeded time limit |
| `MemoryLimitExceeded` | Exceeded memory limit |
| `DependencyDepthExceeded` | Dependency chain too deep |
| `TooManyCandidates` | Too many version candidates |
| `SatSolverLimitExceeded` | SAT solver complexity too high |

### Security Considerations

Resource limits protect against:

1. **Malicious manifests**: Crafted to cause exponential resolution time
2. **Dependency bombs**: Packages with thousands of transitive dependencies
3. **Circular complexity**: Deeply nested or recursive structures
4. **Memory exhaustion**: Large candidate sets consuming all RAM

---

## Performance Considerations

### Current Complexity

- Time: O(P × V × D)
  - P = number of packages
  - V = versions per package
  - D = average dependency count
  
- Space: O(P + C)
  - P = number of packages
  - C = number of constraints

### Optimization Strategies

1. **Index Caching**: Cache package store queries
2. **Constraint Merging**: Combine redundant constraints early
3. **Parallel Resolution**: Resolve independent packages in parallel
4. **Memoization**: Cache resolution results for sub-problems

## Testing Strategy

### Unit Tests

- Constraint satisfaction logic
- Version comparison
- Candidate selection

### Integration Tests

- Simple profiles (2-3 packages)
- Complex profiles (10+ packages with deep dependencies)
- Conflict scenarios
- Circular dependency detection

### Performance Tests

- Large dependency graphs (100+ packages)
- Many constraints per package
- Deep dependency trees (10+ levels)

---

**Author**: Vester "Vic" Thacker  
**Organization**: Pacific Grove Software Distribution Foundation  
**License**: BSD 2-Clause
