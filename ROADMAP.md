# Axiom Roadmap

## Overview

This document outlines the planned enhancements for Axiom beyond the core 8 phases. Each enhancement is designed to extend Axiom's capabilities while maintaining the foundational principles of ZFS-native immutability, reproducibility, and 20+ year maintainability.

## Enhancement Summary

| Phase | Enhancement | Priority | Complexity | Dependencies | Status |
|-------|-------------|----------|------------|--------------|--------|
| 9 | Package Import | High | Medium | None | ✓ Complete |
| 10 | Build System Integration | High | High | Phase 9 | ✓ Complete |
| 11 | Shell Completions | Medium | Low | None | ✓ Complete |
| 12 | Multi-user Support | Medium | Medium | None | ✓ Complete |
| 13 | Virtual Packages | Medium | Medium | None | ✓ Complete |
| 14 | Conflict Resolution | Medium | Medium | Phase 13 | ✓ Complete |
| 15 | Signature Verification | High | Medium | Phase 9 | ✓ Complete |
| 16 | SAT Solver | Low | High | None | ✓ Complete |
| 17 | Binary Cache | High | High | Phase 15 | ✓ Complete |

---

## Phase 9: Package Import

**Priority**: High  
**Complexity**: Medium  
**Estimated Effort**: 2-3 weeks

### Purpose

Enable importing packages from build outputs, tarballs, and other package formats into the Axiom store. This is the bridge between package building and package management.

### Requirements

1. **Import Sources**
   - Local directory (build output)
   - Tarball (.tar.gz, .tar.xz, .tar.zst)
   - FreeBSD pkg files (.pkg)
   - Raw ZFS send streams

2. **Manifest Generation**
   - Auto-detect package metadata when possible
   - Interactive manifest creation
   - Manifest templates for common package types

3. **Validation**
   - Verify file permissions
   - Check for conflicts with existing packages
   - Validate manifest completeness

### Design

```
axiom import <source> [options]

Options:
  --name <n>           Package name (auto-detect if not specified)
  --version <ver>        Package version
  --manifest <file>      Use existing manifest file
  --template <type>      Use manifest template (binary, library, data)
  --dry-run              Show what would be imported
```

### Implementation

**New Files:**
- `src/import.zig` - Import engine
- `src/detect.zig` - Package detection heuristics

**Key Structures:**

```zig
pub const ImportSource = union(enum) {
    directory: []const u8,
    tarball: []const u8,
    pkg_file: []const u8,
    zfs_stream: std.fs.File,
};

pub const ImportOptions = struct {
    name: ?[]const u8 = null,
    version: ?types.Version = null,
    manifest_path: ?[]const u8 = null,
    template: ?ManifestTemplate = null,
    dry_run: bool = false,
};

pub const Importer = struct {
    allocator: std.mem.Allocator,
    store: *PackageStore,
    
    pub fn import(self: *Importer, source: ImportSource, options: ImportOptions) !PackageId;
    fn detectMetadata(self: *Importer, source: ImportSource) !DetectedMetadata;
    fn extractTarball(self: *Importer, path: []const u8, dest: []const u8) !void;
    fn generateManifest(self: *Importer, metadata: DetectedMetadata) !manifest.Manifest;
};
```

**Detection Heuristics:**

```zig
pub const DetectedMetadata = struct {
    name: ?[]const u8,
    version: ?types.Version,
    description: ?[]const u8,
    dependencies: []types.Dependency,
    file_type: FileType,
    
    pub const FileType = enum {
        binary,      // Has executables in bin/
        library,     // Has .so/.a files in lib/
        headers,     // Has .h files in include/
        data,        // Data files only
        mixed,       // Multiple types
    };
};

fn detectFromDirectory(path: []const u8) !DetectedMetadata {
    // Scan directory structure
    // Look for common patterns:
    //   bin/* -> binary
    //   lib/*.so -> library
    //   include/*.h -> headers
    // Parse any existing metadata files:
    //   package.json, Cargo.toml, setup.py, etc.
}
```

### CLI Commands

```bash
# Import from build directory
axiom import ./build/output --name myapp --version 1.0.0

# Import tarball
axiom import myapp-1.0.0.tar.gz

# Import with manifest
axiom import ./output --manifest myapp.yaml

# Import FreeBSD pkg
axiom import bash-5.2.0.pkg

# Dry run
axiom import ./output --dry-run
```

### Workflow Integration

```
Build System → Build Output → axiom import → Package Store → Profile → Environment
```

---

## Phase 10: Build System Integration

**Priority**: High  
**Complexity**: High  
**Estimated Effort**: 4-6 weeks

### Purpose

Native package building within Axiom, enabling source-to-package workflows with reproducible builds.

### Requirements

1. **Build Recipes**
   - Declarative build specifications
   - Support for common build systems (make, cmake, meson, cargo, etc.)
   - Sandboxed build environments

2. **Build Isolation**
   - Clean build environments via ZFS clones
   - Dependency injection from store
   - Network isolation options

3. **Reproducibility**
   - Capture build environment in provenance
   - Deterministic builds where possible
   - Build cache for incremental builds

### Design

**Build Recipe Format (build.yaml):**

```yaml
name: bash
version: "5.2.0"
source:
  url: https://ftp.gnu.org/gnu/bash/bash-5.2.tar.gz
  sha256: a139c166df7ff4471c5e0733051642ee5556c1cc8a4a78f145583c5c81c32fb2

build_dependencies:
  - name: gcc
    version: ">=12.0.0"
  - name: make
    version: "*"

runtime_dependencies:
  - name: readline
    version: "~8.2.0"
  - name: ncurses
    version: "^6.0.0"

phases:
  configure:
    command: "./configure --prefix=$OUTPUT"
    environment:
      CFLAGS: "-O2 -pipe"
  
  build:
    command: "make -j$JOBS"
  
  install:
    command: "make install DESTDIR=$OUTPUT"

  test:
    command: "make test"
    optional: true

output:
  strip_binaries: true
  compress_man: true
```

**Implementation:**

```zig
pub const BuildRecipe = struct {
    name: []const u8,
    version: types.Version,
    source: Source,
    build_deps: []types.Dependency,
    runtime_deps: []types.Dependency,
    phases: []BuildPhase,
    output: OutputConfig,
};

pub const BuildPhase = struct {
    name: []const u8,
    command: []const u8,
    environment: ?std.StringHashMap([]const u8),
    working_dir: ?[]const u8,
    optional: bool = false,
};

pub const Builder = struct {
    allocator: std.mem.Allocator,
    zfs_handle: *ZfsHandle,
    store: *PackageStore,
    
    pub fn build(self: *Builder, recipe: BuildRecipe) !PackageId {
        // 1. Create build sandbox (ZFS clone)
        const sandbox = try self.createSandbox(recipe);
        defer self.destroySandbox(sandbox);
        
        // 2. Inject build dependencies
        try self.injectDependencies(sandbox, recipe.build_deps);
        
        // 3. Fetch and extract source
        try self.fetchSource(sandbox, recipe.source);
        
        // 4. Execute build phases
        for (recipe.phases) |phase| {
            try self.executePhase(sandbox, phase);
        }
        
        // 5. Collect output and import
        return try self.collectOutput(sandbox, recipe);
    }
};
```

### CLI Commands

```bash
# Build from recipe
axiom build bash.yaml

# Build with options
axiom build bash.yaml --jobs 8 --no-test

# Build and import
axiom build bash.yaml --import

# Show build plan
axiom build bash.yaml --dry-run
```

---

## Phase 11: Shell Completions

**Priority**: Medium  
**Complexity**: Low  
**Estimated Effort**: 1 week

### Purpose

Provide tab completion for Bash, Zsh, and Fish shells to improve CLI usability.

### Requirements

1. **Shell Support**
   - Bash completion
   - Zsh completion
   - Fish completion

2. **Completion Types**
   - Command completion
   - Option completion
   - Dynamic completion (profile names, package names, etc.)

### Implementation

**Bash Completion (axiom.bash):**

```bash
_axiom_completions() {
    local cur prev commands
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    
    commands="help version profile profile-create profile-show profile-update profile-delete install remove search info list resolve realize activate env env-destroy gc build import"
    
    case "${prev}" in
        axiom)
            COMPREPLY=($(compgen -W "${commands}" -- "${cur}"))
            ;;
        profile-show|profile-update|profile-delete|resolve)
            # Complete with profile names
            local profiles=$(axiom profile --names-only 2>/dev/null)
            COMPREPLY=($(compgen -W "${profiles}" -- "${cur}"))
            ;;
        realize)
            # First arg: env name, second arg: profile name
            if [[ ${COMP_CWORD} -eq 3 ]]; then
                local profiles=$(axiom profile --names-only 2>/dev/null)
                COMPREPLY=($(compgen -W "${profiles}" -- "${cur}"))
            fi
            ;;
        activate|env-destroy)
            # Complete with environment names
            local envs=$(axiom env --names-only 2>/dev/null)
            COMPREPLY=($(compgen -W "${envs}" -- "${cur}"))
            ;;
        install|remove|info)
            # Complete with package names
            local packages=$(axiom list --names-only 2>/dev/null)
            COMPREPLY=($(compgen -W "${packages}" -- "${cur}"))
            ;;
        gc)
            COMPREPLY=($(compgen -W "--dry-run" -- "${cur}"))
            ;;
        import)
            # Complete with files
            COMPREPLY=($(compgen -f -- "${cur}"))
            ;;
        build)
            # Complete with .yaml files
            COMPREPLY=($(compgen -f -X '!*.yaml' -- "${cur}"))
            ;;
        *)
            COMPREPLY=()
            ;;
    esac
}

complete -F _axiom_completions axiom
```

**Zsh Completion (_axiom):**

```zsh
#compdef axiom

_axiom() {
    local -a commands
    commands=(
        'help:Show help message'
        'version:Show version information'
        'profile:List profiles'
        'profile-create:Create a new profile'
        'profile-show:Show profile details'
        'profile-update:Update a profile'
        'profile-delete:Delete a profile'
        'install:Add package to profile'
        'remove:Remove package from profile'
        'search:Search for packages'
        'info:Show package information'
        'list:List installed packages'
        'resolve:Resolve profile dependencies'
        'realize:Create environment from profile'
        'activate:Activate an environment'
        'env:List environments'
        'env-destroy:Destroy an environment'
        'gc:Run garbage collector'
        'build:Build package from recipe'
        'import:Import package into store'
    )
    
    _arguments -C \
        '1: :->command' \
        '*: :->args'
    
    case $state in
        command)
            _describe 'command' commands
            ;;
        args)
            case $words[2] in
                profile-show|profile-update|profile-delete|resolve)
                    _axiom_profiles
                    ;;
                activate|env-destroy)
                    _axiom_environments
                    ;;
                install|remove|info)
                    _axiom_packages
                    ;;
                import)
                    _files
                    ;;
                build)
                    _files -g '*.yaml'
                    ;;
            esac
            ;;
    esac
}

_axiom_profiles() {
    local -a profiles
    profiles=(${(f)"$(axiom profile --names-only 2>/dev/null)"})
    _describe 'profile' profiles
}

_axiom_environments() {
    local -a envs
    envs=(${(f)"$(axiom env --names-only 2>/dev/null)"})
    _describe 'environment' envs
}

_axiom_packages() {
    local -a packages
    packages=(${(f)"$(axiom list --names-only 2>/dev/null)"})
    _describe 'package' packages
}

_axiom
```

### Installation

```bash
# Bash
axiom completions bash > /usr/local/share/bash-completion/completions/axiom

# Zsh
axiom completions zsh > /usr/local/share/zsh/site-functions/_axiom

# Fish
axiom completions fish > ~/.config/fish/completions/axiom.fish
```

---

## Phase 12: Multi-user Support

**Priority**: Medium  
**Complexity**: Medium  
**Estimated Effort**: 2-3 weeks

### Purpose

Enable per-user profiles and environments without requiring root access for day-to-day operations.

### Requirements

1. **User Isolation**
   - Per-user profile storage
   - Per-user environments
   - Shared package store (read-only for users)

2. **Permission Model**
   - Root: Manage store, global profiles
   - Users: Create personal profiles/environments
   - Groups: Shared team profiles

3. **Storage Layout**
   - System store: `/axiom/store` (root-managed)
   - User profiles: `~/.axiom/profiles`
   - User environments: `~/.axiom/env`

### Design

**Dataset Structure:**

```
zroot/axiom/
├── store/              # Shared, root-managed
│   └── pkg/
├── profiles/           # System profiles (root)
├── env/                # System environments (root)
└── users/              # Per-user data
    ├── alice/
    │   ├── profiles/
    │   └── env/
    └── bob/
        ├── profiles/
        └── env/
```

**Permission Model:**

```zig
pub const AccessLevel = enum {
    root,       // Full access
    user,       // Own profiles/envs only
    group,      // Group-shared profiles
    readonly,   // Read-only access
};

pub const UserContext = struct {
    uid: u32,
    gid: u32,
    username: []const u8,
    groups: []u32,
    access_level: AccessLevel,
    
    pub fn canModifyProfile(self: UserContext, profile_path: []const u8) bool {
        // Check ownership and group membership
    }
    
    pub fn canCreateEnvironment(self: UserContext) bool {
        // Check quota and permissions
    }
};
```

**Delegated Operations:**

```zig
pub const UserOperations = struct {
    // Operations users can perform without root
    pub fn createUserProfile(ctx: UserContext, name: []const u8) !void;
    pub fn realizeUserEnvironment(ctx: UserContext, name: []const u8, profile: []const u8) !void;
    pub fn activateUserEnvironment(ctx: UserContext, name: []const u8) !void;
    
    // Operations requiring root (via setuid helper or polkit)
    pub fn requestPackageImport(ctx: UserContext, request: ImportRequest) !void;
    pub fn requestGarbageCollection(ctx: UserContext) !void;
};
```

### CLI Changes

```bash
# User commands (no root required)
axiom user profile-create my-dev
axiom user resolve my-dev
axiom user realize my-env my-dev
source ~/.axiom/env/my-env/activate

# System commands (root required)
sudo axiom system import package.tar.gz
sudo axiom system gc

# List user's profiles
axiom user profile

# List system profiles
axiom system profile
```

---

## Phase 13: Virtual Packages

**Priority**: Medium  
**Complexity**: Medium  
**Estimated Effort**: 2 weeks

### Purpose

Support abstract package capabilities through provides/conflicts declarations, enabling package alternatives and mutual exclusion.

### Requirements

1. **Provides**
   - Package can provide virtual capabilities
   - Multiple packages can provide same capability
   - Version constraints on provides

2. **Conflicts**
   - Declare incompatibility with other packages
   - Prevent co-installation of conflicting packages

3. **Replaces**
   - Declare that package replaces another
   - Handle upgrade paths

### Design

**Extended Manifest:**

```yaml
name: gnu-make
version: "4.4.0"
provides:
  - name: make
    version: "4.4.0"
  - name: build-tool
conflicts:
  - name: bmake
    reason: "Both provide 'make' command"
replaces:
  - name: make
    before_version: "4.0.0"
```

**Implementation:**

```zig
pub const VirtualPackage = struct {
    name: []const u8,
    version: ?types.Version,
};

pub const Conflict = struct {
    name: []const u8,
    version_constraint: ?types.VersionConstraint,
    reason: ?[]const u8,
};

pub const Replacement = struct {
    name: []const u8,
    before_version: ?types.Version,
};

pub const ExtendedManifest = struct {
    // Existing fields...
    provides: []VirtualPackage,
    conflicts: []Conflict,
    replaces: []Replacement,
};
```

**Resolver Changes:**

```zig
pub const VirtualResolver = struct {
    // Map virtual name -> providing packages
    providers: std.StringHashMap(std.ArrayList(PackageId)),
    
    pub fn resolveVirtual(self: *VirtualResolver, virtual_name: []const u8, constraint: VersionConstraint) ![]PackageId {
        // Find all packages providing this virtual
        // Filter by version constraint
        // Return candidates
    }
    
    pub fn checkConflicts(self: *VirtualResolver, packages: []PackageId) !?ConflictSet {
        // Check for conflicts between selected packages
        // Return conflict details if found
    }
};
```

### Example Usage

```yaml
# Profile can depend on virtual package
name: development
packages:
  - name: make        # Resolved to gnu-make or bmake
    version: "*"
  - name: c-compiler  # Resolved to gcc or clang
    version: "*"
```

---

## Phase 14: Conflict Resolution ✓

**Priority**: Medium
**Complexity**: Medium
**Estimated Effort**: 2 weeks
**Dependencies**: Phase 13 (Virtual Packages)
**Status**: Complete

### Purpose

Handle file conflicts between packages during environment realization.

### Implementation

**Files Created:**
- `src/conflict.zig` - Conflict detection and resolution module

**Features Implemented:**
- File conflict detection (same_content, different_content, type_mismatch, permission_diff)
- SHA-256 content hashing for accurate comparison
- Resolution strategies: error, priority, keep-both
- CLI `--conflict-policy` flag for `realize` and `user-realize`
- Per-path conflict rules with glob patterns
- Conflict tracking and summary reporting

### Requirements

1. **Conflict Detection**
   - Detect overlapping files during realization
   - Report conflicts clearly

2. **Resolution Strategies**
   - Priority-based (later package wins)
   - Alternatives (rename conflicting files)
   - Error (fail on conflict)
   - Interactive (user choice)

3. **Conflict Tracking**
   - Record how conflicts were resolved
   - Enable rollback

### Design

**Conflict Types:**

```zig
pub const FileConflict = struct {
    path: []const u8,
    packages: []PackageId,
    conflict_type: ConflictType,
    
    pub const ConflictType = enum {
        same_content,      // Files are identical (no real conflict)
        different_content, // Files differ
        type_mismatch,     // File vs directory
    };
};

pub const ConflictResolution = union(enum) {
    use_package: PackageId,      // Use file from specific package
    rename: RenameStrategy,      // Rename to avoid conflict
    merge: MergeStrategy,        // Attempt to merge (for config files)
    skip: void,                  // Skip the file
    error: void,                 // Fail on conflict
};

pub const RenameStrategy = struct {
    pattern: []const u8,  // e.g., "{name}.{package}"
};
```

**Resolution Configuration:**

```yaml
# Profile-level conflict settings
name: development
conflict_policy:
  default: error
  rules:
    - path: "/etc/*"
      strategy: merge
    - path: "/bin/*"
      strategy: priority
      priority_order:
        - gnu-coreutils
        - busybox
    - path: "/share/man/*"
      strategy: coexist
      rename_pattern: "{name}.{package}.{section}"
```

**Implementation:**

```zig
pub const ConflictResolver = struct {
    policy: ConflictPolicy,
    
    pub fn detectConflicts(self: *ConflictResolver, packages: []PackageId) ![]FileConflict {
        // Scan all package file lists
        // Find overlapping paths
        // Classify conflict types
    }
    
    pub fn resolveConflicts(self: *ConflictResolver, conflicts: []FileConflict) ![]ResolvedConflict {
        // Apply policy rules
        // Return resolution for each conflict
    }
    
    pub fn applyResolutions(self: *ConflictResolver, env: *Environment, resolutions: []ResolvedConflict) !void {
        // Apply resolutions during realization
    }
};
```

---

## Phase 15: Signature Verification

**Priority**: High  
**Complexity**: Medium  
**Estimated Effort**: 2-3 weeks  
**Dependencies**: Phase 9 (Package Import)

### Purpose

Cryptographic verification of package integrity and authenticity.

### Requirements

1. **Signature Types**
   - Package signatures (per-package)
   - Manifest signatures (metadata)
   - Repository signatures (index)

2. **Key Management**
   - Trust store for public keys
   - Key rotation support
   - Multiple signers

3. **Verification Modes**
   - Strict (fail on missing/invalid signature)
   - Warn (warn but allow)
   - Disabled (no verification)

### Design

**Signature Format:**

```yaml
# Package signature file (manifest.sig)
signature:
  algorithm: ed25519
  signer: "PGSD Release Key <release@pgsdf.org>"
  key_id: "A1B2C3D4E5F6"
  timestamp: "2024-01-15T10:30:00Z"
  value: "base64-encoded-signature"
  
  # Covers these files
  files:
    - path: manifest.yaml
      sha256: "..."
    - path: deps.yaml
      sha256: "..."
    - path: root/
      sha256: "..." # Merkle root of directory tree
```

**Implementation:**

```zig
const ed25519 = @import("std").crypto.sign.Ed25519;

pub const Signature = struct {
    algorithm: Algorithm,
    signer: []const u8,
    key_id: []const u8,
    timestamp: i64,
    value: [64]u8,
    files: []FileHash,
    
    pub const Algorithm = enum {
        ed25519,
    };
};

pub const TrustStore = struct {
    keys: std.StringHashMap(PublicKey),
    
    pub fn addKey(self: *TrustStore, key: PublicKey) !void;
    pub fn removeKey(self: *TrustStore, key_id: []const u8) !void;
    pub fn getKey(self: *TrustStore, key_id: []const u8) ?PublicKey;
    pub fn isKeyTrusted(self: *TrustStore, key_id: []const u8) bool;
};

pub const SignatureVerifier = struct {
    trust_store: *TrustStore,
    mode: VerificationMode,
    
    pub const VerificationMode = enum {
        strict,
        warn,
        disabled,
    };
    
    pub fn verifyPackage(self: *SignatureVerifier, pkg_path: []const u8) !VerificationResult {
        // 1. Read signature file
        // 2. Find public key in trust store
        // 3. Verify signature covers manifest
        // 4. Verify file hashes
    }
};
```

**CLI Commands:**

```bash
# Key management
axiom key list
axiom key add pgsd-release.pub
axiom key remove A1B2C3D4E5F6
axiom key trust A1B2C3D4E5F6

# Sign a package (for maintainers)
axiom sign ./package --key maintainer.key

# Verify package
axiom verify ./package

# Import with verification
axiom import package.tar.gz --verify
```

---

## Phase 16: SAT Solver ✓

**Priority**: Low
**Complexity**: High
**Estimated Effort**: 4-6 weeks
**Status**: Complete

### Purpose

Advanced dependency resolution using Boolean Satisfiability (SAT) solving for complex constraint scenarios.

### Implementation

**Files Created:**
- `src/sat.zig` - Core CDCL SAT solver implementation
- `src/sat_resolver.zig` - SAT-based resolver integration

**Files Modified:**
- `src/resolver.zig` - Added SAT fallback support and resolution strategies
- `src/cli.zig` - Added `--strategy` flag for resolve commands

**Features Implemented:**
- CDCL (Conflict-Driven Clause Learning) SAT solver
- VSIDS heuristic for variable selection
- Unit propagation and conflict analysis
- Package dependency encoding as SAT variables
- Version constraint satisfaction via clauses
- Resolution strategies: greedy, sat, greedy_with_sat_fallback (auto)
- CLI `--strategy` flag for `resolve` and `user-resolve` commands
- Detailed diagnostics for unsatisfiable constraints
- Conflict explanations and suggestions
- MaxSAT optimization for version preferences

**CLI Usage:**
```bash
# Use SAT solver directly
axiom resolve my-profile --strategy sat

# Use automatic fallback (default)
axiom resolve my-profile --strategy auto

# Use fast greedy algorithm
axiom resolve my-profile --strategy greedy
```

### Requirements

1. **SAT Encoding**
   - Encode packages as boolean variables
   - Encode version constraints as clauses
   - Encode conflicts as negative clauses

2. **Optimization**
   - Minimize total packages
   - Prefer newer versions
   - Custom optimization criteria

3. **Diagnostics**
   - Explain unsatisfiable constraints
   - Suggest resolution paths

### Design

**SAT Encoding:**

```
Variables:
  pkg_bash_5.2.0 = Package bash version 5.2.0 is selected
  pkg_bash_5.1.0 = Package bash version 5.1.0 is selected
  pkg_readline_8.2.0 = Package readline version 8.2.0 is selected

Clauses:
  # At least one bash version (if bash is requested)
  (pkg_bash_5.2.0 OR pkg_bash_5.1.0 OR pkg_bash_5.0.0)
  
  # At most one bash version
  NOT(pkg_bash_5.2.0 AND pkg_bash_5.1.0)
  NOT(pkg_bash_5.2.0 AND pkg_bash_5.0.0)
  NOT(pkg_bash_5.1.0 AND pkg_bash_5.0.0)
  
  # Dependency: bash 5.2.0 requires readline >= 8.0
  (NOT pkg_bash_5.2.0 OR pkg_readline_8.2.0 OR pkg_readline_8.1.0 OR pkg_readline_8.0.0)
  
  # Conflict: pkg_a conflicts with pkg_b
  NOT(pkg_a AND pkg_b)
```

**Implementation:**

```zig
pub const SATResolver = struct {
    allocator: std.mem.Allocator,
    solver: *MiniSAT,
    
    // Variable mapping
    pkg_to_var: std.StringHashMap(i32),
    var_to_pkg: std.AutoHashMap(i32, PackageId),
    next_var: i32,
    
    pub fn resolve(self: *SATResolver, requests: []PackageRequest) !?[]PackageId {
        // 1. Collect all candidate packages
        const candidates = try self.collectCandidates(requests);
        
        // 2. Create variables
        for (candidates) |pkg| {
            try self.createVariable(pkg);
        }
        
        // 3. Add clauses
        try self.addRequestClauses(requests);
        try self.addExclusivityClauses(candidates);
        try self.addDependencyClauses(candidates);
        try self.addConflictClauses(candidates);
        
        // 4. Add optimization (prefer newer)
        try self.addOptimizationClauses(candidates);
        
        // 5. Solve
        if (try self.solver.solve()) {
            return try self.extractSolution();
        } else {
            return null;
        }
    }
    
    pub fn explainFailure(self: *SATResolver) ![]Conflict {
        // Use UNSAT core extraction
        // Map back to human-readable conflicts
    }
};
```

**MiniSAT Bindings:**

```zig
// C bindings to MiniSAT or similar SAT solver
pub const MiniSAT = opaque {};

extern fn minisat_new() *MiniSAT;
extern fn minisat_delete(s: *MiniSAT) void;
extern fn minisat_newVar(s: *MiniSAT) i32;
extern fn minisat_addClause(s: *MiniSAT, lits: [*]i32, len: usize) bool;
extern fn minisat_solve(s: *MiniSAT) bool;
extern fn minisat_value(s: *MiniSAT, var_: i32) i32;
```

### Fallback Strategy

```zig
pub fn resolveWithFallback(requests: []PackageRequest) ![]PackageId {
    // Try greedy first (fast path)
    if (greedy_resolver.resolve(requests)) |result| {
        return result;
    }
    
    // Fall back to SAT solver
    return sat_resolver.resolve(requests);
}
```

---

## Phase 17: Binary Cache

**Priority**: High  
**Complexity**: High  
**Estimated Effort**: 4-6 weeks  
**Dependencies**: Phase 15 (Signature Verification)

### Purpose

HTTP-based package distribution using ZFS send/receive for efficient binary caching.

### Requirements

1. **Cache Server**
   - Serve packages over HTTP/HTTPS
   - ZFS send stream format
   - Compressed transfer
   - Delta updates

2. **Cache Client**
   - Download and verify packages
   - Resume interrupted transfers
   - Local cache management

3. **Cache Operations**
   - Push packages to cache
   - Pull packages from cache
   - Sync with cache

### Design

**Cache Protocol:**

```
GET /v1/packages/{name}/{version}/{revision}/{build_id}
  → Returns ZFS send stream

GET /v1/packages/{name}/{version}/{revision}/{build_id}/manifest
  → Returns manifest.yaml

GET /v1/packages/{name}/{version}/{revision}/{build_id}/signature
  → Returns manifest.sig

GET /v1/index
  → Returns package index (signed)

GET /v1/delta/{from_build_id}/{to_build_id}
  → Returns incremental ZFS send stream
```

**Server Implementation:**

```zig
pub const CacheServer = struct {
    store: *PackageStore,
    zfs_handle: *ZfsHandle,
    
    pub fn servePackage(self: *CacheServer, request: Request) !Response {
        const pkg_id = try parsePackageId(request.path);
        const dataset = try self.store.paths.packageDataset(self.allocator, pkg_id);
        
        // Create ZFS send stream
        const snapshot = try std.fmt.allocPrint(self.allocator, "{s}@installed", .{dataset});
        
        // Pipe ZFS send to HTTP response
        var child = std.process.Child.init(
            &[_][]const u8{ "zfs", "send", "-c", snapshot },
            self.allocator,
        );
        // Stream stdout to response...
    }
    
    pub fn serveDelta(self: *CacheServer, from: []const u8, to: []const u8) !Response {
        // ZFS send -i from_snapshot to_snapshot
    }
};
```

**Client Implementation:**

```zig
pub const CacheClient = struct {
    cache_urls: [][]const u8,
    local_cache: []const u8,
    verifier: *SignatureVerifier,
    
    pub fn fetchPackage(self: *CacheClient, pkg_id: PackageId) ![]const u8 {
        // 1. Check local cache
        if (try self.checkLocalCache(pkg_id)) |path| {
            return path;
        }
        
        // 2. Try each cache URL
        for (self.cache_urls) |base_url| {
            const url = try self.packageUrl(base_url, pkg_id);
            
            if (try self.downloadPackage(url, pkg_id)) |path| {
                // 3. Verify signature
                try self.verifier.verifyPackage(path);
                
                // 4. Receive into store
                try self.receiveIntoStore(path, pkg_id);
                
                return path;
            }
        }
        
        return error.PackageNotFound;
    }
    
    fn downloadPackage(self: *CacheClient, url: []const u8, pkg_id: PackageId) !?[]const u8 {
        // Download with resume support
        // Use HTTP Range headers for resume
        // Verify checksum during download
    }
    
    fn receiveIntoStore(self: *CacheClient, stream_path: []const u8, pkg_id: PackageId) !void {
        // zfs receive into store dataset
        const dataset = try self.store.paths.packageDataset(self.allocator, pkg_id);
        
        var child = std.process.Child.init(
            &[_][]const u8{ "zfs", "receive", dataset },
            self.allocator,
        );
        // Pipe file to stdin...
    }
};
```

**Configuration:**

```yaml
# /etc/axiom/cache.yaml
caches:
  - url: https://cache.pgsdf.org
    priority: 1
    trusted_keys:
      - A1B2C3D4E5F6
  
  - url: https://mirror.example.com/axiom
    priority: 2

local_cache:
  path: /var/cache/axiom
  max_size: 10G
  cleanup_policy: lru

push:
  enabled: true
  url: https://cache.pgsdf.org/upload
  key: /etc/axiom/upload.key
```

**CLI Commands:**

```bash
# Configure cache
axiom cache add https://cache.pgsdf.org

# Fetch from cache
axiom cache fetch bash/5.2.0/1/abc123

# Push to cache
axiom cache push bash/5.2.0/1/abc123

# Sync local cache
axiom cache sync

# Clear local cache
axiom cache clean
```

---

## Implementation Order

### Recommended Sequence

```
Phase 9:  Package Import         ✓ Complete
Phase 15: Signature Verification ✓ Complete
Phase 17: Binary Cache           ✓ Complete
Phase 11: Shell Completions      ✓ Complete
Phase 10: Build System           ✓ Complete
Phase 12: Multi-user Support     ✓ Complete
Phase 13: Virtual Packages       ✓ Complete
Phase 14: Conflict Resolution    ✓ Complete
Phase 16: SAT Solver             ✓ Complete
```

### MVP Path (Minimum for Production)

1. ~~Phase 9: Package Import~~ ✓
2. ~~Phase 15: Signature Verification~~ ✓
3. ~~Phase 17: Binary Cache~~ ✓
4. ~~Phase 11: Shell Completions~~ ✓

**MVP Complete!**

### Full Feature Path

**🎉 All phases complete!** Axiom now includes:
- Core package management (Phases 1-8)
- Package import and build system (Phases 9-10)
- Shell completions (Phase 11)
- Multi-user support (Phase 12)
- Virtual packages and conflict resolution (Phases 13-14)
- Signature verification and binary cache (Phases 15, 17)
- Advanced SAT-based dependency resolution (Phase 16)

---

## Testing Strategy

### Per-Phase Testing

Each phase should include:

1. **Unit Tests**
   - Core logic functions
   - Edge cases
   - Error handling

2. **Integration Tests**
   - Interaction with existing phases
   - ZFS operations
   - CLI commands

3. **Performance Tests**
   - Large package sets
   - Network operations
   - Concurrent access

### Test Infrastructure

```bash
# Test environment setup
tests/setup.sh          # Create test ZFS pool
tests/fixtures/         # Test packages, manifests
tests/integration/      # Integration test scripts

# Run tests
zig build test                    # Unit tests
./tests/integration/run_all.sh    # Integration tests
./tests/performance/benchmark.sh  # Performance tests
```

---

## Documentation Requirements

Each phase should include:

1. **Design Document**
   - Architecture decisions
   - Interface specifications
   - Security considerations

2. **User Documentation**
   - CLI reference
   - Configuration guide
   - Tutorials

3. **Developer Documentation**
   - API reference
   - Extension points
   - Contributing guide

---

**Author**: Vester "Vic" Thacker  
**Organization**: Pacific Grove Software Distribution Foundation  
**License**: BSD 2-Clause  
**Version**: 1.0  
**Date**: 2024
