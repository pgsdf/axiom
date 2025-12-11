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
| 18 | Self-Contained Bundles & Launcher | High | Medium | None | ✓ Complete |
| 19 | Portable Images (.pgsdimg) | High | Medium | Phase 18 | ✓ Complete |
| 20 | Runtime Layers | Medium | Medium | Phase 18 | ✓ Complete |
| 21 | Desktop Integration | Medium | Low | Phase 18 | ✓ Complete |
| 22 | Ports Migration Tool | High | High | Phase 9, 10 | ✓ Complete |
| 23 | Kernel Module Compatibility | Medium | Medium | Phase 22 | ✓ Complete |
| 24 | Secure Tar Extraction | Critical | Medium | Phase 9 | ✓ Complete |
| 25 | Mandatory Signature Verification | Critical | Medium | Phase 15 | ✓ Complete |
| 26 | ZFS Dataset Path Validation | High | Low | None | ✓ Complete |
| 27 | Build Sandboxing | High | High | Phase 10 | ✓ Complete |
| 28 | Secure Bundle Verification | High | Medium | Phase 18 | ✓ Complete |
| 29 | Resolver Resource Limits | Medium | Low | Phase 16 | ✓ Complete |
| 30 | Thread-Safe libzfs | Medium | Medium | None | ✓ Complete |
| 31 | Resolver Backtracking | Medium | Medium | Phase 16 | ✓ Complete |
| 32 | Bootstrap Automation | High | Low | Phase 22 | ✓ Complete |
| 33 | Unified Test Infrastructure | Medium | Low | None | ✓ Complete |
| 34 | CLI Resolution Options | Medium | Low | Phase 31 | Planned |
| 35 | Dependency Graph Visualization | Low | Medium | Phase 16 | Planned |
| 36 | HSM/PKCS#11 Signing | Medium | High | Phase 15 | Planned |
| 37 | Multi-Party Signing | Medium | High | Phase 36 | Planned |
| 38 | Service Management Integration | High | High | Phase 22 | Planned |
| 39 | Boot Environment Support | High | Medium | None | Planned |
| 40 | Remote Binary Cache Protocol | High | High | Phase 17 | Planned |

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
  timestamp: "2025-11-15T10:30:00Z"
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
- AppImage-inspired bundles, launcher, runtimes, and desktop integration (Phases 18-21)

---

## Phase 18: Self-Contained Bundles & Launcher ✓

**Priority**: High
**Complexity**: Medium
**Status**: Complete

### Purpose

Enable running packages directly without environment activation (like AppImage) and support self-contained bundles with complete dependency closures.

### Implementation

**Files Created:**
- `src/closure.zig` - Dependency closure computation
- `src/launcher.zig` - Runtime shim for direct execution
- `src/bundle.zig` - Bundle creation and management

**Features Implemented:**
- Dependency closure computation (transitive dependencies)
- Direct package execution via `axiom run <pkg>@<ver>`
- Isolated mode execution (no system libs)
- LD_LIBRARY_PATH and PATH setup for package execution
- Launcher script generation for packages
- Bundle creation with multiple output formats

**CLI Commands:**
```bash
# Run package directly
axiom run hello@1.0.0

# Run in isolated mode
axiom run bash@5.2.0 --isolated

# Run with arguments
axiom run vim@9.0.0 file.txt

# Show dependency closure
axiom closure bash@5.2.0
axiom closure vim@9.0.0 --tree
```

### Design

**Closure Computation:**
```zig
pub const ClosureComputer = struct {
    // Computes transitive closure of all dependencies
    pub fn computeForPackage(pkg_id: PackageId) !Closure;

    // Base packages excluded from closures (assumed present)
    base_packages: StringHashMap(void),
};
```

**Launcher:**
```zig
pub const Launcher = struct {
    // Launch package directly with environment setup
    pub fn launch(config: LaunchConfig) LaunchResult;

    // Generate standalone launcher script
    pub fn generateLauncherScript(pkg_id: PackageId, output: []const u8) !void;
};
```

---

## Phase 19: Portable Images (.pgsdimg) ✓

**Priority**: High
**Complexity**: Medium
**Dependencies**: Phase 18
**Status**: Complete

### Purpose

Create single-file distributable artifacts (like AppImage) that can be executed directly or imported into the store.

### Implementation

**Features Implemented:**
- `.pgsdimg` portable image format
- Self-extracting executables with embedded payload
- Multiple output formats: pgsdimg, ZFS stream, tarball, directory
- Bundle manifest with provenance information
- CLI export command

**CLI Commands:**
```bash
# Export package as portable image
axiom export hello@1.0.0

# Export with specific format
axiom export bash@5.2.0 --format zfs
axiom export vim@9.0.0 --format tar

# Export without dependencies
axiom export app@1.0.0 --no-closure

# Create bundle from directory
axiom bundle ./my-app
axiom build-bundle . --output app.pgsdimg
```

### Design

**Bundle Format:**
```
hello-1.0.0.pgsdimg
├── [ELF stub / Shell launcher]
├── [Metadata - MANIFEST.yaml]
├── [Signature - optional]
└── [Compressed payload - packages/]
```

**Bundle Config:**
```zig
pub const BundleConfig = struct {
    format: BundleFormat,      // pgsdimg, zfs_stream, tarball, directory
    compression: CompressionType,
    include_closure: bool,
    sign: bool,
    signing_key: ?[]const u8,
};
```

---

## Phase 20: Runtime Layers ✓

**Priority**: Medium
**Complexity**: Medium
**Dependencies**: Phase 18
**Status**: Complete

### Purpose

Create versioned runtime layers (like Flatpak runtimes) that provide ABI-stable library sets for applications to depend on.

### Implementation

**Files Created:**
- `src/runtime.zig` - Runtime layer management

**Features Implemented:**
- Runtime layer creation and management
- ABI version tracking
- Standard runtime definitions (base, full, GUI)
- ZFS snapshot support for runtime versions
- Rollback capability
- Package-to-runtime compatibility checking

### Design

**Runtime Structure:**
```
/axiom/runtimes/
├── pgsd-runtime-base-2025/
│   ├── lib/          # Core libraries
│   ├── share/        # Shared data
│   └── runtime.yaml  # Runtime manifest
├── pgsd-runtime-2025/
└── pgsd-runtime-gui-2025/
```

**Runtime Manifest:**
```yaml
name: pgsd-runtime-2025
version: 2025.1.0
description: PGSD Full Runtime 2025
abi_version: "2025.1"
stable: true
core_packages:
  - libc
  - openssl
  - libcurl
  - sqlite
extensions:
  - name: python
    packages: [python3, python3-pip]
```

**Package Runtime Dependency:**
```yaml
# In package manifest.yaml
name: my-app
runtime: pgsd-runtime-2025
runtime_version: ">=2025.1"
```

---

## Phase 21: Desktop Integration ✓

**Priority**: Medium
**Complexity**: Low
**Dependencies**: Phase 18
**Status**: Complete

### Purpose

Integrate packages with desktop environments by generating .desktop files, installing icons, and registering MIME types.

### Implementation

**Files Created:**
- `src/desktop.zig` - Desktop integration helpers

**Features Implemented:**
- .desktop file generation (freedesktop.org standard)
- Icon installation (multiple sizes, SVG support)
- MIME type registration
- XDG directory support
- Desktop database updates
- Per-user and system-wide installation

### Design

**Desktop Entry in Manifest:**
```yaml
# In package manifest.yaml
desktop:
  name: "PGSD Viewer"
  generic_name: "Document Viewer"
  executable: bin/pgsd-viewer
  icon: icons/pgsd-viewer.svg
  categories: [Graphics, Viewer]
  keywords: [document, pdf, viewer]
  mime_types: [application/pdf, image/png]
  terminal: false
```

**Generated .desktop File:**
```ini
[Desktop Entry]
Type=Application
Version=1.0
Name=PGSD Viewer
GenericName=Document Viewer
Exec=/axiom/store/pkg/pgsd-viewer/1.0.0/1/abc123/root/bin/pgsd-viewer %F
Icon=axiom-pgsd-viewer
Categories=Graphics;Viewer;
Keywords=document;pdf;viewer;
MimeType=application/pdf;image/png;
Terminal=false
StartupNotify=true
```

**CLI Commands:**
```bash
# Install desktop integration
axiom desktop install hello@1.0.0

# Remove desktop integration
axiom desktop uninstall hello@1.0.0

# List installed desktop entries
axiom desktop list
```

---

## Phase 22: Ports Migration Tool

**Priority**: High
**Complexity**: High
**Dependencies**: Phase 9 (Import), Phase 10 (Build System)
**Status**: Complete

### Purpose

Provide a migration path from FreeBSD ports to Axiom packages, enabling rapid ecosystem bootstrapping and comparative testing against the existing pkg/ports infrastructure.

### Rationale

Axiom needs a large package ecosystem to be a viable daily driver. Rather than hand-crafting every manifest, a ports migration tool:

1. **Accelerates adoption** - Mechanical conversion of existing ports metadata
2. **Provides migration story** - Existing FreeBSD users can transition gradually
3. **Exposes design gaps** - Translation failures reveal missing Axiom primitives
4. **Enables comparison** - Build same software with both systems, compare results

### Implementation

#### Source File: `src/ports.zig`

**Key Types:**
- `PortsMigrator` - Main migration coordinator
- `PortMetadata` - Extracted port information from Makefiles
- `PortDependency` - Dependency with origin and version info
- `PortOption` - OPTIONS framework support
- `ConfigureStyle` - Build system detection (gnu_configure, cmake, meson, cargo, etc.)
- `MigrateOptions` - Configuration for migration behavior
- `MigrationResult` - Per-port migration outcome

**Key Functions:**
- `extractMetadata()` - Parse port Makefile using `make -V`
- `generateManifest()` - Convert PortMetadata to Axiom Manifest
- `generateDepsYaml()` - Convert dependencies to deps.yaml format
- `generateBuildYaml()` - Generate build recipe from USES
- `migrate()` - Full migration workflow
- `scanCategory()` - List all ports in a category

### Migration Phases

#### Phase 1: Metadata Only
Extract and convert without building:

```bash
axiom ports-gen editors/vim
# Creates:
#   ./generated/axiom-ports/editors/vim/manifest.yaml
#   ./generated/axiom-ports/editors/vim/deps.yaml
#   ./generated/axiom-ports/editors/vim/build.yaml
```

#### Phase 2: Happy-Path Builds
Build clean ports with Axiom builder:

```bash
axiom ports-gen editors/vim --build
# Generates manifests, then builds with Axiom builder
```

#### Phase 3: Full Import
Complete migration into the store:

```bash
axiom ports-import editors/vim
# Equivalent to: ports-gen --build --import
```

### Makefile Variable Extraction

Uses `make -V <varname>` to extract port metadata:

| Port Variable | Axiom Field |
|---------------|-------------|
| PORTNAME | manifest.name |
| PORTVERSION | manifest.version |
| PORTREVISION | manifest.revision |
| COMMENT | manifest.description |
| WWW | manifest.homepage |
| LICENSE | manifest.license |
| MAINTAINER | manifest.maintainer |
| CATEGORIES | (metadata comment) |
| RUN_DEPENDS | deps.yaml runtime |
| LIB_DEPENDS | deps.yaml runtime |
| BUILD_DEPENDS | deps.yaml build |
| USES | build.yaml phases |
| CONFLICTS | manifest.conflicts |

### Build System Detection

Detects configure style from USES:

| USES Pattern | ConfigureStyle | Generated Phases |
|--------------|----------------|------------------|
| autoreconf, gmake, libtool | gnu_configure | ./configure && make |
| cmake | cmake | cmake -B build && cmake --build |
| meson | meson | meson setup && meson compile |
| cargo | cargo | cargo build --release |
| go: | go | go build |
| python | python | python setup.py |

### CLI Commands

```bash
# Scan ports tree, list categories
axiom ports

# Scan specific category
axiom ports-scan devel

# Generate manifests only
axiom ports-gen editors/vim
axiom ports-gen devel/git --out ./my-ports

# Generate and build
axiom ports-gen shells/bash --build

# Full migration
axiom ports-import www/nginx

# Options
axiom ports-gen editors/vim --ports-tree /usr/ports
axiom ports-gen editors/vim --dry-run
```

### Known Limitations

The migration tool cannot handle:

1. **Complex bsd.port.mk conditionals** - Ports with heavy Makefile logic
2. **LOCALBASE assumptions** - Ports hardcoding /usr/local
3. **OPTIONS/FLAVORS combinatorics** - Only default options migrated
4. **rc.d scripts** - Service integration not yet supported
5. **sysusers/sysgroups** - User/group creation not handled

These limitations are intentional - they represent design questions for Axiom itself, not bugs in the migration tool.

### Example Output

```yaml
# manifest.yaml - Generated from FreeBSD port
name: vim
version: "9.0.2136"
revision: 0
description: Improved version of the vi editor
license: VIM
homepage: https://www.vim.org/
maintainer: adamw@FreeBSD.org

provides:
  - vim

conflicts:
  - vim-console
  - vim-tiny
```

```yaml
# deps.yaml - Generated from FreeBSD port
# Original categories: editors

runtime:
  - name: ncurses
    # origin: devel/ncurses
  - name: libiconv
    # origin: converters/libiconv

build:
  - name: pkgconf
    # origin: devel/pkgconf
```

```yaml
# build.yaml - Generated from FreeBSD port
name: vim
version: "9.0.2136"
description: Improved version of the vi editor

source:
  url: https://github.com/vim/vim/archive/v9.0.2136.tar.gz
  sha256: ...

# FreeBSD USES: ncurses pkgconf iconv

phases:
  configure: |
    ./configure --prefix=$PREFIX
  build: |
    make -j$JOBS
  install: |
    make install DESTDIR=$DESTDIR

post_process:
  strip: true
  compress_man: true
```

### Future Enhancements

1. **OPTIONS mapping** - Convert port options to Axiom variants
2. **FLAVORS support** - Generate multiple packages for flavored ports
3. **Batch migration** - Migrate entire categories with dependency ordering
4. **Conflict resolution** - Handle ports that provide same virtual packages
5. **rc.d integration** - Generate service management metadata

---

## Phase 23: Kernel Module Compatibility

**Priority**: Medium
**Complexity**: Medium
**Dependencies**: Phase 22 (Ports Migration)
**Status**: Complete

### Purpose

Provide kernel version compatibility checking for packages that install kernel modules (.ko files). This ensures that kmod packages are only installed on compatible kernels, preventing crashes and load failures.

### Rationale

FreeBSD kernel modules are tightly coupled to specific kernel versions:

1. **Kernel ABI changes** - Module structures may change between versions
2. **KBI (Kernel Binary Interface)** - Symbol layouts vary per kernel build
3. **KERNCONF variations** - Custom kernels may have different configurations

Unlike userland packages (which are ABI-compatible within major versions), kernel modules require exact or near-exact kernel version matching.

### Implementation

#### Manifest Schema

Added optional `kernel` section to `manifest.yaml`:

```yaml
kernel:
  kmod: true                      # Package installs .ko files
  freebsd_version_min: 1500000    # Minimum __FreeBSD_version
  freebsd_version_max: 1509999    # Maximum __FreeBSD_version
  kernel_idents:                  # Allowed kernel idents
    - "GENERIC"
    - "PGSD-GENERIC"
  require_exact_ident: false      # Strict ident matching
  kld_names:                      # Installed .ko files
    - "drm.ko"
    - "amdgpu.ko"
```

#### Source Files

**`src/manifest.zig`:**
- `KernelCompat` struct with all kernel compatibility fields
- Parsing and serialization of `kernel` section
- `isKernelBound()` helper method

**`src/resolver.zig`:**
- `KernelContext` struct - running kernel info
- `kernelIsCompatible()` - compatibility check function
- Resolver integration - skip incompatible candidates
- `KernelIncompatible` error type

**`src/ports.zig`:**
- `isKernelModule()` - detect kmods from USES/categories
- Automatic kernel section generation for migrated kmods

**`src/cli.zig`:**
- `kernel` / `kernel-check` command

### CLI Commands

```bash
# Check kernel compatibility of installed packages
axiom kernel
axiom kernel-check

# Example output:
# Kernel:
#   FreeBSD version (osreldate): 1502000
#   Kernel ident: GENERIC
#
# Kernel-bound packages:
#
#   [OK] drm-kmod-6.10.0_1
#        freebsd_version: 1500000-1509999
#        kernel_idents: GENERIC, PGSD-GENERIC
#
#   [INCOMPATIBLE] old-driver-0.9.0
#        freebsd_version_min: 1400000
#        freebsd_version_max: 1499999
#        reason: running kernel version exceeds maximum supported
#
# Summary:
#   1 compatible kernel-bound packages
#   1 incompatible kernel-bound packages
```

### Resolver Behavior

During dependency resolution:

1. If `manifest.kernel` is null → userland package, always compatible
2. If `manifest.kernel.kmod` is false → treat as userland
3. If `manifest.kernel.kmod` is true:
   - Check `freebsd_version_min` and `freebsd_version_max`
   - If `require_exact_ident`, check `kernel_idents`
   - Reject candidate if incompatible, try next version

### Ports Migration

When migrating ports with `USES=kmod` or `CATEGORIES=kld`:

1. Detected automatically by `isKernelModule()`
2. Kernel section generated with current system's version range
3. Range set to current major version (e.g., 1500000-1509999 for 15.x)
4. `kld_names` populated from port name

Example generated manifest for a kmod port:

```yaml
name: drm-kmod
version: "6.10.0"
# ... other fields ...

kernel:
  kmod: true
  freebsd_version_min: 1500000
  freebsd_version_max: 1509999
  require_exact_ident: false
  kld_names:
    - "drm-kmod.ko"
```

### Best Practices

1. **Userland packages**: Omit `kernel` section entirely
2. **Kernel modules**: Always set `kmod: true` and version range
3. **GPU drivers**: May need `kernel_idents` if built for specific kernels
4. **Version ranges**: Use major version range (1500000-1509999) for flexibility
5. **Exact ident**: Only enable when module is truly kernel-specific

### Future Enhancements

1. **Automatic detection** - Read `kern.osreldate` via sysctl
2. **Kernel package integration** - Treat kernel+kmods as unit
3. **Rebuild suggestions** - Offer to rebuild incompatible kmods
4. **Profile filtering** - `axiom kernel check --profile pgsd-kernel`

---

## Security Hardening Phases

The following phases address security vulnerabilities identified through threat modeling and code review. These are prioritized based on exploitation risk and attack surface exposure.

---

## Phase 24: Secure Tar Extraction ✓

**Priority**: Critical
**Complexity**: Medium
**Dependencies**: Phase 9 (Package Import)
**Status**: Complete

### Purpose

Harden tarball extraction in the import pipeline to prevent path traversal attacks, symlink escapes, and other archive-based vulnerabilities.

### Implementation

**Files Created:**
- `src/secure_tar.zig` - Secure tar extraction module

**Files Modified:**
- `src/import.zig` - Integrated SecureTarExtractor, added SecurityOptions

**Features Implemented:**
- Path validation (rejects `..`, absolute paths, NUL bytes, control characters)
- Symlink escape prevention (validates target stays within extraction root)
- Hardlink validation and blocking (disabled by default)
- Device node rejection (block devices, character devices)
- FIFO/socket rejection
- Permission controls (setuid/setgid stripping, permission masks)
- File size limits (per-file and total extraction limits)
- Compression support (gzip, xz, zstd via Zig std.compress)
- Extraction statistics reporting
- Legacy fallback mode for compatibility

### Threat Model

**Attack Vector**: Malicious tarball containing:
- Paths with `../` components (path traversal)
- Absolute paths targeting system files
- Symlinks pointing outside extraction directory
- Hardlinks to sensitive files
- Special files (devices, fifos)
- Filenames with embedded NUL bytes or control characters

**Impact**: Arbitrary file write, privilege escalation, system compromise

### Requirements

1. **Path Validation**
   - Reject paths containing `..` components
   - Reject absolute paths
   - Normalize paths before extraction
   - Validate path lengths against system limits

2. **Symlink Safety**
   - Resolve symlinks during extraction
   - Reject symlinks pointing outside extraction root
   - Option to convert symlinks to copies

3. **File Type Restrictions**
   - Reject device nodes (block/char)
   - Reject FIFOs and sockets
   - Configurable whitelist of allowed file types

4. **Permission Controls**
   - Strip setuid/setgid bits
   - Enforce maximum permission mask
   - Validate ownership (no root-owned files in user packages)

### Implementation

```zig
pub const SecureTarExtractor = struct {
    allocator: std.mem.Allocator,
    extraction_root: []const u8,
    options: ExtractOptions,

    pub const ExtractOptions = struct {
        allow_symlinks: bool = true,
        follow_symlinks: bool = false,
        allow_absolute_paths: bool = false,
        allow_parent_refs: bool = false,
        allow_devices: bool = false,
        allow_fifos: bool = false,
        max_path_length: usize = 1024,
        permission_mask: u32 = 0o755,
        strip_setuid: bool = true,
    };

    pub const ExtractionError = error{
        PathTraversal,
        AbsolutePath,
        SymlinkEscape,
        HardlinkEscape,
        DeviceNode,
        FifoSocket,
        PathTooLong,
        InvalidFilename,
        SetuidBit,
    };

    pub fn extract(self: *SecureTarExtractor, tar_path: []const u8) !void {
        // 1. Open tar archive
        // 2. For each entry:
        //    - Validate path (no ../, no absolute, no NUL)
        //    - Check file type against whitelist
        //    - Validate symlink targets stay within root
        //    - Apply permission mask
        //    - Extract to sanitized path
    }

    fn validatePath(self: *SecureTarExtractor, path: []const u8) ![]const u8 {
        // Check for embedded NUL bytes
        if (std.mem.indexOfScalar(u8, path, 0) != null) {
            return error.InvalidFilename;
        }

        // Check length
        if (path.len > self.options.max_path_length) {
            return error.PathTooLong;
        }

        // Check for absolute paths
        if (path[0] == '/') {
            if (!self.options.allow_absolute_paths) {
                return error.AbsolutePath;
            }
        }

        // Check for parent directory references
        var iter = std.mem.splitScalar(u8, path, '/');
        while (iter.next()) |component| {
            if (std.mem.eql(u8, component, "..")) {
                if (!self.options.allow_parent_refs) {
                    return error.PathTraversal;
                }
            }
        }

        // Normalize and resolve the path
        return self.normalizePath(path);
    }

    fn validateSymlink(self: *SecureTarExtractor, link_path: []const u8, target: []const u8) !void {
        // Resolve symlink target relative to link location
        // Verify resolved path stays within extraction_root
        const resolved = try self.resolveSymlinkTarget(link_path, target);
        if (!std.mem.startsWith(u8, resolved, self.extraction_root)) {
            return error.SymlinkEscape;
        }
    }
};
```

### CLI Integration

```bash
# Import with security options
axiom import package.tar.gz --secure  # Default: all hardening enabled

# Explicit options
axiom import package.tar.gz --no-symlinks --strict-paths

# Audit existing package
axiom audit package@1.0.0 --tar-safety
```

### Testing

- Test cases for each attack vector
- Fuzzing with malformed tarballs
- Integration tests with real-world packages
- Regression tests for CVE patterns

---

## Phase 25: Mandatory Signature Verification

**Priority**: Critical
**Complexity**: Medium
**Dependencies**: Phase 15 (Signature Verification)
**Status**: Complete

### Purpose

Enforce cryptographic verification of all packages before installation, with proper type-safe verification status handling.

### Implementation

**Files Modified:**
- `src/signature.zig` - Added type-safe VerificationStatus union, TrustLevel enum, VerifiedContent struct, AuditLog
- `src/import.zig` - Integrated verification enforcement in import pipeline with SecurityOptions
- `src/cli.zig` - Added CLI flags for verification control (--allow-unsigned, --no-verify, --verify-warn)

**Features Implemented:**
- Type-safe `VerificationStatus` union that prevents accidental use of unverified content
- `TrustLevel` enum (official, community, third_party, unknown) for signing key categorization
- `VerifiedContent` struct with content hash, signer key ID, signature time, and trust level
- `AuditLog` for tracking verification events with file-based logging
- `verifyPackageTypeSafe()` method in Verifier returning the type-safe status
- Verification enforcement in import pipeline before package processing
- CLI flags for user control over verification behavior

### Threat Model

**Attack Vector**:
- Installing unsigned packages via cache poisoning
- MITM attacks on package downloads
- Compromised mirror serving malicious packages
- Logic bugs where verification is skipped

**Impact**: Arbitrary code execution, supply chain compromise

### Requirements

1. **Verification Enforcement**
   - Default to strict verification mode
   - Explicit user action required to bypass
   - No silent fallback to unverified

2. **Type-Safe Verification**
   - Verification result as enum, not boolean
   - Cannot accidentally use unverified content
   - Compiler-enforced verification checks

3. **Trust Chain**
   - Verify repository index signatures
   - Verify individual package signatures
   - Cross-reference content hashes

4. **User Experience**
   - Clear messaging about verification status
   - Easy key management
   - Audit trail of verification decisions

### Implementation

```zig
/// Verification status - deliberately not a boolean to prevent
/// accidental use of unverified content
pub const VerificationStatus = union(enum) {
    verified: VerifiedContent,
    signature_missing: SignatureMissingInfo,
    signature_invalid: SignatureInvalidInfo,
    key_untrusted: KeyInfo,
    hash_mismatch: HashMismatchInfo,

    /// Only callable on verified status - compiler enforced
    pub fn getVerifiedContent(self: VerificationStatus) ?VerifiedContent {
        return switch (self) {
            .verified => |v| v,
            else => null,
        };
    }

    pub fn isVerified(self: VerificationStatus) bool {
        return self == .verified;
    }

    pub fn requireVerified(self: VerificationStatus) !VerifiedContent {
        return self.getVerifiedContent() orelse error.NotVerified;
    }
};

pub const VerifiedContent = struct {
    content_hash: [32]u8,
    signer_key_id: []const u8,
    signature_time: i64,
    trust_level: TrustLevel,
};

pub const TrustLevel = enum {
    official,      // PGSD release key
    community,     // Trusted community maintainer
    third_party,   // User-added key
    unknown,       // Key not in trust store
};

pub const SignatureVerifier = struct {
    trust_store: *TrustStore,
    mode: VerificationMode,
    audit_log: ?*AuditLog,

    pub const VerificationMode = enum {
        strict,      // Fail on any verification failure
        warn,        // Warn but allow (requires --allow-unverified)
        audit_only,  // Log but don't block (for migration)
    };

    pub fn verifyPackage(self: *SignatureVerifier, pkg_path: []const u8) VerificationStatus {
        // 1. Read signature file
        const sig_path = try std.fmt.allocPrint(self.allocator, "{s}/manifest.sig", .{pkg_path});
        const sig_data = std.fs.cwd().readFile(sig_path) catch {
            return .{ .signature_missing = .{ .path = pkg_path } };
        };

        // 2. Parse signature
        const signature = parseSignature(sig_data) catch |err| {
            return .{ .signature_invalid = .{ .parse_error = err } };
        };

        // 3. Find key in trust store
        const key = self.trust_store.getKey(signature.key_id) orelse {
            return .{ .key_untrusted = .{ .key_id = signature.key_id } };
        };

        // 4. Verify signature
        if (!ed25519.verify(signature.value, manifest_data, key.public)) {
            return .{ .signature_invalid = .{ .reason = "cryptographic verification failed" } };
        }

        // 5. Verify content hashes
        for (signature.files) |file_hash| {
            const actual_hash = try hashFile(file_hash.path);
            if (!std.mem.eql(u8, &actual_hash, &file_hash.sha256)) {
                return .{ .hash_mismatch = .{
                    .path = file_hash.path,
                    .expected = file_hash.sha256,
                    .actual = actual_hash,
                } };
            }
        }

        // 6. Log successful verification
        if (self.audit_log) |log| {
            log.recordVerification(pkg_path, signature.key_id, .success);
        }

        return .{ .verified = .{
            .content_hash = signature.content_hash,
            .signer_key_id = signature.key_id,
            .signature_time = signature.timestamp,
            .trust_level = key.trust_level,
        } };
    }
};

/// Import wrapper that enforces verification
pub fn importPackage(
    importer: *Importer,
    source: ImportSource,
    options: ImportOptions,
) !PackageId {
    // Verify before any extraction
    const verify_status = importer.verifier.verifyPackage(source);

    switch (verify_status) {
        .verified => |verified| {
            // Safe to proceed
            return importer.doImport(source, options, verified);
        },
        .signature_missing => |info| {
            if (options.allow_unsigned) {
                log.warn("Installing unsigned package: {s}", .{info.path});
                return importer.doImportUnverified(source, options);
            }
            return error.SignatureMissing;
        },
        else => |err_info| {
            log.err("Verification failed: {}", .{err_info});
            return error.VerificationFailed;
        },
    }
}
```

### CLI Integration

```bash
# Default: strict verification
axiom install package@1.0.0

# Explicit unsigned (requires confirmation)
axiom install package.tar.gz --allow-unsigned
# Warning: Installing unsigned package. This package has not been verified.
# Type 'yes' to continue:

# Check verification status
axiom verify package@1.0.0
# Package: package@1.0.0
# Status: VERIFIED
# Signer: PGSD Release Key <release@pgsdf.org>
# Key ID: A1B2C3D4E5F6
# Signed: 2025-11-15T10:30:00Z
# Trust Level: Official
```

---

## Phase 26: ZFS Dataset Path Validation

**Priority**: High
**Complexity**: Low
**Dependencies**: None
**Status**: Complete

### Purpose

Prevent ZFS operation injection and ensure all dataset operations target intended locations within the Axiom store hierarchy.

### Implementation

**Files Modified:**
- `src/zfs.zig` - Added `ZfsPathValidator` struct with comprehensive path validation
- `src/store.zig` - Integrated validation into `DatasetPaths.packageDataset()` and added validation helpers
- `src/cli.zig` - Added `zfs-validate` CLI command for testing path validation

**Features Implemented:**
- `ZfsPathValidator` with component and path validation
- Character allowlist enforcement (a-z, A-Z, 0-9, -, _, .)
- Reserved name rejection (., .., zfs, zpool, snapshot, bookmark, clone, origin)
- Snapshot reference (@) detection in dataset paths
- Bookmark reference (#) detection
- Path traversal (..) prevention
- Null byte and control character rejection
- Store hierarchy enforcement
- Snapshot path validation (`dataset@snapshot`)
- Component sanitization for user input
- Human-readable error messages

**CLI Command:**
```bash
axiom zfs-validate bash                    # Validate as component
axiom zfs-validate ../../../etc/passwd     # Detects traversal
axiom zfs-validate pkg@snap --type dataset # Detects snapshot in dataset
axiom zfs-validate 'pkg name'              # Detects invalid chars
```

### Threat Model

**Attack Vector**:
- Package names containing ZFS special characters
- Path injection via crafted version strings
- Dataset names escaping store hierarchy
- Snapshot name manipulation

**Impact**: Data destruction, unauthorized access to other datasets

### Requirements

1. **Path Canonicalization**
   - Validate all path components
   - Reject special characters in dataset names
   - Use allowlist for valid characters

2. **Hierarchy Enforcement**
   - All operations must target store subtree
   - Verify parent dataset ownership
   - Prevent cross-pool operations

3. **Command Injection Prevention**
   - Never interpolate user input into shell commands
   - Use libzfs APIs directly
   - Validate arguments before ZFS calls

### Implementation

```zig
pub const ZfsPathValidator = struct {
    store_root: []const u8,  // e.g., "zroot/axiom"

    /// Valid characters for dataset name components
    const valid_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.";

    pub const ValidationError = error{
        InvalidCharacter,
        EmptyComponent,
        ComponentTooLong,
        PathTooLong,
        OutsideStoreRoot,
        ReservedName,
        SnapshotInPath,
    };

    pub fn validateDatasetPath(self: *ZfsPathValidator, path: []const u8) ![]const u8 {
        // 1. Check path is within store root
        if (!std.mem.startsWith(u8, path, self.store_root)) {
            return error.OutsideStoreRoot;
        }

        // 2. Validate each component
        const relative = path[self.store_root.len..];
        var iter = std.mem.splitScalar(u8, relative, '/');
        while (iter.next()) |component| {
            if (component.len == 0) continue;
            try self.validateComponent(component);
        }

        // 3. Check for embedded snapshot references
        if (std.mem.indexOfScalar(u8, path, '@') != null) {
            return error.SnapshotInPath;
        }

        return path;
    }

    pub fn validateComponent(self: *ZfsPathValidator, component: []const u8) !void {
        _ = self;
        if (component.len == 0) {
            return error.EmptyComponent;
        }

        if (component.len > 255) {
            return error.ComponentTooLong;
        }

        // Check each character against allowlist
        for (component) |c| {
            if (std.mem.indexOfScalar(u8, valid_chars, c) == null) {
                return error.InvalidCharacter;
            }
        }

        // Check for reserved names
        const reserved = [_][]const u8{ ".", "..", "zfs", "zpool" };
        for (reserved) |r| {
            if (std.mem.eql(u8, component, r)) {
                return error.ReservedName;
            }
        }
    }

    pub fn validateSnapshotName(self: *ZfsPathValidator, dataset: []const u8, snap: []const u8) !void {
        try self.validateDatasetPath(dataset);
        try self.validateComponent(snap);
    }

    /// Build a safe dataset path from package ID
    pub fn buildPackagePath(
        self: *ZfsPathValidator,
        name: []const u8,
        version: []const u8,
        revision: u32,
        build_id: []const u8,
    ) ![]const u8 {
        // Validate each component
        try self.validateComponent(name);
        try self.validateComponent(version);
        try self.validateComponent(build_id);

        // Build path safely
        return std.fmt.allocPrint(
            self.allocator,
            "{s}/store/pkg/{s}/{s}/{d}/{s}",
            .{ self.store_root, name, version, revision, build_id },
        );
    }
};
```

### Integration Points

- `src/zfs.zig` - Wrap all ZFS operations with path validation
- `src/store.zig` - Use validator for package path construction
- `src/gc.zig` - Validate before dataset destruction

---

## Phase 27: Build Sandboxing

**Priority**: High
**Complexity**: High
**Dependencies**: Phase 10 (Build System)
**Status**: Complete

### Purpose

Isolate package builds to prevent build scripts from accessing or modifying the host system beyond their designated build environment.

### Implementation

**Files Modified:**
- `src/build.zig` - Added `SecureBuildSandbox` with FreeBSD jail integration, resource limits, and network policies
- `src/cli.zig` - Added CLI flags for sandbox security configuration

**Features Implemented:**
- `SecureBuildSandbox` struct with FreeBSD jail isolation
- `NetworkPolicy` union (none, fetch_only, full) for network control
- `ResourceLimits` struct for CPU, memory, disk, process limits
- `SandboxSecurityConfig` for comprehensive security settings
- Filesystem isolation with nullfs, tmpfs, and devfs mounts
- Resource limits enforcement via rctl (FreeBSD resource controls)
- Security audit logging for all sandbox operations
- CLI flags: `--allow-network`, `--no-sandbox`, `--memory`, `--cpu-time`, `--audit-log`

**Security Features:**
- FreeBSD jail(2) for process namespace isolation
- Network disabled by default (ip4=disable, ip6=disable)
- Read-only mounts for dependencies via nullfs
- tmpfs for /tmp to prevent disk abuse
- Restricted devfs ruleset
- Configurable securelevel (default: 3)
- CPU, memory, and process count limits via rctl

### Threat Model

**Attack Vector**:
- Malicious build.yaml executing arbitrary commands
- Build scripts accessing network
- Build scripts reading sensitive host files
- Build scripts modifying system state

**Impact**: System compromise, data exfiltration, supply chain attacks

### Requirements

1. **Filesystem Isolation**
   - Read-only access to dependencies
   - Write access only to build output
   - No access to host filesystem
   - Isolated /tmp and /var

2. **Network Isolation**
   - No network access by default
   - Explicit allowlist for source fetching
   - Proxy support for controlled access

3. **Process Isolation**
   - Separate UID/GID namespace
   - Limited capabilities
   - Resource limits (CPU, memory, disk)

4. **Syscall Filtering**
   - Capsicum capability mode
   - Seccomp-like restrictions
   - Audit logging of violations

### Implementation

```zig
pub const BuildSandbox = struct {
    allocator: std.mem.Allocator,
    config: SandboxConfig,
    jail_id: ?i32 = null,

    pub const SandboxConfig = struct {
        // Filesystem mounts
        build_root: []const u8,          // /build (rw)
        output_root: []const u8,         // /output (rw)
        deps_root: []const u8,           // /deps (ro)
        source_root: []const u8,         // /src (ro)

        // Resource limits
        max_cpu_seconds: u64 = 3600,     // 1 hour
        max_memory_mb: u64 = 4096,       // 4GB
        max_disk_mb: u64 = 10240,        // 10GB
        max_processes: u32 = 100,
        max_open_files: u32 = 1024,

        // Network policy
        network_access: NetworkPolicy = .none,

        // Security options
        allow_setuid: bool = false,
        allow_raw_sockets: bool = false,
        allow_mlock: bool = false,
    };

    pub const NetworkPolicy = union(enum) {
        none,
        fetch_only: []const []const u8,  // Allowlisted URLs for source fetch
        full,                             // Unrestricted (requires explicit flag)
    };

    pub fn create(self: *BuildSandbox) !void {
        // 1. Create jail with restricted permissions
        self.jail_id = try self.createJail();

        // 2. Set up filesystem namespace
        try self.mountFilesystems();

        // 3. Configure network restrictions
        try self.configureNetwork();

        // 4. Apply resource limits
        try self.applyResourceLimits();
    }

    fn createJail(self: *BuildSandbox) !i32 {
        // Use FreeBSD jail(2) for isolation
        var params = [_]jailparam{
            .{ .name = "name", .value = "axiom-build" },
            .{ .name = "path", .value = self.config.build_root },
            .{ .name = "securelevel", .value = "3" },
            .{ .name = "allow.raw_sockets", .value = if (self.config.allow_raw_sockets) "1" else "0" },
            .{ .name = "allow.set_hostname", .value = "0" },
            .{ .name = "allow.mount", .value = "0" },
        };
        return jail_set(&params, params.len, JAIL_CREATE);
    }

    fn mountFilesystems(self: *BuildSandbox) !void {
        // Mount dependencies read-only using nullfs
        try self.nullfsMount(self.config.deps_root, "/deps", .read_only);
        try self.nullfsMount(self.config.source_root, "/src", .read_only);

        // Mount output directory read-write
        try self.nullfsMount(self.config.output_root, "/output", .read_write);

        // Create tmpfs for /tmp
        try self.tmpfsMount("/tmp", 1024 * 1024 * 1024); // 1GB tmpfs
    }

    pub fn execute(self: *BuildSandbox, command: []const u8, env: []const []const u8) !ExecResult {
        // Fork and enter jail
        const pid = try std.os.fork();
        if (pid == 0) {
            // Child: enter jail and exec
            try jail_attach(self.jail_id.?);

            // Drop privileges
            try self.dropPrivileges();

            // Enter Capsicum capability mode (no new file opens)
            if (self.config.network_access == .none) {
                try cap_enter();
            }

            // Execute command
            try std.os.execve(command, env);
        }

        // Parent: wait and collect result
        return self.waitForChild(pid);
    }

    pub fn destroy(self: *BuildSandbox) void {
        if (self.jail_id) |id| {
            jail_remove(id);
        }
        self.unmountFilesystems();
    }
};
```

### Build Recipe Security

```yaml
# build.yaml security section
name: untrusted-package
version: "1.0.0"

security:
  sandbox: strict              # strict | permissive | none
  network: fetch-only          # none | fetch-only | full
  allowed_fetch_urls:
    - https://github.com/*
    - https://crates.io/*
  max_build_time: 1h
  max_disk_usage: 5G

phases:
  fetch:
    command: "curl -O ${SOURCE_URL}"
    network: fetch-only        # Phase-specific override
  build:
    command: "make"
    network: none              # No network during build
```

### CLI Integration

```bash
# Build with strict sandboxing (default)
axiom build package.yaml

# Build with permissive sandbox (for debugging)
axiom build package.yaml --sandbox=permissive

# Build without sandbox (requires explicit flag)
axiom build package.yaml --no-sandbox --i-understand-the-risks
```

---

## Phase 28: Secure Bundle Verification

**Priority**: High
**Complexity**: Medium
**Dependencies**: Phase 18 (Bundles)
**Status**: ✓ Complete

### Purpose

Ensure bundle integrity and authenticity before extraction and execution, preventing execution of tampered or malicious bundles.

### Threat Model

**Attack Vector**:
- Tampered bundle downloaded from unofficial source
- MITM attack substituting malicious bundle
- Bundle with embedded malware
- Bundle exploiting extraction vulnerabilities

**Impact**: Arbitrary code execution, malware installation

### Requirements

1. **Pre-Execution Verification**
   - Verify signature before extraction
   - Verify content hash before execution
   - Cache verification status

2. **Bundle Format Security**
   - Signed manifest at known offset
   - Content hash covers entire payload
   - No execution without verification

3. **Launcher Hardening**
   - Verify bundle before mounting
   - Secure temporary extraction
   - Clean up on failure

### Implementation

```zig
pub const SecureBundleLauncher = struct {
    verifier: *SignatureVerifier,
    temp_dir: []const u8,

    pub fn launch(self: *SecureBundleLauncher, bundle_path: []const u8) !LaunchResult {
        // 1. Verify bundle signature BEFORE any extraction
        const bundle_file = try std.fs.cwd().openFile(bundle_path, .{});
        defer bundle_file.close();

        // 2. Read and verify manifest from known offset
        const manifest_offset = try self.readManifestOffset(bundle_file);
        const manifest = try self.readAndVerifyManifest(bundle_file, manifest_offset);

        // 3. Verify payload hash matches manifest
        const payload_hash = try self.hashPayload(bundle_file, manifest.payload_offset, manifest.payload_size);
        if (!std.mem.eql(u8, &payload_hash, &manifest.payload_hash)) {
            return error.PayloadHashMismatch;
        }

        // 4. Only now safe to extract
        const extract_dir = try self.secureExtract(bundle_file, manifest);
        defer self.cleanup(extract_dir);

        // 5. Launch with verification token
        return self.launchVerified(extract_dir, manifest);
    }

    fn readAndVerifyManifest(
        self: *SecureBundleLauncher,
        file: std.fs.File,
        offset: u64,
    ) !BundleManifest {
        try file.seekTo(offset);
        const manifest_data = try file.readAlloc(self.allocator, 64 * 1024);

        // Verify manifest signature
        const sig_offset = std.mem.indexOf(u8, manifest_data, "---SIGNATURE---") orelse
            return error.SignatureNotFound;

        const manifest_bytes = manifest_data[0..sig_offset];
        const sig_bytes = manifest_data[sig_offset + 15 ..];

        const verify_result = self.verifier.verifyData(manifest_bytes, sig_bytes);
        switch (verify_result) {
            .verified => {},
            else => return error.ManifestVerificationFailed,
        }

        return try BundleManifest.parse(manifest_bytes);
    }

    fn secureExtract(
        self: *SecureBundleLauncher,
        file: std.fs.File,
        manifest: BundleManifest,
    ) ![]const u8 {
        // Create extraction directory with secure permissions
        const extract_dir = try std.fmt.allocPrint(
            self.allocator,
            "{s}/axiom-bundle-{x}",
            .{ self.temp_dir, std.crypto.random.int(u64) },
        );

        try std.fs.cwd().makePath(extract_dir);
        try std.fs.cwd().chmod(extract_dir, 0o700);

        // Extract using secure tar extractor
        var extractor = SecureTarExtractor{
            .allocator = self.allocator,
            .extraction_root = extract_dir,
            .options = .{
                .allow_symlinks = false,  // Bundles shouldn't need symlinks
                .strip_setuid = true,
            },
        };

        try file.seekTo(manifest.payload_offset);
        try extractor.extractFromReader(file.reader());

        return extract_dir;
    }
};
```

### Implementation Notes

**Completed**: December 2025

**Key Components Implemented**:

1. **BundleVerificationStatus enum** (`src/bundle.zig`)
   - Status tracking: unverified, verifying, verified, untrusted, invalid, tampered, unsigned
   - Helper methods: `isValid()`, `isSafe()`, `toString()`

2. **BundleVerificationResult struct** (`src/bundle.zig`)
   - Detailed verification information including signer ID, hashes, timestamps
   - Error message capture for debugging

3. **SecureBundleManifest struct** (`src/bundle.zig`)
   - Extended manifest format with verification fields
   - Payload offset, size, and SHA-256 hash
   - YAML parsing for manifest content

4. **SecureBundleLauncher struct** (`src/bundle.zig`)
   - Pre-execution signature verification
   - Ed25519 signature verification against trust store
   - SHA-256 payload hash verification
   - Secure extraction with restricted permissions
   - Verification result caching

5. **CLI Commands** (`src/cli.zig`)
   - `bundle-verify <file>` - Verify bundle integrity without running
   - `bundle-run <file>` - Run bundle with mandatory verification
   - Options: `--trust-store`, `--allow-unsigned`, `--allow-untrusted`, `--skip-verify`

**Security Features**:
- Signature verified BEFORE any extraction
- Payload hash verified BEFORE execution
- Extraction uses restricted permissions (0o700)
- Tar extraction with `--no-same-owner`, `--no-same-permissions`
- Clear warnings for unsigned/untrusted bundles
- DANGEROUS flag required to skip verification

---

## Phase 29: Resolver Resource Limits

**Priority**: Medium
**Complexity**: Low
**Dependencies**: Phase 16 (SAT Solver)
**Status**: ✓ Complete

### Purpose

Prevent denial-of-service through resource exhaustion during dependency resolution, particularly when using the SAT solver.

### Threat Model

**Attack Vector**:
- Malicious manifest with exponentially complex dependencies
- Circular dependencies causing infinite loops
- Memory exhaustion via large clause sets
- CPU exhaustion via complex SAT instances

**Impact**: System hang, denial of service, memory exhaustion

### Requirements

1. **Time Limits**
   - Maximum resolution time
   - Per-phase timeouts
   - Graceful degradation

2. **Memory Limits**
   - Maximum clause count
   - Maximum variable count
   - Arena allocator with cap

3. **Complexity Limits**
   - Maximum dependency depth
   - Maximum candidates per package
   - Cycle detection and limits

### Implementation

```zig
pub const ResourceLimitedResolver = struct {
    inner_resolver: *Resolver,
    limits: ResourceLimits,
    stats: ResourceStats,

    pub const ResourceLimits = struct {
        max_resolution_time_ms: u64 = 30_000,  // 30 seconds
        max_memory_bytes: usize = 256 * 1024 * 1024,  // 256MB
        max_dependency_depth: u32 = 100,
        max_candidates_per_package: u32 = 1000,
        max_sat_variables: u32 = 100_000,
        max_sat_clauses: u32 = 1_000_000,
    };

    pub const ResourceStats = struct {
        start_time: i64,
        memory_used: usize,
        depth_reached: u32,
        candidates_examined: u32,
        sat_variables: u32,
        sat_clauses: u32,
    };

    pub fn resolve(self: *ResourceLimitedResolver, requests: []PackageRequest) ![]PackageId {
        self.stats = .{
            .start_time = std.time.milliTimestamp(),
            .memory_used = 0,
            .depth_reached = 0,
            .candidates_examined = 0,
            .sat_variables = 0,
            .sat_clauses = 0,
        };

        // Create arena with memory limit
        var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena.deinit();

        // Wrap allocator with limit checking
        const limited_alloc = self.createLimitedAllocator(&arena);

        // Run resolution with resource checks
        return self.inner_resolver.resolveWithCallbacks(
            limited_alloc,
            requests,
            .{
                .on_candidate = self.checkCandidateLimits,
                .on_depth = self.checkDepthLimit,
                .on_sat_var = self.checkSatVarLimit,
                .on_sat_clause = self.checkSatClauseLimit,
            },
        );
    }

    fn checkTimeLimit(self: *ResourceLimitedResolver) !void {
        const elapsed = std.time.milliTimestamp() - self.stats.start_time;
        if (elapsed > self.limits.max_resolution_time_ms) {
            return error.ResolutionTimeout;
        }
    }

    fn checkMemoryLimit(self: *ResourceLimitedResolver, size: usize) !void {
        self.stats.memory_used += size;
        if (self.stats.memory_used > self.limits.max_memory_bytes) {
            return error.MemoryLimitExceeded;
        }
    }
};
```

### CLI Integration

```bash
# Resolve with custom limits
axiom resolve my-profile --timeout 60s --max-memory 512M

# Show resource usage
axiom resolve my-profile --stats
# Resolution completed in 1.2s
# Memory used: 45MB
# Candidates examined: 1234
# Maximum depth: 12
```

### Implementation Notes

**Completed**: December 2025

**Key Components Implemented**:

1. **ResourceLimits struct** (`src/resolver.zig`)
   - Configurable limits for time, memory, depth, candidates, SAT solver
   - Default limits: 30s timeout, 256MB memory, 100 depth
   - `strict()` preset for untrusted inputs
   - `unlimited()` preset for testing

2. **ResourceStats struct** (`src/resolver.zig`)
   - Tracks resolution time, memory, candidates examined
   - Per-package candidate counting
   - SAT variable/clause counting
   - Limit violation detection with specific type

3. **ResourceChecker struct** (`src/resolver.zig`)
   - Time limit checking with periodic verification
   - Memory tracking and limit enforcement
   - Depth limit enforcement
   - Candidate limit enforcement (per-package and total)
   - SAT complexity limit enforcement

4. **Resolver Integration** (`src/resolver.zig`)
   - `setResourceLimits()` method
   - `setShowStats()` method
   - `getLastStats()` method
   - Automatic stats initialization and cleanup

5. **CLI Options** (`src/cli.zig`)
   - `--timeout <seconds>` - Set resolution timeout
   - `--max-memory <MB>` - Set memory limit
   - `--max-depth <n>` - Set dependency depth limit
   - `--strict` - Use strict limits for untrusted inputs
   - `--stats` - Show resolution statistics

6. **Error Handling**
   - New error types: `ResolutionTimeout`, `MemoryLimitExceeded`,
     `DepthLimitExceeded`, `CandidateLimitExceeded`, `ComplexityLimitExceeded`
   - Detailed diagnostics showing which limit was hit
   - Contextual suggestions for resolving limit issues

**Security Features**:
- Prevents DoS through malicious manifests with exponential complexity
- Detects and blocks circular dependencies that cause infinite loops
- Memory capping prevents system exhaustion
- Time limits prevent CPU exhaustion
- Strict mode available for processing untrusted package sources

---

## Phase 30: Thread-Safe libzfs

**Priority**: Medium
**Complexity**: Medium
**Dependencies**: None
**Status**: ✓ Complete

### Purpose

Ensure thread-safe operation of ZFS operations throughout Axiom to prevent race conditions and data corruption in concurrent scenarios.

### Implementation Notes (Completed)

The thread-safe libzfs implementation provides:

1. **ThreadSafeZfs struct** (`src/zfs.zig`)
   - Global mutex serializing all libzfs operations
   - Lazy handle initialization with double-checked locking
   - Atomic reference counting for lifecycle management
   - Per-thread error context using thread ID-keyed hash map

2. **ScopedOperation for RAII-style management**
   - Automatic lock acquisition/release
   - Safe handle access within scope
   - Proper cleanup via deinit()

3. **Thread-safe operation wrappers**
   - datasetExists(), createDataset(), destroyDataset()
   - snapshot(), clone(), setProperty()
   - mount(), unmount()

4. **Global singleton pattern**
   - getGlobalThreadSafeZfs() for shared access
   - deinitGlobalThreadSafeZfs() for cleanup

5. **Tests**
   - Basic initialization tests
   - ScopedOperation lifecycle tests
   - Error context operations
   - Concurrent reference counting stress test (10 threads, 1000 iterations each)

### Threat Model

**Attack Vector**:
- Race conditions in concurrent ZFS operations
- Use-after-free in libzfs handles
- Inconsistent state from interleaved operations
- Double-free or handle leaks

**Impact**: Data corruption, crashes, undefined behavior

### Requirements

1. **Handle Safety**
   - Single handle per thread OR global lock
   - RAII-style handle management
   - Safe handle sharing

2. **Operation Atomicity**
   - Compound operations protected
   - Consistent error handling
   - Transaction semantics where possible

3. **Progress Isolation**
   - Per-operation progress tracking
   - Thread-local error context
   - Safe cancellation

### Implementation

```zig
pub const ThreadSafeZfs = struct {
    /// Global lock for libzfs operations
    /// libzfs is not thread-safe, so we serialize all access
    global_lock: std.Thread.Mutex = .{},

    /// Per-thread handles to avoid handle sharing issues
    thread_handles: std.Thread.LocalStorage(*libzfs_handle_t),

    pub fn getHandle(self: *ThreadSafeZfs) !*libzfs_handle_t {
        // Check for existing thread-local handle
        if (self.thread_handles.get()) |handle| {
            return handle;
        }

        // Create new handle for this thread
        self.global_lock.lock();
        defer self.global_lock.unlock();

        const handle = libzfs_init() orelse return error.ZfsInitFailed;
        self.thread_handles.set(handle);
        return handle;
    }

    /// Execute a ZFS operation with proper locking
    pub fn withLock(self: *ThreadSafeZfs, comptime func: anytype, args: anytype) !@TypeOf(func).ReturnType {
        self.global_lock.lock();
        defer self.global_lock.unlock();

        const handle = try self.getHandle();
        return @call(.auto, func, .{handle} ++ args);
    }

    /// Scoped ZFS operation with automatic cleanup
    pub fn scopedOperation(self: *ThreadSafeZfs) ScopedOperation {
        return .{
            .zfs = self,
            .lock_held = false,
        };
    }

    pub const ScopedOperation = struct {
        zfs: *ThreadSafeZfs,
        lock_held: bool,

        pub fn begin(self: *ScopedOperation) !*libzfs_handle_t {
            self.zfs.global_lock.lock();
            self.lock_held = true;
            return self.zfs.getHandle();
        }

        pub fn end(self: *ScopedOperation) void {
            if (self.lock_held) {
                self.zfs.global_lock.unlock();
                self.lock_held = false;
            }
        }

        pub fn deinit(self: *ScopedOperation) void {
            self.end();
        }
    };
};

// Example usage in store operations
pub fn createPackageDataset(store: *PackageStore, pkg_id: PackageId) !void {
    var op = store.zfs.scopedOperation();
    defer op.deinit();

    const handle = try op.begin();

    // All ZFS operations are now serialized
    const dataset_name = try store.paths.packageDataset(store.allocator, pkg_id);
    const dataset = zfs_create(handle, dataset_name, ZFS_TYPE_FILESYSTEM, null);
    if (dataset == null) {
        return error.DatasetCreateFailed;
    }
    defer zfs_close(dataset);

    // Create snapshot
    const snapshot_name = try std.fmt.allocPrint(store.allocator, "{s}@installed", .{dataset_name});
    if (zfs_snapshot(handle, snapshot_name, 0, null) != 0) {
        return error.SnapshotCreateFailed;
    }
}
```

### Testing

```zig
test "concurrent ZFS operations" {
    var zfs = ThreadSafeZfs{};

    // Spawn multiple threads performing ZFS operations
    var threads: [10]std.Thread = undefined;
    for (&threads) |*t| {
        t.* = try std.Thread.spawn(.{}, concurrentZfsWorker, .{&zfs});
    }

    for (threads) |t| {
        t.join();
    }
}

fn concurrentZfsWorker(zfs: *ThreadSafeZfs) void {
    for (0..100) |i| {
        _ = zfs.withLock(listDatasets, .{}) catch continue;
    }
}
```

---

## Phase 31: Resolver Backtracking

**Priority**: Medium
**Complexity**: Medium
**Status**: ✓ Complete

### Purpose

Enhance the greedy resolver with backtracking capability for small dependency graphs, improving resolution success rate without the overhead of full SAT solving.

### Features Implemented

1. **Backtracking Strategy**
   - New `greedy_with_backtracking` resolution strategy
   - Tries alternative versions when conflicts detected
   - Automatic fallback to SAT for large graphs (>20 packages)
   - Configurable backtrack limits

2. **Version Preferences**
   - `newest` - Pick newest satisfying version (default)
   - `stable` - Prefer .0 patch releases and older versions
   - `oldest` - Pick oldest satisfying version

3. **Configuration**
   ```zig
   pub const BacktrackConfig = struct {
       max_backtracks_per_package: u32 = 5,
       max_total_backtracks: u32 = 50,
       small_graph_threshold: u32 = 20,
   };
   ```

### Usage

```bash
# Use backtracking strategy
axiom resolve myprofile --strategy backtracking

# Use stable version preference
axiom resolve myprofile --prefer stable
```

---

## Phase 32: Bootstrap Automation

**Priority**: High
**Complexity**: Low
**Status**: ✓ Complete

### Purpose

Provide a single command to bootstrap Axiom from FreeBSD ports, eliminating the need for users to manually determine and sequence the bootstrap chain.

### Features Implemented

1. **`axiom bootstrap-ports` Command**
   - Automatically builds help2man → m4 → gmake chain
   - Supports minimal (3 packages) or full (9 packages) bootstrap
   - Checks for existing installations and skips
   - Dry-run mode to preview build plan

2. **Bootstrap Chain**
   - Minimal: help2man, m4, gmake
   - Full: + gettext-runtime, perl, autoconf, automake, libtool, pkgconf

### Usage

```bash
# Full bootstrap
sudo axiom bootstrap-ports

# Minimal bootstrap
sudo axiom bootstrap-ports --minimal

# Preview what would be built
axiom bootstrap-ports --dry-run

# With parallel jobs
sudo axiom bootstrap-ports --jobs 8
```

---

## Phase 33: Unified Test Infrastructure

**Priority**: Medium
**Complexity**: Low
**Status**: ✓ Complete

### Purpose

Consolidate test execution into unified build targets for CI/CD and local development.

### Features Implemented

1. **New Build Targets**
   - `zig build check` - Quick compilation check
   - `zig build test` - Unit tests (no root required)
   - `zig build test-full` - All unit tests including ZFS
   - `zig build ci` - CI suite (build + safe unit tests)
   - `zig build ci-full` - Full CI (requires root + ZFS)

2. **Test Organization**
   - Tests organized by privilege requirements
   - Module-level unit tests for types, manifest, signature
   - Integration tests via test executables

### CI Usage

```bash
# GitHub Actions / CI Pipeline
zig build ci           # Safe for unprivileged CI runners

# Local development with ZFS
sudo zig build ci-full # Complete test suite
```

---

## Phase 34: CLI Resolution Options

**Priority**: Medium
**Complexity**: Low
**Status**: Planned

### Purpose

Expose resolver backtracking and version preference options through the CLI.

### Requirements

1. **Strategy Selection**
   ```bash
   axiom resolve myprofile --strategy greedy
   axiom resolve myprofile --strategy backtracking
   axiom resolve myprofile --strategy sat
   ```

2. **Version Preference**
   ```bash
   axiom resolve myprofile --prefer newest
   axiom resolve myprofile --prefer stable
   axiom resolve myprofile --prefer oldest
   ```

3. **Backtrack Configuration**
   ```bash
   axiom resolve myprofile --max-backtracks 100
   axiom resolve myprofile --backtrack-threshold 30
   ```

4. **Profile-Level Defaults**
   ```yaml
   # profile.yaml
   name: production
   resolver:
     strategy: greedy_with_sat_fallback
     preference: stable
     max_backtracks: 50
   ```

---

## Phase 35: Dependency Graph Visualization

**Priority**: Low
**Complexity**: Medium
**Status**: Planned

### Purpose

Provide tools to visualize and analyze dependency graphs for debugging and optimization.

### Requirements

1. **Graph Export**
   ```bash
   axiom deps-graph myprofile --format dot > deps.dot
   axiom deps-graph myprofile --format json > deps.json
   ```

2. **Analysis Tools**
   ```bash
   axiom deps-analyze myprofile    # Show depth, breadth, cycles
   axiom deps-why myprofile pkg    # Why is pkg included?
   axiom deps-path myprofile a b   # Path from a to b
   ```

3. **Output Formats**
   - DOT (Graphviz)
   - JSON (for tooling)
   - ASCII tree (for terminal)

---

## Phase 36: HSM/PKCS#11 Signing

**Priority**: Medium
**Complexity**: High
**Status**: Planned

### Purpose

Support hardware security modules for package signing in high-security environments.

### Requirements

1. **PKCS#11 Integration**
   - Load keys from HSM
   - Sign packages without exposing private key
   - Support for YubiKey, SoftHSM, cloud HSMs

2. **Configuration**
   ```yaml
   # /etc/axiom/signing.yaml
   signing:
     provider: pkcs11
     library: /usr/lib/opensc-pkcs11.so
     slot: 0
     key_id: "axiom-release"
   ```

3. **CLI**
   ```bash
   axiom sign mypackage --hsm --slot 0
   axiom key-list --hsm
   ```

---

## Phase 37: Multi-Party Signing

**Priority**: Medium
**Complexity**: High
**Status**: Planned

### Purpose

Require multiple signatures for critical packages, implementing threshold signing.

### Requirements

1. **Threshold Configuration**
   ```yaml
   # Package requires 2-of-3 signatures
   signing:
     threshold: 2
     signers:
       - pgsd-release-key
       - security-team-key
       - qa-team-key
   ```

2. **Verification**
   - Count valid signatures
   - Verify threshold met
   - Report which signers approved

3. **CLI**
   ```bash
   axiom sign mypackage --key my-key    # Add signature
   axiom verify mypackage --threshold 2  # Verify threshold
   axiom signatures mypackage           # List all signatures
   ```

---

## Phase 38: Service Management Integration

**Priority**: High
**Complexity**: High
**Status**: Planned

### Purpose

Integrate with FreeBSD rc.d service management for packages that provide services.

### Requirements

1. **Service Declaration**
   ```yaml
   # manifest.yaml
   services:
     - name: nginx
       type: daemon
       rc_script: etc/rc.d/nginx
       dependencies: [networking]
   ```

2. **Service Commands**
   ```bash
   axiom service list                  # List services from profile
   axiom service enable nginx          # Enable service
   axiom service start nginx           # Start service
   axiom service status                # Show all service status
   ```

3. **Environment Activation**
   - Automatically configure rc.conf.d
   - Handle service conflicts between environments
   - Support service restart on package update

---

## Phase 39: Boot Environment Support

**Priority**: High
**Complexity**: Medium
**Status**: Planned

### Purpose

First-class support for ZFS boot environments, enabling atomic system upgrades with rollback.

### Requirements

1. **Boot Environment Commands**
   ```bash
   axiom be list                       # List boot environments
   axiom be create myenv               # Create from current
   axiom be activate myenv             # Set as default boot
   axiom be destroy myenv              # Remove boot environment
   axiom be rollback                   # Revert to previous
   ```

2. **System Profile Integration**
   ```bash
   axiom system-upgrade --be           # Upgrade in new BE
   axiom realize-system prod --be new  # Realize to new BE
   ```

3. **Automatic BE Creation**
   - Create BE before system changes
   - Name with timestamp
   - Configurable retention policy

---

## Phase 40: Remote Binary Cache Protocol

**Priority**: High
**Complexity**: High
**Status**: Planned

### Purpose

Define and implement a standard protocol for Axiom binary caches, enabling efficient package distribution.

### Requirements

1. **Protocol Specification**
   - RESTful API for package queries
   - Efficient binary transfer (range requests, compression)
   - Signature verification at source
   - Metadata synchronization

2. **Cache Server**
   ```bash
   axiom-cache-server --port 8080 --store /path/to/store
   ```

3. **Client Configuration**
   ```yaml
   # /etc/axiom/caches.yaml
   caches:
     - url: https://cache.pgsd.org
       priority: 100
       trust: pgsd-release-key
     - url: https://internal.example.com/axiom
       priority: 50
       trust: internal-key
   ```

4. **Operations**
   ```bash
   axiom cache fetch bash@5.2.0       # Fetch from cache
   axiom cache push bash@5.2.0        # Push to cache
   axiom cache sync                   # Sync metadata
   ```

---

## Security Hardening Roadmap Summary

| Phase | Risk Level | Attack Surface | Status |
|-------|------------|----------------|--------|
| 24 | Critical | Tarball import | ✓ Complete |
| 25 | Critical | All package operations | ✓ Complete |
| 26 | High | ZFS operations | ✓ Complete |
| 27 | High | Build execution | ✓ Complete |
| 28 | High | Bundle execution | ✓ Complete |
| 29 | Medium | Resolver DoS | ✓ Complete |
| 30 | Medium | Concurrent operations | ✓ Complete |

### Recommended Implementation Order

1. **Phase 25** - Mandatory signature verification (blocks supply chain attacks)
2. **Phase 24** - Secure tar extraction (blocks immediate code execution)
3. **Phase 26** - ZFS path validation (low complexity, high impact)
4. **Phase 28** - Bundle verification (extends existing signature work)
5. **Phase 27** - Build sandboxing (complex but high value)
6. **Phase 29** - Resolver limits (protects against DoS)
7. **Phase 30** - Thread-safe libzfs (stability improvement)

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
**Date**: 2025
