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
| 34 | CLI Resolution Options | Medium | Low | Phase 31 | ✓ Complete |
| 35 | Dependency Graph Visualization | Low | Medium | Phase 16 | ✓ Complete |
| 36 | HSM/PKCS#11 Signing | Medium | High | Phase 15 | ✓ Complete |
| 37 | Multi-Party Signing | Medium | High | Phase 36 | ✓ Complete |
| 38 | Service Management Integration | High | High | Phase 22 | ✓ Complete |
| 39 | Boot Environment Support | High | Medium | None | ✓ Complete |
| 40 | Remote Binary Cache Protocol | High | High | Phase 17 | ✓ Complete |
| 41 | Format Versioning | High | Low | None | ✓ Complete |
| 42 | Store Invariants & GC Guarantees | High | Medium | None | ✓ Complete |
| 43 | Advanced Resolver Semantics | Medium | High | Phase 16 | ✓ Complete |
| 44 | Realization Specification | High | Medium | None | ✓ Complete |
| 45 | Build Provenance Enforcement | High | Medium | Phase 15 | ✓ Complete |
| 46 | Binary Cache Trust Model | High | Medium | Phase 40 | ✓ Complete |
| 47 | Boot Environment Deep Integration | Medium | High | Phase 39 | ✓ Complete |
| 48 | Multi-User Security Model | High | High | Phase 12 | ✓ Complete |
| 49 | Error Model & Recovery | High | Medium | None | ✓ Complete |
| 50 | Testing & Validation Framework | Critical | High | None | ✓ Complete |
| 51 | Critical Security Fixes | Critical | Medium | None | ✓ Complete |
| 52 | Error Handling Overhaul | High | Medium | None | ✓ Complete |
| 53 | Input Validation Framework | High | Medium | None | ✓ Complete |
| 54 | Memory Safety Audit | High | Medium | None | ✓ Complete |
| 55 | Concurrency Safety | High | Medium | Phase 30 | ✓ Complete |
| 56 | Module Decoupling | Medium | High | None | Planned |

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
**Status**: Complete

### Purpose

Expose resolver backtracking and version preference options through the CLI.

### Changes Made

1. **Strategy Selection** - Added `--strategy` option with `backtracking` support:
   ```bash
   axiom resolve myprofile --strategy greedy
   axiom resolve myprofile --strategy backtracking
   axiom resolve myprofile --strategy sat
   axiom resolve myprofile --strategy auto  # default - greedy with SAT fallback
   ```

2. **Version Preference** - Added `--prefer` option:
   ```bash
   axiom resolve myprofile --prefer newest   # default
   axiom resolve myprofile --prefer stable   # for production environments
   axiom resolve myprofile --prefer oldest   # minimum required versions
   ```

3. **Backtrack Configuration** - Added granular control:
   ```bash
   axiom resolve myprofile --max-backtracks 10      # per-package limit
   axiom resolve myprofile --total-backtracks 100   # total limit
   axiom resolve myprofile --backtrack-threshold 30 # graph size threshold
   ```

4. **Combined Usage Example**:
   ```bash
   # Production-grade resolution with stable versions
   axiom resolve production --strategy backtracking --prefer stable --max-backtracks 10

   # Fast development resolution
   axiom resolve dev --strategy greedy --prefer newest
   ```

### Future Enhancement

Profile-level defaults (deferred to future phase):
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
**Status**: Complete

### Purpose

Provide tools to visualize and analyze dependency graphs for debugging and optimization.

### Changes Made

1. **Graph Export** - `axiom deps-graph` command:
   ```bash
   axiom deps-graph myprofile                    # ASCII tree (default)
   axiom deps-graph myprofile --format dot       # Graphviz DOT format
   axiom deps-graph myprofile --format json      # JSON for tooling
   axiom deps-graph myprofile --depth 3          # Limit tree depth
   axiom deps-graph myprofile --output deps.dot  # Write to file
   ```

2. **Graph Analysis** - `axiom deps-analyze` command:
   ```bash
   axiom deps-analyze myprofile
   # Output:
   # Package Count:     47
   # Direct Dependencies: 5
   # Transitive Dependencies: 42
   # Maximum Depth:     8
   # Average Depth:     4.2
   # Maximum Fanout:    12
   # Most Depended On:  libc (23 dependents)
   ```

3. **Dependency Explanation** - `axiom deps-why` command:
   ```bash
   axiom deps-why myprofile openssl
   # Shows:
   # - Whether directly requested
   # - Which packages depend on it
   # - Full dependency chains from requested packages
   ```

4. **Path Finding** - `axiom deps-path` command:
   ```bash
   axiom deps-path myprofile bash openssl
   # Shows shortest dependency path:
   # bash
   # └─ readline
   #    └─ ncurses
   #       └─ openssl
   ```

### Output Formats

- **tree**: ASCII tree with box-drawing characters (default)
- **dot**: Graphviz DOT format for visualization with `dot -Tpng deps.dot -o deps.png`
- **json**: Machine-readable JSON with full package metadata

---

## Phase 36: HSM/PKCS#11 Signing

**Priority**: Medium
**Complexity**: High
**Status**: ✓ Complete

### Purpose

Support hardware security modules for package signing in high-security environments.

### Implementation

1. **PKCS#11 Abstraction Layer** (`src/hsm.zig`)
   - PKCS#11 constants (CKR, CKO, CKK, CKM, CKA, CKU, CKF)
   - `HsmConfig` for configuration management
   - `HsmProvider` for HSM operations (initialize, listSlots, listKeys, login, sign)
   - `HsmSigner` for unified software/HSM signing interface
   - Support for YubiKey, SoftHSM, OpenSC, AWS CloudHSM

2. **Configuration**
   ```yaml
   # /etc/axiom/hsm.yaml
   library: /usr/lib/softhsm/libsofthsm2.so
   slot: 0
   key_label: axiom-signing
   ```

3. **CLI Commands**
   ```bash
   # List available HSM slots
   axiom hsm-list [--library <path>] [--verbose]

   # List signing keys on HSM
   axiom hsm-keys --slot 0 --pin <pin> [--library <path>]
   ```

4. **Key Structures**
   - `SlotInfo`: HSM slot information (slot_id, description, token_present, token_label)
   - `KeyInfo`: Key metadata (key_id, label, key_type, can_sign)
   - `SigningMode`: enum for software vs HSM signing

### Common PKCS#11 Library Paths

| Device/Software | Linux Path | FreeBSD Path |
|----------------|------------|--------------|
| SoftHSM | `/usr/lib/softhsm/libsofthsm2.so` | `/usr/local/lib/softhsm/libsofthsm2.so` |
| YubiKey | `/usr/lib/libykcs11.so` | `/usr/local/lib/libykcs11.so` |
| OpenSC | `/usr/lib/opensc-pkcs11.so` | `/usr/local/lib/opensc-pkcs11.so` |
| AWS CloudHSM | `/opt/cloudhsm/lib/libcloudhsm_pkcs11.so` | N/A |

---

## Phase 37: Multi-Party Signing

**Priority**: Medium
**Complexity**: High
**Status**: ✓ Complete

### Purpose

Require multiple signatures for critical packages, implementing threshold signing.

### Implementation

1. **Multi-Signature Data Structures** (`src/signature.zig`)
   - `MultiSignatureConfig`: Threshold and authorized signer configuration
   - `MultiSignature`: Container for multiple signatures on a package
   - `SignatureEntry`: Individual signature with metadata
   - `MultiSignatureResult`: Verification result with detailed status
   - `MultiSignatureVerifier`: Verify packages against multi-party policies
   - `MultiSignatureSigner`: Add signatures to packages

2. **Configuration Format**
   ```yaml
   # Multi-party signing policy
   threshold: 2
   policy_name: "Release Policy"
   signers:
     - pgsd-release-key
     - security-team-key
     - qa-team-key
   required_signers:
     - pgsd-release-key
   ```

3. **CLI Commands**
   ```bash
   # List all signatures on a package
   axiom signatures mypackage

   # Verify threshold requirement
   axiom signatures mypackage --threshold 2

   # Add signature (existing command, creates .msig for multi-sig)
   axiom sign mypackage --key my-key
   ```

4. **File Format**
   - Single signature: `manifest.sig` (YAML)
   - Multi-signature: `manifest.msig` (YAML with multiple signature entries)

### Features

- **Threshold Verification**: M-of-N signature requirements
- **Authorized Signers**: Restrict which keys can sign
- **Required Signers**: Mandate specific key signatures
- **Backward Compatible**: Falls back to single signature verification
- **Trust Level Tracking**: Each signature tracks key trust level

---

## Phase 38: Service Management Integration

**Priority**: High
**Complexity**: High
**Status**: ✓ Complete

### Purpose

Integrate with FreeBSD rc.d service management for packages that provide services.

### Implementation

1. **Service Module** (`src/service.zig`)
   - `ServiceDeclaration`: Service definition in package manifests
   - `ServiceType`: daemon, oneshot, periodic, network
   - `ServiceStatus`: running, stopped, starting, stopping, failed, unknown
   - `ServiceManager`: FreeBSD rc.d integration
   - `ServiceConfig`: rc.conf.d configuration generator

2. **Manifest Integration**
   ```yaml
   # manifest.yaml
   services:
     - name: nginx
       type: daemon
       rc_script: etc/rc.d/nginx
       description: "Web server"
       default_enabled: true
       dependencies:
         - networking
         - syslogd
       ports:
         - 80
         - 443
       user: www
       group: www
   ```

3. **CLI Commands**
   ```bash
   axiom service-list                  # List services from profile
   axiom service-status nginx          # Show service status
   axiom service-enable nginx          # Enable service at boot
   axiom service-disable nginx         # Disable service
   axiom service-start nginx           # Start service
   axiom service-stop nginx            # Stop service
   axiom service-restart nginx         # Restart service
   ```

4. **rc.conf.d Integration**
   - Generates `/etc/rc.conf.d/<service>` configuration files
   - Non-destructive: doesn't modify main rc.conf
   - Supports custom service variables

### Features

- **Service Declaration**: Packages can declare services in manifest
- **FreeBSD rc.d Integration**: Uses native `service` command
- **rc.conf.d Management**: Clean separation of Axiom-managed config
- **Service Dependencies**: Tracks service dependencies
- **Conflict Detection**: Prevents conflicting services
- **Status Monitoring**: Check running state of services

---

## Phase 39: Boot Environment Support

**Priority**: High
**Complexity**: Medium
**Status**: ✅ Implemented

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

### Implementation

Created `src/bootenv.zig` with complete ZFS boot environment management:

**Core Types:**
- `BootEnvironment` - BE information (name, active status, mountpoint, space, creation time)
- `CreateOptions` - Options for BE creation (source, activate, description)
- `ActivateOptions` - Options for BE activation (temporary)
- `RetentionPolicy` - Policy for automatic BE cleanup (max count, max age, patterns)
- `BeHooks` - Integration hooks for automatic snapshots before system changes

**Boot Environment Manager:**
- `list()` - List all boot environments via `bectl list -H`
- `getActive()` - Get currently active boot environment
- `create()` - Create new BE with optional source and activation
- `createTimestamped()` - Create BE with automatic timestamp naming
- `activate()` - Activate BE for next boot (permanent or temporary)
- `destroy()` - Remove BE (with active protection)
- `rename()` - Rename a boot environment
- `mount()` / `unmount()` - Mount/unmount BE for inspection
- `rollback()` - Revert to previous boot environment
- `applyRetention()` - Apply retention policy to clean old BEs
- `isSupported()` - Check if system supports boot environments

**CLI Commands:**
- `axiom be` / `axiom be-list` - List all boot environments
- `axiom be-create <name> [--source <be>] [--activate]` - Create new BE
- `axiom be-activate <name> [--temporary]` - Activate BE for next boot
- `axiom be-destroy <name> [--force]` - Remove boot environment
- `axiom be-rollback` - Revert to previous BE
- `axiom be-rename <old> <new>` - Rename boot environment
- `axiom be-mount <name> [path]` - Mount BE for inspection
- `axiom be-unmount <name> [--force]` - Unmount boot environment

**Helper Functions:**
- `epochToDatetime()` - Convert timestamps for BE naming
- `parseSize()` - Parse ZFS size strings (K, M, G, T)
- `matchGlob()` - Glob pattern matching for retention policies

---

## Phase 40: Remote Binary Cache Protocol

**Priority**: High
**Complexity**: High
**Status**: ✅ Implemented

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

### Implementation

Created `src/cache_protocol.zig` with complete binary cache protocol:

**Protocol Specification (v1.0):**
- `PROTOCOL_VERSION` - Protocol version for compatibility
- `Endpoints` - RESTful API endpoint definitions
- `HttpStatus` - Standard HTTP response codes
- `CacheRequest` / `CacheResponse` - HTTP request/response handling

**Data Types:**
- `CacheInfo` - Server information (name, version, package count, features)
- `PackageMeta` - Package metadata (name, version, hash, size, compression, signatures)
- `CacheSource` - Cache source configuration (URL, priority, trust key)
- `CacheConfig` - Full configuration with YAML parsing
- `FetchResult` - Result of fetch operations with metadata and data
- `SyncResult` - Result of metadata synchronization

**Cache Server:**
- `CacheServer.init()` - Initialize server with store path and port
- `CacheServer.start()` - Start listening for connections
- `CacheServer.getInfo()` - Return server information
- `CacheServer.listPackages()` - List all available packages
- `CacheServer.getPackageMeta()` - Get package metadata
- `CacheServer.getPackageNar()` - Get package archive
- `CacheServer.handleRequest()` - Route and handle HTTP requests

**Cache Client:**
- `CacheClient.init()` / `initWithTrust()` - Initialize with optional trust store
- `CacheClient.fetchPackage()` - Fetch from configured sources by priority
- `CacheClient.pushPackage()` - Push package to remote cache
- `CacheClient.syncMetadata()` - Sync metadata from all sources

**CLI Commands:**
- `axiom cache-server` - Start binary cache server
  - `--port <n>` - Listen port (default: 8080)
  - `--store <path>` - Package store path
- `axiom cache-info [url]` - Get cache server information
- `axiom remote-fetch <pkg>[@ver]` - Fetch package from remote cache
  - `--source <url>` - Specific cache URL
- `axiom remote-push <pkg>[@ver]` - Push package to remote cache
  - `--target <url>` - Target cache URL
- `axiom remote-sync` - Sync metadata from all sources
- `axiom remote-sources` - Manage cache source configuration
  - `--add <url>` - Add new source
  - `--remove <url>` - Remove source

**API Endpoints:**
- `GET /api/v1/info` - Cache server information
- `GET /api/v1/packages` - List all packages
- `GET /api/v1/packages/{name}/{version}` - Package metadata
- `GET /api/v1/packages/{name}/{version}/nar` - Package archive
- `GET /api/v1/packages/{name}/{version}/meta` - Package metadata
- `GET /api/v1/packages/{name}/{version}/sig` - Package signatures
- `POST /api/v1/upload/{name}/{version}` - Upload package

**Features:**
- Multi-source support with priority ordering
- Signature verification integration
- Compression support (zstd, gzip, xz)
- YAML configuration file parsing
- HTTP range requests for efficient transfers

---

## Phase 41: Format Versioning

**Priority**: High
**Complexity**: Low
**Status**: ✅ Implemented

### Purpose

Define version identifiers for all on-disk formats to enable future migrations, compatibility checking, and graceful upgrades.

### Requirements

1. **Manifest Format Versioning**
   ```yaml
   # manifest.yaml
   format_version: "1.0"
   name: bash
   version: "5.2.0"
   ...
   ```

2. **Profile Format Versioning**
   ```yaml
   # profile.yaml
   format_version: "1.0"
   name: development
   ...
   ```

3. **Store Layout Versioning**
   ```
   /axiom/store/
   ├── .store_version    # Contains "1.0"
   ├── pkg/
   └── meta/
   ```

4. **Lock File Versioning**
   ```yaml
   # profile.lock.yaml
   format_version: "1.0"
   resolved_at: "2025-01-15T10:30:00Z"
   ...
   ```

### Implementation

**Required Changes:**

1. **Version Constants**
   ```zig
   pub const FormatVersions = struct {
       pub const manifest: []const u8 = "1.0";
       pub const profile: []const u8 = "1.0";
       pub const lock: []const u8 = "1.0";
       pub const store: []const u8 = "1.0";
       pub const provenance: []const u8 = "1.0";
   };
   ```

2. **Version Validation**
   - Parse version field first in all YAML files
   - Reject incompatible versions with clear error
   - Warn on older-but-compatible versions

3. **Migration Framework**
   ```zig
   pub const Migration = struct {
       from_version: []const u8,
       to_version: []const u8,
       migrate: *const fn(allocator: Allocator, data: []const u8) anyerror![]const u8,
   };
   ```

4. **CLI Commands**
   ```bash
   axiom store-version              # Show store format version
   axiom migrate --check            # Check if migration needed
   axiom migrate --dry-run          # Show migration plan
   axiom migrate                    # Perform migration
   ```

### Deliverables

- [x] Add `format_version` field to manifest.yaml schema
- [x] Add `format_version` field to profile.yaml schema
- [x] Add `format_version` field to profile.lock.yaml schema
- [x] Add `format_version` field to provenance.yaml schema
- [x] Create `.store_version` file in store root
- [x] Implement version parsing and validation
- [x] Implement migration framework
- [x] Document version compatibility matrix

### Implementation Notes

**New Files:**
- `src/format_version.zig` - Format versioning module with:
  - `FormatVersions` - Current version constants for all formats
  - `SemanticVersion` - Version parsing and comparison
  - `CompatibilityResult` - Compatibility check results
  - `StoreVersion` - Store version file management
  - `Migration` - Migration framework
  - `extractFormatVersion()` - Extract version from YAML
  - `validateVersion()` - Validate format compatibility

**Modified Files:**
- `src/manifest.zig` - Added `format_version` field, parsing, validation, deinit
- `src/profile.zig` - Added `format_version` field to Profile and ProfileLock
- `src/cli.zig` - Added `store-version` and `migrate` commands

**CLI Commands:**
```bash
axiom store-version              # Show all format versions
axiom migrate --check            # Check if migration needed
axiom migrate --dry-run          # Show migration plan
axiom migrate                    # Perform migration
```

---

## Phase 42: Store Invariants & GC Guarantees

**Priority**: High
**Complexity**: Medium
**Status**: ✓ Complete

### Purpose

Define and enforce formal invariants for the package store, providing strong guarantees for garbage collection, concurrent operations, and crash recovery.

### Requirements

1. **Formal Store Invariants**
   - Every package in `/axiom/store/pkg/` has a valid manifest
   - Package hashes match content (content-addressable guarantee)
   - No orphaned datasets (every dataset has a package)
   - Reference counts are accurate

2. **Reference Counting Model**
   ```
   Package Reference Sources:
   ├── Profiles (profile.lock.yaml references)
   ├── Environments (realized environments)
   ├── Running processes (in-use packages)
   └── Build dependencies (active builds)
   ```

3. **GC Safety Guarantees**
   - Never delete packages with active references
   - Atomic deletion (package fully removed or not at all)
   - Safe concurrent GC with imports/realizations
   - Crash-safe (no partial states after power loss)

4. **Partial Import Handling**
   - Detect incomplete imports on startup
   - Clean up or resume partial imports
   - Transaction log for import operations

### Implementation

**Core Components:**

1. **Store Integrity Checker**
   ```zig
   pub const StoreIntegrity = struct {
       pub fn verify(store_path: []const u8) !IntegrityReport;
       pub fn repair(store_path: []const u8, report: IntegrityReport) !void;

       pub const IntegrityReport = struct {
           orphaned_datasets: [][]const u8,
           missing_manifests: [][]const u8,
           hash_mismatches: []HashMismatch,
           broken_references: []BrokenRef,
           partial_imports: [][]const u8,
       };
   };
   ```

2. **Reference Counter**
   ```zig
   pub const RefCounter = struct {
       pub fn countRefs(pkg_id: PackageId) !u32;
       pub fn getRefSources(pkg_id: PackageId) ![]RefSource;
       pub fn isReferenced(pkg_id: PackageId) !bool;

       pub const RefSource = union(enum) {
           profile: []const u8,
           environment: []const u8,
           process: std.posix.pid_t,
           build: []const u8,
       };
   };
   ```

3. **Garbage Collector with Guarantees**
   ```zig
   pub const GarbageCollector = struct {
       pub fn collect(options: GcOptions) !GcResult;

       pub const GcOptions = struct {
           dry_run: bool = false,
           check_processes: bool = true,  // Check /proc for in-use packages
           max_delete: ?u32 = null,        // Safety limit
           exclude_patterns: [][]const u8 = &.{},
       };

       pub const GcResult = struct {
           deleted_count: u32,
           freed_bytes: u64,
           skipped_referenced: u32,
           errors: []GcError,
       };
   };
   ```

4. **Transaction Log**
   ```
   /axiom/store/.txlog/
   ├── 00001.import.pending     # In-progress import
   ├── 00002.import.complete    # Completed import
   └── 00003.gc.pending         # In-progress GC
   ```

### CLI Commands

```bash
axiom store-verify              # Verify store integrity
axiom store-verify --repair     # Repair detected issues
axiom gc --dry-run              # Show what would be deleted
axiom gc --max 100              # Delete at most 100 packages
axiom gc --check-processes      # Check for in-use packages
axiom refs <package>            # Show all references to package
```

### Deliverables

- [x] Document formal store invariants
- [x] Implement StoreIntegrity checker
- [x] Implement RefCounter with all reference sources
- [x] Implement process scanning for in-use packages
- [x] Implement transaction log for crash recovery
- [x] Add --repair flag to store-verify
- [x] Add comprehensive GC safety checks
- [x] Write invariant verification tests

### Implementation Notes

**Files Created/Modified:**
- `src/store_integrity.zig` - New module with StoreIntegrity, RefCounter, TransactionLog
- `src/gc.zig` - Updated with transaction logging and integrity verification
- `src/cli.zig` - Added store-verify and refs commands

**Key Components:**

1. **StoreIntegrity Checker**
   - Verifies manifests exist for all packages
   - Detects orphaned datasets
   - Identifies hash mismatches (optional deep verification)
   - Finds broken references
   - Detects partial imports via transaction log
   - Repair mode for automated cleanup

2. **RefCounter**
   - Counts references from profiles, environments, processes, and builds
   - `countRefs()` returns total reference count
   - `getRefSources()` returns detailed reference sources
   - `isReferenced()` for quick checks

3. **TransactionLog**
   - Records import, gc_remove, and realize operations
   - Supports begin/complete/abort workflow
   - `findIncomplete()` for crash recovery
   - Stored in `.axiom-txlog/` directory

4. **GC Safety Guarantees**
   - Transaction logging wraps all removal operations
   - `verifyBeforeCollect()` checks integrity before GC
   - `recoverFromCrash()` handles incomplete operations
   - Safety snapshot before destructive operations

**CLI Commands:**
```bash
axiom store-verify              # Verify store integrity
axiom store-verify --repair     # Repair detected issues
axiom store-verify --deep       # Include hash verification
axiom refs <package>            # Show all references to package
axiom refs <package> --verbose  # Include reference details
```

---

## Phase 43: Advanced Resolver Semantics

**Priority**: Medium
**Complexity**: High
**Status**: ✓ Complete

### Purpose

Extend the SAT-based resolver with advanced dependency semantics required for a mature package ecosystem.

### Requirements

1. **Virtual Providers**
   ```yaml
   # openssl package
   provides:
     - ssl-library
     - crypto-library

   # libressl package
   provides:
     - ssl-library
     - crypto-library

   # dependent package
   dependencies:
     - name: ssl-library  # Satisfied by either openssl or libressl
       virtual: true
   ```

2. **Optional Dependencies**
   ```yaml
   dependencies:
     - name: readline
       optional: true
       description: "Enables command-line editing"
   ```

3. **Feature Flags (Conditional Dependencies)**
   ```yaml
   features:
     gui:
       description: "Build with GUI support"
       dependencies:
         - name: gtk4
         - name: cairo

     ssl:
       description: "Enable SSL/TLS support"
       dependencies:
         - name: openssl

   default_features:
     - ssl
   ```

4. **Conflict Declarations**
   ```yaml
   conflicts:
     - name: openssl
       reason: "LibreSSL replaces OpenSSL"
   ```

5. **Version Pinning and Preferences**
   ```yaml
   # profile.yaml
   preferences:
     - name: python
       prefer: "3.11.*"    # Prefer 3.11.x versions
       avoid: "3.12.*"     # Avoid 3.12.x versions

   pins:
     - name: openssl
       version: "3.0.12"   # Exact pin
   ```

### Implementation

**Extended SAT Encoding:**

```zig
pub const ResolverExtensions = struct {
    // Virtual providers
    pub fn encodeVirtual(
        encoder: *SatEncoder,
        virtual_name: []const u8,
        providers: []const PackageId,
    ) !void;

    // Optional dependencies
    pub fn encodeOptional(
        encoder: *SatEncoder,
        pkg: PackageId,
        dep: Dependency,
        enabled: bool,
    ) !void;

    // Feature flags
    pub fn encodeFeatures(
        encoder: *SatEncoder,
        pkg: PackageId,
        enabled_features: []const []const u8,
    ) !void;

    // Conflicts
    pub fn encodeConflict(
        encoder: *SatEncoder,
        pkg_a: PackageId,
        pkg_b: PackageId,
    ) !void;

    // Preferences (soft constraints)
    pub fn addPreference(
        encoder: *SatEncoder,
        pkg_name: []const u8,
        weight: i32,
    ) !void;
};
```

**CLI Commands:**

```bash
axiom resolve myprofile --with-feature gui
axiom resolve myprofile --without-feature ssl
axiom resolve myprofile --prefer "python@3.11.*"
axiom resolve myprofile --pin "openssl@3.0.12"
axiom why-depends bash openssl         # Explain dependency chain
axiom alternatives ssl-library         # List virtual providers
```

### Deliverables

- [x] Extend manifest schema for `provides`, `conflicts`, `features`
- [x] Extend profile schema for `preferences`, `pins`
- [x] Implement virtual provider resolution
- [x] Implement optional dependency handling
- [x] Implement feature flag system
- [x] Implement conflict detection
- [x] Implement preference/pin weighting
- [x] Add `why-depends` command
- [x] Add `alternatives` command
- [x] Document advanced resolver semantics

### Implementation Notes

**Files Created/Modified:**
- `src/types.zig` - Extended Dependency struct with optional, virtual, description, feature fields
- `src/manifest.zig` - Added Feature struct with implies/conflicts_with, added features/default_features to Manifest
- `src/profile.zig` - Added Preference, Pin structs and features/disabled_features to PackageRequest
- `src/resolver_advanced.zig` - New module with advanced resolver components
- `src/cli.zig` - Added why-depends and alternatives commands

**Key Components:**

1. **Extended Dependency**
   ```zig
   pub const Dependency = struct {
       name: []const u8,
       constraint: VersionConstraint,
       optional: bool = false,       // Can be omitted
       virtual: bool = false,        // Satisfied by providers
       description: ?[]const u8,     // For optional deps
       feature: ?[]const u8,         // Feature-gated
   };
   ```

2. **Feature System**
   - Features have dependencies, implies (auto-enable), and conflicts_with
   - Packages declare default_features enabled by default
   - Profiles can enable/disable features per-package
   - Transitive closure of implies relationships computed

3. **Virtual Provider Index**
   - Builds index from manifest 'provides' declarations
   - Supports priority-based provider selection
   - Used by resolver to satisfy virtual dependencies

4. **Preference Handler**
   - Supports 'prefer' patterns (e.g., "3.11.*")
   - Supports 'avoid' patterns
   - Calculates weight adjustments for SAT optimization

5. **Dependency Explanation**
   - Traces paths from root packages to target
   - Distinguishes direct, dependency, virtual, feature reasons

**CLI Commands:**
```bash
axiom why-depends <source> <target>  # Explain dependency chain
axiom why <source> <target>          # Alias
axiom alternatives <virtual>         # List providers
axiom providers <virtual>            # Alias
```

---

## Phase 44: Realization Specification

**Priority**: High
**Complexity**: Medium
**Status**: Complete

### Purpose

Formally specify how packages are merged into realized environments, defining the exact semantics for directory merging, symlink handling, and ABI boundaries.

### Requirements

1. **Directory Merge Specification**
   ```
   Environment Layout:
   /axiom/env/<name>/
   ├── bin/           # Merged executables (symlinks to store)
   ├── lib/           # Merged libraries (symlinks to store)
   ├── share/         # Merged data files (symlinks to store)
   ├── include/       # Merged headers (for dev environments)
   ├── etc/           # Merged configuration templates
   └── .axiom/        # Environment metadata
       ├── manifest.yaml
       ├── packages/   # List of included packages
       └── activate    # Activation script
   ```

2. **Merge Strategies**
   ```yaml
   # Environment realization config
   merge_strategy:
     bin: symlink       # Symlink to store package
     lib: symlink       # Symlink to store package
     share: symlink     # Symlink to store package
     etc: copy          # Copy (allows local modifications)
   ```

3. **Multiple Outputs**
   ```yaml
   # Package with multiple outputs
   outputs:
     bin:
       description: "Runtime binaries"
       paths: ["bin/"]
     lib:
       description: "Runtime libraries"
       paths: ["lib/"]
     dev:
       description: "Development headers and static libs"
       paths: ["include/", "lib/*.a", "lib/pkgconfig/"]
     doc:
       description: "Documentation"
       paths: ["share/doc/", "share/man/"]

   default_outputs: [bin, lib]
   ```

4. **ABI Boundary Definition**
   ```
   System Libraries (always from base):
   ├── libc.so
   ├── libm.so
   ├── libpthread.so
   └── libthr.so

   Environment Libraries (from Axiom store):
   ├── libssl.so
   ├── libz.so
   └── application-specific libs
   ```

### Implementation

**Realization Engine:**

```zig
pub const RealizationSpec = struct {
    pub const MergeStrategy = enum {
        symlink,        // Create symlink to store
        hardlink,       // Create hardlink (same filesystem only)
        copy,           // Copy file (allows modification)
        overlay,        // ZFS overlay dataset
    };

    pub const DirectoryRule = struct {
        pattern: []const u8,      // e.g., "bin/*", "lib/*.so"
        strategy: MergeStrategy,
        conflict_policy: ConflictPolicy,
    };

    pub const OutputSelection = struct {
        package: []const u8,
        outputs: []const []const u8,  // ["bin", "lib"] or ["*"] for all
    };
};

pub const Realizer = struct {
    pub fn realize(
        env_name: []const u8,
        packages: []const PackageId,
        spec: RealizationSpec,
    ) !Environment;

    pub fn verifyAbi(env: *Environment) !AbiReport;
};
```

**CLI Commands:**

```bash
axiom realize myenv myprofile --outputs "python:bin,lib" --outputs "gcc:*"
axiom realize myenv myprofile --merge-strategy lib=overlay
axiom env-verify myenv                  # Verify environment integrity
axiom env-outputs myenv                 # Show output breakdown
```

### Deliverables

- [ ] Document formal realization specification
- [ ] Extend manifest schema for multiple outputs
- [ ] Implement output selection in realize command
- [ ] Implement configurable merge strategies
- [ ] Define and enforce ABI boundaries
- [ ] Add environment verification command
- [ ] Document ABI boundary rules

---

## Phase 45: Build Provenance Enforcement

**Priority**: High
**Complexity**: Medium
**Status**: Complete

### Purpose

Enforce build provenance requirements, ensuring all packages have verifiable build history with cryptographic binding.

### Requirements

1. **Mandatory Provenance**
   ```yaml
   # provenance.yaml (required for all packages)
   format_version: "1.0"
   builder:
     name: "axiom-builder"
     version: "1.0.0"
     host: "builder01.pgsdf.org"

   source:
     url: "https://ftp.gnu.org/gnu/bash/bash-5.2.tar.gz"
     sha256: "abc123..."
     fetched_at: "2025-01-15T10:00:00Z"

   build:
     started_at: "2025-01-15T10:05:00Z"
     completed_at: "2025-01-15T10:15:00Z"
     environment:
       PATH: "/axiom/env/build/bin:/usr/bin"
       CC: "gcc"
     commands:
       - "./configure --prefix=/usr/local"
       - "make -j8"
       - "make install DESTDIR=$OUTPUT"

   output:
     hash: "sha256:def456..."
     files_count: 142
     total_size: 5242880

   signature:
     key_id: "PGSD0001A7E3F9B2"
     algorithm: "ed25519"
     value: "base64..."
   ```

2. **Hash Chain Binding**
   ```
   output_hash = sha256(package_contents)
   provenance_hash = sha256(provenance_yaml_without_signature)
   binding = sign(output_hash || provenance_hash, private_key)
   ```

3. **Reproducibility Verification**
   ```bash
   axiom verify-provenance bash@5.2.0
   # Output:
   #   Source: verified (sha256 match)
   #   Build: reproducible (output hash match)
   #   Signature: valid (PGSD0001A7E3F9B2)
   ```

4. **Policy Enforcement**
   ```yaml
   # /etc/axiom/policy.yaml
   provenance:
     require: true                    # Reject packages without provenance
     require_signature: true          # Reject unsigned provenance
     trusted_builders:
       - "builder01.pgsdf.org"
       - "builder02.pgsdf.org"
     max_age_days: 365               # Reject old builds
   ```

### Implementation

**Provenance Verifier:**

```zig
pub const ProvenanceVerifier = struct {
    pub fn verify(pkg_path: []const u8) !ProvenanceReport;
    pub fn verifyReproducibility(pkg_path: []const u8) !ReproducibilityReport;

    pub const ProvenanceReport = struct {
        has_provenance: bool,
        source_verified: bool,
        signature_valid: bool,
        signer_trusted: bool,
        build_age_days: u32,
        policy_violations: []PolicyViolation,
    };

    pub const ReproducibilityReport = struct {
        source_available: bool,
        build_attempted: bool,
        output_matches: bool,
        diff_summary: ?[]const u8,
    };
};
```

**CLI Commands:**

```bash
axiom verify-provenance <package>       # Verify provenance
axiom verify-provenance --rebuild       # Attempt reproducible rebuild
axiom provenance-policy --check         # Check policy compliance
axiom provenance-show <package>         # Display provenance details
```

### Deliverables

- [ ] Make provenance.yaml mandatory for new imports
- [ ] Implement hash chain binding (output + provenance)
- [ ] Implement ProvenanceVerifier
- [ ] Add reproducibility check (rebuild and compare)
- [ ] Implement policy enforcement
- [ ] Add verify-provenance command
- [ ] Add provenance-policy command
- [ ] Document provenance requirements

---

## Phase 46: Binary Cache Trust Model

**Priority**: High
**Complexity**: Medium
**Status**: Complete

### Purpose

Complete the binary cache trust model with formal specifications for cache index format, metadata integrity, and conflict resolution.

### Requirements

1. **Cache Index Format**
   ```yaml
   # cache-index.yaml
   format_version: "1.0"
   cache_id: "pgsd-official-cache"
   updated_at: "2025-01-15T12:00:00Z"

   packages:
     bash:
       versions:
         "5.2.0":
           hash: "sha256:abc123..."
           size: 5242880
           compression: zstd
           signatures: ["PGSD0001A7E3F9B2"]
         "5.1.16":
           hash: "sha256:def456..."
           size: 5100000
           compression: zstd
           signatures: ["PGSD0001A7E3F9B2"]

   signature:
     key_id: "PGSD0001A7E3F9B2"
     value: "base64..."
   ```

2. **Metadata Integrity**
   ```
   Index Integrity Chain:
   ├── index_hash = sha256(cache-index.yaml without signature)
   ├── index_signature = sign(index_hash, cache_key)
   └── Each package entry references signed package
   ```

3. **Cache Eviction Rules**
   ```yaml
   # cache-policy.yaml
   eviction:
     max_size_gb: 100
     max_age_days: 180
     keep_latest_versions: 3
     never_evict:
       - "bash"
       - "gcc"
       - "python"
   ```

4. **Local/Remote Conflict Resolution**
   ```yaml
   conflict_policy:
     same_version:
       strategy: prefer_local     # local, remote, newest, hash_check
     different_version:
       strategy: prefer_newest
     hash_mismatch:
       strategy: fail             # fail, prefer_local, prefer_remote
   ```

### Implementation

**Cache Index Manager:**

```zig
pub const CacheIndex = struct {
    format_version: []const u8,
    cache_id: []const u8,
    updated_at: i64,
    packages: std.StringHashMap(PackageVersions),
    signature: ?Signature,

    pub fn verify(self: *CacheIndex, trust_store: *TrustStore) !bool;
    pub fn merge(self: *CacheIndex, other: *CacheIndex) !MergeResult;
};

pub const CacheEvictionPolicy = struct {
    pub fn apply(cache_path: []const u8, policy: EvictionPolicy) !EvictionResult;
};

pub const ConflictResolver = struct {
    pub fn resolve(
        local: ?PackageMeta,
        remote: ?PackageMeta,
        policy: ConflictPolicy,
    ) !Resolution;
};
```

**CLI Commands:**

```bash
axiom cache-index --update              # Update local index from remotes
axiom cache-index --verify              # Verify index signatures
axiom cache-evict --dry-run             # Show eviction plan
axiom cache-evict                       # Apply eviction policy
axiom cache-conflicts                   # Show local/remote conflicts
axiom cache-conflicts --resolve         # Resolve conflicts per policy
```

### Deliverables

- [x] Define cache-index.yaml format specification
- [x] Implement signed index verification
- [x] Implement index merging from multiple sources
- [x] Implement eviction policy engine
- [x] Implement conflict detection and resolution
- [x] Add cache-index management commands
- [x] Add cache-evict command
- [x] Document cache trust model

---

## Phase 47: Boot Environment Deep Integration

**Priority**: Medium
**Complexity**: High
**Status**: Complete

### Purpose

Extend Phase 39's boot environment support with deeper integration into profiles, bootloader configuration, and automatic rollback semantics.

### Requirements

1. **BE-Aware Profile Layout**
   ```
   /axiom/
   ├── profiles/
   │   └── system/              # System profile
   │       ├── profile.yaml
   │       └── profile.lock.yaml
   └── be/
       ├── default/             # Default BE
       │   └── system -> /axiom/profiles/system
       ├── pre-upgrade/         # Snapshot BE
       │   └── system/          # Frozen profile copy
       │       └── profile.lock.yaml
       └── testing/             # Test BE
           └── system/
               └── profile.lock.yaml
   ```

2. **Bootloader Integration**
   ```bash
   # FreeBSD boot menu integration
   axiom be-activate testing
   # Updates /boot/loader.conf.local:
   #   vfs.root.mountfrom="zfs:zroot/ROOT/testing"

   # GRUB integration (for Linux VMs)
   axiom be-activate testing --bootloader grub
   ```

3. **Rollback Semantics**
   ```yaml
   # /etc/axiom/rollback-policy.yaml
   rollback:
     auto_rollback:
       enabled: true
       trigger:
         - boot_failure           # Failed to boot
         - service_failure        # Critical services down
         - health_check_failure   # Custom health checks
       grace_period_seconds: 300  # Time before auto-rollback

     health_checks:
       - name: "network"
         command: "ping -c1 8.8.8.8"
         required: true
       - name: "sshd"
         command: "service sshd status"
         required: true
   ```

4. **Activation Hooks**
   ```yaml
   # BE activation hooks
   hooks:
     pre_activate:
       - "/etc/axiom/hooks/pre-activate.sh"
     post_activate:
       - "/etc/axiom/hooks/post-activate.sh"
     on_rollback:
       - "/etc/axiom/hooks/notify-rollback.sh"
   ```

### Implementation

**BE Profile Manager:**

```zig
pub const BeProfileManager = struct {
    pub fn snapshotProfile(profile: []const u8, be_name: []const u8) !void;
    pub fn restoreProfile(be_name: []const u8, profile: []const u8) !void;
    pub fn diffProfiles(be_a: []const u8, be_b: []const u8) !ProfileDiff;
};

pub const BootloaderIntegration = struct {
    pub fn activateBe(be_name: []const u8, options: ActivateOptions) !void;
    pub fn configureAutoRollback(policy: RollbackPolicy) !void;
    pub fn runHealthChecks() !HealthCheckResult;
};
```

**CLI Commands:**

```bash
axiom be-snapshot myenv                 # Snapshot current profile to BE
axiom be-diff default testing           # Show profile differences
axiom be-health                         # Run health checks
axiom be-rollback --reason "failed"     # Manual rollback with reason
axiom system-upgrade --be               # Upgrade in new BE
```

### Deliverables

- [x] Design BE-aware profile storage layout
- [x] Implement profile snapshotting to BEs
- [x] Implement FreeBSD bootloader integration
- [x] Implement auto-rollback with health checks
- [x] Implement activation hooks
- [x] Add be-diff command
- [x] Add be-health command
- [x] Document BE integration workflows

---

## Phase 48: Multi-User Security Model

**Priority**: High
**Complexity**: High
**Status**: Complete

### Purpose

Define and implement comprehensive multi-user security including isolation rules, access control, and safe handling of privileged binaries.

### Requirements

1. **Per-User Isolation**
   ```
   /axiom/
   ├── store/                  # Shared (read-only for users)
   │   └── pkg/
   └── users/
       ├── alice/
       │   ├── profiles/       # Alice's private profiles
       │   ├── env/            # Alice's environments
       │   └── .config/        # User-specific config
       └── bob/
           ├── profiles/
           └── env/
   ```

2. **Access Control Rules**
   ```yaml
   # /etc/axiom/access.yaml
   store:
     owner: root
     group: axiom
     mode: 0755              # Users can read

   users:
     template:
       owner: $USER
       group: $USER
       mode: 0700            # Private by default

   groups:
     developers:
       members: [alice, bob]
       shared_profiles: [devtools]
   ```

3. **Setuid Binary Handling**
   ```yaml
   # Package manifest
   setuid_binaries:
     - path: "bin/sudo"
       owner: root
       mode: 4755
       audit: true           # Log all executions

   # Realization policy
   setuid_policy:
     allow: [sudo, ping, su]
     deny_unknown: true
     require_signature: true
   ```

4. **Privilege Separation**
   ```
   Operations by privilege level:

   Root only:
   ├── store imports
   ├── system profile changes
   ├── setuid binary installation
   └── gc on shared store

   Per-user (no root):
   ├── user profile management
   ├── user environment realization
   └── user-local imports
   ```

### Implementation

**Access Control Manager:**

```zig
pub const AccessControl = struct {
    pub fn checkStoreAccess(user: User, operation: StoreOp) !bool;
    pub fn checkUserSpace(user: User, target_user: User) !bool;
    pub fn getEffectivePolicy(user: User) !Policy;

    pub const StoreOp = enum {
        read,
        import,
        gc,
        modify_metadata,
    };
};

pub const SetuidManager = struct {
    pub fn validateSetuid(manifest: Manifest, policy: SetuidPolicy) !ValidationResult;
    pub fn installSetuid(pkg_path: []const u8, binary: SetuidBinary) !void;
    pub fn auditSetuidExecution(binary: []const u8, user: User) !void;
};
```

**CLI Commands:**

```bash
axiom user-init                         # Initialize user space
axiom user-profile-create dev           # Create user profile (no sudo)
axiom user-realize myenv dev            # Realize to user space (no sudo)
axiom access --show                     # Show access policy
axiom audit-setuid                      # Show setuid audit log
```

### Deliverables

- [x] Design multi-user filesystem layout
- [x] Implement per-user profile isolation
- [x] Implement access control checks
- [x] Implement setuid binary policy enforcement
- [x] Implement setuid audit logging
- [x] Add user-* commands for unprivileged operation
- [x] Document multi-user security model
- [x] Write security policy configuration guide

---

## Phase 49: Error Model & Recovery

**Priority**: High
**Complexity**: Medium
**Status**: Complete

### Purpose

Define a unified error taxonomy with comprehensive recovery procedures for all failure modes.

### Requirements

1. **Error Taxonomy**
   ```zig
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
   ```

2. **Recovery Procedures**
   ```yaml
   # Recovery procedure definitions
   recovery:
     ImportInterrupted:
       automatic: true
       procedure:
         - "Check transaction log"
         - "Clean partial dataset"
         - "Retry import"
       command: "axiom import-recover"

     RealizationInterrupted:
       automatic: true
       procedure:
         - "Identify incomplete environment"
         - "Remove partial files"
         - "Re-realize from lock file"
       command: "axiom env-recover <name>"

     StoreCorrupted:
       automatic: false
       procedure:
         - "Run store verification"
         - "Identify corrupted packages"
         - "Re-fetch from cache or rebuild"
       command: "axiom store-repair"
   ```

3. **Store Integrity Verification**
   ```bash
   axiom verify
   # Output:
   #   Store: OK
   #   Profiles: 3 valid, 0 corrupted
   #   Environments: 2 valid, 1 needs repair
   #   Recommended: axiom env-recover dev-env
   ```

4. **Transaction Recovery**
   ```bash
   axiom recover
   # Scans for:
   #   - Interrupted imports
   #   - Interrupted realizations
   #   - Orphaned datasets
   # Offers automatic or interactive recovery
   ```

### Implementation

**Recovery Engine:**

```zig
pub const RecoveryEngine = struct {
    pub fn scan() !RecoveryPlan;
    pub fn execute(plan: RecoveryPlan, mode: RecoveryMode) !RecoveryResult;

    pub const RecoveryMode = enum {
        automatic,      // Apply safe automatic fixes
        interactive,    // Ask for each action
        dry_run,        // Show plan only
    };

    pub const RecoveryPlan = struct {
        interrupted_imports: []ImportRecovery,
        interrupted_realizations: []RealizationRecovery,
        orphaned_datasets: [][]const u8,
        corrupted_packages: []PackageRecovery,
    };
};

pub const ErrorReporter = struct {
    pub fn report(err: anyerror, context: ErrorContext) void;
    pub fn suggest(err: anyerror) ?[]const u8;  // Recovery suggestion
};
```

**CLI Commands:**

```bash
axiom verify                            # Full system verification
axiom verify --quick                    # Quick check (no hash verification)
axiom recover                           # Interactive recovery
axiom recover --auto                    # Automatic safe recovery
axiom import-recover                    # Recover interrupted import
axiom env-recover <name>                # Recover interrupted realization
```

### Deliverables

- [x] Define complete error taxonomy
- [x] Implement unified error type with context
- [x] Implement recovery procedures for each error type
- [x] Implement transaction log scanning
- [x] Implement RecoveryEngine
- [x] Add verify command with detailed output
- [x] Add recover command with modes
- [x] Document error taxonomy and recovery procedures

---

## Phase 50: Testing & Validation Framework

**Priority**: Critical
**Complexity**: High
**Status**: Complete

### Purpose

Establish comprehensive testing infrastructure to ensure correctness, prevent regressions, and validate the system against specification.

### Requirements

1. **Unit Test Framework**
   ```zig
   // test/unit/resolver_test.zig
   test "resolver handles virtual providers" {
       var resolver = Resolver.init(test_allocator);
       defer resolver.deinit();

       // Add packages with virtual providers
       try resolver.addPackage(openssl_pkg);
       try resolver.addPackage(libressl_pkg);

       // Resolve with virtual dependency
       const result = try resolver.resolve(ssl_dependent_profile);

       // Verify exactly one provider selected
       try testing.expect(result.hasPackage("openssl") != result.hasPackage("libressl"));
   }
   ```

2. **Golden File Tests**
   ```
   test/golden/
   ├── manifests/
   │   ├── valid/
   │   │   ├── basic.yaml
   │   │   ├── with-deps.yaml
   │   │   └── with-features.yaml
   │   └── invalid/
   │       ├── missing-name.yaml
   │       └── bad-version.yaml
   ├── profiles/
   │   └── ...
   └── resolutions/
       ├── simple.input.yaml
       └── simple.expected.yaml
   ```

3. **Integration Tests**
   ```bash
   # test/integration/full_workflow.sh
   set -e

   # Setup test environment
   ./setup_test_pool.sh

   # Test full workflow
   axiom setup --pool testpool --yes
   axiom ports-import devel/gmake --dry-run
   axiom profile-create test
   axiom profile-add-package test gmake
   axiom resolve test
   axiom realize test-env test

   # Verify
   test -x /axiom/env/test-env/bin/gmake

   # Cleanup
   ./cleanup_test_pool.sh
   ```

4. **ZFS Simulation Framework**
   ```zig
   // test/mock/mock_zfs.zig
   pub const MockZfs = struct {
       datasets: std.StringHashMap(Dataset),
       snapshots: std.StringHashMap(Snapshot),

       pub fn create(self: *MockZfs, name: []const u8) !void;
       pub fn destroy(self: *MockZfs, name: []const u8) !void;
       pub fn snapshot(self: *MockZfs, name: []const u8) !void;
       pub fn clone(self: *MockZfs, snap: []const u8, target: []const u8) !void;

       // Failure injection
       pub fn injectFailure(self: *MockZfs, op: Op, err: anyerror) void;
   };
   ```

5. **Fuzzing Infrastructure**
   ```zig
   // test/fuzz/manifest_fuzz.zig
   pub fn fuzz(input: []const u8) void {
       const result = manifest.parse(test_allocator, input);
       if (result) |m| {
           m.deinit();
       } else |_| {
           // Invalid input is expected, just ensure no crash
       }
   }
   ```

6. **Regression Test Suite**
   ```yaml
   # test/regression/cases.yaml
   cases:
     - name: "issue-42-cyclic-deps"
       description: "Resolver should detect cyclic dependencies"
       input: "cyclic_deps_profile.yaml"
       expected_error: "CyclicDependency"

     - name: "issue-57-partial-import"
       description: "Interrupted import should be recoverable"
       setup: "inject_import_failure.sh"
       verify: "verify_recovery.sh"
   ```

### Implementation

**Test Runner:**

```zig
pub const TestRunner = struct {
    pub fn runUnit() !TestResults;
    pub fn runGolden() !TestResults;
    pub fn runIntegration() !TestResults;
    pub fn runFuzz(duration_seconds: u32) !FuzzResults;
    pub fn runRegression() !TestResults;
    pub fn runAll() !TestSummary;
};
```

**CI Integration:**

```yaml
# .github/workflows/test.yml
test:
  runs-on: freebsd-14
  steps:
    - uses: actions/checkout@v4

    - name: Unit Tests
      run: zig build test

    - name: Golden File Tests
      run: ./test/golden/run.sh

    - name: Integration Tests
      run: |
        ./test/integration/setup.sh
        ./test/integration/run_all.sh
        ./test/integration/cleanup.sh

    - name: Regression Tests
      run: ./test/regression/run.sh
```

### Deliverables

- [x] Set up test directory structure
- [x] Implement unit tests for all core modules
- [x] Create golden file test suite for manifests/profiles
- [x] Implement ZFS mock for unit testing
- [x] Create integration test framework
- [x] Implement fuzzing targets for parsers
- [x] Create regression test suite
- [x] Set up CI pipeline with all test types
- [x] Document testing procedures
- [x] Achieve >80% code coverage target

---

## Phase 51: Critical Security Fixes

**Priority**: Critical
**Complexity**: Medium
**Status**: Complete

### Purpose

Address critical security vulnerabilities identified in the code-boundary assessment that could lead to arbitrary code execution or privilege escalation.

### Issues Identified

1. **Shell Command Injection in zfs.zig**
   - **Location**: `zfs.zig` lines 208-225, 248-269
   - **Severity**: Critical
   - **Issue**: User-provided paths concatenated directly into shell commands without quoting
   ```zig
   // VULNERABLE - user path not quoted
   const cmd = try std.fmt.allocPrint(allocator, "zfs destroy -r {s}", .{path});
   var child = std.process.Child.init(&[_][]const u8{ "sh", "-c", cmd }, allocator);
   ```
   - **Risk**: Arbitrary command execution if path contains `$(...)`, `;`, or backticks

2. **Path Traversal in Tar Extraction**
   - **Location**: `secure_tar.zig` lines 319-370
   - **Severity**: Critical
   - **Issue**: Path validation edge cases may allow escape
   - **Risk**: Files extracted outside intended directory

3. **Symlink Escape Vulnerability**
   - **Location**: `secure_tar.zig` lines 282-317
   - **Severity**: High
   - **Issue**: Symlink target validation may not catch all escapes
   - **Risk**: Symlink to sensitive files like `/etc/passwd`

### Implementation

**Fix 1: Shell Command Injection**

```zig
// BEFORE (vulnerable)
const cmd = try std.fmt.allocPrint(allocator, "zfs destroy -r {s}", .{path});

// AFTER (safe) - use execve directly, not shell
pub fn destroyRecursive(allocator: Allocator, dataset: []const u8) !void {
    // Validate dataset name contains no shell metacharacters
    if (!isValidDatasetName(dataset)) return error.InvalidDatasetName;

    // Use direct execve, not shell
    var child = std.process.Child.init(&[_][]const u8{
        "/sbin/zfs", "destroy", "-r", dataset
    }, allocator);
    // ...
}

fn isValidDatasetName(name: []const u8) bool {
    // Only allow: alphanumeric, underscore, hyphen, slash, colon
    for (name) |c| {
        if (!std.ascii.isAlphanumeric(c) and
            c != '_' and c != '-' and c != '/' and c != ':' and c != '.') {
            return false;
        }
    }
    return true;
}
```

**Fix 2: Path Traversal Hardening**

```zig
pub fn validateExtractPath(base: []const u8, target: []const u8) ![]const u8 {
    // Resolve to absolute path
    const resolved = try std.fs.path.resolve(allocator, &.{ base, target });
    defer allocator.free(resolved);

    // Verify resolved path starts with base
    if (!std.mem.startsWith(u8, resolved, base)) {
        return error.PathTraversal;
    }

    // Check no component is ".." after normalization
    var it = std.mem.split(u8, target, "/");
    while (it.next()) |component| {
        if (std.mem.eql(u8, component, "..")) {
            return error.PathTraversal;
        }
    }

    return resolved;
}
```

**Fix 3: Symlink Target Validation**

```zig
pub fn validateSymlinkTarget(base: []const u8, link_path: []const u8, target: []const u8) !void {
    // Get directory containing the symlink
    const link_dir = std.fs.path.dirname(link_path) orelse base;

    // Resolve symlink target relative to link location
    const resolved = try std.fs.path.resolve(allocator, &.{ link_dir, target });
    defer allocator.free(resolved);

    // Verify target stays within base
    if (!std.mem.startsWith(u8, resolved, base)) {
        return error.SymlinkEscape;
    }
}
```

### CLI Commands

```bash
axiom security-audit               # Run security audit on codebase
axiom security-audit --fix         # Apply automatic fixes where safe
```

### Deliverables

- [x] Replace shell command construction with direct execve in zfs.zig
- [x] Add dataset name validation function
- [x] Harden path traversal checks in secure_tar.zig
- [x] Implement symlink target resolution validation
- [ ] Add security audit command
- [x] Write regression tests for each vulnerability
- [ ] Document secure coding guidelines

---

## Phase 52: Error Handling Overhaul

**Priority**: High
**Complexity**: Medium
**Status**: ✓ Complete

### Purpose

Eliminate silent error swallowing and establish consistent error handling patterns across all modules.

### Issues Identified

1. **Silent Error Swallowing (40+ instances)**
   - **Files**: hsm.zig, bootstrap.zig, desktop.zig, service.zig, import.zig, bundle.zig, launcher.zig, runtime.zig, sat.zig
   - **Pattern**: `catch {}` blocks silently ignore errors
   ```zig
   // PROBLEMATIC - error silently ignored
   std.fs.deleteTreeAbsolute(tmp_dir) catch {};
   ```

2. **Inconsistent Error Types**
   - Each module defines its own error enum: `ZfsError`, `StoreError`, `ServiceError`, `CacheError`
   - No common error interface for module boundaries

3. **Unchecked C Interop Returns**
   - **Location**: `zfs.zig` lines 91-125
   - **Pattern**: `_ = c.nvlist_add_string(...)` ignores return values

### Implementation

**Error Abstraction Layer:**

```zig
// src/errors.zig - Unified error module
pub const AxiomError = error{
    // Categorized errors with context
    SecurityViolation,
    PathTraversal,
    SymlinkEscape,
    CommandInjection,

    StoreCorruption,
    PackageNotFound,
    ManifestInvalid,

    ZfsOperationFailed,
    DatasetNotFound,
    PoolNotAvailable,

    NetworkError,
    CacheUnreachable,
    FetchTimeout,

    PermissionDenied,
    InsufficientPrivileges,
};

pub const ErrorContext = struct {
    err: AxiomError,
    message: []const u8,
    source_file: []const u8,
    source_line: u32,
    module: []const u8,
    recoverable: bool,
    suggestion: ?[]const u8,

    pub fn format(self: ErrorContext, writer: anytype) !void {
        try writer.print("{s}:{d}: {s} error: {s}\n", .{
            self.source_file, self.source_line, self.module, self.message
        });
        if (self.suggestion) |s| {
            try writer.print("  suggestion: {s}\n", .{s});
        }
    }
};

pub fn logError(comptime src: std.builtin.SourceLocation, err: anyerror, msg: []const u8) void {
    // Log with full context for debugging
    std.log.err("{s}:{d} in {s}: {s} - {}", .{
        src.file, src.line, src.fn_name, msg, err
    });
}
```

**Replace Silent Catch Blocks:**

```zig
// BEFORE
std.fs.deleteTreeAbsolute(tmp_dir) catch {};

// AFTER - Log and continue if non-critical
std.fs.deleteTreeAbsolute(tmp_dir) catch |err| {
    logError(@src(), err, "Failed to clean up temp directory");
    // Continue - cleanup failure is non-fatal
};

// OR - Propagate if critical
std.fs.deleteTreeAbsolute(tmp_dir) catch |err| {
    return ErrorContext{
        .err = .CleanupFailed,
        .message = "Failed to remove temporary directory",
        .recoverable = true,
        .suggestion = "Manually remove: " ++ tmp_dir,
    };
};
```

**Check C Interop Returns:**

```zig
// BEFORE
_ = c.nvlist_add_string(props, "mountpoint", mountpoint);

// AFTER
const ret = c.nvlist_add_string(props, "mountpoint", mountpoint);
if (ret != 0) {
    return error.NvlistOperationFailed;
}
```

### Deliverables

- [ ] Create unified error module (src/errors.zig)
- [ ] Replace all `catch {}` with logged handlers (40+ instances)
- [ ] Add return value checks for all C interop calls
- [ ] Implement ErrorContext for rich error information
- [ ] Add error aggregation for batch operations
- [ ] Create error handling style guide
- [ ] Add linter rule to detect empty catch blocks

---

## Phase 53: Input Validation Framework

**Priority**: High
**Complexity**: Medium
**Status**: ✓ Complete

### Purpose

Establish comprehensive input validation for all external data including URLs, YAML, JSON, and user-provided paths.

### Issues Identified

1. **URL Parsing Without Validation**
   - **Location**: `cache_protocol.zig` lines 783-798
   - **Issue**: Host/port extraction without sanitization
   ```zig
   const host = url[host_start..path_start];  // No validation
   const path = if (path_start < url.len) url[path_start..] else "/";  // Could contain traversal
   ```

2. **JSON Generation Without Escaping**
   - **Location**: `cache_protocol.zig` lines 37-62, 117-147
   - **Issue**: String interpolation without escaping special characters
   ```zig
   try std.fmt.format(buffer.writer(), "\"name\":\"{s}\",", .{self.name});  // No escaping!
   ```

3. **Incomplete YAML Parser**
   - **Location**: `manifest.zig` lines 117-149
   - **Issue**: Custom parser with documented limitations, silently ignores constructs

4. **Missing Numeric Bounds Checking**
   - **Location**: `bootenv.zig` lines 139-140
   - **Issue**: `parseSize()` and `parseTimestamp()` accept unbounded input

### Implementation

**URL Validator:**

```zig
// src/validation.zig
pub const UrlValidator = struct {
    pub const ValidationResult = struct {
        valid: bool,
        scheme: ?[]const u8,
        host: ?[]const u8,
        port: ?u16,
        path: ?[]const u8,
        error_message: ?[]const u8,
    };

    pub fn validate(url: []const u8) ValidationResult {
        // Check scheme
        if (!std.mem.startsWith(u8, url, "http://") and
            !std.mem.startsWith(u8, url, "https://")) {
            return .{ .valid = false, .error_message = "Invalid scheme" };
        }

        // Parse and validate host
        const host = extractHost(url) orelse
            return .{ .valid = false, .error_message = "Invalid host" };

        // Validate host characters (no control chars, null bytes)
        for (host) |c| {
            if (c < 0x20 or c == 0x7F) {
                return .{ .valid = false, .error_message = "Invalid character in host" };
            }
        }

        // Validate port range
        const port = extractPort(url) orelse 80;
        if (port == 0) {
            return .{ .valid = false, .error_message = "Invalid port" };
        }

        // Validate path (no traversal)
        const path = extractPath(url);
        if (std.mem.indexOf(u8, path, "..")) |_| {
            return .{ .valid = false, .error_message = "Path traversal detected" };
        }

        return .{
            .valid = true,
            .scheme = extractScheme(url),
            .host = host,
            .port = port,
            .path = path,
        };
    }
};
```

**JSON Escaping:**

```zig
pub fn escapeJsonString(allocator: Allocator, input: []const u8) ![]const u8 {
    var result = std.ArrayList(u8).init(allocator);
    errdefer result.deinit();

    for (input) |c| {
        switch (c) {
            '"' => try result.appendSlice("\\\""),
            '\\' => try result.appendSlice("\\\\"),
            '\n' => try result.appendSlice("\\n"),
            '\r' => try result.appendSlice("\\r"),
            '\t' => try result.appendSlice("\\t"),
            0x00...0x1F => {
                // Control characters as \uXXXX
                try result.writer().print("\\u{X:0>4}", .{c});
            },
            else => try result.append(c),
        }
    }

    return result.toOwnedSlice();
}

// Usage in cache_protocol.zig
const escaped_name = try escapeJsonString(allocator, self.name);
defer allocator.free(escaped_name);
try std.fmt.format(buffer.writer(), "\"name\":\"{s}\",", .{escaped_name});
```

**Numeric Bounds Validation:**

```zig
pub fn parseSize(input: []const u8) !u64 {
    const max_size: u64 = 1 << 50;  // 1 PB max

    // Parse numeric part
    var i: usize = 0;
    while (i < input.len and std.ascii.isDigit(input[i])) : (i += 1) {}

    if (i == 0) return error.InvalidSize;

    const num = std.fmt.parseInt(u64, input[0..i], 10) catch
        return error.SizeOverflow;

    // Parse suffix
    const suffix = input[i..];
    const multiplier: u64 = switch (suffix.len) {
        0 => 1,
        else => switch (suffix[0]) {
            'K', 'k' => 1024,
            'M', 'm' => 1024 * 1024,
            'G', 'g' => 1024 * 1024 * 1024,
            'T', 't' => 1024 * 1024 * 1024 * 1024,
            else => return error.InvalidSuffix,
        },
    };

    // Check overflow
    if (num > max_size / multiplier) return error.SizeOverflow;

    return num * multiplier;
}
```

### Deliverables

- [ ] Create validation module (src/validation.zig)
- [ ] Implement URL validator with full sanitization
- [ ] Implement JSON string escaping
- [ ] Add bounds checking to all numeric parsers
- [ ] Harden YAML parser or document limitations clearly
- [ ] Add validation for package names, version strings
- [ ] Create fuzz tests for all parsers
- [ ] Document validation requirements per input type

---

## Phase 54: Memory Safety Audit

**Priority**: High
**Complexity**: Medium
**Status**: ✓ Complete

### Purpose

Audit and fix memory management issues including improper cleanup, missing deinit calls, and allocation tracking.

### Issues Identified

1. **Global Config Lifecycle**
   - **Location**: `config.zig` lines 188-212
   - **Issue**: Global mutable state with poor cleanup semantics
   ```zig
   var global_config: ?Config = null;  // Never properly freed in production
   ```

2. **ArrayList Cleanup in Error Paths**
   - **Locations**: `cli.zig` (17), `service.zig` (14), `manifest.zig` (9), `resolver.zig` (31)
   - **Issue**: Not all error paths have proper `errdefer` for cleanup

3. **toOwnedSlice Failure Handling**
   - **Location**: `service.zig` lines 578-580
   - **Issue**: Failure returns empty slice but original list not freed
   ```zig
   svc.dependencies = deps_list.toOwnedSlice() catch &[_][]const u8{};
   // deps_list still holds allocations if this fails!
   ```

4. **Fragile Deferred Cleanup**
   - **Location**: `cache_protocol.zig` lines 816-835
   - **Issue**: ArrayList deinit timing issues

### Implementation

**Global Config Lifecycle:**

```zig
// BEFORE
var global_config: ?Config = null;

// AFTER - Proper lifecycle management
pub const ConfigManager = struct {
    config: ?Config = null,
    allocator: Allocator,
    ref_count: u32 = 0,

    pub fn acquire(self: *ConfigManager) !*Config {
        self.ref_count += 1;
        if (self.config) |*cfg| return cfg;

        self.config = try Config.load(self.allocator);
        return &self.config.?;
    }

    pub fn release(self: *ConfigManager) void {
        if (self.ref_count > 0) self.ref_count -= 1;
        if (self.ref_count == 0 and self.config != null) {
            self.config.?.deinit();
            self.config = null;
        }
    }
};

// Thread-local or passed explicitly
threadlocal var config_manager: ?ConfigManager = null;
```

**Safe ArrayList Pattern:**

```zig
// BEFORE - toOwnedSlice failure leaks
svc.dependencies = deps_list.toOwnedSlice() catch &[_][]const u8{};

// AFTER - Proper cleanup on failure
svc.dependencies = deps_list.toOwnedSlice() catch |err| {
    // Free all items in the list
    for (deps_list.items) |item| {
        allocator.free(item);
    }
    deps_list.deinit();
    return err;  // Or return empty and log
};
```

**Allocation Tracker for Debug:**

```zig
pub const TrackedAllocator = struct {
    backing: Allocator,
    allocations: std.AutoHashMap(usize, AllocationInfo),
    mutex: std.Thread.Mutex = .{},

    const AllocationInfo = struct {
        size: usize,
        source: std.builtin.SourceLocation,
        stack_trace: ?*std.builtin.StackTrace,
    };

    pub fn alloc(self: *TrackedAllocator, len: usize, src: std.builtin.SourceLocation) ![]u8 {
        const ptr = try self.backing.alloc(len);
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.allocations.put(@intFromPtr(ptr.ptr), .{
            .size = len,
            .source = src,
        });
        return ptr;
    }

    pub fn dumpLeaks(self: *TrackedAllocator) void {
        var it = self.allocations.iterator();
        while (it.next()) |entry| {
            std.log.warn("Leak: {d} bytes from {s}:{d}", .{
                entry.value_ptr.size,
                entry.value_ptr.source.file,
                entry.value_ptr.source.line,
            });
        }
    }
};
```

### Deliverables

- [ ] Audit all ArrayList/HashMap allocations (264+ instances)
- [ ] Add errdefer to all allocation error paths
- [ ] Fix toOwnedSlice failure handling
- [ ] Implement ConfigManager with proper lifecycle
- [ ] Create TrackedAllocator for debug builds
- [ ] Add leak detection to test suite
- [ ] Document ownership conventions
- [ ] Add static analysis for missing deinit

---

## Phase 55: Concurrency Safety

**Priority**: High
**Complexity**: Medium
**Status**: ✓ Complete
**Dependencies**: Phase 30 (Thread-Safe libzfs)

### Purpose

Address race conditions, mutex handling, and concurrent operation safety throughout the codebase.

### Issues Identified

1. **ZFS Handle Mutex Undocumented**
   - **Location**: `zfs.zig` line 137
   - **Issue**: Mutex exists but no documentation on which operations require locking

2. **GC Lock File Race Condition**
   - **Location**: `gc.zig` lines 85-115, 123
   - **Issue**: TOCTOU between lock release and file deletion
   ```zig
   fn releaseLock(self: *GarbageCollector) void {
       file.close();
       self.lock_file = null;
       std.fs.cwd().deleteFile(GC_LOCK_FILE_PATH) catch {};  // Race here!
   }
   ```

3. **Global Config Mutex Panic**
   - **Location**: `config.zig` lines 189-201
   - **Issue**: `getGlobalConfig()` may panic if initialization fails

4. **Lock Acquisition Fallback Logic**
   - **Location**: `gc.zig` lines 85-115
   - **Issue**: Returns from catch block without verifying lock acquired

### Implementation

**ZFS Operation Locking Documentation:**

```zig
pub const ZfsHandle = struct {
    handle: *c.libzfs_handle_t,
    mutex: std.Thread.Mutex = .{},

    /// Thread-safety documentation:
    /// - All dataset operations (create, destroy, snapshot) MUST hold mutex
    /// - Property reads are thread-safe without mutex
    /// - Multiple ZfsHandle instances can operate concurrently
    ///
    /// Operations requiring mutex:
    /// - createDataset()
    /// - destroyDataset()
    /// - createSnapshot()
    /// - cloneSnapshot()
    /// - setProperty()
    ///
    /// Thread-safe without mutex:
    /// - getProperty()
    /// - listDatasets() [read-only]
    /// - exists()

    pub fn withLock(self: *ZfsHandle, comptime func: anytype) @TypeOf(func).ReturnType {
        self.mutex.lock();
        defer self.mutex.unlock();
        return func(self);
    }
};
```

**Atomic Lock File Handling:**

```zig
pub fn acquireLock(self: *GarbageCollector) !void {
    // Use O_EXCL for atomic creation
    const lock_file = std.fs.cwd().createFile(GC_LOCK_FILE_PATH, .{
        .exclusive = true,
        .lock = .exclusive,
    }) catch |err| switch (err) {
        error.PathAlreadyExists => return GCError.GCAlreadyRunning,
        error.WouldBlock => return GCError.GCAlreadyRunning,
        else => return err,
    };

    // Write PID for debugging
    try lock_file.writer().print("{d}\n", .{std.os.linux.getpid()});

    self.lock_file = lock_file;
}

pub fn releaseLock(self: *GarbageCollector) void {
    if (self.lock_file) |file| {
        // Unlink while still holding lock - atomic
        std.fs.cwd().deleteFile(GC_LOCK_FILE_PATH) catch {};
        file.close();
        self.lock_file = null;
    }
}
```

**Config Initialization Safety:**

```zig
pub fn getGlobalConfig() !*Config {
    global_config_mutex.lock();
    defer global_config_mutex.unlock();

    if (global_config) |*cfg| return cfg;

    global_config = Config.load(default_allocator) catch |err| {
        // Don't panic - return error
        std.log.err("Failed to load config: {}", .{err});
        return err;
    };

    return &global_config.?;
}
```

### Deliverables

- [ ] Document thread-safety requirements for all public APIs
- [ ] Fix GC lock file race condition
- [ ] Add withLock() helper for ZfsHandle
- [ ] Remove panic paths from config initialization
- [ ] Add thread-safety tests
- [ ] Implement lock ordering documentation to prevent deadlocks
- [ ] Add deadlock detection in debug builds

---

## Phase 56: Module Decoupling

**Priority**: Medium
**Complexity**: High
**Status**: Planned

### Purpose

Reduce tight coupling between modules, especially in the CLI module which imports 26 other modules directly.

### Issues Identified

1. **CLI Module Coupling**
   - **Location**: `cli.zig` lines 1-56
   - **Issue**: CLI imports 26 modules directly
   ```zig
   const zfs = @import("zfs.zig");
   const store = @import("store.zig");
   const profile = @import("profile.zig");
   // ... 23 more imports
   ```

2. **No Abstraction Between Modules**
   - Each module directly accesses internals of other modules
   - No interface/trait system for polymorphism

3. **Error Type Fragmentation**
   - Each module has its own error enum
   - Errors don't compose at boundaries

### Implementation

**Module Interface Pattern:**

```zig
// src/interfaces.zig - Define module contracts

pub const PackageStore = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    const VTable = struct {
        getPackage: *const fn(*anyopaque, []const u8) anyerror!?Package,
        listPackages: *const fn(*anyopaque) anyerror![]Package,
        importPackage: *const fn(*anyopaque, ImportSource) anyerror!PackageId,
    };

    pub fn getPackage(self: PackageStore, name: []const u8) !?Package {
        return self.vtable.getPackage(self.ptr, name);
    }

    // ... other methods
};

// Implementations can vary (real store, mock store, etc.)
pub fn createRealStore(allocator: Allocator) PackageStore {
    return .{
        .ptr = @ptrCast(real_store),
        .vtable = &real_vtable,
    };
}

pub fn createMockStore(allocator: Allocator) PackageStore {
    return .{
        .ptr = @ptrCast(mock_store),
        .vtable = &mock_vtable,
    };
}
```

**CLI Dependency Injection:**

```zig
// src/cli.zig - Use interfaces instead of direct imports

pub const CliContext = struct {
    allocator: Allocator,
    store: interfaces.PackageStore,
    profile_manager: interfaces.ProfileManager,
    resolver: interfaces.Resolver,
    output: interfaces.Output,

    pub fn init(allocator: Allocator) !CliContext {
        return .{
            .allocator = allocator,
            .store = try store_impl.create(allocator),
            .profile_manager = try profile_impl.create(allocator),
            .resolver = try resolver_impl.create(allocator),
            .output = .{ .writer = std.io.getStdOut().writer() },
        };
    }
};

// Commands receive context, not global state
pub fn cmdResolve(ctx: *CliContext, args: ResolveArgs) !void {
    const profile = try ctx.profile_manager.load(args.profile_name);
    const result = try ctx.resolver.resolve(profile, ctx.store);
    try ctx.output.printResolution(result);
}
```

**Layered Architecture:**

```
┌─────────────────────────────────────────┐
│              CLI Layer                   │
│  (cli.zig - thin, uses interfaces)      │
└─────────────────┬───────────────────────┘
                  │ depends on
┌─────────────────▼───────────────────────┐
│           Service Layer                  │
│  (interfaces.zig - contracts)           │
└─────────────────┬───────────────────────┘
                  │ implemented by
┌─────────────────▼───────────────────────┐
│         Implementation Layer             │
│  (store.zig, resolver.zig, etc.)        │
└─────────────────┬───────────────────────┘
                  │ depends on
┌─────────────────▼───────────────────────┐
│          Foundation Layer                │
│  (zfs.zig, errors.zig, validation.zig)  │
└─────────────────────────────────────────┘
```

### Deliverables

- [ ] Create interfaces.zig with module contracts
- [ ] Refactor CLI to use dependency injection
- [ ] Create mock implementations for testing
- [ ] Reduce direct imports in CLI from 26 to ~5
- [ ] Document module boundaries and dependencies
- [ ] Create architecture diagram
- [ ] Add circular dependency detection to build

---

## Code-Boundary Assessment Summary

| Phase | Category | Severity | Issues | Files Affected |
|-------|----------|----------|--------|----------------|
| 51 | Security | Critical | 3 | zfs.zig, secure_tar.zig |
| 52 | Error Handling | High | 40+ | Multiple (hsm, bootstrap, desktop, service, etc.) |
| 53 | Input Validation | High | 5+ | cache_protocol, manifest, bootenv |
| 54 | Memory Safety | High | 3+ | config, service, cache_protocol |
| 55 | Concurrency | High | 4 | gc, config, zfs |
| 56 | Architecture | Medium | Multiple | cli, all modules |

### Priority Order

1. **Phase 51** - Critical security fixes (command injection, path traversal)
2. **Phase 53** - Input validation (prevents exploitation)
3. **Phase 52** - Error handling (enables debugging)
4. **Phase 54** - Memory safety (stability)
5. **Phase 55** - Concurrency safety (reliability)
6. **Phase 56** - Module decoupling (maintainability)

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
