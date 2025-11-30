# Axiom Architecture

## Overview

Axiom is a ZFS-native system manager that provides immutable package storage, declarative profiles, and deterministic dependency resolution for PGSD systems.

## Source File Reference

This section provides a comprehensive overview of each source file in the Axiom codebase.

### Core Infrastructure

#### `src/zfs.zig` - ZFS Integration Layer
The foundational layer providing direct bindings to FreeBSD's libzfs.

**Key Types:**
- `ZfsHandle` - Main handle for ZFS operations, wraps `libzfs_handle_t`
- `DatasetProperties` - Strongly-typed ZFS property configuration
- `ZfsError` - Error set for all ZFS operations

**Key Functions:**
- `init()` / `deinit()` - Initialize/cleanup ZFS library handle
- `createDataset()` - Create new ZFS datasets with properties
- `destroyDataset()` - Recursively destroy datasets
- `snapshot()` - Create point-in-time snapshots
- `clone()` - Clone snapshots to new datasets
- `setProperty()` / `getProperty()` - Manage dataset properties
- `mount()` / `unmount()` - Control dataset mounting
- `send()` / `receive()` - ZFS stream operations for distribution

**Dependencies:** libzfs, libnvpair, libzfs_core (C libraries)

#### `src/types.zig` - Core Type Definitions
Shared types used across all modules.

**Key Types:**
- `Version` - Semantic version (major.minor.patch) with comparison methods
- `VersionConstraint` - Union type for version matching:
  - `exact` - Exact version match
  - `range` - Min/max bounds with inclusivity
  - `tilde` - Patch-level updates (~1.2.3)
  - `caret` - Compatible updates (^1.2.3)
  - `any` - Wildcard matching
- `PackageId` - Unique package identifier (name, version, revision, build_id)
- `Dependency` - Package dependency with constraint

**Key Functions:**
- `Version.parse()` - Parse version string to struct
- `Version.compare()` - Three-way version comparison
- `VersionConstraint.satisfies()` - Check if version satisfies constraint

---

### Package Management

#### `src/store.zig` - Package Store Operations
Manages the immutable package store at `zroot/axiom/store/pkg/`.

**Key Types:**
- `PackageStore` - Main interface to the package store
- `PackageMetadata` - Full package information including manifest and dependencies

**Key Functions:**
- `init()` - Initialize store with ZFS handle
- `addPackage()` - Import package into store, set readonly
- `removePackage()` - Remove package (with safety checks)
- `getPackage()` - Retrieve package metadata
- `listPackages()` - Enumerate all packages in store
- `packageExists()` - Check package existence

**Dataset Layout:**
```
zroot/axiom/store/pkg/<name>/<version>/<revision>/<build-id>/
├── manifest.yaml
├── deps.yaml
└── root/
```

#### `src/manifest.zig` - Manifest Parsing
YAML manifest parsing for package metadata.

**Key Types:**
- `Manifest` - Package manifest structure
- `DependencySpec` - Dependency specification from YAML
- `ManifestParser` - YAML parsing state machine

**Key Functions:**
- `parse()` - Parse manifest.yaml content
- `parseDeps()` - Parse deps.yaml content
- `serialize()` - Write manifest back to YAML
- `deinit()` - Clean up parsed manifest

**Manifest Fields:**
- `name`, `version`, `revision` - Package identity
- `description`, `license`, `homepage` - Metadata
- `provides` - Virtual packages provided
- `conflicts` - Conflicting packages
- `replaces` - Superseded packages

#### `src/import.zig` - Package Import
Import packages from external sources into the store.

**Key Types:**
- `PackageImporter` - Handles import workflow
- `ImportSource` - Source type (directory, tarball, URL)
- `ImportOptions` - Configuration for import behavior

**Key Functions:**
- `importFromDirectory()` - Import from build output directory
- `importFromTarball()` - Import from compressed archive
- `detectMetadata()` - Auto-detect package info from files
- `validatePackage()` - Verify package structure

**Supported Formats:**
- Directories with manifest.yaml
- .tar.gz, .tar.xz, .tar.bz2, .tar.zst archives
- Auto-detection from package.json, Cargo.toml, CMakeLists.txt

---

### Profile & Environment Management

#### `src/profile.zig` - Profile Management
Manages declarative package profiles.

**Key Types:**
- `Profile` - Profile definition with requested packages
- `ProfileManager` - CRUD operations on profiles
- `LockFile` - Resolved dependency lock file

**Key Functions:**
- `create()` - Create new profile dataset
- `load()` / `save()` - Read/write profile.yaml
- `loadLock()` / `saveLock()` - Read/write profile.lock.yaml
- `delete()` - Remove profile and its dataset
- `list()` - Enumerate all profiles
- `snapshot()` - Create profile snapshot for rollback

**Profile Structure:**
```
zroot/axiom/profiles/<name>/
├── profile.yaml       # User intent
└── profile.lock.yaml  # Resolved state
```

#### `src/realization.zig` - Environment Realization
Creates usable environments from resolved profiles.

**Key Types:**
- `RealizationEngine` - Main realization coordinator
- `Environment` - Realized environment metadata
- `ActivationScript` - Shell script for environment activation

**Key Functions:**
- `realize()` - Create environment from lock file
- `clonePackages()` - Clone package datasets into environment
- `generateActivationScript()` - Create activate/deactivate scripts
- `destroy()` - Remove environment dataset

**Environment Layout:**
```
zroot/axiom/env/<name>/
├── bin/           # Merged executables
├── lib/           # Merged libraries
├── share/         # Merged data
└── activate       # Activation script
```

The `bin`, `lib`, and `share` directories represent the **logical merged view** of all packages. Internally, Axiom can implement this as either:
1. A premerged tree under the environment dataset, or
2. A stack of package `root/` trees overlaid with unionfs or similar mechanism.

The external layout remains consistent regardless of implementation.

#### `src/conflict.zig` - File Conflict Resolution
Handles file conflicts when merging packages.

**Key Types:**
- `ConflictDetector` - Detects file conflicts between packages
- `ConflictType` - Enum: same_content, different_content, type_mismatch, permission_diff
- `ConflictPolicy` - Resolution strategy: error, priority, keep_both
- `ConflictReport` - Summary of detected conflicts

**Key Functions:**
- `detectConflicts()` - Scan packages for overlapping files
- `resolveConflicts()` - Apply resolution policy
- `hashFile()` - SHA-256 content hashing for comparison

---

### Dependency Resolution

#### `src/resolver.zig` - Dependency Resolver
Core dependency resolution using greedy algorithm.

**Key Types:**
- `Resolver` - Main resolver interface
- `ResolutionResult` - Resolved package set or error
- `ResolutionStrategy` - greedy, sat, or auto

**Key Functions:**
- `resolve()` - Resolve profile dependencies
- `resolvePackage()` - Resolve single package with constraints
- `buildDependencyGraph()` - Construct transitive dependency graph
- `detectCycles()` - Check for circular dependencies
- `selectVersion()` - Choose best version satisfying constraints

**Algorithm:**
1. Parse profile package requests
2. For each package, find newest satisfying version
3. Recursively resolve dependencies
4. Check for conflicts
5. Generate lock file

#### `src/sat.zig` - SAT Solver Core
CDCL (Conflict-Driven Clause Learning) Boolean satisfiability solver.

**Key Types:**
- `SatSolver` - Main SAT solver instance
- `Clause` - Disjunction of literals
- `Literal` - Variable with polarity
- `Assignment` - Variable truth assignments

**Key Functions:**
- `addClause()` - Add constraint clause
- `solve()` - Find satisfying assignment
- `propagate()` - Unit propagation
- `analyze()` - Conflict analysis for learning
- `backtrack()` - Non-chronological backtracking

**Features:**
- VSIDS heuristic for variable selection
- Clause learning from conflicts
- Two-watched-literal scheme
- Restart strategies

#### `src/sat_resolver.zig` - SAT-Based Resolution
Encodes dependency resolution as SAT problem.

**Key Types:**
- `SatResolver` - SAT-based dependency resolver
- `PackageVariable` - SAT variable for package selection

**Key Functions:**
- `resolve()` - Resolve using SAT solver
- `encodeConstraints()` - Convert dependencies to clauses
- `decodeSolution()` - Extract packages from SAT solution
- `explainConflict()` - Human-readable conflict explanation

**Encoding:**
- Each package version = SAT variable
- At-most-one constraint per package name
- Dependency = implication clause
- Conflict = exclusion clause

---

### AppImage-Inspired Features (Phases 18-21)

#### `src/closure.zig` - Dependency Closure Computation
Computes complete transitive dependency closures.

**Key Types:**
- `ClosureComputer` - Computes package closures
- `Closure` - Complete dependency set with metadata
- `ClosureEntry` - Package with depth and required_by info

**Key Functions:**
- `computeForPackage()` - Compute closure for single package
- `computeForProfile()` - Compute closure for entire profile
- `getTopologicalOrder()` - Return packages in dependency order
- `estimateSize()` - Estimate total disk space

**Base Packages:** libc, libm, libpthread, and the runtime linker (e.g., `ld-elf.so.1` on FreeBSD) are excluded from closures.

#### `src/launcher.zig` - Runtime Launcher
Direct package execution without full environment setup.

**Key Types:**
- `Launcher` - Package execution coordinator
- `LaunchConfig` - Execution configuration
- `IsolationMode` - normal, isolated, system_first
- `LaunchResult` - Execution outcome

**Key Functions:**
- `launch()` - Execute package with closure
- `buildEnvironment()` - Construct LD_LIBRARY_PATH, PATH
- `detectMainExecutable()` - Find package entry point
- `spawn()` - Fork and exec with environment

**Environment Setup:**
```bash
LD_LIBRARY_PATH=/axiom/store/.../lib:...
PATH=/axiom/store/.../bin:...
exec /axiom/store/.../bin/program "$@"
```

#### `src/bundle.zig` - Bundle Creation
Creates portable, self-contained package bundles.

**Key Types:**
- `BundleBuilder` - Bundle creation coordinator
- `BundleFormat` - pgsdimg, zfs_stream, tarball, directory
- `BundleConfig` - Bundle options (compression, signing)
- `BundleManifest` - Embedded manifest for bundles
- `BundleResult` - Creation outcome

**Key Functions:**
- `createBundle()` - Create bundle in specified format
- `createPgsdimg()` - Self-extracting executable
- `createZfsStream()` - ZFS send stream bundle
- `createTarball()` - Compressed tar archive
- `writeSelfExtractor()` - Generate shell script header

**PGSDIMG Format:**
```
#!/bin/sh
# Self-extracting Axiom bundle
# axiom-bundle: version=1 format=pgsdimg
# axiom-bundle: name=<package> pkgver=<version>
# axiom-bundle: manifest-offset=<offset>
__ARCHIVE_START__
[compressed tarball]
```

The structured `# axiom-bundle:` comments provide machine-readable metadata that can be extracted without parsing the entire file.

#### `src/runtime.zig` - Runtime Layer Management
Manages shared runtime layers (similar to Flatpak runtimes).

**Key Types:**
- `RuntimeManager` - Runtime CRUD operations
- `RuntimeManifest` - Runtime specification
- `RuntimeVersion` - ABI version tracking

**Key Functions:**
- `createRuntime()` - Create new runtime layer
- `listRuntimes()` - Enumerate available runtimes
- `getRuntimePath()` - Get runtime dataset path
- `snapshotRuntime()` - Version runtime with snapshot

**Standard Runtimes:**
- `base-2025` - Minimal (libc, libm, libpthread)
- `full-2025` - Common libraries
- `gui-2025` - X11/Wayland support

#### `src/desktop.zig` - Desktop Integration
Freedesktop.org compliant desktop integration.

**Key Types:**
- `DesktopIntegration` - Desktop entry management
- `DesktopEntry` - .desktop file specification
- `IconInstaller` - Icon installation handler

**Key Functions:**
- `install()` - Install desktop entry, icons, MIME types
- `uninstall()` - Remove desktop integration
- `generateDesktopEntry()` - Create .desktop file content
- `installIcon()` - Install icon to XDG directories
- `registerMimeType()` - Associate MIME types

**XDG Paths:**
- `~/.local/share/applications/` - Desktop entries
- `~/.local/share/icons/` - Icons
- `~/.local/share/mime/` - MIME types

---

### Auxiliary Features

#### `src/gc.zig` - Garbage Collection
Removes unreferenced packages from the store.

**Key Types:**
- `GarbageCollector` - GC coordinator
- `GcStats` - Collection statistics
- `GcOptions` - Configuration (dry-run, grace period)

**Key Functions:**
- `collect()` - Run garbage collection
- `findReferences()` - Scan profiles and environments
- `markReachable()` - Mark referenced packages
- `sweep()` - Remove unreferenced packages

**Safety Features:**
- Dry-run mode
- Pre-GC snapshot
- Grace period for recent packages
- Interactive confirmation

#### `src/signature.zig` - Cryptographic Signatures
Ed25519 package signing and verification.

**Key Types:**
- `SignatureManager` - Signing/verification coordinator
- `KeyPair` - Ed25519 public/private key pair
- `Signature` - Package signature with file hashes
- `TrustStore` - Trusted public key storage

**Key Functions:**
- `generateKeyPair()` - Create new Ed25519 keys
- `sign()` - Sign package with private key
- `verify()` - Verify signature with public key
- `addTrustedKey()` / `removeTrustedKey()` - Manage trust store
- `hashFiles()` - SHA-256 hash all package files

**Signature Format:**
```yaml
signer: key-id
algorithm: ed25519
signature: base64...
files:
  - path: bin/program
    hash: sha256:...
```

#### `src/cache.zig` - Binary Cache
HTTP-based package distribution.

**Key Types:**
- `CacheClient` - Download packages from remote
- `CacheServer` - Serve packages over HTTP
- `CacheEntry` - Local cache entry metadata
- `RemoteCache` - Remote cache configuration

**Key Functions:**
- `fetch()` - Download package from cache
- `push()` - Upload package to cache
- `sync()` - Synchronize with remote
- `clean()` - Apply cleanup policy (LRU, LFU, FIFO)

**Features:**
- Priority-based cache selection
- Delta transfers (incremental ZFS send)
- Signature verification
- Resume support

#### `src/build.zig` - Build System
Build packages from source recipes.

**Key Types:**
- `Builder` - Build coordinator
- `BuildRecipe` - YAML build specification
- `BuildPhase` - configure, build, install, test
- `BuildSandbox` - Isolated build environment

**Key Functions:**
- `build()` - Execute full build pipeline
- `fetchSource()` - Download/extract source
- `runPhase()` - Execute build phase
- `postProcess()` - Strip binaries, compress man pages

**Recipe Format:**
```yaml
name: package
version: "1.0.0"
source:
  url: https://...
  sha256: ...
phases:
  configure: "./configure --prefix=$PREFIX"
  build: "make -j$JOBS"
  install: "make install"
```

#### `src/user.zig` - Multi-User Support
Per-user profiles and environments.

**Key Types:**
- `UserContext` - Current user information
- `UserManager` - User data management
- `AccessLevel` - root, user, readonly

**Key Functions:**
- `getCurrentUser()` - Detect running user
- `getUserDataPath()` - Get user-specific paths
- `createUserStructure()` - Initialize user datasets
- `listUsers()` - Enumerate users with Axiom data

**User Dataset Layout:**
```
zroot/axiom/users/<username>/
├── profiles/
└── env/
```

#### `src/completions.zig` - Shell Completions
Generate shell completion scripts.

**Key Functions:**
- `generateBash()` - Bash completion script
- `generateZsh()` - Zsh completion script
- `generateFish()` - Fish completion script

**Features:**
- Command completion
- Option completion
- Dynamic completion for profiles, environments, packages

---

### CLI Layer

#### `src/cli.zig` - Command-Line Interface
Main CLI implementation with all user commands.

**Key Types:**
- `CLI` - Main CLI handler
- `Command` - Enum of all commands
- `CommandResult` - Execution result

**Command Categories:**
- **Profile**: profile, profile-create, profile-show, profile-update, profile-delete
- **Package**: install, remove, search, info, list
- **Environment**: resolve, realize, activate, env, env-destroy
- **Signature**: key, key-generate, key-add, key-remove, sign, verify
- **Cache**: cache, cache-add, cache-remove, cache-fetch, cache-push
- **Build**: build
- **Bundles**: run, closure, export, bundle
- **Runtime**: runtime, runtime-create, runtime-use
- **Desktop**: desktop-install, desktop-remove
- **Multi-user**: user-*, system-*
- **Maintenance**: gc, completions, help, version

#### `src/axiom-cli.zig` - CLI Entry Point
Minimal entry point that initializes and runs CLI.

#### `src/main.zig` - Library Entry Point
Library entry point for programmatic use.

---

### Test Files

| File | Tests |
|------|-------|
| `test-store.zig` | Package store operations |
| `test-manifest.zig` | Manifest parsing |
| `test-profile.zig` | Profile management |
| `test-resolver.zig` | Dependency resolution |
| `test-realization.zig` | Environment realization |
| `test-gc.zig` | Garbage collection |
| `test-import.zig` | Package import |
| `test-signature.zig` | Cryptographic operations |
| `test-cache.zig` | Binary cache operations |

**Running Tests:**
```bash
# Unit tests (no root needed)
zig build test

# Integration tests (requires root for ZFS)
sudo zig build test
```

---

## Core Design Philosophy

### 1. ZFS as Foundation

Rather than fighting the filesystem (symlink farms, hardlink pools), Axiom embraces ZFS as the fundamental primitive:

- **Datasets** are packages
- **Snapshots** are package versions
- **Clones** are environments
- **Properties** are metadata
- **Send/receive** is distribution

This eliminates entire classes of problems that plague traditional package managers:
- No broken symlinks
- No permission issues from hardlinks
- No manual deduplication
- Atomic operations by design
- Built-in compression and checksumming

### 2. Immutability by Design

```
zroot/axiom/store/pkg/bash/5.2.0/1/abc123def/
├── manifest.yaml       [immutable]
├── deps.yaml           [immutable]
├── provenance.yaml     [immutable]
└── root/               [readonly after creation]
    ├── bin/bash
    └── ...
```

Once a package dataset is created:
1. Write package files
2. Write manifests
3. Set `readonly=on`
4. Never modified again

This prevents:
- Dependency drift
- Version skew
- Reproducibility issues
- Cache invalidation problems

### 3. Six-Stage Pipeline

```
Build → Store → Index → Resolve → Realise → Activate
```

Each stage has a single responsibility:

**Build**: Compile source into artifacts (external to Axiom)
**Store**: Import built packages into immutable datasets
**Index**: Build searchable database from manifests (disposable)
**Resolve**: Solve dependency constraints
**Realise**: Create environment from resolved packages
**Activate**: Mount/link environment for use

## ZFS Integration Layer

### libzfs Binding Strategy

Direct C bindings via Zig's `@cImport`:

```zig
const c = @cImport({
    @cInclude("libzfs.h");
    @cInclude("sys/nvpair.h");
});
```

**Why not use an existing Zig libzfs wrapper?**
- None exist for FreeBSD
- Direct bindings give full control
- No dependency on third-party maintenance
- Optimized for Axiom's specific use patterns

### Error Handling

Zig's error sets map cleanly to libzfs errno values:

```zig
pub const ZfsError = error{
    InitFailed,
    DatasetNotFound,
    DatasetExists,
    PermissionDenied,
    InvalidOperation,
    PropertyError,
    OutOfMemory,
    Unknown,
};
```

All ZFS operations are fallible and return `!T`:

```zig
pub fn createDataset(
    self: *ZfsHandle,
    allocator: std.mem.Allocator,
    path: []const u8,
    props: ?DatasetProperties,
) !void
```

This forces callers to handle errors explicitly.

### Memory Management

ZFS operations use multiple allocation strategies:

**1. Temporary allocations** (C strings for libzfs):
```zig
const c_path = try allocator.dupeZ(u8, path);
defer allocator.free(c_path);
```

**2. nvlist allocation** (nvpair library):
```zig
var nvlist: ?*c.nvlist_t = null;
_ = c.nvlist_alloc(&nvlist, c.NV_UNIQUE_NAME, 0);
defer if (nvlist) |list| c.nvlist_free(list);
```

**3. Returned data** (properties, mountpoints):
```zig
pub fn getProperty(...) ![]u8 {
    var buf: [1024]u8 = undefined;
    // ... get property into buf ...
    return try allocator.dupe(u8, buf[0..value_len]);
}
```

Callers own returned memory and must free it.

### Property Management

ZFS properties are strongly typed:

```zig
pub const DatasetProperties = struct {
    canmount: ?bool = null,
    mountpoint: ?[]const u8 = null,
    readonly: ?bool = null,
    compression: ?[]const u8 = null,
    quota: ?u64 = null,
    reservation: ?u64 = null,
    recordsize: ?u32 = null,
    atime: ?bool = null,
};
```

This prevents property type errors at compile time.

### Dataset Operations

**Creation**:
```zig
try zfs.createDataset(allocator, "zroot/axiom/store/pkg/bash/5.2.0/1/abc123", .{
    .compression = "lz4",
    .atime = false,
    .readonly = false,  // Set to true after population
});
```

**Snapshot**:
```zig
try zfs.snapshot(allocator, "zroot/axiom/store/pkg/bash/5.2.0/1/abc123", "installed", false);
```

**Clone** (for environments):
```zig
try zfs.clone(
    allocator,
    "zroot/axiom/store/pkg/bash/5.2.0/1/abc123@installed",
    "zroot/axiom/env/my-env/bash",
    null,
);
```

**Property modification**:
```zig
try zfs.setProperty(allocator, "zroot/axiom/store/pkg/bash/5.2.0/1/abc123", "readonly", "on");
```

## Package Store Design

### Dataset Layout

```
zroot/axiom/store/pkg/
└── <package-name>/
    └── <version>/
        └── <revision>/
            └── <build-id>/
                ├── manifest.yaml
                ├── deps.yaml
                ├── provenance.yaml
                └── root/
                    └── [package files]
```

**Why build-id?**
- Same source can be built multiple times
- Different build flags produce different outputs
- Allows bit-for-bit reproducibility verification
- Build ID = content hash of build inputs

### Manifest Format

**manifest.yaml**:
```yaml
name: bash
version: 5.2.0
revision: 1
description: GNU Bourne Again Shell
license: GPL-3.0
homepage: https://www.gnu.org/software/bash/
```

**deps.yaml**:
```yaml
dependencies:
  - name: readline
    version: ">=8.0.0"
  - name: ncurses
    version: "~6.4"
```

**provenance.yaml**:
```yaml
build_time: 1700000000
builder: build-host-01
source_hash: sha256:abc123...
compiler: clang-16.0.0
build_flags:
  - -O2
  - -march=native
```

### Store Operations

**Add package**:
1. Create dataset: `zroot/axiom/store/pkg/<n>/<v>/<r>/<id>`
2. Copy files to dataset mountpoint
3. Write manifest.yaml, deps.yaml, provenance.yaml
4. Set readonly=on
5. Create snapshot: `@installed`
6. Update index

**Remove package**:
1. Check if any profiles reference it
2. If not: `zfs destroy -r <dataset>`
3. Update index

**Query package**:
1. Check index for metadata
2. If needed, open dataset and read manifests

## Profile Management

### Profile Structure

```
zroot/axiom/profiles/dev/
├── profile.yaml       # User intent
└── profile.lock.yaml  # Resolved state
```

**profile.yaml**:
```yaml
name: dev
packages:
  - name: gcc
    version: ">=13.0"
  - name: git
    version: "*"
  - name: vim
    version: "~9.0"
```

**profile.lock.yaml**:
```yaml
name: dev
resolved:
  - id: gcc/13.2.0/1/xyz789
    dependencies:
      - binutils/2.40/1/def456
      - gmp/6.2.1/1/ghi789
  - id: git/2.42.0/1/jkl012
    dependencies:
      - curl/8.3.0/1/mno345
  - id: vim/9.0.1/1/pqr678
    dependencies: []
```

### Profile Operations

**Create profile**:
1. Write profile.yaml
2. Run dependency resolution
3. Generate profile.lock.yaml
4. Store both in profile dataset

**Update profile**:
1. Modify profile.yaml
2. Re-run dependency resolution
3. Generate new profile.lock.yaml
4. Snapshot old profile: `@before-update`

**Realize profile**:
1. Read profile.lock.yaml
2. For each resolved package:
   - Clone package dataset to env
3. Build unified tree
4. Mount/activate

## Environment Realization

### Clone-Based Approach

```
zroot/axiom/env/my-env/
├── gcc/           # clone of store/pkg/gcc/.../...@installed
├── git/           # clone of store/pkg/git/.../...@installed
├── vim/           # clone of store/pkg/vim/.../...@installed
└── .axiom/
    └── env.yaml   # Environment metadata
```

Each package is a ZFS clone, not a copy.

**Benefits**:
- Instant "copy" (clone is pointer to snapshot)
- Space-efficient (COW only on writes)
- Independent modification (if needed)
- Easy cleanup (destroy clones)

### Activation

Two strategies:

**1. Mount overlay**:
```
mount -t unionfs -o ro /axiom/env/my-env/gcc/root:/axiom/env/my-env/git/root:... /usr/local
```

**2. Direct mount**:
```
mount /axiom/env/my-env/gcc/root/bin /usr/local/bin
mount /axiom/env/my-env/gcc/root/lib /usr/local/lib
...
```

Choice depends on use case and system configuration.

## Dependency Resolution

### Constraint Solving

**Version constraints**:
- Exact: `1.2.3`
- Range: `>=1.2.0,<2.0.0`
- Tilde: `~1.2.3` → `>=1.2.3,<1.3.0`
- Caret: `^1.2.3` → `>=1.2.3,<2.0.0`
- Wildcard: `*` → any version

**Algorithm** (initial implementation):
1. Start with user requests
2. Find latest version satisfying each constraint
3. Recursively resolve dependencies
4. Check for conflicts
5. Backtrack if needed
6. Return solution or error

**Future**: SAT solver for optimal resolution

### Index Structure

Disposable SQLite database:

```sql
CREATE TABLE packages (
    name TEXT,
    version TEXT,
    revision INTEGER,
    build_id TEXT,
    dataset_path TEXT,
    PRIMARY KEY (name, version, revision, build_id)
);

CREATE TABLE dependencies (
    package_name TEXT,
    package_version TEXT,
    package_revision INTEGER,
    package_build_id TEXT,
    dep_name TEXT,
    dep_constraint TEXT,
    FOREIGN KEY (package_name, package_version, package_revision, package_build_id)
        REFERENCES packages(name, version, revision, build_id)
);

CREATE INDEX idx_name ON packages(name);
CREATE INDEX idx_deps ON dependencies(package_name);
```

Index can be rebuilt from store manifests at any time.

## Garbage Collection

### Reference Counting

**Live references**:
1. Profiles (profile.lock.yaml)
2. Active environments (env.yaml)
3. Explicit holds (manual pins)

**GC algorithm**:
1. Enumerate all package datasets in store
2. Build reference graph from profiles + environments
3. Mark all referenced packages and dependencies
4. Sweep unreferenced packages
5. Confirm before destruction

**Safety**:
- Dry-run mode shows what would be deleted
- Snapshot before GC: `zfs snapshot -r zroot/axiom/store@before-gc`
- Keep recent packages even if unreferenced (grace period)

### Future: Generation-Based GC

Track environment generations:
```
zroot/axiom/profiles/dev@gen-1
zroot/axiom/profiles/dev@gen-2
zroot/axiom/profiles/dev@gen-3
```

Keep packages for N generations back.

## Bootstrap Strategy

### Minimal Requirements

1. FreeBSD base system
2. ZFS dataset: `zroot/axiom`
3. Zig compiler (for building Axiom)
4. `axiom` binary

### Bootstrap Process

1. Build Axiom from source
2. Create root dataset: `zfs create zroot/axiom`
3. Initialize store: `zfs create zroot/axiom/store`
4. Import bootstrap packages (core system)
5. Create first profile
6. Realize and activate

### Self-Hosting

Once Axiom manages core packages, Axiom itself becomes a package:

```
zroot/axiom/store/pkg/axiom/1.0.0/1/abc123/
├── manifest.yaml
├── deps.yaml
├── provenance.yaml
└── root/
    └── bin/
        └── axiom
```

Axiom can then update itself through the normal package mechanism.

## Future Considerations

### Distribution

**ZFS send/receive**:
```bash
# Server
zfs send -R zroot/axiom/store/pkg/gcc/13.2.0/1/xyz789@installed | \
    ssh client zfs receive zroot/axiom/store/pkg/gcc/13.2.0/1/xyz789
```

**Binary cache**:
- HTTP server serving ZFS send streams
- Client: `axiom fetch gcc@13.2.0`
- Pipes ZFS receive directly

### Signing and Verification

**Package signatures**:
```yaml
# provenance.yaml
signatures:
  - key_id: PGSD-BUILD-01
    algorithm: ed25519
    signature: base64...
```

**Verification**:
1. Download package dataset
2. Verify signature before importing
3. Store verification status in dataset property

### Cross-Platform

While designed for FreeBSD/GhostBSD:
- Linux with ZFS could work
- Needs platform-specific build infrastructure
- Core design is platform-agnostic

---

**Author**: Vester "Vic" Thacker  
**Organization**: Pacific Grove Software Distribution Foundation  
**License**: BSD 2-Clause
