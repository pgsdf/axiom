# Axiom Architecture

## Overview

Axiom is a ZFS-native system manager that provides immutable package storage, declarative profiles, and deterministic dependency resolution for PGSD systems.

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
