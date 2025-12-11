# Axiom System Manager

Axiom is the system manager for the Pacific Grove Software Distribution (PGSD). It provides an immutable ZFS-backed software store, declarative profiles, deterministic dependency resolution, and atomic environment activation.

## Architecture

Axiom is built on six core principles:

1. **Canonical truth is simple and human readable** - YAML manifests, not complex DSLs
2. **Immutable package store as ZFS datasets** - Leverages ZFS copy-on-write and snapshots
3. **Profiles define whole system state** - Declarative configuration
4. **Deterministic dependency resolution** - Reproducible builds
5. **ZFS first operations** - Create, snapshot, clone, send, receive
6. **Separation of concerns** - Build → Store → Index → Resolve → Realise → Activate

## Dataset Model

```
zroot/axiom/
├── store/pkg/<name>/<version>/<revision>/<build-id>/
│   ├── manifest.yaml       # Package metadata
│   ├── deps.yaml           # Dependencies
│   ├── provenance.yaml     # Build provenance
│   └── root/               # Package files
├── profiles/<name>/
│   ├── profile.yaml        # Requested packages
│   └── profile.lock.yaml   # Resolved dependencies
└── env/<name>/             # Realized environments (clones)
```

## Quick Start

### Prerequisites

- FreeBSD 14.x or GhostBSD with ZFS
- Zig 0.13.0 or later
- FreeBSD ports tree (`portsnap fetch extract` or `git clone`)

### Option 1: Automated Bootstrap (Recommended)

```bash
# Step 1: Build and install Axiom
zig build
sudo cp zig-out/bin/axiom /usr/local/bin/axiom

# Step 2: Run the setup wizard (creates ZFS datasets)
sudo axiom setup

# Step 3: Bootstrap from ports (automatic dependency ordering)
sudo axiom bootstrap-ports --minimal    # Quick: gmake, m4, help2man
# Or for full bootstrap:
sudo axiom bootstrap-ports              # Full: includes autoconf, automake, etc.

# Step 4: Import packages
sudo axiom ports-import shells/bash
sudo axiom ports-import editors/vim

# Step 5: Create profile, resolve, realize, activate
sudo axiom profile-create myprofile
sudo axiom profile-add-package myprofile bash vim
sudo axiom resolve myprofile
sudo axiom realize myenv myprofile
source /axiom/env/myenv/activate
```

### Option 2: Manual Bootstrap

If you prefer manual control or `bootstrap-ports` fails:

```bash
# After axiom setup, import in this exact order:
sudo axiom ports-import misc/help2man   # Required by m4
sudo axiom ports-import devel/m4        # Required by autoconf/gmake
sudo axiom ports-import devel/gmake     # Required by most packages
```

> **Warning**: The bootstrap order matters! `help2man` must be built before `m4`,
> and `m4` must be built before `gmake`. The dependency chain is automatically
> handled by `ports-import`, but if you skip packages, you may see errors.

### Option 3: Import Bootstrap Tarball

For air-gapped systems or faster setup:

```bash
# Download pre-built bootstrap tarball
curl -O https://axiom.pgsd.org/bootstrap/axiom-bootstrap-14.2-amd64.tar.zst

# Import it
sudo axiom bootstrap-import axiom-bootstrap-14.2-amd64.tar.zst
```

## Common Errors and Solutions

| Error | Cause | Solution |
|-------|-------|----------|
| `PackageNotFound` during resolve | Package not imported | Run `axiom ports-import <origin>` first |
| `missing dependency` during build | Bootstrap incomplete | Complete bootstrap chain, see above |
| `ZFS dataset exists` | Previous failed run | `axiom gc` or manually destroy dataset |
| Build fails with `gmake: not found` | gmake not bootstrapped | `axiom ports-import devel/gmake` |

## Important Notes

- **All store operations require root** - Use `sudo` for import, resolve, realize
- **Resolution requires packages in store** - Import before resolving profiles
- **Environment activation modifies PATH** - Do NOT activate as root for untrusted packages
- **The ports tree must exist** - Install with `portsnap fetch extract`

## Building

Requires:
- Zig 0.13.0 or later
- FreeBSD with ZFS or PGSD
- libzfs development headers

```bash
zig build
```

### Testing

Axiom provides several test targets for different use cases:

```bash
# Quick check - verify compilation succeeds
zig build check

# Unit tests - no root required
zig build test

# CI suite - build + unit tests (for automated CI)
zig build ci

# Full test suite - requires root and ZFS
sudo zig build ci-full

# Full unit tests with ZFS - requires root
sudo zig build test-full
```

#### Individual Test Executables

For debugging specific subsystems:

```bash
# Manifest parsing (no root)
./zig-out/bin/test-manifest

# Signature verification (no root)
./zig-out/bin/test-signature

# Package store (requires root + ZFS)
sudo ./zig-out/bin/test-store

# Dependency resolver
./zig-out/bin/test-resolver       # Mock tests
sudo ./zig-out/bin/test-resolver  # Full tests

# Garbage collector
./zig-out/bin/test-gc             # Mock tests
sudo ./zig-out/bin/test-gc        # Full tests

# Package import
./zig-out/bin/test-import         # Mock tests
sudo ./zig-out/bin/test-import    # Full tests
```

### ZFS Integration API

```zig
const zfs = @import("zfs.zig");

// Initialize ZFS library
var zfs_handle = try zfs.ZfsHandle.init();
defer zfs_handle.deinit();

// Create a dataset
try zfs_handle.createDataset(allocator, "zroot/axiom/test", .{
    .compression = "lz4",
    .readonly = false,
    .atime = false,
});

// Create a snapshot
try zfs_handle.snapshot(allocator, "zroot/axiom/test", "snap1", false);

// Clone snapshot to new dataset
try zfs_handle.clone(
    allocator,
    "zroot/axiom/test@snap1",
    "zroot/axiom/test-clone",
    null,
);

// Set property
try zfs_handle.setProperty(allocator, "zroot/axiom/test", "readonly", "on");

// Get property
const compression = try zfs_handle.getProperty(allocator, "zroot/axiom/test", "compression");
defer allocator.free(compression);
```

## Documentation

- [USER_GUIDE.md](USER_GUIDE.md) - **Comprehensive user guide** (start here!)
- [SETUP.md](SETUP.md) - ZFS dataset configuration
- [ARCHITECTURE.md](ARCHITECTURE.md) - System architecture and design
- [MANIFEST_FORMAT.md](MANIFEST_FORMAT.md) - Package manifest specifications
- [RESOLVER.md](RESOLVER.md) - Dependency resolution algorithm
- [CLI.md](CLI.md) - Command-line interface reference
- [SECURITY.md](SECURITY.md) - **Security model and threat documentation**
- [ROADMAP.md](ROADMAP.md) - Future enhancement planning

## License

BSD 2-Clause License

Copyright (c) 2025, Pacific Grove Software Distribution Foundation

## Author

Vester "Vic" Thacker, Principal Scientist, Pacific Grove Software Distribution Foundation
