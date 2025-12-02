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

### Building

Requires:
- Zig 0.13.0 or later
- FreeBSD with ZFS or PGSD
- libzfs development headers

```bash
zig build
```

### Testing

```bash
# Run unit tests (requires root for ZFS operations)
sudo zig build test

# Test ZFS integration
sudo zig build run

# Test manifest parsing
./zig-out/bin/test-manifest

# Test package store operations (requires root)
sudo ./zig-out/bin/test-store

# Test profile management (requires root for ZFS tests)
./zig-out/bin/test-profile  # Parsing only
sudo ./zig-out/bin/test-profile  # Full tests with ZFS

# Test dependency resolver
./zig-out/bin/test-resolver  # Mock tests
sudo ./zig-out/bin/test-resolver  # Full tests with store

# Test realization engine (requires root)
sudo ./zig-out/bin/test-realization

# Test garbage collector
./zig-out/bin/test-gc  # Mock tests
sudo ./zig-out/bin/test-gc  # Full tests with ZFS

# Test package import
./zig-out/bin/test-import  # Mock tests
sudo ./zig-out/bin/test-import  # Full tests with ZFS

# Test signature verification (no root needed)
./zig-out/bin/test-signature

# Test CLI
sudo ./zig-out/bin/axiom help
sudo ./zig-out/bin/axiom key-generate --output mykey
sudo ./zig-out/bin/axiom key-add mykey.pub
sudo ./zig-out/bin/axiom key
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

## Quick Start

```bash
# Install
zig build
sudo cp zig-out/bin/axiom /usr/local/bin/axiom

# Create profile
sudo axiom profile-create development

# Add packages (edit profile.yaml manually for now)

# Resolve dependencies
sudo axiom resolve development

# Create environment
sudo axiom realize dev-env development

# Activate
source /axiom/env/dev-env/activate

# Use your packages!
```

## Documentation

- [USER_GUIDE.md](USER_GUIDE.md) - **Comprehensive user guide** (start here!)
- [SETUP.md](SETUP.md) - ZFS dataset configuration
- [ARCHITECTURE.md](ARCHITECTURE.md) - System architecture and design
- [MANIFEST_FORMAT.md](MANIFEST_FORMAT.md) - Package manifest specifications
- [RESOLVER.md](RESOLVER.md) - Dependency resolution algorithm
- [CLI.md](CLI.md) - Command-line interface reference
- [ROADMAP.md](ROADMAP.md) - Future enhancement planning

## License

BSD 2-Clause License

Copyright (c) 2025, Pacific Grove Software Distribution Foundation

## Author

Vester "Vic" Thacker, Principal Scientist, Pacific Grove Software Distribution Foundation
