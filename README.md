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

## Current Status

**Phase 1: ZFS Integration Layer** ✓

The ZFS integration layer provides direct bindings to libzfs for:

- Dataset creation and destruction
- Snapshot management
- Clone operations
- Property get/set
- Mount/unmount operations

**Phase 2: Manifest Parsing** ✓

Manifest parsing supports:

- Package metadata (manifest.yaml)
- Dependency specifications (deps.yaml)  
- Build provenance (provenance.yaml)
- Version constraint types (exact, tilde, caret, range, any)
- YAML parsing and validation

**Phase 3: Package Store Operations** ✓

Package store provides:

- Add packages to immutable ZFS datasets
- Remove packages with safety checks
- Query package metadata
- Automatic dataset creation with compression
- Manifest storage and retrieval
- Readonly snapshots after package creation

**Phase 4: Profile Management** ✓

Profile management supports:

- Create and manage profiles (sets of packages)
- Profile definitions with version constraints
- Lock files for resolved dependencies
- ZFS-backed profile storage
- Snapshot on profile update
- Profile YAML parsing and serialization

**Phase 5: Dependency Resolver** ✓

Dependency resolver provides:

- Greedy resolution algorithm (newest version selection)
- Version constraint satisfaction (exact, tilde, caret, range, wildcard)
- Transitive dependency resolution
- Circular dependency detection
- Conflict detection for incompatible constraints
- Lock file generation for reproducible builds

**Phase 6: Realization Engine** ✓

Realization engine provides:

- Create environments from lock files
- Clone package datasets into unified directory structure
- Merge multiple packages into single environment
- Generate activation scripts for shell integration
- Environment snapshots for rollback
- Activate/deactivate environments
- Destroy environments when no longer needed

**Phase 7: CLI Interface** ✓

Command-line interface provides:

- Comprehensive command set for all operations
- Profile management (create, list, show, update, delete)
- Package operations (install, remove, search, info, list)
- Environment operations (resolve, realize, activate, destroy)
- Garbage collection
- Interactive confirmations for destructive operations
- Helpful error messages and usage information

**Phase 8: Garbage Collection** ✓

Garbage collector provides:

- Scan package store for all packages
- Identify packages referenced by profiles and environments
- Remove unreferenced packages safely
- Dry-run mode to preview removals
- Safety snapshots before collection
- Statistics reporting (packages removed, space freed)
- Grace period for recent packages
- Performance metrics

**Phase 9: Package Import** ✓

Package import provides:

- Import from directories (build outputs)
- Import from tarballs (.tar.gz, .tar.xz, .tar.bz2, .tar.zst)
- Auto-detection of package metadata
- Support for package.json, Cargo.toml, CMakeLists.txt, Makefile
- Manifest file support for explicit metadata
- Dry-run mode for preview
- Build ID generation for reproducibility

**Phase 15: Signature Verification** ✓

Cryptographic verification provides:

- Ed25519 digital signatures
- Key pair generation
- Trust store for public keys
- Package signing with file hashes
- Signature verification
- Tamper detection via SHA-256 hashes
- Verification modes (strict, warn, disabled)
- Key import/export

**Phase 11: Shell Completions** ✓

Shell completion support provides:

- Bash completion script generation
- Zsh completion script generation
- Fish completion script generation
- Command and option completion
- Dynamic completion for profiles, environments, packages, keys, caches
- Installation instructions for each shell

**Phase 17: Binary Cache** ✓

HTTP-based package distribution provides:

- Cache server for serving packages over HTTP
- Cache client for downloading and verifying packages
- ZFS send/receive for efficient binary transfer
- Multiple remote cache support with priorities
- Local cache management with size limits
- Cleanup policies (LRU, LFU, FIFO)
- Delta transfer support (incremental ZFS send)
- Signature verification integration
- Resume support for interrupted transfers

**Phase 10: Build System Integration** ✓

Native package building from source provides:

- Declarative YAML build recipes
- Support for URL, local path, and git sources
- SHA256 checksum verification
- Build and runtime dependency separation
- Configurable build phases (configure, build, install, test)
- ZFS sandbox isolation for builds
- Parallel job support
- Post-processing (strip binaries, compress man pages)
- Direct import into package store

**Phase 12: Multi-user Support** ✓

Per-user profiles and environments provide:

- Per-user profile storage (zroot/axiom/users/{username}/profiles)
- Per-user environments (zroot/axiom/users/{username}/env)
- Shared package store (read-only access for users)
- User context with access level detection (root, user, readonly)
- User-scoped CLI commands (user-profile-create, user-realize, etc.)
- System administration commands (system-users, system-user-remove)
- Permission model (root operations vs user operations)
- Automatic user dataset structure creation

**Phase 13: Virtual Packages** ✓

Virtual package support provides:

- Provides declarations (virtual package names a package satisfies)
- Conflicts declarations (packages that cannot coexist)
- Replaces declarations (packages this one supersedes)
- Virtual package resolution in the dependency resolver
- CLI commands for querying virtual packages (virtual, virtual-providers)
- CLI commands for package relationships (provides, conflicts, replaces)
- Version constraints on conflict and replace declarations
- Automatic conflict detection during resolution

**Phase 14: Conflict Resolution** ✓

File conflict handling during environment realization provides:

- Detection of file conflicts between packages (same path, different content)
- Conflict types: same_content, different_content, type_mismatch, permission_diff
- SHA-256 content hashing for accurate conflict detection
- Multiple resolution strategies:
  - `error` - Fail on any conflict (safe default)
  - `priority` - Later package in lock file wins
  - `keep-both` - Rename conflicting files with package suffix
- Per-path conflict rules with glob patterns
- Conflict tracking and summary reporting
- CLI `--conflict-policy` flag for realize commands
- Works with both system and user environments

**Phase 16: SAT Solver** ✓

Advanced dependency resolution using Boolean Satisfiability provides:

- CDCL (Conflict-Driven Clause Learning) SAT solver
- VSIDS heuristic for variable selection
- Package dependency encoding as SAT variables
- Version constraint satisfaction via clauses
- Resolution strategies:
  - `greedy` - Fast algorithm, picks newest satisfying version
  - `sat` - SAT solver for complex constraints
  - `auto` - Try greedy first, fallback to SAT on failure
- CLI `--strategy` flag for resolve commands
- Detailed diagnostics for unsatisfiable constraints
- Conflict explanations and suggestions
- MaxSAT optimization for version preferences

### Building

Requires:
- Zig 0.13.0 or later
- FreeBSD/GhostBSD with ZFS
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
sudo ./zig-out/bin/axiom-cli help
sudo ./zig-out/bin/axiom-cli key-generate --output mykey
sudo ./zig-out/bin/axiom-cli key-add mykey.pub
sudo ./zig-out/bin/axiom-cli key
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

## Design Decisions

### Why Zig?

1. **No runtime dependencies** - Static binaries for bootstrap scenarios
2. **Direct C interop** - Clean libzfs integration without cgo overhead
3. **Manual memory management** - Predictable performance for dependency resolution
4. **Comptime** - Zero-cost abstractions for manifest validation
5. **20+ year horizon** - Stable ABI, deterministic behavior

### Why ZFS?

1. **Copy-on-write** - Free cloning for environments
2. **Snapshots** - Atomic package operations
3. **Send/receive** - Efficient distribution
4. **Compression** - Native dataset compression
5. **Provenance** - Dataset properties track metadata

### ZFS Error Handling

The integration layer provides Zig error types for all ZFS operations:

```zig
pub const ZfsError = error{
    InitFailed,           // libzfs_init failed
    DatasetNotFound,      // Dataset doesn't exist
    DatasetExists,        // Dataset already exists
    PermissionDenied,     // Insufficient permissions
    InvalidOperation,     // Invalid name or operation
    PropertyError,        // Property error
    OutOfMemory,          // Allocation failed
    Unknown,              // Other libzfs error
};
```

All ZFS operations return `!void` or `!T`, making error handling explicit.

## Next Steps

- [x] Phase 1: ZFS Integration
- [x] Phase 2: Manifest Parsing
- [x] Phase 3: Package Store Operations
- [x] Phase 4: Profile Management
- [x] Phase 5: Dependency Resolver
- [x] Phase 6: Realization Engine
- [x] Phase 7: CLI Interface
- [x] Phase 8: Garbage Collection
- [x] Phase 9: Package Import
- [x] Phase 15: Signature Verification
- [x] Phase 12: Multi-user Support
- [x] Phase 13: Virtual Packages
- [x] Phase 14: Conflict Resolution
- [x] Phase 16: SAT Solver

**🎉 All phases complete! Full-featured ZFS-native package manager ready for production.**

## Future Enhancements

See [ROADMAP.md](ROADMAP.md) for detailed planning of future phases:

| Phase | Enhancement | Priority | Status |
|-------|-------------|----------|--------|
| 9 | Package Import | High | ✓ Complete |
| 10 | Build System Integration | High | ✓ Complete |
| 11 | Shell Completions | Medium | ✓ Complete |
| 12 | Multi-user Support | Medium | ✓ Complete |
| 13 | Virtual Packages | Medium | ✓ Complete |
| 14 | Conflict Resolution | Medium | ✓ Complete |
| 15 | Signature Verification | High | ✓ Complete |
| 16 | SAT Solver | Low | ✓ Complete |
| 17 | Binary Cache | High | ✓ Complete |

**All Phases Complete!** Axiom includes:
- Core package management (Phases 1-8)
- Package import and build system (Phases 9-10)
- Shell completions (Phase 11)
- Multi-user support (Phase 12)
- Virtual packages and conflict resolution (Phases 13-14)
- Signature verification and binary cache (Phases 15, 17)
- Advanced SAT-based dependency resolution (Phase 16)

## Quick Start

```bash
# Install
zig build
sudo cp zig-out/bin/axiom-cli /usr/local/bin/axiom

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

Copyright (c) 2024, Pacific Grove Software Distribution Foundation

## Author

Vester "Vic" Thacker
Principal Scientist, Pacific Grove Software Distribution Foundation
