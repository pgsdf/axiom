# Axiom Setup Guide

## ZFS Dataset Configuration

Axiom requires proper ZFS dataset configuration before use. Follow these steps **in order**:

### 1. Create Root Dataset

```bash
zfs create zroot/axiom
```

### 2. Set Mountpoint (BEFORE creating children!)

**IMPORTANT**: Set the mountpoint on `zroot/axiom` **before** creating child datasets. Child datasets inherit the mountpoint from their parent, so this must be done first.

```bash
zfs set mountpoint=/axiom zroot/axiom
```

**Why `/axiom`?**
- Automatic mounting by ZFS (no /etc/fstab entries needed)
- Self-contained and independent from system directories
- Cleaner separation of concerns
- Simplifies disaster recovery

### 3. Create Subdataset Structure

Now create the child datasets (they will inherit `/axiom` as their mountpoint base):

```bash
# Package store (contains pkg/ subdataset for actual packages)
zfs create zroot/axiom/store
zfs create zroot/axiom/store/pkg

# Profile storage
zfs create zroot/axiom/profiles

# Environment storage
zfs create zroot/axiom/env

# Build sandbox storage
zfs create zroot/axiom/builds
```

### 4. Verify Configuration

Check that datasets are properly configured:

```bash
zfs list -r zroot/axiom
```

Expected output:
```
NAME                     USED  AVAIL  REFER  MOUNTPOINT
zroot/axiom              XXX   XXX    96K    /axiom
zroot/axiom/store        96K   XXX    96K    /axiom/store
zroot/axiom/store/pkg    96K   XXX    96K    /axiom/store/pkg
zroot/axiom/profiles     96K   XXX    96K    /axiom/profiles
zroot/axiom/env          96K   XXX    96K    /axiom/env
zroot/axiom/builds       96K   XXX    96K    /axiom/builds
```

### 5. Filesystem Layout

After setup, you'll have:

```
/axiom/
├── store/              # Package store root
│   └── pkg/            # Individual package datasets (ZFS dataset per package)
│       ├── bash/       # Example: bash package
│       │   └── 5.2.0/  # Version directory
│       │       └── 1/  # Revision
│       │           └── <build_id>/
│       │               └── root/  # Package contents
│       └── python/     # Example: python package
├── profiles/           # Profile definitions and locks
├── env/                # Realized environments (cloned from packages)
└── builds/             # Build sandbox storage
```

### 6. Permissions

Ensure proper permissions (Axiom typically runs as root for ZFS operations):

```bash
ls -ld /axiom
# Should show: drwxr-xr-x  root  wheel  /axiom
```

## Next Steps

After completing dataset setup:

1. Build Axiom: `zig build`
2. Install CLI: `sudo cp zig-out/bin/axiom /usr/local/bin/axiom`
3. Verify installation: `sudo axiom help`

## Setup Order: Packages Before Profiles

**IMPORTANT**: Packages must exist in the store before you can create profiles that reference them.

The setup order is:

```
ZFS Datasets → Install Axiom → Import Packages → Create Profiles → Resolve → Realize
```

### Why This Order Matters

When you create a profile and try to resolve it, the resolver looks in the store (`/axiom/store/pkg/`) for available packages. If the packages don't exist, resolution will fail with `PackageNotFound`.

### Recommended First-Time Setup Flow

```bash
# 1. Complete ZFS setup (above)

# 2. Build and install Axiom
zig build
sudo cp zig-out/bin/axiom /usr/local/bin/axiom

# 3. Import packages FIRST (choose one method)

# Option A: Import from FreeBSD Ports
axiom ports-import shells/bash
axiom ports-import editors/vim
axiom ports-import devel/git

# Option B: Import pre-built packages
sudo axiom import /path/to/bash-5.2.0.tar.gz
sudo axiom import /path/to/vim-9.0.tar.gz

# Option C: Fetch from binary cache
sudo axiom cache-add https://cache.pgsdf.org 1
sudo axiom cache-fetch bash@5.2.0 --install

# 4. NOW create profiles (packages are available)
sudo axiom profile-create development

# 5. Edit profile to add the packages you imported
sudo vi /axiom/profiles/development/profile.yaml

# 6. Resolve and realize
sudo axiom resolve development
sudo axiom realize dev-env development
```

### Common Mistake

```bash
# WRONG ORDER - This will fail!
sudo axiom profile-create development
# Edit profile.yaml to include bash, vim, git...
sudo axiom resolve development
# Error: PackageNotFound - bash not in store

# CORRECT ORDER
axiom ports-import shells/bash    # First import packages
sudo axiom profile-create development
sudo axiom resolve development    # Now resolution succeeds
```

## Importing from FreeBSD Ports

The `axiom ports-import` command builds ports and imports them into the Axiom store. It automatically resolves the dependency tree and builds packages in the correct order.

### Basic Usage

```bash
# Import a single port with all its dependencies
axiom ports-import shells/bash

# Import with verbose output
axiom ports-import editors/vim --verbose

# Import without auto-dependency resolution
axiom ports-import devel/m4 --no-deps
```

### What ports-import Does

1. **Resolves dependencies** - Recursively discovers all BUILD_DEPENDS, LIB_DEPENDS, and RUN_DEPENDS
2. **Topologically sorts** - Orders packages so dependencies build first (leaves first)
3. **Builds each port** - Uses `make build` and `make stage` with NO_DEPENDS=yes
4. **Imports to store** - Copies staged files into Axiom's ZFS package store

### Bootstrapping (pkg-independent)

Axiom can be fully independent of FreeBSD's pkg package manager. The bootstrap feature provides everything needed to build ports.

**Option 1: Import a bootstrap tarball (recommended)**

```bash
# Download a pre-built bootstrap tarball
curl -O https://axiom.pgsd.org/bootstrap/axiom-bootstrap-14.2-amd64.tar.zst

# Import the bootstrap packages
axiom bootstrap-import axiom-bootstrap-14.2-amd64.tar.zst

# Check bootstrap status
axiom bootstrap

# Now build ports without pkg
axiom ports-import shells/bash
```

**Option 2: Build bootstrap packages from ports**

If you have a working FreeBSD system with build tools available (via ports or base):

```bash
# Build the minimal bootstrap packages first
axiom ports-import devel/gmake
axiom ports-import devel/m4

# Then build the full bootstrap set
axiom ports-import devel/autoconf
axiom ports-import devel/automake
axiom ports-import lang/perl5
axiom ports-import devel/gettext-tools

# Export your bootstrap for other systems
axiom bootstrap-export axiom-bootstrap-14.2-amd64.tar.zst
```

**Bootstrap commands:**

| Command | Description |
|---------|-------------|
| `axiom bootstrap` | Check bootstrap status |
| `axiom bootstrap-import <tarball>` | Import bootstrap packages |
| `axiom bootstrap-export <tarball>` | Create bootstrap tarball |

**Required bootstrap packages:**

| Package | Provides | Needed by |
|---------|----------|-----------|
| `gmake` | GNU make | Most GNU software |
| `m4` | Macro processor | autoconf, bison |
| `autoconf` | Configure scripts | GNU software |
| `automake` | Makefile generation | GNU software |
| `perl5` | Perl interpreter | build scripts |
| `gettext-tools` | msgfmt, xgettext | i18n-enabled software |
| `pkgconf` | pkg-config | library detection |

Once bootstrapped, Axiom is completely self-hosting and doesn't require pkg.

### Example: Building bash

```bash
$ axiom ports-import shells/bash

Resolving dependency tree for shells/bash...

Build order (16 ports):
  1. print/indexinfo
  2. devel/gettext-runtime
  3. devel/libtextstyle
  4. devel/gettext-tools
  5. lang/perl5.42
  ...
  16. shells/bash

============================================================
Processing: print/indexinfo
============================================================
=== Building port: print/indexinfo ===
  Cleaning...
  Dependencies: none
  Building...
  Staging...
  Copying staged files...
  Build completed successfully
=== Importing to store: indexinfo ===
  ⚠ WARNING: Package is not signed
  ✓ Package imported: indexinfo@0.3.1

... (continues for each dependency)

============================================================
Summary: 16 succeeded, 0 failed (of 16 total)
============================================================

✓ Success! shells/bash imported to store.
  Package: bash@5.2.37

You can now use this package in your profiles.
```

### Options

| Option | Description |
|--------|-------------|
| `--ports-tree <path>` | Path to ports tree (default: /usr/ports) |
| `--jobs <n>` | Parallel build jobs (default: 4) |
| `--verbose` | Show detailed build output |
| `--keep-sandbox` | Don't clean up staging directory |
| `--dry-run` | Generate manifests only |
| `--no-deps` | Don't auto-resolve dependencies |

## Troubleshooting

### Dataset already has legacy mountpoint

If you see an error about the legacy mountpoint:

```bash
# Unmount if currently mounted via /etc/fstab
umount /axiom  # if it exists

# Set new mountpoint
zfs set mountpoint=/axiom zroot/axiom

# Mount it
zfs mount zroot/axiom
```

### Incorrect mountpoints (e.g., /zroot/axiom instead of /axiom)

If you created child datasets before setting the mountpoint, they will have inherited the wrong mountpoint (e.g., `/zroot/axiom/store` instead of `/axiom/store`).

To fix this:

```bash
# Set the correct mountpoint on the parent - children inherit automatically
sudo zfs set mountpoint=/axiom zroot/axiom

# Verify all mountpoints are now correct
zfs list -r zroot/axiom
```

Expected output after fix:
```
NAME                              MOUNTPOINT
zroot/axiom                       /axiom
zroot/axiom/builds                /axiom/builds
zroot/axiom/env                   /axiom/env
zroot/axiom/profiles              /axiom/profiles
zroot/axiom/store                 /axiom/store
```

### Permission denied

Axiom requires root privileges for ZFS operations:

```bash
sudo zig build run
```

### Cannot create datasets

Ensure the parent dataset exists and is mounted:

```bash
zfs list zroot/axiom
zfs get mounted zroot/axiom
```

### Profile creation fails

If `axiom profile-create` fails partway through (e.g., dataset created but file writing failed), you need to clean up before retrying:

```bash
# Check if the dataset was created
zfs list zroot/axiom/profiles/<profile-name>

# If it exists, destroy it before retrying
zfs destroy zroot/axiom/profiles/<profile-name>

# Then retry
axiom profile-create <profile-name>
```

## Advanced Configuration

### Custom Mountpoint

If you prefer a different location than `/axiom`:

```bash
zfs set mountpoint=/your/custom/path zroot/axiom
```

Then update Axiom's configuration accordingly (future feature).

### Compression

Enable compression for space efficiency:

```bash
zfs set compression=lz4 zroot/axiom
```

This will be inherited by all subdatasets.

### Quota

Set a quota if desired:

```bash
zfs set quota=100G zroot/axiom
```

---

**Author**: Vester "Vic" Thacker  
**Organization**: Pacific Grove Software Distribution Foundation  
**License**: BSD 2-Clause
