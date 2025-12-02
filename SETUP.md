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
# Package store
zfs create zroot/axiom/store

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
zroot/axiom/profiles     96K   XXX    96K    /axiom/profiles
zroot/axiom/env          96K   XXX    96K    /axiom/env
zroot/axiom/builds       96K   XXX    96K    /axiom/builds
```

### 5. Filesystem Layout

After setup, you'll have:

```
/axiom/
├── store/              # Immutable package storage
│   └── pkg/           # Package datasets will go here
├── profiles/          # Profile definitions
├── env/               # Realized environments
└── builds/            # Build sandbox storage
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
