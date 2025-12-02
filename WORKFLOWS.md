# Axiom Workflows

This document describes common workflows for using the Axiom package manager. Each workflow provides step-by-step instructions for accomplishing specific tasks.

## Table of Contents

1. [Initial Setup](#initial-setup)
2. [Package Installation](#package-installation)
3. [Environment Management](#environment-management)
4. [Building from Source](#building-from-source)
5. [Binary Cache Operations](#binary-cache-operations)
6. [Bundle Distribution](#bundle-distribution)
7. [Multi-User Setup](#multi-user-setup)
8. [Security Operations](#security-operations)
9. [Ports Migration](#ports-migration)
10. [Maintenance Operations](#maintenance-operations)

---

## Initial Setup

### First-Time Installation

```bash
# 1. Build Axiom from source
cd /path/to/axiom
zig build

# 2. Install the CLI
sudo cp zig-out/bin/axiom-cli /usr/local/bin/axiom

# 3. Verify installation
axiom version
```

### Initialize the Package Store

```bash
# Create the root Axiom dataset structure
sudo zfs create zroot/axiom
sudo zfs create zroot/axiom/store
sudo zfs create zroot/axiom/store/pkg
sudo zfs create zroot/axiom/profiles
sudo zfs create zroot/axiom/env

# Set recommended properties
sudo zfs set compression=lz4 zroot/axiom
sudo zfs set atime=off zroot/axiom
```

### Configure Shell Completions

```bash
# Bash
axiom completions bash | sudo tee /usr/local/share/bash-completion/completions/axiom

# Zsh
axiom completions zsh | sudo tee /usr/local/share/zsh/site-functions/_axiom

# Fish
axiom completions fish > ~/.config/fish/completions/axiom.fish
```

### Set Up Trust Store

The official PGSD signing key is **pre-bundled** with Axiom and automatically trusted on startup. No manual setup is required to verify official PGSD releases.

```bash
# Verify the official key is loaded
axiom key

# Output shows:
#   Trusted keys:
#     [1] PGSD0001A7E3F9B2 (official) ✓
#         Owner: PGSD Official
#         Trust Level: Official PGSD Release Key
```

To add additional third-party keys:

```bash
# Add a third-party signing key
sudo axiom key-add /path/to/publisher.pub
sudo axiom key-trust <key-id>

# Verify trusted keys
axiom key
```

---

## Package Installation

### Workflow 1: Install Packages via Profile

The recommended way to manage packages is through profiles.

```
┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐
│  Create Profile │ ──▶ │ Resolve Deps    │ ──▶ │ Realize Env     │
└─────────────────┘      └─────────────────┘      └─────────────────┘
         │                      │                       │
         ▼                      ▼                       ▼
   profile.yaml          profile.lock.yaml      /axiom/env/<name>
```

**Step 1: Create a Profile**

```bash
sudo axiom profile-create development
```

**Step 2: Define Packages**

Edit `/axiom/profiles/development/profile.yaml`:

```yaml
name: development
description: Development environment with common tools
packages:
  - name: bash
    version: "^5.0.0"
    constraint: caret
  - name: git
    version: ">=2.40.0"
    constraint: range
  - name: vim
    version: "*"
    constraint: any
  - name: gcc
    version: "~13.0.0"
    constraint: tilde
```

**Step 3: Resolve Dependencies**

```bash
sudo axiom resolve development

# With resource limits for large profiles
sudo axiom resolve development --timeout 60000 --stats
```

**Step 4: Create Environment**

```bash
sudo axiom realize dev-env development
```

**Step 5: Activate Environment**

```bash
source /axiom/env/dev-env/activate

# Verify
echo $AXIOM_ENV  # Should print: dev-env
which bash       # Should print: /axiom/env/dev-env/bin/bash
```

**Step 6: Deactivate When Done**

```bash
deactivate
```

### Workflow 2: Quick Package Execution

Run a package directly without creating an environment:

```bash
# Run bash from the store
sudo axiom run bash

# Run with arguments
sudo axiom run python -- script.py --arg value

# Run in isolated mode (package closure only)
sudo axiom run node --isolated -- app.js
```

### Workflow 3: Search and Inspect Packages

```bash
# Search for packages
axiom search editor

# View package details
axiom info vim

# Show dependency closure
axiom closure bash
```

---

## Environment Management

### Updating an Environment

```
┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐
│ Update Profile  │ ──▶ │ Re-resolve      │ ──▶ │ Recreate Env    │
└─────────────────┘      └─────────────────┘      └─────────────────┘
```

```bash
# 1. Edit profile.yaml with new package versions
vim /axiom/profiles/development/profile.yaml

# 2. Re-resolve dependencies
sudo axiom resolve development

# 3. Destroy old environment
sudo axiom env-destroy dev-env

# 4. Create new environment
sudo axiom realize dev-env development
```

### Managing Multiple Environments

```bash
# List all environments
axiom env

# Create environment for different purposes
sudo axiom realize prod-env production
sudo axiom realize test-env testing

# Switch between environments
source /axiom/env/prod-env/activate
# ... do work ...
deactivate

source /axiom/env/test-env/activate
# ... do work ...
deactivate
```

### Handling File Conflicts

When packages have overlapping files:

```bash
# Default: fail on conflict
sudo axiom realize my-env myprofile

# Let later packages win
sudo axiom realize my-env myprofile --conflict-policy priority

# Keep both files with suffixes
sudo axiom realize my-env myprofile --conflict-policy keep-both
```

### Rolling Back with ZFS Snapshots

```bash
# List environment snapshots
zfs list -t snapshot -r zroot/axiom/env/dev-env

# Rollback to initial state
sudo zfs rollback zroot/axiom/env/dev-env@initial
```

---

## Building from Source

### Workflow: Build a Package

```
┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐
│ Create Recipe   │ ──▶ │ Build Package   │ ──▶ │ Import to Store │
└─────────────────┘      └─────────────────┘      └─────────────────┘
```

**Step 1: Create Build Recipe**

Create `mypackage.yaml`:

```yaml
name: mypackage
version: "1.0.0"
description: My custom package

source:
  url: https://example.com/mypackage-1.0.0.tar.gz
  sha256: abc123...

build_dependencies:
  - name: gcc
  - name: make

runtime_dependencies:
  - name: libc

phases:
  configure:
    command: "./configure --prefix=$OUTPUT"
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

**Step 2: Build the Package**

```bash
# Build with default settings
sudo axiom build mypackage.yaml

# Build with more parallelism
sudo axiom build mypackage.yaml --jobs 8

# Build without running tests
sudo axiom build mypackage.yaml --no-test

# Dry run to see build plan
sudo axiom build mypackage.yaml --dry-run
```

**Step 3: Sign the Package (Optional)**

```bash
sudo axiom sign /axiom/store/pkg/mypackage/1.0.0/1/abc123 --key mykey.priv
```

### Sandboxed Builds

Builds run in FreeBSD jails for isolation:

```bash
# Build with network disabled (more secure)
sudo axiom build mypackage.yaml --no-network

# Keep sandbox after build for debugging
sudo axiom build mypackage.yaml --keep-sandbox

# Build without importing to store
sudo axiom build mypackage.yaml --no-import
```

---

## Binary Cache Operations

### Workflow: Fetch from Remote Cache

```
┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐
│ Configure Cache │ ──▶ │ Fetch Package   │ ──▶ │ Verify & Import │
└─────────────────┘      └─────────────────┘      └─────────────────┘
```

**Step 1: Add Remote Cache**

```bash
# Add official PGSD cache (priority 1 = highest)
sudo axiom cache-add https://cache.pgsdf.org 1

# Add mirror (lower priority)
sudo axiom cache-add https://mirror.example.com/axiom 10

# List configured caches
axiom cache
```

**Step 2: Fetch Packages**

```bash
# Fetch and import a package
sudo axiom cache-fetch bash@5.2.0 --install

# Fetch without verification (not recommended)
sudo axiom cache-fetch bash@5.2.0 --install --no-verify

# Sync all missing packages
sudo axiom cache-sync
```

### Publishing to Cache

```bash
# Sign the package first
sudo axiom sign /axiom/store/pkg/mypackage/1.0.0/1/abc123 --key mykey.priv

# Push to cache (requires write access)
sudo axiom cache-push mypackage@1.0.0 https://cache.pgsdf.org
```

### Cache Maintenance

```bash
# Show cache status
axiom cache

# Clean local cache
sudo axiom cache-clean

# Force clean without confirmation
sudo axiom cache-clean --force
```

---

## Bundle Distribution

### Workflow: Create and Distribute a Bundle

```
┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐
│ Create Bundle   │ ──▶ │ Sign Bundle     │ ──▶ │ Distribute      │
└─────────────────┘      └─────────────────┘      └─────────────────┘
         │
         ▼
┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐
│ Verify Bundle   │ ──▶ │ Run Bundle      │ ◀── │ End User        │
└─────────────────┘      └─────────────────┘      └─────────────────┘
```

**Step 1: Create a Bundle**

```bash
# Create self-extracting executable
sudo axiom bundle bash --output bash-bundle.pgsdimg

# Create with specific compression
sudo axiom bundle bash --output bash-bundle.pgsdimg --compression zstd

# Include all dependencies
sudo axiom bundle myapp --output myapp-bundle.pgsdimg
```

**Step 2: Sign the Bundle**

```bash
sudo axiom sign bash-bundle.pgsdimg --key publisher.priv
```

**Step 3: Distribute**

Upload `bash-bundle.pgsdimg` to your distribution channel.

### Workflow: Use a Bundle (End User)

**Step 1: Verify the Bundle**

```bash
# Verify signature and integrity
axiom bundle-verify myapp-bundle.pgsdimg

# Verify with custom trust store
axiom bundle-verify myapp-bundle.pgsdimg --trust-store /path/to/keys
```

**Step 2: Run the Bundle**

```bash
# Run directly (verifies first)
axiom bundle-run myapp-bundle.pgsdimg

# Run with arguments
axiom bundle-run myapp-bundle.pgsdimg -- --config /etc/myapp.conf

# Extract only (don't run)
axiom bundle-run myapp-bundle.pgsdimg --extract-only /opt/myapp
```

**Alternative: Run Directly**

```bash
# Make executable
chmod +x myapp-bundle.pgsdimg

# Run
./myapp-bundle.pgsdimg

# Extract
./myapp-bundle.pgsdimg --extract /opt/myapp
```

---

## Multi-User Setup

### Workflow: Set Up Multi-User Environment

```
┌─────────────────┐
│  System Admin   │
│  (root)         │
└────────┬────────┘
         │ Manages shared store
         ▼
┌─────────────────┐
│ Package Store   │ ◀── Shared by all users
│ /axiom/store    │
└────────┬────────┘
         │
    ┌────┴────┐
    ▼         ▼
┌───────┐ ┌───────┐
│ Alice │ │  Bob  │  ◀── Per-user profiles & environments
└───────┘ └───────┘
```

**Admin: Initialize User Space**

```bash
# Create user datasets structure
sudo zfs create zroot/axiom/users
sudo zfs create zroot/axiom/users/alice
sudo zfs create zroot/axiom/users/alice/profiles
sudo zfs create zroot/axiom/users/alice/env

# Set ownership
sudo chown -R alice:alice /axiom/users/alice
```

**User: Create Personal Profile**

```bash
# As alice (no sudo needed)
axiom user-profile-create my-tools
```

**User: Configure Profile**

Edit `~/.axiom/profiles/my-tools/profile.yaml`:

```yaml
name: my-tools
description: Alice's personal tools
packages:
  - name: tmux
    version: "*"
  - name: htop
    version: "*"
```

**User: Create Environment**

```bash
# Resolve (uses shared store)
axiom user-resolve my-tools

# Create personal environment
axiom user-realize my-env my-tools

# Activate
source /axiom/users/alice/env/my-env/activate
```

### Admin: Manage Users

```bash
# List all users with Axiom data
sudo axiom system-users

# Remove user's Axiom data
sudo axiom system-user-remove bob

# System-wide garbage collection
sudo axiom system-gc
```

---

## Security Operations

### Official PGSD Signing Key

Axiom ships with the **official PGSD signing key pre-bundled**. This key is automatically loaded and trusted at the highest level (`.official`) when Axiom starts.

```
Key ID:      PGSD0001A7E3F9B2
Owner:       PGSD Official
Trust Level: Official PGSD Release Key
```

All official PGSD releases are signed with this key. You can immediately verify official packages without any setup.

### Workflow: Key Management

**Generate a Signing Key**

```bash
# Generate key pair
axiom key-generate --output myorg

# This creates:
#   myorg.priv  - Private key (keep secure!)
#   myorg.pub   - Public key (share freely)
```

**Distribute Public Key**

```bash
# Share myorg.pub with users who need to verify your packages
```

**Add Trusted Key**

```bash
# Add a publisher's public key
sudo axiom key-add publisher.pub

# Trust the key
sudo axiom key-trust <key-id>

# List trusted keys (includes pre-bundled official key)
axiom key
```

### Workflow: Sign and Verify Packages

**Sign a Package**

```bash
# Sign with your private key
sudo axiom sign /axiom/store/pkg/mypackage/1.0.0/1/abc123 --key myorg.priv
```

**Verify a Package**

```bash
# Verify signature
axiom verify /axiom/store/pkg/mypackage/1.0.0/1/abc123

# Output shows:
#   Signature: valid/invalid
#   Signer: key-id (trusted/untrusted)
#   Files checked: N
#   All hashes: match/mismatch
```

### Workflow: Secure Bundle Execution

```bash
# Always verify before running untrusted bundles
axiom bundle-verify untrusted-app.pgsdimg

# If verification passes and you trust the source
axiom bundle-run untrusted-app.pgsdimg

# For bundles from unknown sources (use caution!)
axiom bundle-run untrusted-app.pgsdimg --allow-untrusted
```

---

## Ports Migration

### Workflow: Migrate a FreeBSD Port to Axiom

```
┌─────────────────┐      ┌────────────────────┐     ┌─────────────────┐
│ Scan Port       │ ──▶ │ Generate Manifests │ ──▶│ Build & Import  │
└─────────────────┘      └────────────────────┘     └─────────────────┘
```

**Step 1: Explore Available Ports**

```bash
# List port categories
axiom ports

# Scan a category
axiom ports-scan shells
```

**Step 2: Generate Axiom Manifests**

```bash
# Generate manifests for a single port
axiom ports-gen shells/bash

# Generate to custom output directory
axiom ports-gen shells/bash --out ./my-ports

# Dry run to see what would be generated
axiom ports-gen shells/bash --dry-run
```

**Step 3: Review Generated Files**

```
./generated/axiom-ports/shells/bash/
├── manifest.yaml    # Package metadata
├── deps.yaml        # Dependencies
└── build.yaml       # Build recipe
```

**Step 4: Build the Port**

```bash
# Build from generated manifests
axiom ports-build shells/bash
```

**Step 5: Import to Store**

```bash
# Or do all steps at once
axiom ports-import shells/bash
```

### Batch Migration

```bash
# Migrate multiple ports
for port in bash zsh fish; do
  axiom ports-import shells/$port
done
```

---

## Maintenance Operations

### Garbage Collection

```bash
# Show what would be removed (dry run)
sudo axiom gc --dry-run

# Remove unreferenced packages
sudo axiom gc

# Output shows:
#   Found N packages in store
#   Found M referenced packages
#   Removing K unreferenced packages
#   Freed X GB
```

### Kernel Compatibility Check

```bash
# Check kernel module compatibility
axiom kernel

# Output shows:
#   [OK] compatible-kmod
#   [INCOMPATIBLE] old-kmod (reason)
```

### Health Check Workflow

```bash
# 1. Check for incompatible kernel modules
axiom kernel

# 2. Verify all packages in profiles
for profile in $(axiom profile); do
  echo "Checking $profile..."
  axiom resolve $profile --dry-run
done

# 3. Check cache status
axiom cache

# 4. Run garbage collection
sudo axiom gc
```

### Backup and Restore

**Backup**

```bash
# Snapshot the entire Axiom tree
sudo zfs snapshot -r zroot/axiom@backup-$(date +%Y%m%d)

# Send to backup location
sudo zfs send -R zroot/axiom@backup-20250101 > /backup/axiom-backup.zfs
```

**Restore**

```bash
# Receive from backup
sudo zfs receive -F zroot/axiom < /backup/axiom-backup.zfs
```

---

## Quick Reference

### Common Commands

| Task | Command |
|------|---------|
| Create profile | `axiom profile-create <name>` |
| Resolve dependencies | `axiom resolve <profile>` |
| Create environment | `axiom realize <env> <profile>` |
| Activate environment | `source /axiom/env/<env>/activate` |
| Run package directly | `axiom run <package>` |
| Build from source | `axiom build <recipe.yaml>` |
| Fetch from cache | `axiom cache-fetch <pkg>@<ver> --install` |
| Create bundle | `axiom bundle <package> --output <file>` |
| Verify bundle | `axiom bundle-verify <bundle>` |
| Run bundle | `axiom bundle-run <bundle>` |
| Sign package | `axiom sign <path> --key <keyfile>` |
| Garbage collect | `axiom gc` |

### Environment Variables

| Variable | Description |
|----------|-------------|
| `AXIOM_ENV` | Currently active environment name |
| `AXIOM_FREEBSD_VERSION` | Override detected FreeBSD version |
| `AXIOM_KERNEL_IDENT` | Override detected kernel ident |

---

**Author**: Vester "Vic" Thacker
**Organization**: Pacific Grove Software Distribution Foundation
**License**: BSD 2-Clause
