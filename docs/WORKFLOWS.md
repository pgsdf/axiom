# Axiom Workflows

This document describes common workflows for using the Axiom package manager. Each workflow provides step-by-step instructions for accomplishing specific tasks.

## Table of Contents

1. [Initial Setup](#initial-setup)
2. [Package Installation](#package-installation)
3. [Environment Management](#environment-management)
4. [Building from Source](#building-from-source)
5. [Binary Cache Operations](#binary-cache-operations)
6. [Remote Cache Server](#remote-cache-server)
7. [Bundle Distribution](#bundle-distribution)
8. [Multi-User Setup](#multi-user-setup)
9. [Security Operations](#security-operations)
10. [Ports Migration](#ports-migration)
11. [Boot Environments](#boot-environments)
12. [Maintenance Operations](#maintenance-operations)

---

## Initial Setup

### First-Time Installation

```bash
# 1. Build Axiom from source
cd /path/to/axiom
zig build

# 2. Install the CLI
sudo cp zig-out/bin/axiom /usr/local/bin/axiom

# 3. Verify installation
axiom version
```

### Initialize the Package Store (Recommended: Setup Wizard)

The easiest way to set up the package store is using the setup wizard:

```bash
# Run the setup wizard (creates all ZFS datasets)
sudo axiom setup
```

The setup wizard will:
- Create all required ZFS datasets in the correct order
- Set the mountpoint before creating child datasets (critical!)
- Configure recommended ZFS properties (compression=lz4, atime=off)
- Create configuration directories (/etc/axiom, /var/cache/axiom)

**Setup Wizard Options:**

```bash
# Check current setup status
sudo axiom setup --check

# Use a different ZFS pool
sudo axiom setup --pool tank

# Non-interactive mode (for scripting)
sudo axiom setup --yes

# Continue a partial setup
sudo axiom setup --force
```

### Manual ZFS Setup (Alternative)

If you prefer manual control, create the datasets in this exact order:

```bash
# 1. Create the root Axiom dataset
sudo zfs create zroot/axiom

# 2. Set the mountpoint BEFORE creating children (IMPORTANT!)
#    This must be done before child datasets are created so they inherit correctly
sudo zfs set mountpoint=/axiom zroot/axiom

# 3. Set recommended properties
sudo zfs set compression=lz4 zroot/axiom
sudo zfs set atime=off zroot/axiom

# 4. Now create child datasets (they inherit /axiom mountpoint)
sudo zfs create zroot/axiom/store
sudo zfs create zroot/axiom/store/pkg
sudo zfs create zroot/axiom/profiles
sudo zfs create zroot/axiom/env
sudo zfs create zroot/axiom/builds
```

### Bootstrap Build Tools (CRITICAL)

**IMPORTANT**: Before importing packages from FreeBSD ports, you MUST bootstrap essential build tools. Use one of these methods:

**Option 1: Automated Bootstrap (Recommended)**

```bash
# Quick bootstrap: gmake, m4, help2man
sudo axiom bootstrap-ports --minimal

# Full bootstrap: includes autoconf, automake, etc.
sudo axiom bootstrap-ports
```

**Option 2: Manual Bootstrap (in exact order)**

```bash
# Step 1: Bootstrap help2man first (required by m4)
sudo axiom ports-import misc/help2man

# Step 2: Bootstrap m4 (macro processor, required by autoconf)
sudo axiom ports-import devel/m4

# Step 3: Bootstrap gmake (GNU make, required by GNU software)
sudo axiom ports-import devel/gmake
```

**Why this order matters:**
- `help2man` generates man pages and is required to build `m4`
- `m4` is a macro processor required by autoconf and many configure scripts
- `gmake` (GNU make) is required by most GNU software including bash
- If you try to build packages without these bootstrap tools, builds will fail
- These bootstrap packages have minimal dependencies and can build with system tools

**Option 3: Import Bootstrap Tarball (for air-gapped systems)**

```bash
# Download pre-built bootstrap tarball
curl -O https://axiom.pgsd.org/bootstrap/axiom-bootstrap-14.2-amd64.tar.zst

# Import the bootstrap packages
sudo axiom bootstrap-import axiom-bootstrap-14.2-amd64.tar.zst
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

### Import Packages to Store

**IMPORTANT**: Before creating profiles, you must import packages into the store. The resolver cannot find packages that haven't been imported yet.

> **Note**: Ensure you have completed the [Bootstrap Build Tools](#bootstrap-build-tools-critical) step before importing packages via `ports-import`. Without bootstrap tools, builds will fail.

Choose one of these methods to populate the store:

```bash
# Option A: Import from FreeBSD Ports (after bootstrapping)
sudo axiom ports-import shells/bash
sudo axiom ports-import editors/vim
sudo axiom ports-import devel/git

# Option B: Import pre-built packages
sudo axiom import /path/to/package-directory
sudo axiom import package.tar.gz

# Option C: Fetch from binary cache
sudo axiom remote-fetch bash@5.2.0
sudo axiom remote-fetch vim
```

See [Ports Migration](#ports-migration) for details on migrating FreeBSD ports to Axiom.

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

**Prerequisites**:
- ZFS datasets are created (see [Initial Setup](#initial-setup))
- **Packages are imported into the store** (see [Import Packages to Store](#import-packages-to-store))

> **Note**: Resolution will fail with `PackageNotFound` if you try to resolve a profile before importing the packages it references. Always import packages first via `ports-import`, `axiom import`, or `cache-fetch`.

**Step 1: Create a Profile**

```bash
sudo axiom profile-create development
```

If this fails with `DatasetNotFound`, ensure `zroot/axiom/profiles` exists:
```bash
sudo zfs create zroot/axiom/profiles
```

If this fails with `ProfileExists` (from a previous failed attempt):
```bash
sudo zfs destroy zroot/axiom/profiles/development
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

### Using Merge Strategies

Control how files are linked into environments:

```bash
# Default: symbolic links (space-efficient)
sudo axiom realize my-env myprofile --merge-strategy symlink

# Hard links (fast access, space-efficient)
sudo axiom realize my-env myprofile --merge-strategy hardlink

# Full copies (isolated, allows modifications)
sudo axiom realize my-env myprofile --merge-strategy copy

# ZFS clones (requires ZFS, very fast)
sudo axiom realize my-env myprofile --merge-strategy zfs_clone
```

### Selective Output Installation

Install only specific package outputs for minimal environments:

```bash
# Install only binaries and runtime libraries (production)
sudo axiom realize prod-env production --outputs bin,lib

# Include development files for building
sudo axiom realize dev-env development --outputs bin,lib,dev

# Include documentation
sudo axiom realize full-env myprofile --outputs bin,lib,dev,doc
```

**Common output types:**
- `bin` - Executable binaries
- `lib` - Runtime libraries
- `dev` - Headers, static libs, pkg-config files
- `doc` - Documentation and man pages

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
sudo axiom sign /axiom/store/pkg/mypackage/1.0.0/1/abc123 --key mykey.key
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
sudo axiom sign /axiom/store/pkg/mypackage/1.0.0/1/abc123 --key mykey.key

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

## Remote Cache Server

Axiom includes a built-in cache server for hosting your own binary cache, enabling efficient package distribution across your organization.

### Workflow: Run a Cache Server

```
┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐
│ Start Server    │ ──▶ │ Clients Connect │ ──▶ │ Serve Packages  │
└─────────────────┘      └─────────────────┘      └─────────────────┘
```

**Step 1: Start the Cache Server**

```bash
# Start on default port (8080)
axiom cache-server

# Start on custom port
axiom cache-server --port 9000

# Use custom package store
axiom cache-server --store /data/axiom-store --port 8080
```

**Step 2: Verify Server is Running**

```bash
# From another terminal or machine
axiom cache-info http://localhost:8080
```

### API Endpoints

The cache server exposes a RESTful API (Protocol v1.0):

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/info` | GET | Server information |
| `/api/v1/packages` | GET | List all packages |
| `/api/v1/packages/{name}/{version}` | GET | Package metadata |
| `/api/v1/packages/{name}/{version}/nar` | GET | Package archive |
| `/api/v1/upload/{name}/{version}` | POST | Upload package |

### Workflow: Configure Remote Sources

**Step 1: Create Configuration File**

Create `/etc/axiom/caches.yaml`:

```yaml
caches:
  - url: https://cache.pgsdf.org
    priority: 100
    trust: pgsd-release-key
  - url: http://internal-cache.example.com:8080
    priority: 50
    trust: internal-key
  - url: http://backup-cache.example.com:8080
    priority: 10
    trust: internal-key

verify_signatures: true
parallel_downloads: 4
timeout_ms: 30000
retry_count: 3
```

**Step 2: Manage Sources**

```bash
# List configured sources
axiom remote-sources

# Add a new source
axiom remote-sources --add http://new-cache.example.com:8080

# Remove a source
axiom remote-sources --remove http://old-cache.example.com:8080
```

### Workflow: Fetch from Remote Cache

```bash
# Fetch latest version
axiom remote-fetch bash

# Fetch specific version
axiom remote-fetch bash@5.2.0

# Fetch from specific source
axiom remote-fetch bash@5.2.0 --source http://cache.example.com:8080
```

### Workflow: Push to Remote Cache

```bash
# Push a package to remote cache
axiom remote-push mypackage@1.0.0 --target http://cache.example.com:8080
```

### Workflow: Sync Metadata

```bash
# Sync package metadata from all configured sources
axiom remote-sync
```

This updates the local cache index with available packages from all remote caches.

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
sudo axiom sign bash-bundle.pgsdimg --key publisher.key
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
#   myorg.key  - Private key (keep secure!)
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
sudo axiom sign /axiom/store/pkg/mypackage/1.0.0/1/abc123 --key myorg.key
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

### Workflow: Build Provenance Verification

Build provenance provides supply chain verification for packages.

**Verify Package Provenance**

```bash
# Verify provenance of a package
axiom verify-provenance bash

# Output shows:
#   Provenance: present/missing
#   Source: verified/not verified
#   Signature: valid/invalid
#   Trust: trusted/untrusted
#   Build age: N days
```

**View Provenance Details**

```bash
# Display full provenance record
axiom provenance-show bash

# Shows builder info, source URL, build timestamps,
# output hash, and signature details
```

**Check Policy Compliance**

```bash
# Check all packages for policy compliance
axiom provenance-policy --check

# Check specific package
axiom provenance-policy bash

# View current policy settings
axiom provenance-policy --show
```

**Configure Provenance Policy**

Create `/etc/axiom/policy.yaml`:

```yaml
provenance:
  require: true                    # Reject packages without provenance
  require_signature: true          # Reject unsigned provenance
  trusted_builders:
    - "builder01.pgsdf.org"
    - "builder02.pgsdf.org"
  max_age_days: 365               # Reject builds older than 1 year
```

**Attempt Reproducible Rebuild**

```bash
# Verify by rebuilding (experimental)
axiom verify-provenance bash --rebuild
```

---

## Ports Migration

The `ports-import` command is the primary way to populate the Axiom store from FreeBSD ports. It automatically resolves dependencies, builds ports in the correct order, and imports packages to the store.

### Workflow: Import from FreeBSD Ports

```
┌──────────────────┐      ┌────────────────────┐      ┌─────────────────┐
│ Resolve Deps     │ ──▶ │ Topological Sort   │ ──▶ │ Build & Import  │
│ (recursive)      │      │ (leaves first)     │      │ (each port)     │
└──────────────────┘      └────────────────────┘      └─────────────────┘
```

**Basic Usage**

```bash
# Import a port with all its dependencies
axiom ports-import shells/bash

# Import with verbose output
axiom ports-import editors/vim --verbose

# Import without auto-dependency resolution
axiom ports-import devel/m4 --no-deps
```

**What ports-import Does**

1. **Resolves dependencies** - Recursively discovers all BUILD_DEPENDS, LIB_DEPENDS, and RUN_DEPENDS
2. **Topologically sorts** - Orders packages so dependencies build first (leaves first)
3. **Builds each port** - Uses `make build` and `make stage` with NO_DEPENDS=yes
4. **Imports to store** - Copies staged files into Axiom's ZFS package store

**Example Output**

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

### Bootstrap Limitation

**Important**: During initial bootstrap, `ports-import` cannot provide build-time dependencies (headers, libraries, Perl modules) to subsequent builds. This is because packages are imported to the Axiom store but not installed to system paths where compilers and interpreters look.

**Workaround for initial bootstrap:**

```bash
# Install common build-time dependencies via pkg first
pkg install gmake              # GNU make (required by many ports)
pkg install gettext-tools      # msgfmt and gettext utilities
pkg install p5-Locale-gettext  # Perl Locale::gettext module
pkg install p5-Locale-libintl  # Perl Locale::Messages module

# Then use ports-import for the final packages
axiom ports-import shells/bash
```

**Common bootstrap packages by category:**

| Package | Provides | Needed by |
|---------|----------|-----------|
| `gmake` | GNU make | Most GNU software |
| `gettext-tools` | msgfmt, xgettext | i18n-enabled software |
| `p5-Locale-gettext` | Perl Locale::gettext | help2man, texinfo |
| `p5-Locale-libintl` | Perl Locale::Messages | texinfo |
| `libtextstyle` | Text styling library | gettext-tools |
| `libiconv` | Character conversion | Many ports |

This hybrid approach uses `pkg` to provide build-time headers/libraries while Axiom manages the final installed packages.

### ports-import Options

| Option | Description |
|--------|-------------|
| `--ports-tree <path>` | Path to ports tree (default: /usr/ports) |
| `--jobs <n>` | Parallel build jobs (default: 4) |
| `--verbose` | Show detailed build output |
| `--keep-sandbox` | Don't clean up staging directory |
| `--dry-run` | Generate manifests only |
| `--no-deps` | Don't auto-resolve dependencies |
| `--use-system-tools` | Use /usr/local instead of sysroot (see below) |

### Troubleshooting: Using System Tools

When building ports with complex autotools dependencies (autoconf, automake, libtool), you may encounter build failures where configure scripts can't find required tools. This happens because:

1. **Sysroot wrapper issues** - FreeBSD's autoconf-switch provides wrapper scripts that look for versioned binaries (e.g., `autoconf2.72`) using `$0`. When copied to the sysroot, these wrappers may fail.

2. **Broken package layouts** - Packages built before certain fixes may have incorrect directory structures.

**Solution: Use `--use-system-tools`**

This flag bypasses sysroot creation entirely and uses tools from `/usr/local`:

```bash
# First, install required tools via pkg
pkg install autoconf automake libtool

# Then build with system tools
axiom ports-import devel/automake --use-system-tools
```

**When to use this flag:**
- Configure fails with "autoconf is installed... no"
- Build errors mentioning missing autotools binaries
- Wrapper script failures in the sysroot

**Note:** This approach requires the build dependencies to be installed system-wide via `pkg`. Once the initial bootstrap is complete and packages are built with correct layouts, the sysroot approach should work without this flag.

### Advanced: Manual Manifest Generation

For more control over the migration process:

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

### Batch Migration

```bash
# Migrate multiple ports (dependencies resolved automatically)
axiom ports-import shells/bash
axiom ports-import editors/vim
axiom ports-import devel/git
```

---

## Boot Environments

Axiom provides first-class support for ZFS boot environments, enabling atomic system upgrades with safe rollback capabilities.

### Understanding Boot Environments

```
┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐
│ Current System  │      │ Create BE       │      │ Activate BE     │
│ (Running)       │ ──▶ │ (Clone)         │ ──▶ │ (Next Boot)     │
└─────────────────┘      └─────────────────┘      └─────────────────┘
         │                                                │
         │              ┌─────────────────┐               │
         └──────────── │ Rollback        │ ◀─────────────┘
                        │ (If problems)   │
                        └─────────────────┘
```

Boot environments are ZFS clones of the root filesystem. They allow you to:
- Create a snapshot before system changes
- Test upgrades safely
- Instantly rollback if something goes wrong

### Workflow: List Boot Environments

```bash
# List all boot environments
axiom be

# Same as above (explicit)
axiom be-list
```

**Output:**

```
NAME                           ACTIVE   MOUNTPOINT           SPACE
────────────────────────────── ──────── ──────────────────── ──────────
default                        NR       /                    1G+
pre-upgrade-20241201           --       -                    1M+
test-upgrade                   --       -                    1M+

Total: 3 boot environment(s)
```

- `N` = Currently active (running now)
- `R` = Active on reboot (will boot into this)

### Workflow: Safe System Upgrade

**Step 1: Create Pre-Upgrade Snapshot**

```bash
# Create a boot environment before making changes
axiom be-create pre-upgrade

# Or with automatic timestamp naming
axiom be-create pre-upgrade-$(date +%Y%m%d)
```

**Step 2: Perform System Changes**

```bash
# Make your system changes (package updates, config changes, etc.)
sudo axiom resolve production
sudo axiom realize prod-env production
```

**Step 3: Test and Decide**

If everything works, you can delete the old BE later:
```bash
axiom be-destroy pre-upgrade-20241201
```

If something is broken, rollback:
```bash
axiom be-rollback
# Then reboot
```

### Workflow: Test New Configuration

**Step 1: Create Test Environment**

```bash
# Create BE for testing
axiom be-create test-config --activate
```

**Step 2: Reboot into Test Environment**

```bash
sudo reboot
```

**Step 3: Test Changes**

Make your changes and test them in the new boot environment.

**Step 4: Make Permanent or Rollback**

If satisfied, keep the new environment. If not:

```bash
# Activate the previous environment
axiom be-activate default
sudo reboot
```

### Workflow: Inspect Boot Environment

```bash
# Mount a BE for inspection (without booting into it)
axiom be-mount old-backup

# Mount to specific location
axiom be-mount old-backup /mnt/inspect

# Browse the mounted filesystem
ls /mnt/inspect/etc

# Unmount when done
axiom be-unmount old-backup
```

### Boot Environment Commands Reference

| Command | Description |
|---------|-------------|
| `axiom be` | List all boot environments |
| `axiom be-create <name>` | Create new BE from current |
| `axiom be-create <name> --source <be>` | Clone from specific BE |
| `axiom be-create <name> --activate` | Create and activate |
| `axiom be-activate <name>` | Activate for next boot |
| `axiom be-activate <name> --temporary` | Activate for one boot only |
| `axiom be-destroy <name>` | Remove boot environment |
| `axiom be-rollback` | Revert to previous BE |
| `axiom be-rename <old> <new>` | Rename boot environment |
| `axiom be-mount <name> [path]` | Mount BE for inspection |
| `axiom be-unmount <name>` | Unmount boot environment |

### Best Practices

1. **Always create a BE before major changes**
   ```bash
   axiom be-create pre-$(date +%Y%m%d-%H%M)
   ```

2. **Use descriptive names**
   ```bash
   axiom be-create before-kernel-update
   axiom be-create testing-new-nginx
   ```

3. **Clean up old BEs periodically**
   ```bash
   axiom be-list
   axiom be-destroy old-unused-be
   ```

4. **Test with temporary activation first**
   ```bash
   axiom be-activate test-be --temporary
   # After reboot, if you don't explicitly activate,
   # system returns to previous BE on next reboot
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

## Developer Workflows

This section covers development patterns and best practices for working with the Axiom codebase.

### Error Handling Patterns

Axiom uses the `errors.zig` module for consistent error handling. Never silently swallow errors.

**Bad Pattern (avoid):**
```zig
file.close() catch {};  // Silent failure - loses error context
```

**Good Pattern:**
```zig
const errors = @import("errors.zig");

file.close() catch |err| {
    errors.logFileCleanup(err, path, @src());
};
```

**Error Categories:**
- `logFileCleanup()` - File operations during cleanup
- `logProcessCleanup()` - Process cleanup failures
- `logZfsCleanup()` - ZFS operation failures
- `logConfigLoadOptional()` - Optional config loading
- `logServiceOp()` - Service management operations
- `logCollectionError()` - Collection iteration errors

### Input Validation

Always validate external input using `validation.zig`:

```zig
const validation = @import("validation.zig");

// Validate URLs before use
const result = validation.UrlValidator.validate(user_url);
if (!result.valid) {
    return error.InvalidUrl;
}

// Parse sizes with bounds checking
const size = try validation.parseSize(size_str, 100 * 1024 * 1024 * 1024 * 1024); // 100TB max

// Escape strings for JSON output
var buf: [1024]u8 = undefined;
const json_safe = validation.escapeJsonString(user_input, &buf);
```

### Memory Safety Patterns

**ArrayList with errdefer:**
```zig
var list = std.ArrayList([]const u8).init(allocator);
errdefer {
    for (list.items) |item| {
        allocator.free(item);
    }
    list.deinit();
}

// Safe to use try now - cleanup happens on error
try list.append(try allocator.dupe(u8, str));
```

**Config lifecycle:**
```zig
const cfg = try config.getGlobalConfig(allocator);
defer config.releaseGlobalConfig();
// use cfg...
```

### Testing with Mock Implementations

Use `interfaces.zig` for testable code:

```zig
const interfaces = @import("interfaces.zig");

// Production code uses interface
fn processPackages(store: interfaces.PackageStore) !void {
    const pkgs = try store.listPackages(allocator);
    // ...
}

// Test with mock
test "processPackages handles empty store" {
    var mock = interfaces.MockPackageStore.init(std.testing.allocator);
    defer mock.deinit();

    try processPackages(mock.asInterface());
}
```

### Thread Safety Guidelines

**Lock ordering (to prevent deadlocks):**
1. GC lock file (acquired first)
2. ZfsHandle.mutex
3. ConfigManager.mutex
4. Other application locks

**ZfsHandle operations:**
- All methods are internally mutex-protected
- Use `withLock()` for compound operations
- Never call ZfsHandle methods from within `withLock()` callback

```zig
// Compound operation with lock held
try zfs.withLock(struct {
    pub fn call(handle: *c.libzfs_handle_t) !void {
        // Multiple libzfs calls here are atomic
    }
}.call);
```

### Running Tests

```bash
# Unit tests (no root required)
zig build test

# Integration tests (requires root for ZFS)
sudo zig build test

# Run specific test file
zig build test --test-filter "config"
```

---

## Quick Reference

### Common Commands

| Task | Command |
|------|---------|
| Run setup wizard | `sudo axiom setup` |
| Bootstrap build tools | `sudo axiom bootstrap-ports --minimal` |
| Import from ports | `sudo axiom ports-import <origin>` |
| Create profile | `axiom profile-create <name>` |
| Resolve dependencies | `axiom resolve <profile>` |
| Create environment | `axiom realize <env> <profile>` |
| Activate environment | `source /axiom/env/<env>/activate` |
| Run package directly | `axiom run <package>` |
| Build from source | `axiom build <recipe.yaml>` |
| Fetch from cache | `axiom remote-fetch <pkg>[@ver]` |
| Create bundle | `axiom bundle <package> --output <file>` |
| Verify bundle | `axiom bundle-verify <bundle>` |
| Run bundle | `axiom bundle-run <bundle>` |
| Sign package | `axiom sign <path> --key <keyfile>` |
| Garbage collect | `axiom gc` |
| List boot environments | `axiom be` |
| Create boot environment | `axiom be-create <name>` |
| Activate boot environment | `axiom be-activate <name>` |
| Rollback boot environment | `axiom be-rollback` |
| Start cache server | `axiom cache-server` |
| Fetch from remote | `axiom remote-fetch <pkg>[@ver]` |
| Sync remote metadata | `axiom remote-sync` |

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
