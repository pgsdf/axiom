# Axiom User Guide

A comprehensive guide to using the Axiom package manager for the Pacific Grove Software Distribution.

## Table of Contents

1. [Introduction](#introduction)
2. [Installation](#installation)
3. [Quick Start](#quick-start)
4. [Core Concepts](#core-concepts)
5. [Managing Profiles](#managing-profiles)
6. [Working with Packages](#working-with-packages)
7. [Environments](#environments)
8. [Dependency Resolution](#dependency-resolution)
9. [Package Signing & Verification](#package-signing--verification)
10. [Binary Cache](#binary-cache)
11. [Multi-user Support](#multi-user-support)
12. [Building Packages](#building-packages)
13. [Direct Execution & Bundles](#direct-execution--bundles)
14. [Troubleshooting](#troubleshooting)
15. [Best Practices](#best-practices)

---

## Introduction

Axiom is a ZFS-native package manager designed for the Pacific Grove Software Distribution (PGSD). It provides:

- **Immutable packages** stored as ZFS datasets
- **Declarative profiles** defining system or user environments
- **Deterministic resolution** ensuring reproducible builds
- **Atomic operations** leveraging ZFS snapshots
- **Cryptographic verification** with Ed25519 signatures

### Design Philosophy

1. **Canonical truth is simple** - YAML manifests, not complex DSLs
2. **Immutability by default** - Packages are read-only after creation
3. **ZFS-first operations** - Snapshots, clones, and send/receive for efficiency
4. **Separation of concerns** - Build → Store → Index → Resolve → Realize → Activate

---

## Installation

### Prerequisites

- FreeBSD or GhostBSD with ZFS
- Zig 0.13.0 or later
- Root access for ZFS operations

### Building from Source

```bash
# Clone the repository
git clone https://github.com/pgsdf/axiom.git
cd axiom

# Build
zig build

# Install (optional)
sudo cp zig-out/bin/axiom-cli /usr/local/bin/axiom
```

### ZFS Setup

Before using Axiom, set up the required ZFS datasets:

```bash
# Create the main dataset
sudo zfs create zroot/axiom
sudo zfs set mountpoint=/axiom zroot/axiom

# Create subdatasets
sudo zfs create zroot/axiom/store
sudo zfs create zroot/axiom/profiles
sudo zfs create zroot/axiom/env

# Enable compression (recommended)
sudo zfs set compression=lz4 zroot/axiom
```

Verify the setup:

```bash
zfs list -r zroot/axiom
```

---

## Quick Start

### Create Your First Profile

```bash
# Create a profile for development tools
sudo axiom profile-create development

# View the profile
sudo axiom profile-show development
```

### Add Packages to Profile

Edit the profile to add packages:

```bash
# The profile is stored at /axiom/profiles/development/profile.yaml
sudo vi /axiom/profiles/development/profile.yaml
```

Example profile.yaml:

```yaml
name: development
packages:
  - name: bash
    version: "^5.0"
  - name: git
    version: ">=2.40"
  - name: vim
    version: "*"
```

### Resolve Dependencies

```bash
# Resolve all dependencies
sudo axiom resolve development
```

### Create an Environment

```bash
# Realize the profile into an environment
sudo axiom realize dev-env development
```

### Activate the Environment

```bash
# Activate (modifies PATH, etc.)
source /axiom/env/dev-env/activate

# When done
deactivate
```

---

## Core Concepts

### Packages

A **package** is an immutable unit of software stored as a ZFS dataset:

```
/axiom/store/pkg/<name>/<version>/<revision>/<build-id>/
├── manifest.yaml       # Package metadata
├── deps.yaml           # Dependencies
├── provenance.yaml     # Build information
└── root/               # Actual package files
```

Each package is identified by:
- **Name**: Package identifier (e.g., `bash`)
- **Version**: Semantic version (e.g., `5.2.0`)
- **Revision**: Package revision number
- **Build ID**: Unique build identifier

### Profiles

A **profile** defines a set of packages you want installed:

```yaml
name: development
packages:
  - name: bash
    version: "^5.0"
  - name: git
    version: ">=2.40"
```

Profiles support version constraints:
- `*` - Any version
- `1.2.3` - Exact version
- `^1.2.3` - Compatible versions (same major)
- `~1.2.3` - Patch versions only (same minor)
- `>=1.0,<2.0` - Version range

### Environments

An **environment** is a realized profile - actual files ready to use:

```
/axiom/env/dev-env/
├── bin/           # Executables
├── lib/           # Libraries
├── share/         # Shared data
└── activate       # Activation script
```

### Lock Files

When you resolve a profile, Axiom creates a **lock file** (`profile.lock.yaml`) that records the exact versions selected:

```yaml
name: development
resolved_at: 2024-01-15T10:30:00Z
packages:
  - name: bash
    version: "5.2.0"
    revision: 1
    build_id: abc123
    requested: true
  - name: readline
    version: "8.2.0"
    revision: 1
    build_id: def456
    requested: false  # Dependency
```

---

## Managing Profiles

### Creating Profiles

```bash
# Create a new profile
sudo axiom profile-create <name>

# Examples
sudo axiom profile-create development
sudo axiom profile-create server
sudo axiom profile-create minimal
```

### Listing Profiles

```bash
sudo axiom profile-list
```

Output:
```
Available profiles:
  development
  server
  minimal
```

### Viewing Profile Details

```bash
sudo axiom profile-show development
```

Output:
```
Profile: development

Requested packages:
  bash ^5.0
  git >=2.40
  vim *

Lock file: present
Last resolved: 2024-01-15 10:30:00
Resolved packages: 8
```

### Updating Profiles

Edit the profile YAML directly:

```bash
sudo vi /axiom/profiles/development/profile.yaml
```

Then re-resolve:

```bash
sudo axiom resolve development
```

### Deleting Profiles

```bash
sudo axiom profile-delete development
```

---

## Working with Packages

### Listing Available Packages

```bash
# List all packages in the store
sudo axiom package-list
```

### Searching for Packages

```bash
# Search by name
sudo axiom search bash

# Search by tag
sudo axiom search --tag shell
```

### Package Information

```bash
# Show package details
sudo axiom package-info bash
```

Output:
```
Package: bash
Available versions:
  5.2.0-r1 (build: abc123)
  5.1.16-r2 (build: def456)

Latest: 5.2.0-r1

Description: GNU Bourne Again Shell
License: GPL-3.0-or-later
Homepage: https://www.gnu.org/software/bash/

Dependencies:
  readline >=8.0
  ncurses ~6.4
```

### Importing Packages

Import packages from directories or tarballs:

```bash
# Import from directory
sudo axiom import /path/to/package-dir

# Import from tarball
sudo axiom import package-5.2.0.tar.gz

# Preview without importing
sudo axiom import --dry-run /path/to/package

# Import with signature verification
sudo axiom import --verify package.tar.gz
```

### Package Relationships

```bash
# Show what virtual packages a package provides
sudo axiom provides bash
# Output: shell, sh

# Show what packages conflict
sudo axiom conflicts bash
# Output: dash (provides same shell)

# Show what packages are replaced
sudo axiom replaces bash
# Output: sh
```

---

## Environments

### Resolving Dependencies

Before creating an environment, resolve the profile's dependencies:

```bash
# Standard resolution (greedy algorithm)
sudo axiom resolve development

# Use SAT solver for complex constraints
sudo axiom resolve development --strategy sat

# Automatic fallback (try greedy, then SAT)
sudo axiom resolve development --strategy auto
```

Resolution strategies:
- `greedy` - Fast, picks newest satisfying version (default)
- `sat` - SAT solver for complex interdependencies
- `auto` - Try greedy first, fall back to SAT on failure

### Creating Environments

```bash
# Basic realization
sudo axiom realize dev-env development

# With conflict handling
sudo axiom realize dev-env development --conflict-policy priority
```

Conflict policies:
- `error` - Fail on any file conflict (default, safest)
- `priority` - Later packages in lock file override earlier ones
- `keep-both` - Keep both files with package name suffixes

### Activating Environments

```bash
# Show activation instructions
sudo axiom activate dev-env

# Activate (in your shell)
source /axiom/env/dev-env/activate

# Your PATH, LD_LIBRARY_PATH, etc. are now updated
which bash  # /axiom/env/dev-env/bin/bash

# Deactivate when done
deactivate
```

### Listing Environments

```bash
sudo axiom env-list
```

### Destroying Environments

```bash
sudo axiom env-destroy dev-env
```

### Rollback with Snapshots

Environments are snapshotted after creation:

```bash
# List snapshots
zfs list -t snapshot -r zroot/axiom/env/dev-env

# Rollback to a snapshot
sudo zfs rollback zroot/axiom/env/dev-env@initial
```

---

## Dependency Resolution

### How Resolution Works

1. **Parse profile** - Read requested packages and constraints
2. **Query store** - Find available versions of each package
3. **Build graph** - Create dependency graph with all transitive dependencies
4. **Resolve** - Select versions that satisfy all constraints
5. **Generate lock** - Write exact versions to lock file

### Resolution Strategies

#### Greedy (Default)

Fast algorithm that selects the newest satisfying version for each package:

```bash
sudo axiom resolve my-profile --strategy greedy
```

Best for:
- Simple dependency trees
- Quick iterations
- Most common use cases

#### SAT Solver

Uses Boolean Satisfiability solving for complex constraints:

```bash
sudo axiom resolve my-profile --strategy sat
```

Best for:
- Complex interdependencies
- Version conflicts that greedy can't resolve
- Diamond dependency problems

Features:
- CDCL (Conflict-Driven Clause Learning)
- VSIDS heuristic for variable selection
- Detailed conflict explanations

#### Automatic Fallback

Try greedy first, fall back to SAT on failure:

```bash
sudo axiom resolve my-profile --strategy auto
```

This is the recommended approach for production use.

### Understanding Conflicts

When resolution fails, Axiom provides explanations:

```
Resolution failed:

Conflicts detected:
  - Version conflict: openssl 1.1.1 conflicts with openssl 3.0.0
    Required by: curl (needs ^1.1), python (needs ^3.0)

Suggestions:
  - Try relaxing version constraints
  - Check for conflicting packages in your profile
  - Consider using the SAT solver (--strategy sat)
```

### Virtual Packages

Some packages provide "virtual" functionality:

```yaml
# bash provides the "shell" virtual package
provides:
  - shell
  - sh
```

You can depend on virtual packages:

```yaml
dependencies:
  - name: shell
    version: "*"
```

Axiom will select any package that provides `shell`.

```bash
# Query virtual package providers
sudo axiom virtual-providers shell
```

---

## Package Signing & Verification

Axiom uses Ed25519 signatures for package integrity.

### Generating Keys

```bash
# Generate a key pair
sudo axiom key-generate --output mykey

# Creates:
#   mykey.priv  - Private key (keep secret!)
#   mykey.pub   - Public key (distribute)
```

### Managing the Trust Store

```bash
# Add a public key to trust store
sudo axiom key-add mykey.pub

# Add with a name
sudo axiom key-add --name "My Signing Key" mykey.pub

# List trusted keys
sudo axiom key-list

# Remove a key
sudo axiom key-remove <key-id>
```

### Signing Packages

```bash
# Sign a package
sudo axiom sign /path/to/package --key mykey.priv

# This creates a signature file in the package
```

### Verifying Packages

```bash
# Verify a package
sudo axiom verify /path/to/package

# Import with verification
sudo axiom import package.tar.gz --verify
```

### Verification Modes

Configure in Axiom settings:
- `strict` - Require valid signature, reject unsigned packages
- `warn` - Warn about unsigned packages, but allow them
- `disabled` - No signature checking

---

## Binary Cache

Axiom supports HTTP-based binary caches for fast package distribution.

### Configuring Remote Caches

```bash
# Add a remote cache
sudo axiom cache-add https://cache.pgsdf.org --priority 10

# List configured caches
sudo axiom cache-list

# Remove a cache
sudo axiom cache-remove https://cache.pgsdf.org
```

Priority determines which cache is tried first (higher = first).

### Using Cached Packages

When resolving/realizing, Axiom automatically checks caches:

```bash
sudo axiom realize dev-env development
# Axiom will download packages from cache if available
```

### Running a Cache Server

```bash
# Start a cache server
sudo axiom cache-serve --port 8080 --dir /var/cache/axiom
```

### Cache Management

```bash
# Show cache status
sudo axiom cache-status

# Clean old cached packages
sudo axiom cache-clean --older-than 30d

# Set cache size limit
sudo axiom cache-config --max-size 10G
```

### Delta Transfers

Axiom supports incremental ZFS send for efficient transfers:

```bash
# Enable delta mode (default when available)
sudo axiom cache-config --delta-mode auto
```

---

## Multi-user Support

Axiom supports per-user profiles and environments while sharing the system package store.

### User Commands

Regular users can create their own profiles:

```bash
# Create a user profile
axiom user-profile-create my-tools

# List your profiles
axiom user-profile-list

# Resolve dependencies
axiom user-resolve my-tools

# Create user environment
axiom user-realize my-env my-tools

# Activate
source ~/axiom/env/my-env/activate
```

### User Data Location

User data is stored under their home directory:
```
~/axiom/
├── profiles/
│   └── my-tools/
│       ├── profile.yaml
│       └── profile.lock.yaml
└── env/
    └── my-env/
```

Or in ZFS datasets:
```
zroot/axiom/users/<username>/
├── profiles/
└── env/
```

### System Administration

Admins can manage all users:

```bash
# List users with Axiom data
sudo axiom system-users

# Remove a user's Axiom data
sudo axiom system-user-remove alice
```

### Shared Package Store

All users share the read-only package store at `/axiom/store`. Users cannot modify packages, only create profiles and environments that reference them.

---

## Building Packages

Axiom includes a build system for creating packages from source.

### Build Recipes

Create a `recipe.yaml`:

```yaml
name: hello
version: 1.0.0
revision: 1

source:
  url: https://example.com/hello-1.0.0.tar.gz
  sha256: abc123...

build_dependencies:
  - gcc
  - make

runtime_dependencies:
  - libc

phases:
  configure: |
    ./configure --prefix=$PREFIX

  build: |
    make -j$JOBS

  install: |
    make install DESTDIR=$DESTDIR

  test: |
    make check
```

### Building

```bash
# Build a package
sudo axiom build recipe.yaml

# Build with custom options
sudo axiom build recipe.yaml --jobs 8

# Build and import to store
sudo axiom build recipe.yaml --import
```

### Build Environment

Builds run in an isolated ZFS sandbox with:
- Clean environment
- Only specified build dependencies
- Separate output directory

### Post-processing

Axiom can automatically:
- Strip debug symbols from binaries
- Compress man pages
- Check for common issues

```yaml
post_process:
  strip: true
  compress_man: true
```

---

## Direct Execution & Bundles

Axiom provides AppImage-inspired features for running packages directly and creating portable bundles.

### Running Packages Directly

Instead of creating full environments, you can run packages directly:

```bash
# Run a package
sudo axiom run bash

# Run with arguments
sudo axiom run python -- script.py

# Run in isolated mode
sudo axiom run --isolated myapp
```

This automatically:
1. Computes the package's dependency closure
2. Sets up `LD_LIBRARY_PATH` and `PATH`
3. Executes the main binary
4. Cleans up on exit

### Viewing Dependency Closures

See all dependencies (direct and transitive) for a package:

```bash
sudo axiom closure bash
```

Output:
```
Dependency closure for bash@5.2.0:
==================================

Direct dependencies:
  - readline 8.2.0
  - ncurses 6.4.0

Transitive dependencies:
  - libc 2.38.0

Total: 4 packages
```

### Exporting Packages

Export packages in portable formats:

```bash
# Export as tarball
sudo axiom export bash --format tarball --output bash.tar.gz

# Export with dependencies
sudo axiom export bash --format tarball --include-deps

# Export as ZFS stream (for ZFS-to-ZFS transfer)
sudo axiom export bash --format zfs-stream
```

### Creating Portable Bundles

Create self-contained bundles that work without Axiom or ZFS:

```bash
# Create a .pgsdimg bundle (self-extracting executable)
sudo axiom bundle bash --output bash.pgsdimg

# With compression
sudo axiom bundle bash --output bash.pgsdimg --compression zstd

# Signed bundle
sudo axiom bundle bash --output bash.pgsdimg --sign
```

#### Using .pgsdimg Bundles

The generated bundle is a self-extracting shell script:

```bash
# Run directly
./bash.pgsdimg

# Extract to a directory
./bash.pgsdimg --extract /opt/bash

# Show bundle information
./bash.pgsdimg --info
```

### Bundle Formats

| Format | Description | Use Case |
|--------|-------------|----------|
| `pgsdimg` | Self-extracting executable | Distribution to any Linux system |
| `zfs-stream` | ZFS send stream | Fast transfer between ZFS systems |
| `tarball` | Compressed tar archive | Traditional distribution |
| `directory` | Plain directory | Development and testing |

### Runtime Layers

Runtime layers provide shared base environments (similar to Flatpak runtimes):

```bash
# List available runtimes
sudo axiom runtime

# Create a custom runtime
sudo axiom runtime-create my-runtime libc ncurses readline

# Run a package with a specific runtime
sudo axiom runtime-use base-2025 myapp
```

Standard runtimes:
- `base-2025` - Minimal runtime (libc, libm, libpthread)
- `full-2025` - Full runtime with common libraries
- `gui-2025` - GUI runtime with X11/Wayland support

### Desktop Integration

Integrate packages with your desktop environment:

```bash
# Install desktop integration
sudo axiom desktop-install firefox

# This creates:
# - ~/.local/share/applications/firefox.desktop
# - Icons in ~/.local/share/icons/
# - MIME type associations

# Remove desktop integration
sudo axiom desktop-remove firefox
```

### When to Use Each Approach

| Approach | Best For |
|----------|----------|
| Full environment (`realize`) | Long-term development, production |
| Direct execution (`run`) | Quick testing, one-off runs |
| Bundle (`.pgsdimg`) | Distributing to non-Axiom systems |
| Export (`export`) | Sharing between Axiom systems |

---

## Troubleshooting

### Common Issues

#### "Dataset not found"

```bash
# Ensure ZFS datasets exist
zfs list -r zroot/axiom

# Create missing datasets
sudo zfs create zroot/axiom/store
sudo zfs create zroot/axiom/profiles
sudo zfs create zroot/axiom/env
```

#### "Permission denied"

Axiom requires root for ZFS operations:

```bash
sudo axiom <command>
```

#### "Package not found"

Check if the package exists in the store:

```bash
sudo axiom package-list | grep <package-name>
```

Import it if missing:

```bash
sudo axiom import /path/to/package
```

#### "Resolution failed"

Try the SAT solver:

```bash
sudo axiom resolve my-profile --strategy sat
```

Check for conflicting version requirements in your profile.

#### "File conflict during realization"

Use a conflict policy:

```bash
# Let later packages win
sudo axiom realize env profile --conflict-policy priority

# Keep both files
sudo axiom realize env profile --conflict-policy keep-both
```

### Getting Help

```bash
# General help
axiom help

# Command-specific help
axiom help resolve
axiom help realize
```

### Debug Mode

For detailed output:

```bash
sudo axiom --verbose resolve my-profile
```

---

## Best Practices

### Profile Management

1. **Use descriptive names**: `development`, `server-prod`, `minimal-base`
2. **Pin versions in production**: Use exact versions or tight ranges
3. **Document constraints**: Add comments explaining why specific versions are needed
4. **Keep profiles focused**: Separate concerns (dev tools, runtime, testing)

### Version Constraints

| Scenario | Recommended Constraint |
|----------|----------------------|
| Library dependency | `~1.2.3` (patch updates only) |
| Tool dependency | `^1.2.3` (minor updates OK) |
| Production lock | `1.2.3` (exact version) |
| Flexible requirement | `>=1.0,<3.0` (range) |

### Environment Hygiene

1. **Don't modify environments directly**: They should be immutable
2. **Use profiles**: Changes should go through profile → resolve → realize
3. **Name environments clearly**: Include purpose and date if needed
4. **Clean up unused environments**: `axiom env-destroy old-env`

### Security

1. **Verify signatures**: Use `--verify` when importing packages
2. **Keep keys secure**: Store private keys safely, never commit them
3. **Trust carefully**: Only add trusted public keys to your keyring
4. **Use strict mode in production**: Require signatures on all packages

### ZFS Best Practices

1. **Enable compression**: `zfs set compression=lz4 zroot/axiom`
2. **Set quotas**: Prevent runaway disk usage
3. **Regular snapshots**: For easy rollback
4. **Monitor space**: `zfs list -r zroot/axiom`

### Garbage Collection

Periodically clean unused packages:

```bash
# Preview what would be removed
sudo axiom gc --dry-run

# Actually remove
sudo axiom gc
```

---

## Shell Completions

Install shell completions for better UX:

### Bash

```bash
sudo axiom completions bash > /usr/local/share/bash-completion/completions/axiom
```

### Zsh

```bash
sudo axiom completions zsh > /usr/local/share/zsh/site-functions/_axiom
```

### Fish

```bash
sudo axiom completions fish > ~/.config/fish/completions/axiom.fish
```

---

## Additional Resources

- [README.md](README.md) - Project overview
- [CLI.md](CLI.md) - Complete CLI reference
- [MANIFEST_FORMAT.md](MANIFEST_FORMAT.md) - Package manifest specification
- [SETUP.md](SETUP.md) - Detailed ZFS setup instructions
- [ARCHITECTURE.md](ARCHITECTURE.md) - System design and internals
- [RESOLVER.md](RESOLVER.md) - Dependency resolution algorithm
- [ROADMAP.md](ROADMAP.md) - Feature roadmap

---

**Author**: Vester "Vic" Thacker
**Organization**: Pacific Grove Software Distribution Foundation
**License**: BSD 2-Clause
