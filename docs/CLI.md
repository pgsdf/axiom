# Axiom CLI Reference

## Overview

The Axiom CLI provides a user-friendly interface to the Axiom package manager. It combines all subsystems (store, profiles, resolver, realization) into cohesive workflows.

## Installation

```bash
zig build
sudo cp zig-out/bin/axiom /usr/local/bin/axiom
```

## General Usage

```bash
axiom <command> [options]
```

All commands require root privileges (via `sudo`) since they interact with ZFS.

## Commands

### Help and Version

#### `axiom help`

Show help message with all available commands.

```bash
axiom help
```

#### `axiom version`

Display version information.

```bash
axiom version
```

---

### Setup

The setup wizard initializes Axiom's ZFS datasets and configuration directories.

#### `axiom setup`

Run the interactive setup wizard to initialize Axiom.

```bash
sudo axiom setup
```

**What it does:**
1. Creates the base dataset (`zroot/axiom`)
2. Sets the mountpoint to `/axiom` (before creating children - critical!)
3. Sets recommended properties (compression=lz4, atime=off)
4. Creates child datasets (store, store/pkg, profiles, env, builds)
5. Creates configuration directories (`/etc/axiom`, `/var/cache/axiom`)

**Options:**

| Option | Description |
|--------|-------------|
| `--pool <name>` | Use a different ZFS pool (default: zroot) |
| `--dataset <name>` | Use a different dataset name (default: axiom) |
| `--mountpoint <path>` | Use a different mountpoint (default: /axiom) |
| `--yes`, `-y` | Non-interactive mode (assume yes to all prompts) |
| `--force`, `-f` | Continue setup even if partially configured |
| `--check`, `-c` | Check current setup status and exit |
| `--help`, `-h` | Show setup help |

**Examples:**

```bash
# Interactive setup with defaults
sudo axiom setup

# Check if Axiom is already set up
sudo axiom setup --check

# Use a different pool
sudo axiom setup --pool tank

# Non-interactive setup for scripting
sudo axiom setup --yes

# Continue a partial setup
sudo axiom setup --force
```

**Example output (--check):**
```
Current Status:
  ✓ Pool 'zroot'
  ✓ Base dataset (zroot/axiom)
  ✓ Mountpoint correct (/axiom)
  ✓ Store dataset
  ✓ Profiles dataset
  ✓ Env dataset
  ✓ Builds dataset
  ✓ Config directory (/etc/axiom)
  ✓ Cache directory (/var/cache/axiom)

Setup is complete.
```

---

### Profile Management

Profiles define sets of packages you want installed.

#### `axiom profile`

List all available profiles.

```bash
axiom profile
```

**Example output:**
```
Available profiles:
  development
  server
  desktop
```

#### `axiom profile-create <name>`

Create a new empty profile.

```bash
axiom profile-create development
```

**Creates:**
- Dataset: `zroot/axiom/profiles/development`
- File: `/axiom/profiles/development/profile.yaml`

#### `axiom profile-show <name>`

Display profile details and packages.

```bash
axiom profile-show development
```

**Example output:**
```
Profile: development
Description: Created via axiom CLI
Packages (0):
```

#### `axiom profile-update <name>`

Update a profile (interactive).

```bash
axiom profile-update development
```

**Note:** Currently shows workflow - full implementation pending.

#### `axiom profile-delete <name>`

Delete a profile.

```bash
axiom profile-delete development
```

**Warning:** This destroys the ZFS dataset. Use with caution.

#### `axiom profile-add-package <profile> <package> [version]`

Add a package to an existing profile without editing YAML files.

```bash
# Add package with any version
axiom profile-add-package development bash

# Add package with exact version
axiom profile-add-package development bash 5.2.0

# Add package with caret constraint (compatible versions)
axiom profile-add-package development bash "^5.0"

# Add package with tilde constraint (patch updates only)
axiom profile-add-package development bash "~5.2"

# Add package with range constraint
axiom profile-add-package development bash ">=5.0"
```

**Version constraint formats:**
| Format | Meaning |
|--------|---------|
| `*` or omitted | Any version |
| `5.2.0` | Exact version 5.2.0 |
| `^5.0` | Compatible with 5.0 (5.x.x) |
| `~5.2` | Patch updates only (5.2.x) |
| `>=5.0` | Version 5.0 or higher |
| `>=5.0,<6.0` | Range between versions |

**Alias:** `axiom profile-add`

#### `axiom profile-remove-package <profile> <package>`

Remove a package from an existing profile.

```bash
axiom profile-remove-package development bash
```

**Alias:** `axiom profile-remove`

---

### Package Operations

Manage packages in the store and profiles.

#### `axiom install <package>`

Add a package to the current profile.

```bash
axiom install bash
```

**Workflow:**
1. Adds package to profile.yaml
2. Run `axiom resolve` to update dependencies
3. Run `axiom realize` to create/update environment

#### `axiom remove <package>`

Remove a package from the current profile.

```bash
axiom remove vim
```

#### `axiom search <query>`

Search for available packages.

```bash
axiom search bash
```

#### `axiom info <package>`

Show detailed package information.

```bash
axiom info bash
```

**Example output:**
```
Package: bash
Version: 5.2.0
Revision: 1
Description: GNU Bourne Again Shell
License: GPL-3.0-or-later
Dependencies:
  - readline ~8.2.0
  - ncurses ^6.0.0
```

#### `axiom list`

List all installed packages in the store.

```bash
axiom list
```

---

### Environment Operations

Create and manage environments from profiles.

#### `axiom resolve <profile> [options]`

Resolve profile dependencies and create lock file.

```bash
axiom resolve development
axiom resolve development --strict
axiom resolve development --timeout 60000 --stats
```

**Options:**
- `--timeout <ms>` - Maximum resolution time in milliseconds (default: 30000)
- `--max-memory <bytes>` - Maximum memory usage in bytes (default: 256MB)
- `--max-depth <n>` - Maximum dependency chain depth (default: 100)
- `--strict` - Use strict resource limits (tighter constraints)
- `--stats` - Show resolution statistics after completion

**Process:**
1. Loads `profile.yaml`
2. Resolves all dependencies (within resource limits)
3. Saves `profile.lock.yaml`

**Example output:**
```
Resolving profile: development
  Request: bash ^5.0.0
  Request: git >=2.40.0
  → Resolved bash to 5.2.0
  → Resolved git to 2.43.0
  → Resolved readline to 8.2.0 (dependency)
  → Resolved ncurses to 6.4.0 (dependency)
✓ Resolved 4 packages (2 requested, 2 dependencies)

✓ Profile resolved and lock file saved
```

**With --stats:**
```
Resolution Statistics:
  Time elapsed: 0.45s
  Peak memory: 12 MB
  Candidates examined: 234
  Dependency depth reached: 4
  Packages resolved: 4
```

**Resource limit errors:**
```
✗ Resolution failed: ResolutionTimeout
  Resolution exceeded time limit (30000ms)
  Consider using --timeout with a higher value
```

#### `axiom realize <env-name> <profile> [options]`

Create an environment from a profile's lock file.

```bash
axiom realize dev-env development
axiom realize dev-env development --conflict-policy priority
axiom realize dev-env development --merge-strategy hardlink
axiom realize dev-env development --outputs bin,lib
```

**Options:**
- `--conflict-policy <policy>` - How to handle file conflicts between packages
- `--merge-strategy <strategy>` - File merge strategy for environment creation
- `--outputs <outputs>` - Comma-separated list of package outputs to install

**Conflict Policies:**
- `error` - Fail on any file conflict (default)
- `priority` - Later packages in the lock file override earlier ones
- `keep-both` - Keep both files with package name suffix

**Merge Strategies:**
- `symlink` - Use symbolic links (default, space-efficient)
- `hardlink` - Use hard links (space-efficient, fast)
- `copy` - Copy files (isolated, allows modifications)
- `zfs_clone` - Use ZFS clones (requires ZFS, fast, space-efficient)

**Common Outputs:**
- `bin` - Executable binaries
- `lib` - Runtime libraries
- `dev` - Development headers and pkg-config files
- `doc` - Documentation and man pages

**Process:**
1. Loads `profile.lock.yaml`
2. Creates dataset `zroot/axiom/env/dev-env`
3. Clones all packages into environment (detecting file conflicts)
4. Applies conflict resolution policy
5. Generates activation script

**Example output:**
```
Realizing environment: dev-env
From profile: development
Conflict policy: error_on_conflict

Creating environment dataset...
  Environment root: /axiom/env/dev-env

Cloning packages...
  [1/4] bash 5.2.0
  [2/4] git 2.43.0
  [3/4] readline 8.2.0
  [4/4] ncurses 6.4.0

Creating snapshot...

✓ Environment realized
To activate: source /axiom/env/dev-env/activate
```

**With conflicts (priority policy):**
```
Realizing environment: dev-env
From profile: development
Conflict policy: priority_wins

...
  [2/4] git 2.43.0
    ⚠ 1 file conflict(s) detected

Conflict Summary:
  Total conflicts: 1
  - Different content: 1
  Resolved: 1

✓ Environment realized
```

**With blocking conflicts (error policy):**
```
Realizing environment: dev-env
From profile: development
Conflict policy: error_on_conflict

...
  [2/4] git 2.43.0
    ⚠ 1 file conflict(s) detected

✗ Realization blocked by 1 unresolved conflict(s)
  - bin/gettext

✗ File conflicts detected. Options:
  - Use --conflict-policy priority to let later packages win
  - Use --conflict-policy keep-both to keep both files
```

#### `axiom activate <env>`

Show how to activate an environment.

```bash
axiom activate dev-env
```

**Output:**
```
Activating environment: dev-env
  Mountpoint: /axiom/env/dev-env

To activate in your shell, run:
  source /axiom/env/dev-env/activate
```

#### `axiom env`

List all environments.

```bash
axiom env
```

**Example output:**
```
Available environments:
  dev-env (profile: development)
  prod-env (profile: production)
```

#### `axiom env-destroy <env>`

Destroy an environment.

```bash
axiom env-destroy dev-env
```

**Interactive confirmation:**
```
Destroying environment: dev-env
Are you sure? (y/N): y
  ✓ Environment destroyed
```

---

### Maintenance

#### `axiom gc`

Run garbage collector to remove unreferenced packages.

```bash
axiom gc
```

**Process:**
1. Scans all profiles and environments
2. Identifies referenced packages
3. Removes unreferenced packages from store

**Example output:**
```
Running garbage collector...
  Found 42 packages in store
  Found 15 referenced packages
  Removing 27 unreferenced packages
  Freed 2.3 GB
✓ Garbage collection complete
```

---

### Signature Operations

Manage cryptographic keys and package signatures.

#### `axiom key`

List trusted public keys.

```bash
axiom key
```

**Example output:**
```
Trusted keys:
  [1] pgsd-main (trusted)
      ID: a1b2c3d4e5f6...
      Added: 2025-11-15
  [2] developer-alice
      ID: f6e5d4c3b2a1...
      Added: 2025-11-20
```

#### `axiom key-generate --output <name>`

Generate a new Ed25519 key pair.

```bash
axiom key-generate --output mykey
```

**Creates:**
- `mykey.key` - Private key (keep secure!)
- `mykey.pub` - Public key (share freely)

#### `axiom key-add <keyfile>`

Add a public key to the trust store.

```bash
axiom key-add developer.pub
```

#### `axiom key-remove <key-id>`

Remove a key from the trust store.

```bash
axiom key-remove a1b2c3d4
```

#### `axiom key-trust <key-id>`

Mark a key as trusted for signature verification.

```bash
axiom key-trust a1b2c3d4
```

#### `axiom sign <package-path> --key <keyfile>`

Sign a package with a private key.

```bash
axiom sign /axiom/store/pkg/bash/5.2.0/1/abc123 --key mykey.key
```

**Creates:** `signature.yaml` in the package directory containing:
- Ed25519 signature
- SHA-256 hashes of all files
- Signing timestamp

#### `axiom verify <package-path>`

Verify a package's signature.

```bash
axiom verify /axiom/store/pkg/bash/5.2.0/1/abc123
```

**Example output:**
```
Verifying package: bash 5.2.0
  Signature: valid
  Signed by: pgsd-main (trusted)
  Files checked: 47
  All hashes: match
✓ Package verification passed
```

---

### Build Provenance Operations

Verify build provenance and policy compliance for packages.

#### `axiom verify-provenance <package> [options]`

Verify build provenance of a package.

```bash
axiom verify-provenance bash
axiom verify-provenance openssl --rebuild
```

**Options:**
- `--rebuild` - Attempt reproducible rebuild to verify output matches

**Example output:**
```
Verifying provenance for: bash

Provenance Report for bash:
───────────────────────────────────────────────────────────────
  Provenance: ✓ Present
  Builder: axiom-builder
  Source: ✓ Verified
  Signature: ✓ Valid
  Signer: PGSD0001A7E3F9B2
  Trust: ✓ Signer is trusted
  Build age: 15 days

Result: ✓ Package provenance is valid and trusted
```

#### `axiom provenance-show <package>`

Display detailed provenance information for a package.

```bash
axiom provenance-show bash
axiom provenance openssl
```

**Example output:**
```yaml
format_version: "1.0"

builder:
  name: "axiom-builder"
  version: "1.0.0"
  host: "builder01.pgsdf.org"

source:
  url: "https://ftp.gnu.org/gnu/bash/bash-5.2.tar.gz"
  sha256: "abc123..."
  fetched_at: "2025-01-15T10:00:00Z"

build:
  started_at: "2025-01-15T10:05:00Z"
  completed_at: "2025-01-15T10:15:00Z"

output:
  hash: "sha256:def456..."
  files_count: 142
  total_size: 5242880

signature:
  key_id: "PGSD0001A7E3F9B2"
  algorithm: "ed25519"
  value: "base64..."
```

#### `axiom provenance-policy [options] [package]`

Check provenance policy compliance.

```bash
axiom provenance-policy --show
axiom provenance-policy --check
axiom provenance-policy bash
```

**Options:**
- `--show` - Display current policy settings
- `--check` - Check all packages for policy compliance

**Example output (--check):**
```
Checking provenance policy compliance for all packages...

  ✓ bash
  ✓ git
  ✗ custom-pkg
      - Package has no provenance record
  ✓ openssl

───────────────────────────────────────────────────────────────
Summary: 3 compliant, 1 non-compliant
```

**Policy violations:**
- `missing_provenance` - Package has no provenance record
- `missing_signature` - Provenance is not signed
- `untrusted_builder` - Builder is not in trusted list
- `untrusted_signer` - Signer is not trusted
- `expired_build` - Build is older than maximum allowed age
- `source_hash_mismatch` - Source hash does not match
- `output_hash_mismatch` - Output hash does not match package contents
- `signature_invalid` - Provenance signature is invalid

---

### Binary Cache Operations

Manage remote package caches for binary distribution.

#### `axiom cache`

List configured remote caches.

```bash
axiom cache
```

**Example output:**
```
Configured caches:
  [1] https://cache.pgsdf.org (priority 1)
  [2] https://mirror.example.com/axiom (priority 2)

Local cache:
  Path: /var/cache/axiom
  Size: 2.3 GB / 10 GB
  Entries: 47
```

#### `axiom cache-add <url> [priority]`

Add a remote cache.

```bash
axiom cache-add https://cache.pgsdf.org 1
```

**Parameters:**
- `url` - Cache server URL
- `priority` - Lower numbers tried first (default: 10)

#### `axiom cache-remove <url>`

Remove a remote cache.

```bash
axiom cache-remove https://mirror.example.com/axiom
```

#### `axiom cache-fetch <package> [--no-verify] [--install]`

Fetch a package from remote cache.

```bash
axiom cache-fetch bash@5.2.0 --install
```

**Options:**
- `--no-verify` - Skip signature verification
- `--install` - Import into local store after download

**Process:**
1. Queries configured caches by priority
2. Downloads ZFS stream
3. Verifies signature (unless `--no-verify`)
4. Optionally imports to local store

#### `axiom cache-push <package> <cache-url>`

Push a package to a remote cache (requires write access).

```bash
axiom cache-push bash@5.2.0 https://cache.pgsdf.org
```

#### `axiom cache-sync`

Sync local store with remote caches.

```bash
axiom cache-sync
```

**Process:**
1. Compares local packages with cache index
2. Downloads missing packages
3. Verifies signatures

#### `axiom cache-clean [-f|--force]`

Clean local cache to free disk space.

```bash
axiom cache-clean
```

**Options:**
- `-f, --force` - Skip confirmation prompt

**Process:**
1. Applies cleanup policy (LRU by default)
2. Removes entries exceeding size limit
3. Reports space freed

#### `axiom cache-index [options]`

Show cache index information and statistics.

```bash
axiom cache-index
axiom cache-index --packages
```

**Options:**
- `--packages` - Show all indexed packages
- `--stats` - Show cache statistics (default)
- `--path <dir>` - Use specified cache path

**Example output:**
```
Cache Index: pgsd-official-cache
Format Version: 1.0
Last Updated: 2025-01-15T12:00:00Z

Statistics:
  Total Packages: 1847
  Total Versions: 4523
  Index Signed: Yes
```

#### `axiom cache-index-update [options]`

Update local cache index from remote sources.

```bash
axiom cache-index-update
axiom cache-index-update --no-verify
```

**Options:**
- `--path <dir>` - Use specified cache path
- `--no-verify` - Skip signature verification

**Process:**
1. Fetches latest index from all configured remotes
2. Verifies index signatures (unless --no-verify)
3. Merges new package entries into local index
4. Reports added/updated/conflicting entries

#### `axiom cache-evict [options]`

Run cache eviction to free space based on policy.

```bash
axiom cache-evict                    # Dry run with defaults
axiom cache-evict --apply            # Actually evict
axiom cache-evict --max-size 50      # Limit to 50GB
axiom cache-evict --max-age 90       # Remove items older than 90 days
```

**Options:**
- `--apply` - Actually delete files (default is dry-run)
- `--max-size <GB>` - Maximum cache size in GB
- `--max-age <days>` - Maximum age in days
- `--keep <n>` - Keep at least N versions per package (default: 3)
- `--path <dir>` - Use specified cache path

**Example output (dry-run):**
```
Cache Eviction Analysis
========================
Policy:
  Max Size: 100 GB
  Max Age: 180 days
  Keep Versions: 3

Current Cache:
  Size: 127456 MB
  Target: 102400 MB

Eviction Candidates: 23
Space to Free: 28156 MB

  old-pkg@1.0.0 (1024 MB) - excess_versions
  legacy-tool@2.1.0 (512 MB) - age_limit
  ...

Dry run - no files deleted.
Use --apply to actually evict these items.
```

#### `axiom cache-conflicts [options]`

Show and resolve cache conflicts between local and remote indices.

```bash
axiom cache-conflicts
axiom cache-conflicts --resolve --prefer-remote
```

**Options:**
- `--resolve` - Automatically resolve conflicts
- `--prefer-local` - Prefer local versions (default)
- `--prefer-remote` - Prefer remote versions
- `--prefer-newest` - Prefer newest versions
- `--path <dir>` - Use specified cache path

**Example output:**
```
Cache Conflicts
===============
Strategy: prefer_local

Conflicts with mirror.example.com:
  openssl@3.0.8:
    Local:  sha256:abc123...
    Remote: sha256:def456...
    Resolution: use_local

Total conflicts: 1
```

---

### Build Operations

Build packages from source using YAML recipes.

#### `axiom build <recipe.yaml>`

Build a package from a recipe file.

```bash
axiom build bash.yaml
```

**Options:**
- `--jobs <n>` - Number of parallel jobs (default: 4)
- `--no-test` - Skip test phase
- `--dry-run` - Show build plan without executing
- `--keep-sandbox` - Don't destroy build sandbox after completion
- `--no-import` - Don't import result into store
- `--verbose` - Show detailed output

**Example recipe (bash.yaml):**
```yaml
name: bash
version: "5.2.0"
description: GNU Bourne Again SHell

source:
  url: https://ftp.gnu.org/gnu/bash/bash-5.2.tar.gz
  sha256: a139c166df7ff4471c5e0733051642ee5556c1cc8a4a78f145583c5c81c32fb2

build_dependencies:
  - name: gcc
  - name: make

runtime_dependencies:
  - name: readline
  - name: ncurses

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

**Build process:**
1. Creates isolated ZFS sandbox for the build
2. Fetches and extracts source (URL, local path, or git)
3. Injects build dependencies into sandbox
4. Executes build phases (configure, build, install, test)
5. Post-processes output (strip binaries, compress man pages)
6. Imports result into package store

---

### Boot Environment Operations

Manage boot environments with profile snapshots, health checks, and automatic rollback.

#### `axiom be-snapshot <be-name> [options]`

Snapshot current profile to a boot environment.

```bash
axiom be-snapshot pre-upgrade
axiom be-snapshot testing --profile dev
```

**Options:**
- `--profile <name>` - Profile to snapshot (default: system)

#### `axiom be-diff <be-a> <be-b> [options]`

Show profile differences between boot environments.

```bash
axiom be-diff default testing
axiom be-diff pre-upgrade current --profile dev
```

**Options:**
- `--profile <name>` - Profile to compare (default: system)

**Example output:**
```
Profile Diff: system ('default') vs ('testing')
================================================

Packages in 'testing' but not 'default':
  + nodejs@18.0.0

Packages in 'default' but not 'testing':
  - python@3.10.0

Version changes:
  bash: 5.1.0 -> 5.2.0
  openssl: 3.0.7 -> 3.0.8

Summary: 1 added, 1 removed, 2 changed
```

#### `axiom be-health [options]`

Run health checks for the current boot environment.

```bash
axiom be-health
axiom be-health --verbose
```

**Options:**
- `--verbose` - Show detailed output including commands

**Health checks verify:**
- Network connectivity
- Critical services (sshd, etc.)
- Custom user-defined checks from `/etc/axiom/rollback-policy.yaml`

**Example output:**
```
Running Boot Environment Health Checks
======================================

  ✓ network
  ✓ sshd
  ✓ filesystem

All health checks passed.
```

#### `axiom be-rollback [options] [target-be]`

Rollback to a previous boot environment.

```bash
axiom be-rollback
axiom be-rollback pre-upgrade --reason "upgrade failed" --force
```

**Options:**
- `--reason <text>` - Reason for rollback (logged)
- `--force` - Skip confirmation prompt

**Process:**
1. Runs on_rollback hooks
2. Updates bootloader to boot target BE
3. Logs rollback event to `/var/log/axiom-rollback.log`

#### `axiom system-upgrade [options]`

Perform system upgrade in a new boot environment with automatic rollback support.

```bash
axiom system-upgrade
axiom system-upgrade --be 2025-01-upgrade
axiom system-upgrade --dry-run
```

**Options:**
- `--be <name>` - Name for new BE (default: upgrade-<date>)
- `--profile <name>` - Profile to upgrade (default: system)
- `--dry-run` - Show what would be done without making changes

**Process:**
1. Snapshot current profile to 'pre-upgrade' BE
2. Create new BE for upgrade
3. Perform upgrade in new BE
4. Set new BE as next boot target

**Example output:**
```
System Upgrade in Boot Environment
===================================

Step 1: Snapshot 'system' to 'pre-upgrade' BE
  Creating snapshot...

Step 2: Create new BE 'upgrade-2025-01'
  Creating boot environment...

Step 3: Perform upgrade in 'upgrade-2025-01'
  Resolving package updates...
  Realizing updated environment...

Step 4: Set 'upgrade-2025-01' as next boot target
  Updating bootloader configuration...

✓ System upgrade prepared in BE 'upgrade-2025-01'.
  Reboot to complete upgrade.
  If issues occur, rollback with: axiom be-rollback pre-upgrade
```

---

### Multi-User Security Operations (Phase 48)

Commands for managing multi-user security, access control, and setuid binary handling.

#### `axiom user-init [username]`

Initialize user space directory structure.

```bash
axiom user-init
axiom user-init alice
```

**Creates directories:**
- `/axiom/users/<user>/profiles` - User profiles
- `/axiom/users/<user>/env` - User environments
- `/axiom/users/<user>/.config` - User configuration

**Example output:**
```
Initializing User Space
=======================

User: alice
Base path: /axiom/users/alice

  Creating profiles/...
  Creating env/...
  Creating .config/...

✓ User space initialized for 'alice'.
```

#### `axiom access-check <operation> [target]`

Check if current user can perform an operation.

```bash
axiom access-check read
axiom access-check import
axiom access-check user-space 1001
```

**Operations:**
- `read` - Read from package store
- `import` - Import packages to store
- `gc` - Garbage collect store
- `profile-create` - Create system profile
- `profile-delete` - Delete system profile
- `user-space` - Access user space (specify target uid)

**Example output:**
```
Access Check: import
========================

Current user: uid=1000 (root=no)

Operation: import
Status: DENIED (requires root)
```

#### `axiom access-show`

Show current access control policy configuration.

```bash
axiom access-show
```

**Example output:**
```
Access Control Policy
=====================

Store Settings:
  Owner UID:        0
  Owner GID:        0
  Store mode:       0755

User Space Settings:
  Template mode:    0700
  User imports:     denied

Setuid Settings:
  Require sig:      yes
  Audit setuid:     yes
```

#### `axiom setuid-list [options]`

List setuid binaries managed by Axiom.

```bash
axiom setuid-list
axiom setuid-list --all
```

**Options:**
- `--all` - Show all setuid binaries (including system)

**Example output:**
```
Setuid Binaries
===============

Axiom-managed setuid binaries:

  PATH                                     OWNER    MODE     SIGNED
  ----                                     -----    ----     ------
  /axiom/store/.../sudo                    0        4755     yes
  /axiom/store/.../ping                    0        4755     yes
  /axiom/store/.../passwd                  0        4755     yes

Total: 3 Axiom-managed setuid binaries
```

#### `axiom setuid-audit [options]`

Show setuid execution audit log.

```bash
axiom setuid-audit
axiom setuid-audit --limit 50
```

**Options:**
- `--limit <n>` - Number of entries to show (default: 20)

**Log location:** `/var/log/axiom-setuid.log`

**Example output:**
```
Setuid Audit Log (last 20 entries)
=====================================

TIMESTAMP            UID      BINARY                         STATUS
---------            ---      ------                         ------
1736600400           1000     /axiom/store/.../sudo          SUCCESS
1736599200           1001     /axiom/store/.../passwd        SUCCESS
```

#### `axiom privilege-show [filter]`

Show privilege requirements for Axiom operations.

```bash
axiom privilege-show
axiom privilege-show root
```

**Arguments:**
- `filter` - Filter by privilege level (root, group, any)

**Privilege levels:**
- `root_only` - Requires root/sudo
- `user_with_group` - Requires axiom group membership
- `any_user` - Any user can perform

**Example output:**
```
Operation Privilege Requirements
================================

Root Only Operations:
  import               - Import packages to store
  system-gc            - Garbage collect shared store
  profile-create       - Create system profile
  profile-delete       - Delete system profile
  setuid-install       - Install setuid binaries

Group Membership Operations (axiom group):
  store-read           - Read from package store
  cache-fetch          - Fetch from binary cache

Any User Operations:
  user-profile-create  - Create user profile
  user-profile-delete  - Delete user profile
  user-realize         - Realize user environment
  user-activate        - Activate user environment
  user-env-list        - List user environments

Note: Per-user operations only affect the user's own space.
```

---

### Error Model & Recovery Operations (Phase 49)

Commands for verifying system integrity and recovering from errors.

#### `axiom verify [options]`

Verify system integrity.

```bash
axiom verify
axiom verify --quick
```

**Options:**
- `--quick` - Quick check (skip hash verification)

**Checks:**
- Store integrity
- Profile validity
- Environment completeness
- Package hashes (full mode only)

**Example output:**
```
System Verification
===================

Mode: Full

Store:        OK
Profiles:     3 valid, 0 invalid (OK)
Environments: 2 valid, 1 invalid (WARNING)
Packages:     150 valid, 0 invalid (OK)

Overall: ⚠ WARNING

Recommendations:
  - Run 'axiom recover' to fix environment issues
```

#### `axiom recover [options]`

Scan for and recover from issues.

```bash
axiom recover
axiom recover --auto
axiom recover --dry-run
```

**Options:**
- `--auto` - Automatic safe recovery
- `--dry-run` - Show plan without executing

**Scans for:**
- Interrupted imports
- Interrupted realizations
- Orphaned datasets
- Corrupted packages

**Example output:**
```
System Recovery
===============

Mode: automatic

Scanning for issues...

Found 2 issue(s):

Interrupted imports: 1
  - mypackage (45% complete)

Interrupted realizations: 1
  - dev-env (15/20 packages)

Executing recovery...

Recovery complete:
  Actions taken:   2
  Actions failed:  0
  Actions skipped: 0

✓ Recovery successful.
```

#### `axiom import-recover [package]`

Recover from an interrupted import.

```bash
axiom import-recover
axiom import-recover mypackage
```

**Arguments:**
- `package` - Specific package to recover (optional)

**Actions:**
- Check transaction log for incomplete imports
- Clean partial package data
- Remove incomplete datasets

**Example output:**
```
Import Recovery
===============

Target: All interrupted imports

Scanning transaction log...
Found 1 interrupted import(s).

Recovering: mypackage
  Cleaning partial data...
  Removing transaction entry...

✓ Import recovery complete.
  You can now retry the import with 'axiom import <source>'
```

#### `axiom env-recover <name>`

Recover an interrupted environment realization.

```bash
axiom env-recover dev
axiom env-recover production
```

**Arguments:**
- `name` - Environment name to recover

**Actions:**
- Identify incomplete environment
- Remove partial files
- Re-realize from lock file

**Example output:**
```
Environment Recovery: dev
==========================

Checking for partial environment...
Found partial environment.

Step 1: Removing partial files...
Step 2: Checking for lock file...
  Lock file found. Can re-realize.

✓ Cleanup complete.
  To re-realize: axiom realize dev
```

#### `axiom error-suggest [error_name]`

Show recovery suggestions for errors.

```bash
axiom error-suggest
axiom error-suggest StoreCorrupted
axiom error-suggest PermissionDenied
```

**Arguments:**
- `error_name` - Specific error to get suggestions for

With no arguments, shows all known error suggestions.

**Example output:**
```
Error Suggestions
=================

ERROR                     SUGGESTED ACTION
-----                     ----------------
StoreCorrupted            axiom store-repair
PackageNotFound           axiom search <name>
ImportInterrupted         axiom import-recover
RealizationInterrupted    axiom env-recover <name>
DependencyConflict        axiom deps-analyze <pkg>
CacheUnreachable          Check network connectivity
PermissionDenied          Run with sudo
PoolNotAvailable          zpool import <pool>

For detailed help on a specific error:
  axiom error-suggest <error_name>
```

---

### Testing & Validation Operations (Phase 50)

Commands for running tests and validating system correctness.

#### `axiom test [options]`

Run all test suites.

```bash
axiom test
axiom test --verbose
```

**Options:**
- `--verbose` - Show detailed test output

**Example output:**
```
Axiom Test Runner
=================

Running all test suites...

Unit Tests:         47/47 passed
Golden File Tests:  23/23 passed
Integration Tests:  12/12 passed
Regression Tests:   8/8 passed

=====================================
Overall: PASSED (90 tests)
=====================================
```

#### `axiom test-unit [options]`

Run unit tests only.

```bash
axiom test-unit
axiom test-unit --verbose
```

**Options:**
- `--verbose` - Show individual test results

**Example output:**
```
Unit Tests
==========

Running unit tests...

  ✓ resolver_basic
  ✓ resolver_virtual_providers
  ✓ manifest_parsing
  ✓ profile_validation
  ...

Passed: 47/47
Failed: 0
Skipped: 0

✓ All unit tests passed!
```

#### `axiom test-golden [options]`

Run golden file tests (manifest/profile/resolution validation).

```bash
axiom test-golden
axiom test-golden --verbose
```

**Options:**
- `--verbose` - Show individual test file results

**Example output:**
```
Golden File Tests
=================

Running golden file tests...

Manifest tests:
  ✓ valid/basic.yaml
  ✓ valid/with-deps.yaml
  ✓ invalid/missing-name.yaml (expected failure)

Profile tests:
  ✓ valid/development.yaml
  ✓ valid/server.yaml

Resolution tests:
  ✓ simple.input.yaml -> simple.expected.yaml

Passed: 23/23
Failed: 0

✓ All golden file tests passed!
```

#### `axiom test-integration [options]`

Run integration tests (full workflow tests).

```bash
axiom test-integration
axiom test-integration --verbose
```

**Options:**
- `--verbose` - Show detailed workflow output

**Example output:**
```
Integration Tests
=================

Running integration tests...

  ✓ full_workflow
  ✓ profile_lifecycle
  ✓ environment_creation
  ✓ garbage_collection
  ...

Passed: 12/12
Failed: 0

✓ All integration tests passed!
```

#### `axiom test-regression [options]`

Run regression tests for known issues.

```bash
axiom test-regression
axiom test-regression --verbose
```

**Options:**
- `--verbose` - Show test case details

**Example output:**
```
Regression Tests
================

Running regression tests...

  ✓ issue-42-cyclic-deps
  ✓ issue-57-partial-import
  ✓ issue-89-version-constraint
  ...

Passed: 8/8
Failed: 0

✓ All regression tests passed!
```

#### `axiom test-fuzz [options]`

Run fuzz tests on parsers.

```bash
axiom test-fuzz
axiom test-fuzz --duration 60
axiom test-fuzz --verbose
```

**Options:**
- `--duration <seconds>` - How long to run fuzz tests (default: 10)
- `--verbose` - Show fuzz iteration progress

**Example output:**
```
Fuzz Tests
==========

Running fuzz tests for 10 seconds...

Target: manifest_parser
  Iterations: 15234
  Crashes: 0
  Unique paths: 847

Target: profile_parser
  Iterations: 12456
  Crashes: 0
  Unique paths: 623

Target: version_parser
  Iterations: 18901
  Crashes: 0
  Unique paths: 234

=====================================
Total iterations: 46591
Total crashes: 0
Duration: 10.0s
=====================================

✓ Fuzz testing completed with no crashes!
```

---

### Shell Completions

Generate shell completion scripts for command-line autocompletion.

#### `axiom completions <shell>`

Generate completion script for the specified shell.

```bash
axiom completions bash
axiom completions zsh
axiom completions fish
```

**Installation:**

**Bash:**
```bash
axiom completions bash > /usr/local/share/bash-completion/completions/axiom
# Or for user-local:
axiom completions bash >> ~/.bashrc
```

**Zsh:**
```bash
axiom completions zsh > /usr/local/share/zsh/site-functions/_axiom
# Or add to fpath in ~/.zshrc:
# fpath=(~/.zsh/completions $fpath)
axiom completions zsh > ~/.zsh/completions/_axiom
```

**Fish:**
```bash
axiom completions fish > ~/.config/fish/completions/axiom.fish
```

**Features:**
- Command completion
- Option completion
- Dynamic completion for profiles, environments, packages, and keys
- File completion where appropriate

---

### Multi-user Operations

Phase 12 adds support for per-user profiles and environments, allowing non-root users to manage their own package configurations.

#### User Profile Operations

##### `axiom user`

List user profiles.

```bash
axiom user
```

**Example output:**
```
User Profiles for 'alice':
========================

  - development
  - testing

2 profile(s) total
```

##### `axiom user-profile-create <name>`

Create a user-scoped profile (no root required).

```bash
axiom user-profile-create my-dev
```

**Creates:**
- Dataset: `zroot/axiom/users/alice/profiles/my-dev`
- Profile stored in user's area

##### `axiom user-profile-show <name>`

Show user profile details.

```bash
axiom user-profile-show my-dev
```

##### `axiom user-profile-update <name>`

Update a user profile.

```bash
axiom user-profile-update my-dev
```

##### `axiom user-profile-delete <name>`

Delete a user profile.

```bash
axiom user-profile-delete my-dev
```

#### User Environment Operations

##### `axiom user-resolve <profile>`

Resolve dependencies for a user profile.

```bash
axiom user-resolve my-dev
```

**Note:** Uses packages from the shared system store.

##### `axiom user-realize <env-name> <profile> [options]`

Create a user environment from a profile.

```bash
axiom user-realize my-env my-dev
axiom user-realize my-env my-dev --conflict-policy priority
```

**Options:**
- `--conflict-policy <policy>` - How to handle file conflicts between packages
  - `error` - Fail on any file conflict (default)
  - `priority` - Later packages override earlier ones
  - `keep-both` - Keep both files with package name suffix

**Creates:**
- Dataset: `zroot/axiom/users/alice/env/my-env`
- Activation script in user's area

##### `axiom user-activate <env>`

Activate a user environment.

```bash
axiom user-activate my-env
```

**Output:**
```
Activating user environment: my-env
  Mountpoint: /axiom/users/alice/env/my-env

To activate in your shell, run:
  source /axiom/users/alice/env/my-env/activate
```

##### `axiom user-env`

List user environments.

```bash
axiom user-env
```

##### `axiom user-env-destroy <env>`

Destroy a user environment.

```bash
axiom user-env-destroy my-env
```

#### System Administration Commands (Root Only)

##### `axiom system-import <source>`

Import a package to the system store.

```bash
sudo axiom system-import /path/to/package.tar.gz
```

**Note:** This is the privileged version of import.

##### `axiom system-gc`

Run system-wide garbage collection.

```bash
sudo axiom system-gc
```

##### `axiom system-users`

List all users with Axiom data.

```bash
sudo axiom system-users
```

**Example output:**
```
Axiom Users
===========

  alice: 2147483648 bytes
  bob: 1073741824 bytes

2 user(s) total
```

##### `axiom system-user-remove <username>`

Remove all Axiom data for a user (root only).

```bash
sudo axiom system-user-remove bob
```

**Warning:** Destroys all profiles and environments for the user.

---

## Virtual Package Operations

Virtual packages provide an abstraction layer for package capabilities. For example, multiple packages can provide "shell" capability, allowing users to depend on the capability rather than a specific implementation.

### Listing Virtual Packages

##### `axiom virtual`

List all known virtual packages and their providers.

```bash
axiom virtual
```

Output:
```
Virtual Packages
================

Scanning package store for virtual package declarations...

Common virtual packages:
  shell          - Command line shell (bash, zsh, fish, etc.)
  http-client    - HTTP download tools (curl, wget, etc.)
  editor         - Text editors (vim, emacs, nano, etc.)
  cc             - C compiler (gcc, clang, etc.)
  c++            - C++ compiler (g++, clang++, etc.)
```

### Querying Virtual Package Providers

##### `axiom virtual-providers <name>`

List packages that provide a virtual package.

```bash
axiom virtual-providers shell
```

Output:
```
Packages providing 'shell':
===========================

  - bash
  - zsh
  - fish
```

### Package Provides Query

##### `axiom provides <package>`

Show what virtual packages a package provides.

```bash
axiom provides bash
```

Output:
```
Virtual packages provided by 'bash':
=====================================

  - shell
  - posix-shell
```

### Conflict Query

##### `axiom conflicts <package>`

Show packages that conflict with a given package.

```bash
axiom conflicts bash
```

Output:
```
Packages conflicting with 'bash':
=================================

  - csh (explicit conflict)
  - zsh<5.0.0 (version-constrained conflict)
```

### Replace Query

##### `axiom replaces <package>`

Show packages that a package replaces/supersedes.

```bash
axiom replaces bash
```

Output:
```
Packages replaced by 'bash':
============================

  - sh
```

---

### Manifest Virtual Package Fields

Packages declare virtual package relationships in `manifest.yaml`:

```yaml
name: bash
version: 5.2.0
revision: 1
description: GNU Bourne Again Shell

# Virtual packages this package provides
provides:
  - shell
  - posix-shell

# Packages that cannot coexist with this one
conflicts:
  - csh              # Conflicts with any version
  - zsh<5.0.0        # Conflicts with specific versions

# Packages this one supersedes
replaces:
  - sh               # Replaces any sh version
```

**Provides:** Declares abstract capabilities this package satisfies. When a profile requests a virtual package, the resolver finds packages that provide it.

**Conflicts:** Declares packages that cannot be installed alongside this one. The resolver will fail if conflicting packages are requested.

**Replaces:** Declares packages this one supersedes. During resolution, if a replaced package is already resolved, it will be removed in favor of the replacing package.

---

### Dataset Structure (Multi-user)

With multi-user support, the ZFS dataset structure is:

```
zroot/axiom/
├── store/              # Shared package store (root-managed)
│   └── pkg/
├── profiles/           # System-wide profiles (root)
├── env/                # System-wide environments (root)
└── users/              # Per-user data
    ├── alice/
    │   ├── profiles/   # Alice's profiles
    │   └── env/        # Alice's environments
    └── bob/
        ├── profiles/   # Bob's profiles
        └── env/        # Bob's environments
```

---

### Direct Execution (AppImage-style)

Run packages directly without creating full environments.

#### `axiom run <package> [args...]`

Execute a package directly with automatic environment setup.

```bash
axiom run bash
axiom run python --version
axiom run node script.js
```

**Options:**
- `--isolated` - Run with minimal environment (package closure only)
- `--system-first` - Prefer system libraries over package libraries

**Example:**
```bash
# Run bash from the package store
sudo axiom run bash

# Run python in isolated mode
sudo axiom run python --isolated -- script.py

# Run with arguments
sudo axiom run ffmpeg -- -i input.mp4 output.webm
```

**How it works:**
1. Computes the package's dependency closure
2. Sets up LD_LIBRARY_PATH and PATH
3. Executes the package's main binary
4. Cleans up on exit

#### `axiom closure <package>`

Show the dependency closure for a package (all transitive dependencies).

```bash
axiom closure bash
```

**Example output:**
```
Dependency closure for bash@5.2.0:
==================================

Direct dependencies:
  - readline 8.2.0
  - ncurses 6.4.0

Transitive dependencies:
  - libc 2.38.0

Total: 4 packages (including bash)
Estimated size: 45 MB
```

**Options:**
- `--depth <n>` - Limit depth of closure computation
- `--format json` - Output as JSON for scripting

---

### Package Export & Bundles

Export packages in portable formats for distribution without ZFS.

#### `axiom export <package> [options]`

Export a package to a portable format.

```bash
axiom export bash --format tarball --output bash-5.2.0.tar.gz
```

**Options:**
- `--format <format>` - Export format (tarball, zfs-stream, directory)
- `--output <path>` - Output file path
- `--include-deps` - Include all dependencies in export
- `--sign` - Sign the export with your key

**Formats:**
- `tarball` - Standard tar.gz archive
- `zfs-stream` - ZFS send stream (for ZFS-to-ZFS transfer)
- `directory` - Plain directory structure

#### `axiom bundle <package> [options]`

Create a self-contained, portable bundle (.pgsdimg).

```bash
axiom bundle bash --output bash-bundle.pgsdimg
```

**Options:**
- `--format <format>` - Bundle format:
  - `pgsdimg` - Self-extracting executable (default)
  - `zfs-stream` - ZFS send stream with manifest
  - `tarball` - Compressed tar archive
  - `directory` - Directory structure
- `--output <path>` - Output path
- `--compression <type>` - Compression (none, gzip, zstd, lz4, xz)
- `--sign` - Sign the bundle

**Example output:**
```
Creating bundle: bash-bundle.pgsdimg
  Package: bash 5.2.0
  Dependencies: 3
  Total size: 12 MB

Bundle created successfully!
  Output: bash-bundle.pgsdimg
  Size: 4.2 MB (compressed)
  Packages: 4
```

**Using a .pgsdimg bundle:**

The generated `.pgsdimg` is a self-extracting shell script:

```bash
# Make executable (usually already is)
chmod +x bash-bundle.pgsdimg

# Run directly
./bash-bundle.pgsdimg

# Extract to directory
./bash-bundle.pgsdimg --extract /path/to/dir

# Show bundle info
./bash-bundle.pgsdimg --info
```

#### `axiom bundle-verify <bundle-path> [options]`

Verify a bundle's signature and integrity before execution.

```bash
axiom bundle-verify myapp.pgsdimg
axiom bundle-verify myapp.pgsdimg --trust-store /path/to/keys
axiom bundle-verify myapp.pgsdimg --allow-untrusted
```

**Options:**
- `--trust-store <path>` - Path to trusted keys directory
- `--allow-untrusted` - Allow bundles from untrusted signers (show warning)
- `--require-signature` - Fail if bundle is unsigned (default: true)

**Verification checks:**
1. **Signature verification** - Ed25519 signature validity
2. **Payload hash** - SHA-256 integrity check
3. **Manifest validation** - Bundle metadata consistency
4. **Trust chain** - Signer key in trust store

**Example output (verified):**
```
Bundle Verification: myapp.pgsdimg
==================================

Signature:    ✓ Valid (Ed25519)
Signer:       PGSD-Official (trusted)
Payload hash: ✓ Matches (SHA-256)
Manifest:     ✓ Valid

Package: myapp 1.2.0
Packages included: 4
Total size: 12.4 MB

✓ Bundle verification passed
```

**Example output (untrusted):**
```
Bundle Verification: myapp.pgsdimg
==================================

Signature:    ✓ Valid (Ed25519)
Signer:       Unknown-Key-abc123 (NOT TRUSTED)
Payload hash: ✓ Matches (SHA-256)

⚠ Warning: Bundle signer is not in trust store
  To trust this signer: axiom key-add <key-file>

✗ Bundle verification failed: untrusted signer
```

#### `axiom bundle-run <bundle-path> [args...]`

Verify and execute a bundle securely.

```bash
axiom bundle-run myapp.pgsdimg
axiom bundle-run myapp.pgsdimg --allow-untrusted -- --app-arg value
axiom bundle-run myapp.pgsdimg --extract-only /tmp/myapp
```

**Options:**
- `--trust-store <path>` - Path to trusted keys directory
- `--allow-untrusted` - Run bundles from untrusted signers (with warning)
- `--require-signature` - Fail if bundle is unsigned (default: true)
- `--extract-only <path>` - Extract but don't run
- `--` - Separator for arguments passed to the bundle

**Process:**
1. Verify bundle signature and integrity
2. Check trust chain
3. Extract to temporary directory
4. Execute main binary with provided arguments
5. Clean up temporary files on exit

**Example output:**
```
Verifying bundle: myapp.pgsdimg
  ✓ Signature valid
  ✓ Signer trusted: PGSD-Official
  ✓ Payload integrity verified

Extracting to: /tmp/axiom-bundle-xyz123
Launching: myapp 1.2.0

[Application output follows...]
```

**Security notes:**
- Bundles are verified before any code execution
- Untrusted bundles require explicit `--allow-untrusted` flag
- Temporary extraction directory has restricted permissions
- Bundle contents are validated against manifest

---

### Runtime Layers

Manage runtime layers (shared base environments similar to Flatpak runtimes).

#### `axiom runtime`

List available runtime layers.

```bash
axiom runtime
```

**Example output:**
```
Available runtimes:
  base-2025    - Minimal base runtime (libc, libm, libpthread)
  full-2025    - Full runtime with common libraries
  gui-2025     - GUI runtime with X11/Wayland support
```

#### `axiom runtime-create <name> [packages...]`

Create a new runtime layer.

```bash
axiom runtime-create my-runtime libc readline ncurses
```

#### `axiom runtime-use <runtime> <package>`

Run a package using a specific runtime layer.

```bash
axiom runtime-use base-2025 myapp
```

---

### Desktop Integration

Integrate packages with the desktop environment (freedesktop.org compliance).

#### `axiom desktop-install <package>`

Install desktop integration for a package (creates .desktop file, icons, MIME types).

```bash
axiom desktop-install firefox
```

**Creates:**
- `~/.local/share/applications/<package>.desktop`
- Icons in `~/.local/share/icons/`
- MIME type associations

#### `axiom desktop-remove <package>`

Remove desktop integration for a package.

```bash
axiom desktop-remove firefox
```

---

### Ports Migration (FreeBSD)

Migrate packages from the FreeBSD ports tree to Axiom manifests.

#### `axiom ports`

List available port categories or scan the ports tree.

```bash
axiom ports
```

**Example output:**
```
FreeBSD Ports Scanner
=====================

Ports tree: /usr/ports

Available categories:

  devel
  editors
  lang
  net
  security
  shells
  sysutils
  www
  ...

To scan a category:
  axiom ports-scan <category>
  axiom ports-scan devel
```

#### `axiom ports-gen <origin> [options]`

Generate Axiom manifests from a FreeBSD port.

```bash
axiom ports-gen editors/vim
axiom ports-gen devel/git --out ./my-ports
axiom ports-gen shells/bash --build --import
```

**Options:**
- `--ports-tree <path>` - Path to ports tree (default: /usr/ports)
- `--out <dir>` - Output directory (default: ./generated/axiom-ports)
- `--build` - Also build after generating manifests
- `--import` - Also import to store after building
- `--dry-run` - Show what would be generated without writing

**Creates:**
```
./generated/axiom-ports/<category>/<portname>/
├── manifest.yaml    # Package metadata
├── deps.yaml        # Dependencies
└── build.yaml       # Build recipe
```

#### `axiom ports-build <origin>`

Build a port using Axiom's builder from previously generated manifests.

```bash
axiom ports-build editors/vim
```

**Note:** Requires running `axiom ports-gen` first to create manifests.

#### `axiom ports-import <origin>`

Full migration: generate manifests, build, and import to store.

```bash
axiom ports-import editors/vim
axiom ports-import devel/automake --use-system-tools
```

**Options:**
- `--ports-tree <path>` - Path to ports tree (default: /usr/ports)
- `--jobs <n>` - Number of parallel build jobs (default: 4)
- `--verbose` - Show detailed build output
- `--keep-sandbox` - Don't clean up build staging directory
- `--dry-run` - Generate manifests only, don't build
- `--no-deps` - Don't auto-resolve dependencies
- `--use-system-tools` - Use /usr/local tools instead of sysroot (see Troubleshooting)

This is equivalent to `axiom ports-gen <origin> --build --import`.

**Troubleshooting: `--use-system-tools`**

When building ports that depend on autotools (autoconf, automake) or other complex tool chains, you may encounter build failures due to wrapper script issues in the sysroot. The `--use-system-tools` flag bypasses sysroot creation and uses tools installed in `/usr/local` directly.

```bash
# First, ensure required tools are installed via pkg
pkg install autoconf automake

# Then build with system tools
axiom ports-import devel/automake --use-system-tools
```

This is recommended when:
- Configure scripts fail to find autoconf/automake
- Wrapper scripts (like autoconf-switch) don't work in the sysroot
- Old packages in the store have broken layouts

#### `axiom ports-scan <category>`

Scan a ports category for migratable ports.

```bash
axiom ports-scan devel
axiom ports-scan shells --ports-tree /usr/ports
```

**Example output:**
```
FreeBSD Ports Scanner
=====================

Ports tree: /usr/ports

Scanning category: shells

Found 42 ports:
  shells/bash
  shells/fish
  shells/zsh
  shells/tcsh
  ...

To migrate a port:
  axiom ports-gen shells/<portname>
```

---

## Kernel Compatibility

Check compatibility of kernel-bound packages (kernel modules) with the running kernel.

### `axiom kernel`

Check kernel compatibility of installed packages.

```bash
axiom kernel
axiom kernel-check  # alias
```

**Example output:**
```
Kernel Compatibility Check
==========================

Kernel:
  FreeBSD version (osreldate): 1502000
  Kernel ident: GENERIC

Kernel-bound packages:

  [OK] drm-kmod-6.10.0_1
       freebsd_version: 1500000-1509999
       kernel_idents: GENERIC, PGSD-GENERIC

  [OK] pgsd-securefs-1.0.0
       freebsd_version: 1500000-1509999
       kernel_idents: (none)

  [INCOMPATIBLE] old-nvidia-driver-470.223
       freebsd_version_min: 1400000
       freebsd_version_max: 1499999
       reason: running kernel version exceeds maximum supported

Summary:
  2 compatible kernel-bound packages
  1 incompatible kernel-bound packages

⚠ Warning: Incompatible kernel modules may fail to load.
Consider rebuilding these packages for your current kernel.
```

**Environment Variables:**

For testing or non-FreeBSD systems, override detection:
```bash
export AXIOM_FREEBSD_VERSION=1502000
export AXIOM_KERNEL_IDENT=PGSD-GENERIC
axiom kernel
```

**Notes:**
- Userland packages (no `kernel` section in manifest) are not shown
- Only packages with `kernel.kmod: true` are checked
- Compatible packages match both version range and ident (if required)

### Kernel Compatibility in Manifests

Kernel modules require a `kernel` section in their manifest:

```yaml
name: drm-kmod
version: "6.10.0"
revision: 1

kernel:
  kmod: true                      # This is a kernel module
  freebsd_version_min: 1500000    # Minimum __FreeBSD_version
  freebsd_version_max: 1509999    # Maximum __FreeBSD_version
  kernel_idents:                  # Optional: allowed kernel idents
    - "GENERIC"
    - "PGSD-GENERIC"
  require_exact_ident: false      # If true, must match kernel_idents
  kld_names:                      # Installed .ko files
    - "drm.ko"
    - "amdgpu.ko"
```

**Automatic Detection in Ports Migration:**

When migrating ports with `USES=kmod`:
```bash
axiom ports-gen graphics/drm-kmod
# Automatically generates kernel section
```

---

## Complete Workflow Example

### 1. Create a Development Environment

```bash
# Create profile
sudo axiom profile-create development

# Edit profile.yaml manually to add packages
cat > /axiom/profiles/development/profile.yaml << EOF
name: development
description: Development tools
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
EOF

# Resolve dependencies
sudo axiom resolve development

# Create environment
sudo axiom realize dev-env development

# Activate
source /axiom/env/dev-env/activate
```

### 2. Use the Environment

```bash
# Now using packages from environment
which bash
# /axiom/env/dev-env/bin/bash

bash --version
# GNU bash, version 5.2.0

# Check environment variable
echo $AXIOM_ENV
# dev-env
```

### 3. Deactivate

```bash
# Return to system packages
deactivate
```

### 4. Update Environment

```bash
# Update profile
vim /axiom/profiles/development/profile.yaml

# Re-resolve
sudo axiom resolve development

# Destroy old environment
sudo axiom env-destroy dev-env

# Create updated environment
sudo axiom realize dev-env development
```

### 5. Clean Up

```bash
# Remove environment
sudo axiom env-destroy dev-env

# Remove profile
sudo axiom profile-delete development

# Clean unreferenced packages
sudo axiom gc
```

---

## Environment Activation

When you activate an environment, the activation script:

1. **Sets environment variables:**
   ```bash
   export AXIOM_ENV="dev-env"
   export PATH="/axiom/env/dev-env/bin:$PATH"
   export LD_LIBRARY_PATH="/axiom/env/dev-env/lib:$LD_LIBRARY_PATH"
   export MANPATH="/axiom/env/dev-env/share/man:$MANPATH"
   ```

2. **Provides deactivation function:**
   ```bash
   deactivate() {
     unset AXIOM_ENV
     echo "Environment deactivated"
   }
   ```

3. **Notification:**
   ```
   Axiom environment 'dev-env' activated
   To deactivate, run: deactivate
   ```

---

## Configuration Files

### Profile (profile.yaml)

```yaml
name: development
description: Development environment
packages:
  - name: bash
    version: "^5.0.0"
    constraint: caret
  - name: git
    version: ">=2.40.0"
    constraint: range
```

### Lock File (profile.lock.yaml)

```yaml
profile_name: development
lock_version: 1
resolved:
  - name: bash
    version: "5.2.0"
    revision: 1
    build_id: abc123
    requested: true
  - name: readline
    version: "8.2.0"
    revision: 1
    build_id: def456
    requested: false
```

---

## File Conflict Resolution

When realizing an environment, multiple packages may contain files with the same path. Axiom detects these conflicts and handles them according to the configured policy.

### Conflict Types

- **same_content** - Files are identical (no real conflict, handled automatically)
- **different_content** - Files have different content
- **type_mismatch** - One is a file, one is a directory
- **permission_diff** - Same content but different permissions

### Resolution Strategies

| Policy | Behavior |
|--------|----------|
| `error` | Fail immediately on conflict (safe default) |
| `priority` | Later package in lock file wins |
| `keep-both` | Keep both files with package suffix (e.g., `file.bash`, `file.coreutils`) |

### Example Scenarios

**Scenario 1: Two packages provide `/bin/gettext`**
- `gettext` package installs `/bin/gettext`
- `gettext-tiny` package also installs `/bin/gettext`

With `--conflict-policy error`: Realization fails, prompting user to choose.

With `--conflict-policy priority`: The package listed later in the lock file wins.

With `--conflict-policy keep-both`: Both files are kept as:
- `/bin/gettext.gettext`
- `/bin/gettext.gettext-tiny`

**Scenario 2: Identical files from multiple packages**

If both packages contain identical files (same content, same permissions), no conflict is reported - the file is installed once.

---

## Exit Codes

- `0` - Success
- `1` - General error
- `2` - Invalid usage
- `3` - ZFS error
- `4` - Package not found
- `5` - Profile not found
- `6` - Environment not found
- `7` - File conflict (when using `error` policy)

---

## Tips and Best Practices

### Profile Naming

Use descriptive names:
- `development` - Development tools
- `server-production` - Production server packages
- `desktop-minimal` - Minimal desktop environment

### Version Constraints

Choose appropriate constraints:
- Exact (`=1.2.3`) - Pin specific version
- Tilde (`~1.2.3`) - Allow patch updates
- Caret (`^1.2.3`) - Allow compatible updates
- Range (`>=1.0.0,<2.0.0`) - Explicit bounds
- Wildcard (`*`) - Any version (use sparingly)

### Environment Workflow

1. Create profile once
2. Resolve when dependencies change
3. Realize creates new environment instance
4. Multiple environments from same profile OK
5. Destroy old environments after updates

### Garbage Collection

Run `axiom gc` periodically to:
- Reclaim disk space
- Remove old package versions
- Clean up after profile updates

### Snapshots

ZFS snapshots enable rollback:
```bash
# List snapshots
zfs list -t snapshot -r zroot/axiom/env/dev-env

# Rollback
zfs rollback zroot/axiom/env/dev-env@initial
```

---

## Troubleshooting

### "Failed to initialize ZFS"

**Cause:** Not running as root or ZFS not available

**Solution:**
```bash
sudo axiom <command>
```

### "Profile not found"

**Cause:** Profile doesn't exist

**Solution:**
```bash
# List profiles
sudo axiom profile

# Create profile
sudo axiom profile-create <name>
```

### "Environment already exists"

**Cause:** Environment name conflict

**Solution:**
```bash
# Destroy old environment
sudo axiom env-destroy <name>

# Or use different name
sudo axiom realize <new-name> <profile>
```

### "Package not found in store"

**Cause:** Package hasn't been imported

**Solution:**
Import package (Phase 7 TODO):
```bash
sudo axiom import /path/to/package
```

---

**Author**: Vester "Vic" Thacker  
**Organization**: Pacific Grove Software Distribution Foundation  
**License**: BSD 2-Clause
