# Axiom

**Axiom** is a ZFS-native system manager and package infrastructure for the
Pacific Grove Software Distribution (PGSD).

It provides an **immutable ZFS-backed software store**, **declarative system
profiles**, **deterministic dependency resolution**, and **atomic environment
activation**.

Axiom is designed for long-lived systems where **reproducibility,
auditability, and rollback** matter more than convenience abstractions or opaque
automation.

Axiom is not a traditional package manager. It is a **system-level substrate**
for building, storing, resolving, and activating software environments as
*explicit, immutable artifacts*.

---

## What Problem Axiom Solves

Modern Unix-like systems accumulate structural problems over time:

- Package state drifts and becomes difficult to reproduce
- Upgrades are destructive and rollback is unreliable
- Dependency resolution is implicit and hard to audit
- System state is scattered across mutable directories

Axiom addresses these issues by treating **the entire software stack as data**:

- Packages are immutable ZFS datasets
- Desired system state is declared explicitly
- Dependency resolution is deterministic and recorded
- Activation is atomic and reversible

If the system breaks, you do not repair it. You **roll back**.

---

## Core Concepts

Axiom is built around a small set of strict principles:

1. **Canonical truth is simple and human readable**  
   YAML manifests, not complex DSLs.

2. **Immutable package store as ZFS datasets**  
   Leveraging ZFS copy-on-write, snapshots, and clones.

3. **Profiles define whole system state**  
   Declarative configuration as user intent.

4. **Deterministic dependency resolution**  
   Reproducible resolution producing explicit lock files.

5. **ZFS-first operations**  
   Create, snapshot, clone, send, receive as first-class actions.

6. **Separation of concerns**  
   Build → Store → Index → Resolve → Realize → Activate.

These constraints are deliberate. They are what make long-term maintenance
possible.

---

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
└── env/<name>/             # Realized environments

```

Packages are never modified in place. Environments are disposable. Profiles
and lock files capture intent and resolution separately.

---

## High-Level Architecture

```

Build artifacts / Ports / Tarballs
↓
Package Import
↓
Immutable ZFS Store
↓
Profiles
↓
Resolver
↓
Lock Files
↓
Environments
↓
Activation

````

Each phase produces a concrete artifact that can be inspected, validated,
reproduced, or rolled back later.

---

## Quick Start

### Prerequisites

- FreeBSD 14.x or GhostBSD with ZFS
- Zig 0.15.x
- FreeBSD ports tree (`portsnap` or `git`)

### Automated Setup (Recommended)

```sh
zig build
sudo cp zig-out/bin/axiom /usr/local/bin/axiom
sudo axiom setup
````

### Minimal Bootstrap

```sh
sudo axiom bootstrap-ports --minimal
sudo axiom ports-import shells/bash
sudo axiom ports-import editors/vim
```

### Create and Activate an Environment

```sh
sudo axiom profile-create myprofile
sudo axiom profile-add-package myprofile bash vim
sudo axiom resolve myprofile
sudo axiom realize myenv myprofile
source /axiom/env/myenv/activate
```

For detailed setup and troubleshooting, see **SETUP.md** and **USER_GUIDE.md**.

---

## Who Axiom Is For

Axiom is intended for:

* System engineers who value **predictability over convenience**
* Long-lived systems that must survive years or decades of upgrades
* Research, infrastructure, and appliance-style deployments
* Developers building **new OS distributions or platforms** on FreeBSD and ZFS

Axiom is explicitly **not** a drop-in replacement for `pkg` or a convenience-first
desktop package manager.

---

## How Axiom Is Different

Axiom deliberately avoids several common design choices:

* No mutable global package state
* No in-place upgrades
* No implicit dependency resolution
* No hidden rebuilds or side effects

Instead, Axiom treats software as **versioned artifacts** and system state as
**data**. Every step is explicit, inspectable, and reversible.

This makes Axiom suitable for environments where correctness and traceability
matter more than speed of iteration.

---

## Project Status

Axiom is functional and actively developed.

The project prioritizes **architectural stability over feature churn**.
Core commitments are long-term:

* Immutable package store
* Declarative profiles
* Deterministic dependency resolution
* ZFS-native atomic operations

Breaking changes are deliberate, documented, and avoided unless strictly
necessary.

---

## Sponsorship

Axiom is infrastructure software. Its value compounds over time, while its
maintenance cost remains constant.

If you or your organization depend on Axiom, consider supporting its
development. Sponsorship focuses on **continuity and stewardship**, not
exclusive features.

See **SPONSORS.md** for details.

---

## Documentation

* **USER_GUIDE.md** – Comprehensive usage guide
* **SETUP.md** – ZFS and system setup
* **ARCHITECTURE.md** – Internal architecture and source layout
* **CLI.md** – Command-line reference
* **MANIFEST_FORMAT.md** – Package manifest specification
* **RESOLVER.md** – Dependency resolution model
* **SECURITY.md** – Security model and threat assumptions
* **ROADMAP.md** – Planned evolution

---

## License

BSD 2-Clause License

Copyright (c) 2025
Pacific Grove Software Distribution Foundation

---

## Author

Vester “Vic” Thacker
Pacific Grove Software Distribution Foundation


