# Axiom Artifact Lockbox

## Overview

Axiom Artifact Lockbox is a specialized tool for deterministic ingestion, normalization, and deployment of third-party vendor software artifacts on FreeBSD and BSD-derived systems.

**Lockbox is not:**
- A general package manager
- A build system
- A sandbox or container runtime

**Lockbox provides:**
- Operational control over vendor binaries
- Reproducibility and auditability
- Atomic deployment via ZFS
- Guaranteed rollback capability

## Design Principles

1. **Canonical truth is simple and human readable** - YAML for authoring, JSON for machine verification
2. **Machine verification must be deterministic** - Content hashes derived only from canonical JSON
3. **Human authoring and machine hashing are separate concerns** - YAML is never hashed directly
4. **No implicit behavior** - All operations are explicit
5. **All mutations are explicit and reversible** - Every deployment can be rolled back

## Configuration Format

### Dual Format Support

Lockbox accepts metadata in either format:
- `lockbox.yaml` - Human authoring format
- `lockbox.json` - Machine-readable format

Both formats are parsed into the same strict typed data model.

### Generated Output

Lockbox emits `lockbox.canonical.json`:
- Machine generated
- Canonicalized (sorted keys, no whitespace)
- Deterministic
- Never edited by humans

**All content IDs, hashes, and signatures are derived from:**
- `lockbox.canonical.json`
- The Merkle root of the artifact filesystem manifest

## YAML Specification

### Example lockbox.yaml

```yaml
format_version: "1.0"
schema_version: "1.0"

identity:
  name: "oracle-jdk"
  version: "17.0.2"
  description: "Oracle JDK 17 LTS"
  vendor:
    name: "oracle"
    display_name: "Oracle Corporation"
    url: "https://www.oracle.com/java/"

source:
  url: "https://download.oracle.com/java/17/archive/jdk-17.0.2_linux-x64_bin.tar.gz"
  sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
  filename: "jdk-17.0.2_linux-x64_bin.tar.gz"
  size: 185646944
  fetched_at: "2025-01-01T12:00:00Z"

filesystem:
  files:
    - path: "bin/java"
      sha256: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
      size: 16384
      mode: "0755"
      type: regular
    - path: "lib/libjvm.so"
      sha256: "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
      size: 25165824
      mode: "0755"
      type: regular

deployment:
  path: "/opt/oracle/jdk-17"
  dataset: "zroot/axiom/lockbox/oracle-jdk-17"
  snapshot: true
```

### YAML Constraints

When using YAML:
- All scalar values must resolve to explicit types
- Versions are **strings** (e.g., `version: "1.0"`)
- File modes are **strings** (e.g., `mode: "0755"`)
- Timestamps are RFC 3339 UTC strings
- No floats allowed
- No implicit typing
- Unknown keys are rejected
- Comments are allowed (ignored by canonicalization)

## Canonical JSON Format

Canonical JSON must:
- Be UTF-8 encoded
- Have lexicographically sorted object keys
- Use normalized number formats
- Contain no insignificant whitespace
- Follow a single, stable schema version

### Example Output

```json
{"deployment":{"dataset":"zroot/axiom/lockbox/oracle-jdk-17","path":"/opt/oracle/jdk-17","snapshot":true},"filesystem":{"files":[{"mode":"0755","path":"bin/java","sha256":"abcdef...","size":16384,"type":"regular"}]},"format_version":"1.0","identity":{"name":"oracle-jdk","vendor":{"name":"oracle"},"version":"17.0.2"},"schema_version":"1.0","source":{"sha256":"0123456789...","url":"https://download.oracle.com/..."}}
```

## Artifact Identity

An artifact is identified by:

| Type | Description |
|------|-------------|
| **Human Identity** | name, version, vendor (for human reference) |
| **Machine Identity** | Content hash from canonical JSON + filesystem Merkle root |

**Human-friendly names are not authoritative. Content hashes are authoritative.**

## CLI Commands

### lockbox-ingest

Ingest a vendor artifact from a lockbox.yaml specification.

```bash
axiom lockbox-ingest <lockbox.yaml> [--output <file>]
```

This command:
1. Reads and validates the YAML specification
2. Computes the content hash
3. Generates canonical JSON
4. Prepares the artifact for deployment

### lockbox-normalize

Normalize a lockbox specification to canonical JSON.

```bash
axiom lockbox-normalize <lockbox.yaml> [--output <file>]
```

Canonical JSON is the **only** format used for hashing and signing, ensuring cryptographic determinism regardless of YAML formatting.

### lockbox-deploy

Deploy a vendor artifact to its target location.

```bash
axiom lockbox-deploy <lockbox.yaml|lockbox.canonical.json> [--dry-run] [--no-snapshot]
```

Deployment is atomic via ZFS and includes automatic snapshot creation for rollback capability.

### lockbox-rollback

Rollback a deployed artifact to a previous state.

```bash
axiom lockbox-rollback <lockbox.yaml> <snapshot-name>
```

Uses ZFS rollback to atomically restore the previous state.

### lockbox-verify

Verify the integrity of a lockbox artifact.

```bash
axiom lockbox-verify <lockbox.yaml|lockbox.canonical.json>
```

Recomputes the content hash and compares it against the stored machine identity.

### lockbox-show

Display detailed information about a lockbox artifact.

```bash
axiom lockbox-show <lockbox.yaml|lockbox.canonical.json> [--json] [--yaml] [--hash]
```

### lockbox-audit

Show the audit log of lockbox operations.

```bash
axiom lockbox-audit
```

## Scope Boundaries

### Lockbox Must NOT:
- Replace pkg or ports
- Resolve system dependencies
- Auto-update vendor software
- Guess user intent
- Mutate global system state implicitly

### Lockbox Must:
- Fail loudly on invariant violations
- Guarantee atomic deployment via ZFS
- Guarantee rollback capability
- Preserve full audit history

## ZFS Integration

Lockbox leverages ZFS for atomic deployment and guaranteed rollback capability.

### Snapshots

When `snapshot: true` is set in the deployment configuration, Lockbox automatically creates a ZFS snapshot before deploying:

```
<dataset>@lockbox-pre-<content-hash-prefix>
```

For example:
```
zroot/axiom/lockbox/oracle-jdk-17@lockbox-pre-a1b2c3d4
```

The snapshot captures the exact state of the dataset before deployment, enabling instant rollback if needed.

### Rollback

The `lockbox-rollback` command uses ZFS's native rollback functionality:

```bash
axiom lockbox-rollback <lockbox.yaml> <snapshot-name>
```

This performs an atomic rollback to the specified snapshot, restoring:
- All files to their previous state
- File permissions and ownership
- Directory structure

**Important:** ZFS rollback destroys all changes made after the snapshot. Use with caution.

### Dataset Management

Lockbox expects the deployment dataset to exist. The dataset path is specified in the lockbox specification:

```yaml
deployment:
  dataset: "zroot/axiom/lockbox/oracle-jdk-17"
  path: "/opt/oracle/jdk-17"
  snapshot: true
```

The `path` is the mountpoint where the dataset will be accessible. Lockbox does not automatically create datasets - this must be done beforehand using standard ZFS commands:

```bash
zfs create -o mountpoint=/opt/oracle/jdk-17 zroot/axiom/lockbox/oracle-jdk-17
```

## Integration with Axiom

Lockbox fits naturally within the Axiom ecosystem:

- Uses the same ZFS infrastructure as Axiom package management
- Shares signing and verification infrastructure
- Follows Axiom's design philosophy of determinism and reproducibility
- Can coexist with standard Axiom packages

## Enterprise Use Cases

1. **Oracle JDK/JRE Deployment** - Manage Java versions across systems
2. **VMware Tools** - Deploy VMware guest tools consistently
3. **Commercial Database Software** - Oracle, DB2, SQL Server drivers
4. **Vendor Monitoring Agents** - Datadog, New Relic, etc.
5. **Proprietary Middleware** - WebLogic, WebSphere components

## Canonicalization Boundary

The `lockbox_canon` module provides a clean API boundary for all canonicalization operations. This module is intentionally kept separate from Axiom's existing YAML pipeline to avoid conflicts with package manifest processing.

### API Overview

```zig
const lockbox_canon = @import("lockbox_canon.zig");

// Initialize the canonicalization boundary
var canon = lockbox_canon.LockboxCanon.init(allocator);
defer canon.deinit();

// Canonicalize from file (auto-detects format)
var result = try canon.canonicalizeFile("lockbox.yaml");
defer result.deinit();

// Access results
std.debug.print("Content ID: {s}\n", .{result.content_id});
std.debug.print("Canonical JSON: {s}\n", .{result.canonical_bytes});
```

### Canonicalization Flow

1. **Input Detection**: Accepts `.yaml`, `.yml`, or `.json` files
2. **Parsing**: Strict typed parsing into `LockboxSpec`
3. **Emission**: Deterministic canonical JSON output
4. **Hashing**: SHA-256 content hash computation
5. **Signing** (optional): Ed25519 signature over content ID

### Convenience Functions

```zig
// Get canonical JSON bytes
const canonical = try lockbox_canon.canonicalizeFile(allocator, "lockbox.yaml");
defer allocator.free(canonical);

// Compute content ID
const id = try lockbox_canon.computeContentId(allocator, "lockbox.yaml");

// Check semantic equivalence
const same = try lockbox_canon.areEquivalent(allocator, "a.yaml", "b.json");
```

### Signing

The canonicalization boundary supports optional signing:

```zig
var signed = try canon.canonicalizeAndSign(
    content,
    .yaml,
    key_pair,
    "KEY123",
    "Signer Name",
);
defer signed.deinit();

// Write detached signature
try canon.writeSignatureToFile(&signed, "lockbox.sig");
```

Signatures are computed over the content ID (not the raw bytes), ensuring:
- Format-independent verification (YAML and JSON produce identical signatures)
- Merkle root inclusion in signed data
- Standard Ed25519 signature format

## Audit and Compliance

Lockbox maintains a complete audit trail:

| Operation | Description |
|-----------|-------------|
| `ingest` | Artifact ingestion with content hash |
| `normalize` | Canonical JSON generation |
| `deploy` | Deployment to target with snapshot |
| `rollback` | Rollback to previous state |
| `verify` | Integrity verification |

Each entry includes:
- Timestamp (RFC 3339 UTC)
- Operation type
- Content hash at time of operation
- Actor (user or system)
