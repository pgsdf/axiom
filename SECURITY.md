# Axiom Security Model

This document describes the security model, threat assumptions, and operational guidance for Axiom. It is intended for system administrators, security auditors, and contributors.

## Table of Contents

1. [Threat Model](#threat-model)
2. [Trust Anchors](#trust-anchors)
3. [Privilege Requirements](#privilege-requirements)
4. [Key Management](#key-management)
5. [Secure Operations](#secure-operations)
6. [Resource Limits](#resource-limits)
7. [Hardening Recommendations](#hardening-recommendations)

---

## Threat Model

### Adversary Classes

Axiom considers the following adversary classes:

| Adversary | Description | Assumed Capabilities |
|-----------|-------------|---------------------|
| **Untrusted Manifest** | Malicious package manifest from external source | Arbitrary YAML content, crafted constraints |
| **Untrusted Binary Cache** | Compromised or malicious binary cache server | Arbitrary tarball content, modified signatures |
| **Compromised Local User** | Non-root user attempting privilege escalation | Local filesystem access, can run axiom CLI |
| **Network Attacker** | Man-in-the-middle or DNS spoofing | Can intercept HTTP traffic, serve malicious content |

### Out of Scope

The following are explicitly **not** protected against:

- **Compromised root** on the same machine (if root is compromised, all bets are off)
- **Physical access** to the machine
- **Kernel exploits** that bypass userspace protections
- **Supply chain attacks** on the build host before signing (mitigated by provenance tracking)

### Security Boundaries

```
┌─────────────────────────────────────────────────────────────────┐
│                     TRUSTED DOMAIN                               │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │ PGSD Signing │  │ Local Root   │  │ Verified Store       │  │
│  │ Key (offline)│  │ Authority    │  │ (ZFS datasets)       │  │
│  └──────────────┘  └──────────────┘  └──────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ Signature verification
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    UNTRUSTED DOMAIN                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │ Binary Cache │  │ User Input   │  │ Network Resources    │  │
│  │ Servers      │  │ (manifests)  │  │ (ports tree, etc.)   │  │
│  └──────────────┘  └──────────────┘  └──────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Trust Anchors

### PGSD Foundation Signing Key

The Pacific Grove Software Distribution Foundation maintains an offline signing key used to sign official packages and bootstrap tarballs.

**Trust Chain:**
1. **Root Key** (offline, air-gapped) - Signs release keys
2. **Release Key** (per-release) - Signs packages for a specific release
3. **Package Signature** - Ed25519 signature over manifest + content hash

**Key Location:**
- Public keys: `/axiom/keys/trusted/`
- User keys: `~/.axiom/keys/`

### Local Root Authority

The local root user is trusted to:
- Configure the Axiom store
- Add trusted signing keys
- Import packages into the store
- Create and manage profiles

### Build Host Trust

When building from ports:
- The FreeBSD ports tree is fetched over HTTPS
- Build outputs are signed with a local key
- Provenance metadata records build environment

**WARNING**: Building from ports trusts the ports tree content. For maximum security, verify port checksums against known-good values or use pre-signed binary packages.

---

## Privilege Requirements

### Commands Requiring Root

These commands **must** be run as root:

| Command | Reason |
|---------|--------|
| `axiom setup` | Creates ZFS datasets |
| `axiom ports-import` | Writes to package store |
| `axiom import` | Writes to package store |
| `axiom realize` | Creates environment datasets |
| `axiom gc` | Destroys unused datasets |
| `axiom key-add` | Modifies trusted key store |
| `axiom key-remove` | Modifies trusted key store |
| `axiom bootstrap-import` | Imports packages to store |

### Commands Safe as Non-Root

These commands can be run as a regular user:

| Command | Notes |
|---------|-------|
| `axiom help` | Read-only |
| `axiom version` | Read-only |
| `axiom list` | Reads store metadata |
| `axiom search` | Reads store metadata |
| `axiom show` | Reads package manifest |
| `axiom profile-show` | Reads profile YAML |
| `axiom resolve --dry-run` | No filesystem writes |
| `axiom verify` | Signature verification |
| `axiom key-generate` | Creates local key (user directory) |

### Commands That Should NEVER Be Run as Root

| Command | Reason |
|---------|--------|
| `axiom shell` (untrusted env) | Could execute malicious binaries |
| `source /axiom/env/*/activate` | Modifies PATH, could run untrusted code |

**Best Practice**: Activate environments in a non-root shell, then use `sudo` for specific privileged operations if needed.

---

## Key Management

### Key Types

1. **Ed25519 Signing Keys** - Used for package signatures
2. **Trust Store Keys** - Public keys trusted for verification

### Key Generation

```bash
# Generate a new signing keypair (as user)
axiom key-generate --output mykey

# This creates:
#   mykey.priv  - Private key (KEEP SECRET)
#   mykey.pub   - Public key (can be shared)
```

### Adding Trusted Keys

```bash
# Add a public key to the trust store (as root)
sudo axiom key-add /path/to/key.pub

# List trusted keys
axiom key list

# Remove a trusted key (as root)
sudo axiom key-remove <key-id>
```

### Key Storage Security

| Key Type | Location | Permissions | Backup |
|----------|----------|-------------|--------|
| Private signing key | Offline/HSM | 600, owner only | Encrypted, offline |
| Public trust store | `/axiom/keys/trusted/` | 644 | With system backup |
| User private keys | `~/.axiom/keys/` | 600 | User responsibility |

### Key Rotation

1. Generate new keypair
2. Sign new packages with new key
3. Add new public key to trust store
4. Announce deprecation of old key
5. After transition period, remove old key from trust store

---

## Secure Operations

### Package Import Security

When importing packages, Axiom performs:

1. **Path Validation** - Rejects paths containing:
   - `..` (directory traversal)
   - Absolute paths (would overwrite system files)
   - Null bytes
   - Symlinks pointing outside package

2. **Signature Verification** (if signed):
   - Verifies Ed25519 signature over manifest
   - Checks content hash matches signed hash
   - Rejects packages with invalid/missing signatures (when required)

3. **Atomic Operations**:
   - Uses ZFS transactions where possible
   - Writes to temporary location, then renames
   - Rollback on failure

### Resolver Security

The resolver is designed to handle untrusted manifests safely:

**Protected Against:**
- Exponential blowup (resource limits)
- Infinite loops (cycle detection)
- Memory exhaustion (memory limits)
- CPU exhaustion (time limits)

**Resource Limit Presets:**

```bash
# Default limits (balanced)
axiom resolve myprofile

# Strict limits for untrusted manifests
axiom resolve myprofile --strict

# Custom limits
axiom resolve myprofile --timeout 10000 --max-memory 67108864 --max-depth 50
```

### Binary Cache Security

When fetching from binary caches:

1. **HTTPS Required** - All cache connections use TLS
2. **Signature Verification** - Packages must be signed
3. **Hash Verification** - Content hash verified after download
4. **No Arbitrary Code Execution** - Downloaded content is never executed during fetch

**Configuration:**
```yaml
# /etc/axiom/cache.yaml
caches:
  - url: https://cache.pgsd.org
    priority: 100
    trust: pgsd-release-key
  - url: https://my-private-cache.example.com
    priority: 50
    trust: my-signing-key
```

---

## Resource Limits

### Resolver Limits

| Limit | Default | Strict | Purpose |
|-------|---------|--------|---------|
| `max_resolution_time_ms` | 30,000 | 10,000 | Prevent CPU exhaustion |
| `max_memory_bytes` | 256 MB | 64 MB | Prevent memory exhaustion |
| `max_dependency_depth` | 100 | 50 | Prevent stack overflow |
| `max_candidates_per_package` | 1,000 | 100 | Limit version explosion |
| `max_total_candidates` | 100,000 | 10,000 | Limit total work |
| `max_sat_variables` | 100,000 | 10,000 | Limit SAT complexity |
| `max_sat_clauses` | 1,000,000 | 100,000 | Limit SAT complexity |

### When to Use Strict Limits

Use `--strict` when:
- Resolving profiles from untrusted sources
- Processing manifests from third-party repositories
- Running in automated pipelines with untrusted input
- Operating in resource-constrained environments

### Import Limits

| Limit | Value | Purpose |
|-------|-------|---------|
| Max manifest size | 1 MB | Prevent YAML bomb |
| Max package size | 10 GB | Prevent disk exhaustion |
| Max files per package | 100,000 | Prevent inode exhaustion |
| Max path length | 1024 | Prevent buffer overflow |

---

## Hardening Recommendations

### Production Deployment

1. **Separate Build and Runtime**
   ```
   Build Host          Runtime Host
   ┌──────────┐        ┌──────────┐
   │ ports    │  ZFS   │ packages │
   │ build    │ ────►  │ only     │
   │ signing  │  send  │ verify   │
   └──────────┘        └──────────┘
   ```

2. **Read-Only Store**
   - After populating the store, set `readonly=on`
   - Use ZFS send/receive for updates

3. **Network Isolation**
   - Build hosts should have minimal network access
   - Runtime hosts don't need network for package operations

4. **Audit Logging**
   - Enable ZFS dataset auditing
   - Log all `axiom` commands with `--audit`

### Signing Best Practices

1. **Offline Signing**
   - Keep private keys on air-gapped machine
   - Sign packages, transfer signatures only

2. **Hardware Security Module (HSM)**
   - For high-security deployments, use HSM for signing
   - PKCS#11 integration planned

3. **Multi-Party Signing**
   - Require multiple signatures for critical packages
   - Implement threshold signing (planned)

### ZFS Security

1. **Encryption**
   ```bash
   # Create encrypted store
   zfs create -o encryption=aes-256-gcm \
              -o keyformat=passphrase \
              zroot/axiom
   ```

2. **Snapshot Protection**
   ```bash
   # Prevent snapshot deletion
   zfs hold axiom:production zroot/axiom/store@release
   ```

3. **Quota Limits**
   ```bash
   # Prevent store from filling disk
   zfs set quota=100G zroot/axiom/store
   ```

---

## Reporting Security Issues

If you discover a security vulnerability in Axiom:

1. **Do NOT** open a public issue
2. Email: security@pgsd.org
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We aim to respond within 48 hours and coordinate disclosure responsibly.

---

## Security Changelog

| Date | Version | Change |
|------|---------|--------|
| 2025-01 | 0.1.0 | Initial security model |
| 2025-01 | 0.1.0 | Phase 24: Secure tar extraction |
| 2025-01 | 0.1.0 | Phase 25: Mandatory signature verification |
| 2025-01 | 0.1.0 | Phase 26: ZFS path validation |
| 2025-01 | 0.1.0 | Phase 27: Build sandboxing |
| 2025-01 | 0.1.0 | Phase 28: Secure bundle verification |
| 2025-01 | 0.1.0 | Phase 29: Resource limits |
| 2025-01 | 0.1.0 | Phase 30: Thread-safe operations |

---

**Author**: Vester "Vic" Thacker
**Organization**: Pacific Grove Software Distribution Foundation
**License**: BSD 2-Clause
