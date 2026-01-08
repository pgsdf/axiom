# Axiom Manifest Format Specification

## Overview

Axiom uses three YAML files to describe packages:

1. **manifest.yaml** - Package metadata
2. **deps.yaml** - Dependency specifications
3. **provenance.yaml** - Build provenance and reproducibility

## manifest.yaml

Package metadata and identification.

### Required Fields

```yaml
name: package-name         # Package identifier (alphanumeric, -, _, +)
version: 1.2.3            # Semantic version (major.minor.patch)
revision: 1               # Package revision number
```

### Optional Fields

```yaml
description: Short description of the package
license: SPDX-License-Identifier  # e.g., GPL-3.0, MIT, BSD-2-Clause
homepage: https://example.com
maintainer: Name <email@example.com>
tags:
  - category1
  - category2
```

### Package Outputs

Packages can define multiple outputs for selective installation:

```yaml
outputs:
  bin:
    description: "Runtime binaries"
    paths:
      - "bin/"
    default: true

  lib:
    description: "Runtime libraries"
    paths:
      - "lib/"
      - "lib64/"
    default: true

  dev:
    description: "Development headers and static libs"
    paths:
      - "include/"
      - "lib/*.a"
      - "lib/pkgconfig/"
    requires:
      - lib
    default: false

  doc:
    description: "Documentation"
    paths:
      - "share/doc/"
      - "share/man/"
    default: false

default_outputs:
  - bin
  - lib
```

**Output fields:**
- `description` - Human-readable description
- `paths` - File patterns included in this output
- `requires` - Other outputs this output depends on
- `default` - Whether to install by default (if true)

**Usage:**
```bash
# Install only bin and lib outputs (skip dev/doc)
axiom realize prod-env profile --outputs bin,lib

# Install everything including dev headers
axiom realize dev-env profile --outputs bin,lib,dev
```

### Example

```yaml
name: bash
version: 5.2.0
revision: 1
description: GNU Bourne Again Shell
license: GPL-3.0-or-later
homepage: https://www.gnu.org/software/bash/
maintainer: Vester Thacker <vic@pgsdf.org>
tags:
  - shell
  - terminal
  - posix
```

### Validation Rules

- **name**: Must be non-empty, contain only alphanumeric characters, hyphens, underscores, or plus signs
- **version**: Must be valid semantic version (major.minor.patch)
- **revision**: Must be positive integer
- **license**: Should use SPDX identifiers when possible

## deps.yaml

Dependency specifications with version constraints.

### Format

```yaml
dependencies:
  - name: package-name
    version: constraint-expression
    constraint: constraint-type
```

### Constraint Types

#### Any Version (`constraint: any`)

```yaml
- name: libc
  version: "*"
  constraint: any
```

Accepts any version of the package.

#### Exact Version (`constraint: exact`)

```yaml
- name: python
  version: "3.11.0"
  constraint: exact
```

Requires exactly version 3.11.0.

#### Tilde Constraint (`constraint: tilde`)

```yaml
- name: ncurses
  version: "~6.4"
  constraint: tilde
```

Accepts `>=6.4.0` and `<6.5.0`. Compatible within minor version.

**Semantics**: `~X.Y.Z` means `>=X.Y.Z` and `<X.(Y+1).0`

#### Caret Constraint (`constraint: caret`)

```yaml
- name: openssl
  version: "^1.1.0"
  constraint: caret
```

Accepts `>=1.1.0` and `<2.0.0`. Compatible within major version.

**Semantics**: `^X.Y.Z` means `>=X.Y.Z` and `<(X+1).0.0`

#### Range Constraint (`constraint: range`)

```yaml
- name: readline
  version: ">=8.0.0,<9.0.0"
  constraint: range
```

Accepts versions between 8.0.0 (inclusive) and 9.0.0 (exclusive).

**Operators**:
- `>=` - Greater than or equal
- `>` - Greater than
- `<=` - Less than or equal
- `<` - Less than

Multiple constraints separated by commas (AND logic).

### Example

```yaml
dependencies:
  - name: readline
    version: ">=8.0.0"
    constraint: range
  - name: ncurses
    version: "~6.4"
    constraint: tilde
  - name: libc
    version: "*"
    constraint: any
```

## provenance.yaml

Build provenance for reproducibility and verification.

### Required Fields

```yaml
build_time: 1701388800      # Unix timestamp
builder: hostname           # Build machine identifier
```

### Optional Fields

```yaml
build_user: username              # User who performed build
source_url: https://...           # Source code URL
source_hash: sha256:abc123...     # Source archive hash
compiler: gcc                     # Compiler used
compiler_version: 13.2.0          # Compiler version
build_flags:                      # Compiler flags
  - -O2
  - -march=native
environment:                      # Build environment variables
  CC: gcc
  CFLAGS: "-O2"
```

### Example

```yaml
build_time: 1701388800
builder: build-host-01.pgsdf.org
build_user: axiom-builder
source_url: https://ftp.gnu.org/gnu/bash/bash-5.2.tar.gz
source_hash: sha256:a139c166df7ff4471c5e0733051642ee5556c1cc8a4a78f145583c5c81ab32fb
compiler: clang
compiler_version: 16.0.6
build_flags:
  - -O2
  - -march=x86-64
  - -fstack-protector-strong
environment:
  CC: clang
  CFLAGS: "-O2 -march=x86-64"
  PREFIX: /usr/local
```

### Use Cases

**Reproducibility**: Provides enough information to recreate the build environment and verify bit-for-bit reproducibility.

**Security**: Source hash enables verification that the package was built from expected sources.

**Debugging**: Build flags and environment help diagnose platform-specific issues.

**Audit**: Build time and builder provide accountability trail.

## Version Constraint Semantics

### Exact Match

```
version: "1.2.3"
constraint: exact
```

Matches: `1.2.3`  
Does not match: `1.2.4`, `1.3.0`, `2.0.0`

### Tilde (~)

```
version: "~1.2.3"
constraint: tilde
```

Matches: `1.2.3`, `1.2.4`, `1.2.999`  
Does not match: `1.3.0`, `1.1.9`, `2.0.0`

Allows patch-level changes only.

### Caret (^)

```
version: "^1.2.3"
constraint: caret
```

Matches: `1.2.3`, `1.3.0`, `1.999.999`  
Does not match: `2.0.0`, `1.2.2`, `0.9.0`

Allows backwards-compatible changes (SemVer semantics).

### Range

```
version: ">=1.0.0,<2.0.0"
constraint: range
```

Matches: `1.0.0`, `1.5.2`, `1.999.999`  
Does not match: `0.9.9`, `2.0.0`, `2.1.0`

Explicit min/max bounds.

### Wildcard (*)

```
version: "*"
constraint: any
```

Matches: Any version

Use sparingly - makes builds less reproducible.

## File Locations

In a package dataset:

```
zroot/axiom/store/pkg/bash/5.2.0/1/abc123/
├── manifest.yaml       # Package metadata
├── deps.yaml           # Dependencies
├── provenance.yaml     # Build provenance
└── root/               # Package files
    ├── bin/
    │   └── bash
    └── ...
```

## Best Practices

### manifest.yaml

- Use descriptive, concise names (lowercase, hyphens for separators)
- Include meaningful descriptions
- Always specify license (use SPDX identifiers)
- Add homepage for user reference
- Tag appropriately for discoverability

### deps.yaml

- Prefer tilde (~) for libraries (compatible patches)
- Prefer caret (^) for tools (compatible features)
- Use range for specific compatibility windows
- Avoid wildcard (*) except for base system packages
- Document why specific constraints are needed (comments)

### provenance.yaml

- Always include source hash for verification
- Record full compiler version, not just major
- Include all non-default build flags
- Document the build environment completely
- Use standardized builder names

## Validation

Axiom validates manifests on package import:

1. **Schema validation**: All required fields present
2. **Name validation**: Valid package name format
3. **Version validation**: Valid semantic version
4. **Dependency validation**: All dependencies have valid constraints
5. **Hash validation**: Source hashes match expected format

Invalid manifests are rejected during `axiom import`.

## Future Extensions

Planned additions to manifest format:

- **conflicts**: Packages that conflict with this one
- **provides**: Virtual packages this package provides
- **replaces**: Packages this one obsoletes
- **architecture**: Target architecture constraints
- **signatures**: Cryptographic signatures for verification

---

**Author**: Vester "Vic" Thacker  
**Organization**: Pacific Grove Software Distribution Foundation  
**License**: BSD 2-Clause
