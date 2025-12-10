# Axiom Technical Decisions Log

This document captures technical decisions, solved problems, and their rationale to prevent regression and maintain institutional knowledge.

---

## Bootstrap Order

**Decision**: The bootstrap order for building from FreeBSD ports is:
1. `misc/help2man` - Man page generator
2. `devel/m4` - Macro processor
3. `devel/gmake` - GNU make

**Rationale**:
- `m4` requires `help2man` during its build process to generate man pages
- `gmake` is required by most GNU software
- These packages have minimal dependencies and can build with system tools

**Date**: 2025-12-10

---

## ZFS Dataset Ordering

**Decision**: When creating Axiom ZFS datasets, the mountpoint MUST be set on the parent dataset BEFORE creating child datasets.

**Rationale**: Child datasets inherit their mountpoint from the parent. If you create children first, they get the wrong mountpoint (e.g., `/zroot/axiom/store` instead of `/axiom/store`).

**Correct order**:
```bash
zfs create zroot/axiom
zfs set mountpoint=/axiom zroot/axiom  # BEFORE creating children!
zfs create zroot/axiom/store
zfs create zroot/axiom/store/pkg
# ... etc
```

**Date**: 2025-12-10

---

## Perl Module Discovery (PERL5LIB)

**Problem**: When building ports that depend on Perl modules (like `help2man` needing `Locale::gettext`), the configure script can't find the modules even though they're in the Axiom store.

**Root Cause**: FreeBSD Perl modules install to multiple nested directory patterns:
- `lib/perl5/site_perl/` - base directory
- `lib/perl5/site_perl/<version>/` - version-specific (e.g., 5.42)
- `lib/perl5/site_perl/<version>/<arch>/` - architecture-specific (e.g., amd64-freebsd)
- `lib/perl5/site_perl/mach/` - architecture directory (NOT just a symlink!)
- `lib/perl5/site_perl/mach/<version>/` - **CRITICAL: p5-Locale-gettext uses this pattern!**
- `lib/perl5/<version>/` - core Perl modules

**Actual p5-Locale-gettext structure discovered**:
```
lib/perl5/site_perl/mach/5.42/Locale/gettext.pm
lib/perl5/site_perl/mach/5.42/auto/Locale/gettext/gettext.so
```

**Solution**: The `buildPerl5Lib()` function in `ports.zig` must scan recursively:
1. `site_perl` itself
2. All subdirectories under `site_perl` (mach, version dirs, etc.)
3. **All subdirectories within those** (e.g., `site_perl/mach/5.42/`)
4. `perl5/<version>` directories
5. Corresponding `site_perl/<version>` when `perl5/<version>` exists

**Key insight**: The code was only scanning inside VERSION directories (starting with digit) for arch subdirs. It was NOT scanning inside ARCH directories (like `mach`) for version subdirs. The fix is to scan ALL subdirectories recursively, not just specific patterns.

**Important**: Must include symlinks (`.sym_link` kind) not just directories.

**Environment variables needed**:
- `PERL5LIB` - Perl module search path (passed via MAKE_ENV and CONFIGURE_ENV)
- `LD_LIBRARY_PATH` - For loading XS module .so files (they depend on libintl, etc.)

**Current Status**: RESOLVED - Fixed by scanning all subdirectories recursively in buildPerl5Lib().

**Diagnostic commands**:
```bash
# Find .pm files in the package
find /axiom/store/pkg/Locale-gettext -name "*.pm"

# Check sysroot structure
ls -laR /tmp/axiom-sysroot-*/usr/local/lib/perl5/site_perl/

# Test module loading manually
PERL5LIB="<paths>" perl -e "use Locale::gettext; print 'OK\n'"
```

**Date**: 2025-12-10

---

## Build Environment Variables

**Decision**: The following environment variables must be passed to port builds via `MAKE_ENV` and `CONFIGURE_ENV`:

| Variable | Purpose |
|----------|---------|
| `PATH` | Include sysroot bin directory first |
| `LDFLAGS` | Library search paths for linker |
| `CPPFLAGS` | Include paths for preprocessor |
| `PERL5LIB` | Perl module search paths |
| `PYTHONPATH` | Python module search paths |
| `LD_LIBRARY_PATH` | Runtime library loading (needed for XS modules) |
| `CMAKE_PREFIX_PATH` | CMake package discovery |
| `GMAKE` | Path to GNU make (override for ports framework) |

**Rationale**: FreeBSD ports use these to find dependencies. Without them, builds either fail or use system packages instead of Axiom store packages.

**Date**: 2025-12-10

---

## Package Name Mapping

**Decision**: Port origins must be mapped to Axiom package names because FreeBSD ports use different naming conventions.

**Examples**:
- `devel/gmake` → `make` (Axiom package name, NOT the binary name)
- `lang/perl5.42` → `perl`
- `devel/p5-Locale-gettext` → `Locale-gettext`

**Important distinction**: This maps the **package name** in the Axiom store, NOT the binary name. For example, the `devel/gmake` port is stored as package "make" in Axiom, but the binary it installs is still called `gmake`.

**Implementation**: `mapPortNameAlloc()` function in `ports.zig`

**Date**: 2025-12-10

---

## Binary Aliases

**Problem**: On FreeBSD, GNU tools are installed with 'g' prefix (gmake, gsed, gtar) because BSD has its own make/sed/tar. Some build scripts expect the unprefixed names.

**Solution**: The `createBinaryAliases()` function creates symlinks in the sysroot from unprefixed to prefixed names:
- `make` → `gmake` (scripts expecting 'make' will find gmake)
- `sed` → `gsed`
- `tar` → `gtar`

**Important**: On FreeBSD:
- `devel/gmake` installs binary as `gmake` (NOT `make`)
- BSD make is the system `make`
- We create alias so scripts expecting `make` find GNU make

**Date**: 2025-12-10 (corrected)

---

## GMAKE Variable Override

**Problem**: FreeBSD ports framework uses the `GMAKE` variable which defaults to `/usr/local/bin/gmake`. When building ports in the Axiom sysroot, gmake isn't in `/usr/local/bin` - it's in the sysroot's bin directory.

**Root Cause**: Even though we set PATH to include the sysroot, the ports framework uses `GMAKE=/usr/local/bin/gmake` as a hardcoded path.

**Error message**: `env: /usr/local/bin/gmake: No such file or directory`

**Solution**:
1. Added `gmake_path` field to `BuildEnvironment` struct
2. Check if gmake exists in sysroot bin directory
3. Pass `GMAKE={sysroot}/bin/gmake` as a make variable override in MAKE_ENV
4. Fall back to `/usr/local/bin/gmake` when gmake isn't in sysroot

**Implementation**:
- `BuildEnvironment.gmake_path` - stores path to gmake
- `getBuildEnvironment()` - detects gmake in sysroot
- `runMakeTargetNoDeps()` - passes `GMAKE=...` to make

**Status**: RESOLVED

**Date**: 2025-12-10

---

## Adding New Decisions

When solving a problem or making a technical decision, add an entry here with:
1. **Decision**: What was decided
2. **Rationale**: Why this decision was made
3. **Implementation details**: Code locations, functions involved
4. **Date**: When the decision was made
5. **Status**: Resolved/Unresolved/Partial

This prevents re-solving the same problems and losing working solutions.
