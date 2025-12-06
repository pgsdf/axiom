// ports.zig - FreeBSD Ports Migration Tool
//
// Converts FreeBSD ports metadata into Axiom package manifests,
// enabling rapid ecosystem bootstrapping from the existing ports tree.
//
// Phase 1: Metadata extraction and manifest generation
// Phase 2: Happy-path builds for clean ports
// Phase 3: Options and variants mapping

const std = @import("std");
const manifest_pkg = @import("manifest.zig");
const types = @import("types.zig");
const store_pkg = @import("store.zig");
const build_pkg = @import("build.zig");
const import_pkg = @import("import.zig");
const zfs = @import("zfs.zig");
const bootstrap_pkg = @import("bootstrap.zig");

const ZfsHandle = zfs.ZfsHandle;
const PackageStore = store_pkg.PackageStore;
const Builder = build_pkg.Builder;
const Importer = import_pkg.Importer;
const PackageId = types.PackageId;

pub const PortsError = error{
    PortNotFound,
    MakefileParseError,
    DependencyParseError,
    UnsupportedPortFeature,
    BuildFailed,
    ImportFailed,
    InvalidPortsTree,
    MissingRequiredField,
    OutOfMemory,
    ProcessSpawnError,
};

/// FreeBSD port metadata extracted from Makefile
pub const PortMetadata = struct {
    // Identity
    name: []const u8,
    version: []const u8,
    revision: u32,
    epoch: u32,
    categories: []const []const u8,

    // Descriptive
    comment: []const u8,
    description: []const u8,
    maintainer: []const u8,
    www: []const u8,
    license: []const u8,

    // Source
    master_sites: []const []const u8,
    distfiles: []const []const u8,
    distinfo_sha256: []const u8,

    // Dependencies
    build_depends: []const PortDependency,
    lib_depends: []const PortDependency,
    run_depends: []const PortDependency,
    test_depends: []const PortDependency,

    // Build configuration
    uses: []const []const u8,
    options: []const PortOption,
    flavors: []const []const u8,
    conflicts: []const []const u8,

    // Build hints
    configure_style: ConfigureStyle,
    make_jobs_unsafe: bool,
    no_arch: bool,

    allocator: std.mem.Allocator,

    pub fn deinit(self: *PortMetadata) void {
        self.allocator.free(self.name);
        self.allocator.free(self.version);
        for (self.categories) |cat| self.allocator.free(cat);
        self.allocator.free(self.categories);
        self.allocator.free(self.comment);
        self.allocator.free(self.description);
        self.allocator.free(self.maintainer);
        self.allocator.free(self.www);
        self.allocator.free(self.license);
        for (self.master_sites) |site| self.allocator.free(site);
        self.allocator.free(self.master_sites);
        for (self.distfiles) |df| self.allocator.free(df);
        self.allocator.free(self.distfiles);
        self.allocator.free(self.distinfo_sha256);
        for (self.build_depends) |dep| dep.deinit(self.allocator);
        self.allocator.free(self.build_depends);
        for (self.lib_depends) |dep| dep.deinit(self.allocator);
        self.allocator.free(self.lib_depends);
        for (self.run_depends) |dep| dep.deinit(self.allocator);
        self.allocator.free(self.run_depends);
        for (self.test_depends) |dep| dep.deinit(self.allocator);
        self.allocator.free(self.test_depends);
        for (self.uses) |u| self.allocator.free(u);
        self.allocator.free(self.uses);
        for (self.options) |opt| opt.deinit(self.allocator);
        self.allocator.free(self.options);
        for (self.flavors) |f| self.allocator.free(f);
        self.allocator.free(self.flavors);
        for (self.conflicts) |c| self.allocator.free(c);
        self.allocator.free(self.conflicts);
    }
};

/// Port dependency specification
pub const PortDependency = struct {
    origin: []const u8, // e.g., "devel/gmake"
    package: []const u8, // e.g., "gmake"
    version: ?[]const u8, // Optional version constraint
    file_or_lib: ?[]const u8, // The file/lib that triggers the dep

    pub fn deinit(self: PortDependency, allocator: std.mem.Allocator) void {
        allocator.free(self.origin);
        allocator.free(self.package);
        if (self.version) |v| allocator.free(v);
        if (self.file_or_lib) |f| allocator.free(f);
    }
};

/// Port option (from OPTIONS framework)
pub const PortOption = struct {
    name: []const u8,
    description: []const u8,
    default: bool,
    group: ?[]const u8,

    pub fn deinit(self: PortOption, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.description);
        if (self.group) |g| allocator.free(g);
    }
};

/// Configure style detected from USES
pub const ConfigureStyle = enum {
    none,
    gnu_configure,
    cmake,
    meson,
    cargo,
    go,
    python,
    perl,
    ruby,
    qmake,
    scons,
    waf,
    custom,
};

/// Mapping configuration for port-to-axiom name translation
pub const NameMapping = struct {
    port_origin: []const u8,
    axiom_name: []const u8,
    notes: ?[]const u8,
};

/// Migration options
pub const MigrateOptions = struct {
    ports_tree: []const u8 = "/usr/ports",
    output_dir: []const u8 = "./generated/axiom-ports",
    build_after_generate: bool = false,
    import_after_build: bool = false,
    dry_run: bool = false,
    verbose: bool = false,
    name_mappings: []const NameMapping = &[_]NameMapping{},
    skip_options: bool = false,
    default_options_only: bool = true,

    // Dependency resolution
    auto_deps: bool = true, // Automatically build dependencies first

    // Build system dependencies (required if build_after_generate or import_after_build is true)
    zfs_handle: ?*ZfsHandle = null,
    store: ?*PackageStore = null,
    importer: ?*Importer = null,

    // Build options
    build_jobs: u32 = 4,
    keep_sandbox: bool = false,
};

/// Ports migration tool
pub const PortsMigrator = struct {
    allocator: std.mem.Allocator,
    options: MigrateOptions,

    pub fn init(allocator: std.mem.Allocator, options: MigrateOptions) PortsMigrator {
        return .{
            .allocator = allocator,
            .options = options,
        };
    }

    /// Check if minimal bootstrap packages are available and warn if not
    pub fn checkBootstrapStatus(self: *PortsMigrator) !void {
        var missing_minimal = std.ArrayList([]const u8).init(self.allocator);
        defer missing_minimal.deinit();

        // Check for minimal bootstrap packages
        for (bootstrap_pkg.MINIMAL_BOOTSTRAP_PACKAGES) |pkg_name| {
            const pkg_path = try std.fmt.allocPrint(self.allocator, "/axiom/store/pkg/{s}", .{pkg_name});
            defer self.allocator.free(pkg_path);

            var dir = std.fs.openDirAbsolute(pkg_path, .{}) catch {
                try missing_minimal.append(pkg_name);
                continue;
            };
            dir.close();
        }

        if (missing_minimal.items.len > 0) {
            std.debug.print("\n", .{});
            std.debug.print("╔══════════════════════════════════════════════════════════════╗\n", .{});
            std.debug.print("║                    BOOTSTRAP WARNING                         ║\n", .{});
            std.debug.print("╠══════════════════════════════════════════════════════════════╣\n", .{});
            std.debug.print("║ Some bootstrap packages are missing from the Axiom store.    ║\n", .{});
            std.debug.print("║ Building may fail if these tools are not available.          ║\n", .{});
            std.debug.print("║                                                              ║\n", .{});
            std.debug.print("║ Missing packages:                                            ║\n", .{});
            for (missing_minimal.items) |pkg| {
                std.debug.print("║   - {s:<54} ║\n", .{pkg});
            }
            std.debug.print("║                                                              ║\n", .{});
            std.debug.print("║ To bootstrap without pkg:                                    ║\n", .{});
            std.debug.print("║   axiom bootstrap-import axiom-bootstrap-14.2-amd64.tar.zst  ║\n", .{});
            std.debug.print("║                                                              ║\n", .{});
            std.debug.print("║ Or build the minimal packages first:                         ║\n", .{});
            std.debug.print("║   axiom ports-import devel/gmake                             ║\n", .{});
            std.debug.print("║   axiom ports-import devel/m4                                ║\n", .{});
            std.debug.print("╚══════════════════════════════════════════════════════════════╝\n", .{});
            std.debug.print("\n", .{});
        }
    }

    /// Extract metadata from a port
    pub fn extractMetadata(self: *PortsMigrator, origin: []const u8) !PortMetadata {
        const port_path = try std.fs.path.join(self.allocator, &[_][]const u8{
            self.options.ports_tree,
            origin,
        });
        defer self.allocator.free(port_path);

        // Verify port exists
        std.fs.cwd().access(port_path, .{}) catch {
            return PortsError.PortNotFound;
        };

        // Extract variables using make -V
        var metadata: PortMetadata = undefined;
        metadata.allocator = self.allocator;

        // Core identity
        metadata.name = try self.makeVar(port_path, "PORTNAME");
        metadata.version = try self.makeVar(port_path, "PORTVERSION");

        // Parse revision (free the string after parsing)
        const revision_str = try self.makeVarOptional(port_path, "PORTREVISION");
        if (revision_str) |rev| {
            metadata.revision = std.fmt.parseInt(u32, rev, 10) catch 0;
            self.allocator.free(rev);
        } else {
            metadata.revision = 0;
        }

        // Parse epoch (free the string after parsing)
        const epoch_str = try self.makeVarOptional(port_path, "PORTEPOCH");
        if (epoch_str) |ep| {
            metadata.epoch = std.fmt.parseInt(u32, ep, 10) catch 0;
            self.allocator.free(ep);
        } else {
            metadata.epoch = 0;
        }

        // Categories
        const cats_str = try self.makeVar(port_path, "CATEGORIES");
        metadata.categories = try self.splitWhitespace(cats_str);
        self.allocator.free(cats_str);

        // Descriptive
        metadata.comment = try self.makeVarOptional(port_path, "COMMENT") orelse try self.allocator.dupe(u8, "");
        metadata.description = try self.readPkgDescr(port_path);
        metadata.maintainer = try self.makeVarOptional(port_path, "MAINTAINER") orelse try self.allocator.dupe(u8, "ports@FreeBSD.org");
        metadata.www = try self.makeVarOptional(port_path, "WWW") orelse try self.allocator.dupe(u8, "");
        metadata.license = try self.makeVarOptional(port_path, "LICENSE") orelse try self.allocator.dupe(u8, "");

        // Source
        const sites_str = try self.makeVarOptional(port_path, "MASTER_SITES") orelse try self.allocator.dupe(u8, "");
        metadata.master_sites = try self.splitWhitespace(sites_str);
        self.allocator.free(sites_str);

        const distfiles_str = try self.makeVarOptional(port_path, "DISTFILES") orelse try self.allocator.dupe(u8, "");
        metadata.distfiles = try self.splitWhitespace(distfiles_str);
        self.allocator.free(distfiles_str);

        metadata.distinfo_sha256 = try self.readDistinfoSha256(port_path);

        // Dependencies
        metadata.build_depends = try self.parseDependencies(port_path, "BUILD_DEPENDS");
        metadata.lib_depends = try self.parseDependencies(port_path, "LIB_DEPENDS");
        metadata.run_depends = try self.parseDependencies(port_path, "RUN_DEPENDS");
        metadata.test_depends = try self.parseDependencies(port_path, "TEST_DEPENDS");

        // Build configuration
        const uses_str = try self.makeVarOptional(port_path, "USES") orelse try self.allocator.dupe(u8, "");
        metadata.uses = try self.splitWhitespace(uses_str);
        self.allocator.free(uses_str);

        metadata.options = try self.parseOptions(port_path);

        const flavors_str = try self.makeVarOptional(port_path, "FLAVORS") orelse try self.allocator.dupe(u8, "");
        metadata.flavors = try self.splitWhitespace(flavors_str);
        self.allocator.free(flavors_str);

        const conflicts_str = try self.makeVarOptional(port_path, "CONFLICTS") orelse try self.allocator.dupe(u8, "");
        metadata.conflicts = try self.splitWhitespace(conflicts_str);
        self.allocator.free(conflicts_str);

        // Detect configure style
        metadata.configure_style = self.detectConfigureStyle(metadata.uses);
        metadata.make_jobs_unsafe = try self.hasMakeVar(port_path, "MAKE_JOBS_UNSAFE");
        metadata.no_arch = try self.hasMakeVar(port_path, "NO_ARCH");

        return metadata;
    }

    /// Generate Axiom manifest from port metadata
    pub fn generateManifest(self: *PortsMigrator, meta: *const PortMetadata) !manifest_pkg.Manifest {
        var manifest: manifest_pkg.Manifest = undefined;

        manifest.name = try self.allocator.dupe(u8, self.mapPortName(meta.name));
        manifest.version = try types.Version.parse(meta.version);
        manifest.revision = meta.revision;
        manifest.description = try self.allocator.dupe(u8, meta.comment);
        manifest.license = try self.allocator.dupe(u8, meta.license);
        manifest.homepage = try self.allocator.dupe(u8, meta.www);

        // Map provides (the port provides itself as a virtual package)
        var provides = std.ArrayList([]const u8).init(self.allocator);
        try provides.append(try self.allocator.dupe(u8, meta.name));
        manifest.provides = try provides.toOwnedSlice();

        // Map conflicts
        var conflicts = std.ArrayList([]const u8).init(self.allocator);
        for (meta.conflicts) |c| {
            try conflicts.append(try self.allocator.dupe(u8, c));
        }
        manifest.conflicts = try conflicts.toOwnedSlice();

        manifest.replaces = &[_][]const u8{};

        return manifest;
    }

    /// Generate deps.yaml content from port metadata
    pub fn generateDepsYaml(self: *PortsMigrator, meta: *const PortMetadata) ![]const u8 {
        var output = std.ArrayList(u8).init(self.allocator);
        const writer = output.writer();

        try writer.writeAll("# Generated from FreeBSD port: ");
        try writer.writeAll(meta.name);
        try writer.writeAll("\n# Original categories: ");
        for (meta.categories, 0..) |cat, i| {
            if (i > 0) try writer.writeAll(", ");
            try writer.writeAll(cat);
        }
        try writer.writeAll("\n\n");

        // Build dependencies
        if (meta.build_depends.len > 0) {
            try writer.writeAll("build:\n");
            for (meta.build_depends) |dep| {
                try writer.writeAll("  - name: ");
                try writer.writeAll(self.mapPortName(dep.package));
                try writer.writeAll("\n");
                if (dep.version) |v| {
                    try writer.writeAll("    constraint: \"");
                    try writer.writeAll(v);
                    try writer.writeAll("\"\n");
                }
                try writer.writeAll("    # origin: ");
                try writer.writeAll(dep.origin);
                try writer.writeAll("\n");
            }
            try writer.writeAll("\n");
        }

        // Runtime dependencies (lib + run)
        const has_runtime = meta.lib_depends.len > 0 or meta.run_depends.len > 0;
        if (has_runtime) {
            try writer.writeAll("runtime:\n");
            for (meta.lib_depends) |dep| {
                try writer.writeAll("  - name: ");
                try writer.writeAll(self.mapPortName(dep.package));
                try writer.writeAll("\n");
                if (dep.file_or_lib) |lib| {
                    try writer.writeAll("    # lib: ");
                    try writer.writeAll(lib);
                    try writer.writeAll("\n");
                }
                try writer.writeAll("    # origin: ");
                try writer.writeAll(dep.origin);
                try writer.writeAll("\n");
            }
            for (meta.run_depends) |dep| {
                try writer.writeAll("  - name: ");
                try writer.writeAll(self.mapPortName(dep.package));
                try writer.writeAll("\n");
                try writer.writeAll("    # origin: ");
                try writer.writeAll(dep.origin);
                try writer.writeAll("\n");
            }
        }

        return output.toOwnedSlice();
    }

    /// Generate build.yaml recipe from port metadata
    pub fn generateBuildYaml(self: *PortsMigrator, meta: *const PortMetadata) ![]const u8 {
        var output = std.ArrayList(u8).init(self.allocator);
        const writer = output.writer();

        try writer.writeAll("# Generated from FreeBSD port\n");
        try writer.writeAll("# Manual review recommended before building\n\n");

        try writer.writeAll("name: ");
        try writer.writeAll(self.mapPortName(meta.name));
        try writer.writeAll("\n");

        try writer.writeAll("version: \"");
        try writer.writeAll(meta.version);
        try writer.writeAll("\"\n");

        try writer.writeAll("description: ");
        try writer.writeAll(meta.comment);
        try writer.writeAll("\n\n");

        // Source
        try writer.writeAll("source:\n");
        if (meta.master_sites.len > 0 and meta.distfiles.len > 0) {
            try writer.writeAll("  url: ");
            try writer.writeAll(meta.master_sites[0]);
            try writer.writeAll(meta.distfiles[0]);
            try writer.writeAll("\n");
        } else {
            try writer.writeAll("  url: # FIXME: determine source URL\n");
        }
        if (meta.distinfo_sha256.len > 0) {
            try writer.writeAll("  sha256: ");
            try writer.writeAll(meta.distinfo_sha256);
            try writer.writeAll("\n");
        }
        try writer.writeAll("\n");

        // USES hints
        if (meta.uses.len > 0) {
            try writer.writeAll("# FreeBSD USES: ");
            for (meta.uses, 0..) |u, i| {
                if (i > 0) try writer.writeAll(" ");
                try writer.writeAll(u);
            }
            try writer.writeAll("\n\n");
        }

        // Build phases based on configure style
        try writer.writeAll("phases:\n");

        switch (meta.configure_style) {
            .gnu_configure => {
                try writer.writeAll("  configure: |\n");
                try writer.writeAll("    ./configure --prefix=$PREFIX\n");
                try writer.writeAll("  build: |\n");
                if (meta.make_jobs_unsafe) {
                    try writer.writeAll("    make\n");
                } else {
                    try writer.writeAll("    make -j$JOBS\n");
                }
                try writer.writeAll("  install: |\n");
                try writer.writeAll("    make install DESTDIR=$DESTDIR\n");
            },
            .cmake => {
                try writer.writeAll("  configure: |\n");
                try writer.writeAll("    cmake -B build -DCMAKE_INSTALL_PREFIX=$PREFIX\n");
                try writer.writeAll("  build: |\n");
                try writer.writeAll("    cmake --build build -j$JOBS\n");
                try writer.writeAll("  install: |\n");
                try writer.writeAll("    DESTDIR=$DESTDIR cmake --install build\n");
            },
            .meson => {
                try writer.writeAll("  configure: |\n");
                try writer.writeAll("    meson setup build --prefix=$PREFIX\n");
                try writer.writeAll("  build: |\n");
                try writer.writeAll("    meson compile -C build\n");
                try writer.writeAll("  install: |\n");
                try writer.writeAll("    DESTDIR=$DESTDIR meson install -C build\n");
            },
            .cargo => {
                try writer.writeAll("  build: |\n");
                try writer.writeAll("    cargo build --release\n");
                try writer.writeAll("  install: |\n");
                try writer.writeAll("    install -d $DESTDIR$PREFIX/bin\n");
                try writer.writeAll("    install -m 755 target/release/* $DESTDIR$PREFIX/bin/\n");
            },
            .go => {
                try writer.writeAll("  build: |\n");
                try writer.writeAll("    go build -o build/\n");
                try writer.writeAll("  install: |\n");
                try writer.writeAll("    install -d $DESTDIR$PREFIX/bin\n");
                try writer.writeAll("    install -m 755 build/* $DESTDIR$PREFIX/bin/\n");
            },
            .python => {
                try writer.writeAll("  build: |\n");
                try writer.writeAll("    python setup.py build\n");
                try writer.writeAll("  install: |\n");
                try writer.writeAll("    python setup.py install --prefix=$PREFIX --root=$DESTDIR\n");
            },
            else => {
                try writer.writeAll("  # FIXME: determine build steps from USES\n");
                try writer.writeAll("  configure: |\n");
                try writer.writeAll("    # Configure step\n");
                try writer.writeAll("  build: |\n");
                if (meta.make_jobs_unsafe) {
                    try writer.writeAll("    make\n");
                } else {
                    try writer.writeAll("    make -j$JOBS\n");
                }
                try writer.writeAll("  install: |\n");
                try writer.writeAll("    make install DESTDIR=$DESTDIR\n");
            },
        }

        try writer.writeAll("\npost_process:\n");
        try writer.writeAll("  strip: true\n");
        try writer.writeAll("  compress_man: true\n");

        return output.toOwnedSlice();
    }

    /// Write generated files to output directory
    pub fn writeGeneratedFiles(
        self: *PortsMigrator,
        origin: []const u8,
        manifest_yaml: []const u8,
        deps_yaml: []const u8,
        build_yaml: []const u8,
    ) !void {
        // Create output directory: output_dir/category/portname/
        const out_path = try std.fs.path.join(self.allocator, &[_][]const u8{
            self.options.output_dir,
            origin,
        });
        defer self.allocator.free(out_path);

        // Create parent directories
        const parent = std.fs.path.dirname(out_path) orelse ".";
        std.fs.cwd().makePath(parent) catch {};
        std.fs.cwd().makePath(out_path) catch {};

        // Write manifest.yaml
        const manifest_path = try std.fs.path.join(self.allocator, &[_][]const u8{
            out_path,
            "manifest.yaml",
        });
        defer self.allocator.free(manifest_path);

        const manifest_file = try std.fs.cwd().createFile(manifest_path, .{});
        defer manifest_file.close();
        try manifest_file.writeAll(manifest_yaml);

        // Write deps.yaml
        const deps_path = try std.fs.path.join(self.allocator, &[_][]const u8{
            out_path,
            "deps.yaml",
        });
        defer self.allocator.free(deps_path);

        const deps_file = try std.fs.cwd().createFile(deps_path, .{});
        defer deps_file.close();
        try deps_file.writeAll(deps_yaml);

        // Write build.yaml
        const build_path = try std.fs.path.join(self.allocator, &[_][]const u8{
            out_path,
            "build.yaml",
        });
        defer self.allocator.free(build_path);

        const build_file = try std.fs.cwd().createFile(build_path, .{});
        defer build_file.close();
        try build_file.writeAll(build_yaml);
    }

    /// Full migration: extract, generate, optionally build and import
    pub fn migrate(self: *PortsMigrator, origin: []const u8) !MigrationResult {
        var result: MigrationResult = .{
            .origin = origin,
            .status = .pending,
            .manifest_path = null,
            .axiom_package = null,
            .warnings = std.ArrayList([]const u8).init(self.allocator),
            .errors = std.ArrayList([]const u8).init(self.allocator),
        };

        // Phase 1: Extract metadata
        var metadata = self.extractMetadata(origin) catch |err| {
            result.status = .failed;
            try result.errors.append(try std.fmt.allocPrint(
                self.allocator,
                "Failed to extract metadata: {s}",
                .{@errorName(err)},
            ));
            return result;
        };
        defer metadata.deinit();

        // Check if package already exists in store (skip only if same origin)
        if (self.options.store) |store| {
            const pkg_name = self.mapPortName(origin);
            const exists = store.packageNameExists(pkg_name) catch false;
            if (exists) {
                // Check if the existing package has the same origin
                const existing_origin = store.getPackageOriginByName(pkg_name) catch null;
                defer if (existing_origin) |o| self.allocator.free(o);

                const should_skip = if (existing_origin) |existing|
                    std.mem.eql(u8, existing, origin)
                else
                    // No origin recorded - legacy package built before origin tracking
                    // Proceed with build to replace it with properly tracked package
                    false;

                if (should_skip) {
                    std.debug.print("  ✓ Package '{s}' already in store (same origin: {s}), skipping\n", .{ pkg_name, origin });
                    result.status = .skipped;
                    result.axiom_package = try std.fmt.allocPrint(
                        self.allocator,
                        "{s} (existing)",
                        .{pkg_name},
                    );
                    return result;
                } else if (existing_origin) |existing| {
                    // Different origin - warn and proceed
                    std.debug.print("  ⚠ Package '{s}' exists from different origin ({s}), building from {s}\n", .{
                        pkg_name,
                        existing,
                        origin,
                    });
                } else {
                    // Legacy package with no origin - will be replaced
                    std.debug.print("  ⚠ Package '{s}' exists (no origin recorded), rebuilding from {s}\n", .{
                        pkg_name,
                        origin,
                    });
                }
            }
        }

        // Check for unsupported features
        if (metadata.flavors.len > 0 and !self.options.skip_options) {
            try result.warnings.append(try self.allocator.dupe(u8, "Port has FLAVORS - only default flavor generated"));
        }
        if (metadata.options.len > 0 and !self.options.skip_options) {
            try result.warnings.append(try std.fmt.allocPrint(
                self.allocator,
                "Port has {d} OPTIONS - only default options used",
                .{metadata.options.len},
            ));
        }

        // Generate YAML files
        const manifest_yaml = try self.generateManifestYaml(&metadata, origin);
        defer self.allocator.free(manifest_yaml);

        const deps_yaml = try self.generateDepsYaml(&metadata);
        defer self.allocator.free(deps_yaml);

        const build_yaml = try self.generateBuildYaml(&metadata);
        defer self.allocator.free(build_yaml);

        // Write files
        if (!self.options.dry_run) {
            try self.writeGeneratedFiles(origin, manifest_yaml, deps_yaml, build_yaml);

            const out_path = try std.fs.path.join(self.allocator, &[_][]const u8{
                self.options.output_dir,
                origin,
            });
            result.manifest_path = out_path;
        }

        result.status = .generated;

        // Phase 2: Build (optional)
        if (self.options.build_after_generate and !self.options.dry_run) {
            const build_result = self.buildPort(origin, &metadata, result.manifest_path) catch |err| {
                try result.errors.append(try std.fmt.allocPrint(
                    self.allocator,
                    "Build failed: {s}",
                    .{@errorName(err)},
                ));
                result.status = .failed;
                return result;
            };

            result.status = .built;

            // Phase 3: Import (optional)
            if (self.options.import_after_build) {
                const pkg_id = self.importPort(&metadata, build_result.output_dir) catch |err| {
                    try result.errors.append(try std.fmt.allocPrint(
                        self.allocator,
                        "Import failed: {s}",
                        .{@errorName(err)},
                    ));
                    result.status = .failed;
                    // Clean up build output before returning
                    if (!self.options.keep_sandbox) {
                        std.fs.cwd().deleteTree(build_result.output_dir) catch {};
                    }
                    self.allocator.free(build_result.output_dir);
                    return result;
                };

                result.status = .imported;
                result.axiom_package = try std.fmt.allocPrint(
                    self.allocator,
                    "{s}@{}.{}.{}-r{d}",
                    .{ pkg_id.name, pkg_id.version.major, pkg_id.version.minor, pkg_id.version.patch, pkg_id.revision },
                );
            }

            // Clean up build output if we're not keeping the sandbox
            if (!self.options.keep_sandbox) {
                std.fs.cwd().deleteTree(build_result.output_dir) catch {};
            }
            self.allocator.free(build_result.output_dir);
        }

        return result;
    }

    /// Build result from port build
    const PortBuildResult = struct {
        output_dir: []const u8,
        success: bool,
    };

    /// Build environment with sysroot containing symlinked dependencies
    /// The sysroot approach merges all dependency packages into a single directory tree,
    /// allowing wrapper scripts (like autoconf-switch) to find related binaries.
    const BuildEnvironment = struct {
        /// Path to the sysroot directory (e.g., /tmp/axiom-sysroot-XXXX/usr/local)
        /// All dependency binaries, libraries, headers are symlinked here
        sysroot: []const u8,
        /// PATH with sysroot bin/ first, then system paths
        path: []const u8,
        /// LD_LIBRARY_PATH with sysroot lib/ first
        ld_library_path: []const u8,
        /// LDFLAGS pointing to sysroot lib/
        ldflags: []const u8,
        /// CPPFLAGS pointing to sysroot include/
        cppflags: []const u8,
        allocator: std.mem.Allocator,

        pub fn deinit(self: *BuildEnvironment) void {
            // Clean up the sysroot directory
            if (self.sysroot.len > 0) {
                // Get parent of sysroot (the temp directory)
                if (std.fs.path.dirname(self.sysroot)) |sysroot_parent| {
                    if (std.fs.path.dirname(sysroot_parent)) |temp_dir| {
                        std.fs.cwd().deleteTree(temp_dir) catch {};
                    }
                }
            }
            self.allocator.free(self.sysroot);
            self.allocator.free(self.path);
            self.allocator.free(self.ld_library_path);
            self.allocator.free(self.ldflags);
            self.allocator.free(self.cppflags);
        }
    };

    /// Create a sysroot directory with symlinks to all dependency package files
    /// This merges all packages into a single directory tree, solving the problem where
    /// wrapper scripts (like autoconf-switch) need to find related binaries in the same directory.
    ///
    /// Structure created:
    ///   /tmp/axiom-sysroot-XXXX/usr/local/
    ///     ├── bin/      (symlinks to all dependency bin files)
    ///     ├── lib/      (symlinks to all dependency lib files)
    ///     ├── include/  (symlinks to all dependency include files)
    ///     ├── share/    (symlinks to all dependency share files)
    ///     └── libexec/  (symlinks to all dependency libexec files)
    fn createBuildSysroot(self: *PortsMigrator, package_roots: []const []const u8) ![]const u8 {
        // Generate unique sysroot path
        const timestamp = std.time.timestamp();
        var random_bytes: [4]u8 = undefined;
        std.crypto.random.bytes(&random_bytes);

        const sysroot_base = try std.fmt.allocPrint(
            self.allocator,
            "/tmp/axiom-sysroot-{d}-{x:0>2}{x:0>2}{x:0>2}{x:0>2}",
            .{ timestamp, random_bytes[0], random_bytes[1], random_bytes[2], random_bytes[3] },
        );
        defer self.allocator.free(sysroot_base);

        // Create sysroot/usr/local structure (FreeBSD standard layout)
        const sysroot = try std.fs.path.join(self.allocator, &[_][]const u8{
            sysroot_base,
            "usr/local",
        });
        errdefer self.allocator.free(sysroot);

        // Create all required directories
        const subdirs = [_][]const u8{ "bin", "lib", "include", "share", "libexec", "lib/perl5", "share/aclocal" };
        for (subdirs) |subdir| {
            const full_path = try std.fs.path.join(self.allocator, &[_][]const u8{ sysroot, subdir });
            defer self.allocator.free(full_path);
            try std.fs.cwd().makePath(full_path);
        }

        std.debug.print("    [SYSROOT] Creating sysroot at: {s}\n", .{sysroot});

        // Symlink files from each package root into the sysroot
        for (package_roots) |root| {
            std.debug.print("    [SYSROOT]   Linking from: {s}\n", .{root});

            // Try both direct layout (bin/, lib/) and FreeBSD layout (usr/local/bin/, usr/local/lib/)
            const layouts = [_][]const u8{ "", "usr/local" };
            for (layouts) |prefix| {
                const source_base = if (prefix.len > 0)
                    try std.fs.path.join(self.allocator, &[_][]const u8{ root, prefix })
                else
                    try self.allocator.dupe(u8, root);
                defer self.allocator.free(source_base);

                // Link each standard directory
                // bin/ and libexec/ are COPIED (not symlinked) so that $0 in scripts
                // points to the sysroot path, allowing wrapper scripts to find siblings
                // lib/, include/, share/ are symlinked since they don't have the $0 issue
                const dirs_to_copy = [_][]const u8{ "bin", "libexec" };
                for (dirs_to_copy) |dir| {
                    try self.symlinkOrCopyDirectoryContents(source_base, sysroot, dir, true);
                }
                const dirs_to_link = [_][]const u8{ "lib", "include", "share" };
                for (dirs_to_link) |dir| {
                    try self.symlinkOrCopyDirectoryContents(source_base, sysroot, dir, false);
                }
            }
        }

        return sysroot;
    }

    /// Recursively link/copy contents of a directory into the sysroot
    /// For bin/ directories, we COPY files instead of symlinking because:
    /// - When kernel executes a symlinked script, it passes the RESOLVED path to the interpreter
    /// - This makes $0 point to the original package directory, not the sysroot
    /// - Wrapper scripts like autoconf-switch use $0 to find related binaries
    /// - By copying, $0 becomes the sysroot path, so ls -d "$0"[0-9]* works correctly
    fn symlinkOrCopyDirectoryContents(
        self: *PortsMigrator,
        source_base: []const u8,
        dest_base: []const u8,
        subdir: []const u8,
        copy_mode: bool, // true for bin/ directories, false for others
    ) !void {
        const source_dir_path = try std.fs.path.join(self.allocator, &[_][]const u8{ source_base, subdir });
        defer self.allocator.free(source_dir_path);

        const dest_dir_path = try std.fs.path.join(self.allocator, &[_][]const u8{ dest_base, subdir });
        defer self.allocator.free(dest_dir_path);

        var source_dir = std.fs.cwd().openDir(source_dir_path, .{ .iterate = true }) catch {
            // Source directory doesn't exist, skip
            return;
        };
        defer source_dir.close();

        // Ensure destination directory exists
        std.fs.cwd().makePath(dest_dir_path) catch {};

        var iter = source_dir.iterate();
        while (try iter.next()) |entry| {
            const source_path = try std.fs.path.join(self.allocator, &[_][]const u8{ source_dir_path, entry.name });
            defer self.allocator.free(source_path);

            const dest_path = try std.fs.path.join(self.allocator, &[_][]const u8{ dest_dir_path, entry.name });
            defer self.allocator.free(dest_path);

            if (entry.kind == .directory) {
                // Recursively handle subdirectories (keep same copy_mode for nested bin/ dirs)
                const sub_subdir = try std.fs.path.join(self.allocator, &[_][]const u8{ subdir, entry.name });
                defer self.allocator.free(sub_subdir);
                try self.symlinkOrCopyDirectoryContents(source_base, dest_base, sub_subdir, copy_mode);
            } else {
                // Skip if destination already exists
                std.fs.cwd().access(dest_path, .{}) catch {
                    // Doesn't exist, create link or copy
                    if (copy_mode) {
                        // Copy file for bin/ directories (preserves executable permissions)
                        std.fs.copyFileAbsolute(source_path, dest_path, .{}) catch |err| {
                            if (self.options.verbose) {
                                std.debug.print("    [SYSROOT] Warning: could not copy {s}: {}\n", .{ entry.name, err });
                            }
                        };
                    } else {
                        // Symlink for lib/, include/, share/, etc.
                        std.fs.cwd().symLink(source_path, dest_path, .{}) catch |err| {
                            if (self.options.verbose) {
                                std.debug.print("    [SYSROOT] Warning: could not symlink {s}: {}\n", .{ entry.name, err });
                            }
                        };
                    }
                };
            }
        }
    }

    /// Find ALL root paths for a package in the Axiom store by name
    /// Returns paths to all versions' root/ directories (important for packages like autoconf
    /// where autoconf-switch and autoconf both provide different binaries under the same package name)
    fn findAllPackageRootsInStore(self: *PortsMigrator, pkg_name: []const u8) !std.ArrayList([]const u8) {
        var roots = std.ArrayList([]const u8).init(self.allocator);
        errdefer {
            for (roots.items) |r| self.allocator.free(r);
            roots.deinit();
        }

        const store = self.options.store orelse return roots;

        const store_mountpoint = store.zfs_handle.getMountpoint(self.allocator, store.paths.store_root) catch {
            return roots;
        };
        defer self.allocator.free(store_mountpoint);

        const pkg_dir_path = std.fs.path.join(self.allocator, &[_][]const u8{
            store_mountpoint,
            pkg_name,
        }) catch return roots;
        defer self.allocator.free(pkg_dir_path);

        var pkg_dir = std.fs.cwd().openDir(pkg_dir_path, .{ .iterate = true }) catch {
            return roots;
        };
        defer pkg_dir.close();

        // Iterate through ALL versions
        var version_iter = pkg_dir.iterate();
        while (version_iter.next() catch null) |version_entry| {
            if (version_entry.kind != .directory) continue;

            const version_path = std.fs.path.join(self.allocator, &[_][]const u8{
                pkg_dir_path,
                version_entry.name,
            }) catch continue;
            defer self.allocator.free(version_path);

            var version_dir = std.fs.cwd().openDir(version_path, .{ .iterate = true }) catch continue;
            defer version_dir.close();

            // First revision
            var revision_iter = version_dir.iterate();
            const revision_entry = (revision_iter.next() catch continue) orelse continue;
            if (revision_entry.kind != .directory) continue;

            const revision_path = std.fs.path.join(self.allocator, &[_][]const u8{
                version_path,
                revision_entry.name,
            }) catch continue;
            defer self.allocator.free(revision_path);

            var revision_dir = std.fs.cwd().openDir(revision_path, .{ .iterate = true }) catch continue;
            defer revision_dir.close();

            // First build-id
            var build_iter = revision_dir.iterate();
            const build_entry = (build_iter.next() catch continue) orelse continue;
            if (build_entry.kind != .directory) continue;

            const root_path = std.fs.path.join(self.allocator, &[_][]const u8{
                revision_path,
                build_entry.name,
                "root",
            }) catch continue;

            // Verify root directory exists
            std.fs.cwd().access(root_path, .{}) catch {
                self.allocator.free(root_path);
                continue;
            };

            try roots.append(root_path);
        }

        return roots;
    }

    /// Find the root path for a package in the Axiom store by name
    /// Returns the path to the package's root/ directory, or null if not found
    fn findPackageRootInStore(self: *PortsMigrator, pkg_name: []const u8) ?[]const u8 {
        // Axiom store structure: ZFS dataset at {store_root}/{name}/{version}/{revision}/{build-id}
        // with files in the root/ subdirectory of the mountpoint
        // We need to find any version of this package and return its root path

        // Use ZFS to get proper mountpoint if store is available
        const store = self.options.store orelse {
            std.debug.print("      [DEBUG findPkg] store is null\n", .{});
            return null;
        };

        // Get the ROOT store mountpoint (e.g., zroot/axiom/store/pkg -> /axiom/store/pkg)
        // This is more reliable than querying child datasets which may not have explicit mountpoints
        const store_mountpoint = store.zfs_handle.getMountpoint(self.allocator, store.paths.store_root) catch |err| {
            std.debug.print("      [DEBUG findPkg] getMountpoint for store root failed: {}\n", .{err});
            return null;
        };
        defer self.allocator.free(store_mountpoint);

        std.debug.print("      [DEBUG findPkg] Store mountpoint: {s}\n", .{store_mountpoint});

        // Construct the package directory path under the store
        const pkg_dir_path = std.fs.path.join(self.allocator, &[_][]const u8{
            store_mountpoint,
            pkg_name,
        }) catch return null;
        defer self.allocator.free(pkg_dir_path);

        std.debug.print("      [DEBUG findPkg] Looking for package at: {s}\n", .{pkg_dir_path});

        // Open the package name directory
        var pkg_dir = std.fs.cwd().openDir(pkg_dir_path, .{ .iterate = true }) catch |err| {
            std.debug.print("      [DEBUG findPkg] openDir failed: {}\n", .{err});
            return null;
        };
        defer pkg_dir.close();

        // Find first version directory
        var version_iter = pkg_dir.iterate();
        const version_entry = (version_iter.next() catch return null) orelse return null;
        if (version_entry.kind != .directory) return null;

        const version_path = std.fs.path.join(self.allocator, &[_][]const u8{
            pkg_dir_path,
            version_entry.name,
        }) catch return null;
        defer self.allocator.free(version_path);

        // Find first revision directory
        var version_dir = std.fs.cwd().openDir(version_path, .{ .iterate = true }) catch return null;
        defer version_dir.close();

        var revision_iter = version_dir.iterate();
        const revision_entry = (revision_iter.next() catch return null) orelse return null;
        if (revision_entry.kind != .directory) return null;

        const revision_path = std.fs.path.join(self.allocator, &[_][]const u8{
            version_path,
            revision_entry.name,
        }) catch return null;
        defer self.allocator.free(revision_path);

        // Find first build-id directory
        var revision_dir = std.fs.cwd().openDir(revision_path, .{ .iterate = true }) catch return null;
        defer revision_dir.close();

        var build_iter = revision_dir.iterate();
        const build_entry = (build_iter.next() catch return null) orelse return null;
        if (build_entry.kind != .directory) return null;

        // Return path to root/ directory
        const root_path = std.fs.path.join(self.allocator, &[_][]const u8{
            revision_path,
            build_entry.name,
            "root",
        }) catch return null;

        // Verify root directory exists
        std.fs.cwd().access(root_path, .{}) catch {
            self.allocator.free(root_path);
            return null;
        };

        return root_path;
    }

    /// Build environment using sysroot approach
    /// Creates a unified sysroot directory where all dependency packages are symlinked together.
    /// This solves the autoconf-switch problem where wrapper scripts need to find related binaries
    /// in the same directory (e.g., autoconf wrapper looking for autoconf2.72 via ls -d "$0"[0-9]*).
    fn getBuildEnvironment(self: *PortsMigrator, origin: []const u8) !BuildEnvironment {
        // Collect all package roots from dependencies
        var all_roots = std.ArrayList([]const u8).init(self.allocator);
        defer {
            for (all_roots.items) |r| self.allocator.free(r);
            all_roots.deinit();
        }

        // Get ALL transitive dependencies for this port (not just direct ones)
        // This is critical for cases like automake -> autoconf -> autoconf-switch
        var deps = self.resolveDependencyTree(origin) catch {
            // If we can't get dependencies, just return system defaults with empty sysroot
            std.debug.print("    [DEBUG] Failed to get dependencies for {s}, using system defaults\n", .{origin});
            return BuildEnvironment{
                .sysroot = try self.allocator.dupe(u8, ""),
                .path = try self.allocator.dupe(u8, "/usr/local/bin:/usr/bin:/bin"),
                .ld_library_path = try self.allocator.dupe(u8, "/usr/local/lib:/usr/lib:/lib"),
                .ldflags = try self.allocator.dupe(u8, "-L/usr/local/lib"),
                .cppflags = try self.allocator.dupe(u8, "-I/usr/local/include"),
                .allocator = self.allocator,
            };
        };
        defer {
            for (deps.items) |d| self.allocator.free(d);
            deps.deinit();
        }

        std.debug.print("    [DEBUG] Processing {d} transitive dependencies for sysroot\n", .{deps.items.len});

        // For each dependency, collect ALL package roots from the Axiom store
        for (deps.items) |dep_origin| {
            // Skip the package itself
            if (std.mem.eql(u8, dep_origin, origin)) continue;

            // Map port origin to Axiom package name
            const pkg_name = self.mapPortName(dep_origin);
            std.debug.print("    [DEBUG] Looking for {s} (from {s}) in store\n", .{ pkg_name, dep_origin });

            // Find ALL versions of package in store
            var roots = self.findAllPackageRootsInStore(pkg_name) catch continue;
            defer roots.deinit();

            if (roots.items.len == 0) {
                std.debug.print("    [DEBUG] Package {s} NOT found in store\n", .{pkg_name});
                continue;
            }

            std.debug.print("    [DEBUG] Found {d} version(s) of {s}\n", .{ roots.items.len, pkg_name });

            // Add all roots (transfer ownership to all_roots)
            for (roots.items) |root| {
                // Dupe to transfer ownership since roots will be cleaned up
                const root_copy = try self.allocator.dupe(u8, root);
                try all_roots.append(root_copy);
            }
        }

        // If no dependencies found, return system defaults
        if (all_roots.items.len == 0) {
            std.debug.print("    [DEBUG] No dependencies found in store, using system defaults\n", .{});
            return BuildEnvironment{
                .sysroot = try self.allocator.dupe(u8, ""),
                .path = try self.allocator.dupe(u8, "/usr/local/bin:/usr/bin:/bin"),
                .ld_library_path = try self.allocator.dupe(u8, "/usr/local/lib:/usr/lib:/lib"),
                .ldflags = try self.allocator.dupe(u8, "-L/usr/local/lib"),
                .cppflags = try self.allocator.dupe(u8, "-I/usr/local/include"),
                .allocator = self.allocator,
            };
        }

        // Create sysroot with all package roots symlinked
        const sysroot = try self.createBuildSysroot(all_roots.items);
        errdefer self.allocator.free(sysroot);

        // Build paths using the sysroot
        const sysroot_bin = try std.fs.path.join(self.allocator, &[_][]const u8{ sysroot, "bin" });
        defer self.allocator.free(sysroot_bin);

        const sysroot_lib = try std.fs.path.join(self.allocator, &[_][]const u8{ sysroot, "lib" });
        defer self.allocator.free(sysroot_lib);

        const sysroot_include = try std.fs.path.join(self.allocator, &[_][]const u8{ sysroot, "include" });
        defer self.allocator.free(sysroot_include);

        // PATH: sysroot/bin first, then system paths
        const path = try std.fmt.allocPrint(
            self.allocator,
            "{s}:/usr/local/bin:/usr/bin:/bin",
            .{sysroot_bin},
        );

        // LD_LIBRARY_PATH: sysroot/lib first, then system paths
        const ld_library_path = try std.fmt.allocPrint(
            self.allocator,
            "{s}:/usr/local/lib:/usr/lib:/lib",
            .{sysroot_lib},
        );

        // LDFLAGS: -L pointing to sysroot/lib and /usr/local/lib
        const ldflags = try std.fmt.allocPrint(
            self.allocator,
            "-L{s} -L/usr/local/lib",
            .{sysroot_lib},
        );

        // CPPFLAGS: -I pointing to sysroot/include and /usr/local/include
        const cppflags = try std.fmt.allocPrint(
            self.allocator,
            "-I{s} -I/usr/local/include",
            .{sysroot_include},
        );

        std.debug.print("    [DEBUG] Sysroot created: {s}\n", .{sysroot});
        std.debug.print("    [DEBUG] Final PATH: {s}\n", .{path});
        std.debug.print("    [DEBUG] Final LDFLAGS: {s}\n", .{ldflags});

        return BuildEnvironment{
            .sysroot = sysroot,
            .path = path,
            .ld_library_path = ld_library_path,
            .ldflags = ldflags,
            .cppflags = cppflags,
            .allocator = self.allocator,
        };
    }

    /// Build a port using the FreeBSD ports build system
    fn buildPort(
        self: *PortsMigrator,
        origin: []const u8,
        metadata: *const PortMetadata,
        manifest_path: ?[]const u8,
    ) !PortBuildResult {
        _ = manifest_path; // May be used in future for dependency resolution

        std.debug.print("\n=== Building port: {s} ===\n", .{origin});

        const port_path = try std.fs.path.join(self.allocator, &[_][]const u8{
            self.options.ports_tree,
            origin,
        });
        defer self.allocator.free(port_path);

        // Create a temporary output directory for the staged installation
        const timestamp = std.time.timestamp();
        var random_bytes: [4]u8 = undefined;
        std.crypto.random.bytes(&random_bytes);

        const stage_dir = try std.fmt.allocPrint(
            self.allocator,
            "/tmp/axiom-ports-stage-{s}-{d}-{x:0>2}{x:0>2}{x:0>2}{x:0>2}",
            .{ metadata.name, timestamp, random_bytes[0], random_bytes[1], random_bytes[2], random_bytes[3] },
        );
        errdefer self.allocator.free(stage_dir);

        try std.fs.cwd().makePath(stage_dir);

        // Build using FreeBSD ports make with DESTDIR
        std.debug.print("Building in: {s}\n", .{port_path});
        std.debug.print("Staging to: {s}\n", .{stage_dir});

        // Step 1: Clean any previous build
        std.debug.print("  Cleaning...\n", .{});
        var clean_result = try self.runMakeTarget(port_path, "clean", null);
        clean_result.deinit(self.allocator);

        // Step 2: Check and display required dependencies
        // (User must build these first via separate ports-import calls)
        try self.displayDependencies(port_path);

        // Step 3: Set up build environment with Axiom store paths
        // This allows built dependencies to be found by configure scripts and compilers
        std.debug.print("  Setting up build environment...\n", .{});
        var build_env = try self.getBuildEnvironment(origin);
        defer build_env.deinit();

        if (self.options.verbose) {
            std.debug.print("  Axiom store dependencies added to PATH\n", .{});
        }

        // Step 4: Build the port with NO_DEPENDS (skip ports dependency machinery)
        // Dependencies are now available via PATH from Axiom store
        std.debug.print("  Building...\n", .{});
        var build_result = try self.runMakeTargetNoDeps(port_path, "build", null, &build_env, origin);
        if (build_result.exit_code != 0) {
            std.debug.print("  Build failed with exit code: {d}\n", .{build_result.exit_code});
            // Show the last part of stdout (compiler errors are in stdout)
            if (build_result.stdout) |stdout| {
                // Show last 4KB of output to catch the actual error
                const start = if (stdout.len > 4096) stdout.len - 4096 else 0;
                std.debug.print("\n--- Build output (last 4KB) ---\n{s}\n", .{stdout[start..]});
            }
            if (build_result.stderr) |stderr| {
                std.debug.print("--- stderr ---\n{s}\n", .{stderr});
            }
            std.debug.print("-------------------------------\n", .{});
            build_result.deinit(self.allocator);
            return PortsError.BuildFailed;
        }
        build_result.deinit(self.allocator);

        // Step 5: Stage the port (uses internal staging in work/stage)
        std.debug.print("  Staging...\n", .{});
        var stage_result = try self.runMakeTargetNoDeps(port_path, "stage", null, &build_env, origin);
        if (stage_result.exit_code != 0) {
            std.debug.print("  Stage failed with exit code: {d}\n", .{stage_result.exit_code});
            if (stage_result.stdout) |stdout| {
                const start = if (stdout.len > 4096) stdout.len - 4096 else 0;
                std.debug.print("\n--- Stage output (last 4KB) ---\n{s}\n", .{stdout[start..]});
            }
            if (stage_result.stderr) |stderr| {
                std.debug.print("--- stderr ---\n{s}\n", .{stderr});
            }
            std.debug.print("-------------------------------\n", .{});
            stage_result.deinit(self.allocator);
            return PortsError.BuildFailed;
        }
        stage_result.deinit(self.allocator);

        // Step 6: Copy staged files from work/stage to our staging directory
        // The ports system stages to <port_path>/work/stage/usr/local
        std.debug.print("  Copying staged files...\n", .{});
        const work_stage = try std.fs.path.join(self.allocator, &[_][]const u8{
            port_path,
            "work/stage",
        });
        defer self.allocator.free(work_stage);

        // Use cp -a to preserve attributes and copy recursively
        var cp_args = [_][]const u8{
            "cp",
            "-a",
            work_stage,
            stage_dir,
        };

        var cp_child = std.process.Child.init(&cp_args, self.allocator);
        cp_child.stdout_behavior = .Ignore;
        cp_child.stderr_behavior = .Pipe;
        try cp_child.spawn();

        var cp_stderr: ?[]const u8 = null;
        if (cp_child.stderr) |stderr_pipe| {
            cp_stderr = stderr_pipe.readToEndAlloc(self.allocator, 1024 * 1024) catch null;
        }
        defer if (cp_stderr) |s| self.allocator.free(s);

        const cp_term = try cp_child.wait();
        if (cp_term.Exited != 0) {
            std.debug.print("  Copy failed with exit code: {d}\n", .{cp_term.Exited});
            if (cp_stderr) |stderr| {
                std.debug.print("  stderr: {s}\n", .{stderr});
            }
            return PortsError.BuildFailed;
        }

        std.debug.print("  Build completed successfully\n", .{});

        // Return path to the copied stage directory
        const final_stage = try std.fs.path.join(self.allocator, &[_][]const u8{
            stage_dir,
            "stage",
        });
        self.allocator.free(stage_dir);

        return PortBuildResult{
            .output_dir = final_stage,
            .success = true,
        };
    }

    /// Result from running a make target
    const MakeResult = struct {
        exit_code: u8,
        stdout: ?[]const u8,
        stderr: ?[]const u8,

        pub fn deinit(self: *MakeResult, allocator: std.mem.Allocator) void {
            if (self.stdout) |s| allocator.free(s);
            if (self.stderr) |s| allocator.free(s);
        }
    };

    /// Run a make target in the port directory
    fn runMakeTarget(
        self: *PortsMigrator,
        port_path: []const u8,
        target: []const u8,
        destdir: ?[]const u8,
    ) !MakeResult {
        var args = std.ArrayList([]const u8).init(self.allocator);
        defer args.deinit();

        // Track allocated strings to free after process completes
        var destdir_arg: ?[]const u8 = null;
        defer if (destdir_arg) |d| self.allocator.free(d);

        var jobs_arg: ?[]const u8 = null;
        defer if (jobs_arg) |j| self.allocator.free(j);

        try args.append("make");
        try args.append("-C");
        try args.append(port_path);

        // Add BATCH=yes to prevent interactive prompts
        try args.append("BATCH=yes");

        // Disable interactive dialogs
        try args.append("DISABLE_VULNERABILITIES=yes");

        // Add DESTDIR if provided
        if (destdir) |dir| {
            destdir_arg = try std.fmt.allocPrint(self.allocator, "DESTDIR={s}", .{dir});
            try args.append(destdir_arg.?);
        }

        // Add job count for parallel builds
        jobs_arg = try std.fmt.allocPrint(self.allocator, "-j{d}", .{self.options.build_jobs});
        try args.append(jobs_arg.?);

        try args.append(target);

        var child = std.process.Child.init(args.items, self.allocator);

        // Always capture both stdout and stderr so we can show errors
        // (compiler errors go to stdout, make errors go to stderr)
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Pipe;

        try child.spawn();

        // Read stdout (contains compiler output including errors)
        var stdout_output: ?[]const u8 = null;
        if (child.stdout) |stdout_pipe| {
            const stdout_content = stdout_pipe.readToEndAlloc(self.allocator, 10 * 1024 * 1024) catch null;
            if (stdout_content) |content| {
                if (content.len > 0) {
                    stdout_output = content;
                } else {
                    self.allocator.free(content);
                }
            }
        }

        // Read stderr
        var stderr_output: ?[]const u8 = null;
        if (child.stderr) |stderr_pipe| {
            const stderr_content = stderr_pipe.readToEndAlloc(self.allocator, 1024 * 1024) catch null;
            if (stderr_content) |content| {
                if (content.len > 0) {
                    stderr_output = content;
                } else {
                    self.allocator.free(content);
                }
            }
        }

        const term = try child.wait();

        // In verbose mode, show stdout
        if (self.options.verbose) {
            if (stdout_output) |out| {
                std.debug.print("{s}", .{out});
            }
        }

        return MakeResult{
            .exit_code = term.Exited,
            .stdout = stdout_output,
            .stderr = stderr_output,
        };
    }

    /// Run a make target with NO_DEPENDS to skip port-based dependency building
    /// (assumes dependencies were pre-installed from packages or are in Axiom store)
    fn runMakeTargetNoDeps(
        self: *PortsMigrator,
        port_path: []const u8,
        target: []const u8,
        destdir: ?[]const u8,
        build_env: ?*const BuildEnvironment,
        origin: []const u8,
    ) !MakeResult {
        var args = std.ArrayList([]const u8).init(self.allocator);
        defer args.deinit();

        // Track allocated strings to free after process completes
        var destdir_arg: ?[]const u8 = null;
        defer if (destdir_arg) |d| self.allocator.free(d);

        var jobs_arg: ?[]const u8 = null;
        defer if (jobs_arg) |j| self.allocator.free(j);

        // These are passed as make variables so ports framework respects them
        var make_env_arg: ?[]const u8 = null;
        defer if (make_env_arg) |m| self.allocator.free(m);

        var configure_env_arg: ?[]const u8 = null;
        defer if (configure_env_arg) |c| self.allocator.free(c);

        try args.append("make");
        try args.append("-C");
        try args.append(port_path);

        // Add BATCH=yes to prevent interactive prompts
        try args.append("BATCH=yes");

        // Disable interactive dialogs
        try args.append("DISABLE_VULNERABILITIES=yes");

        // Skip dependency building - we installed them from packages
        try args.append("NO_DEPENDS=yes");

        // Don't chroot during install (DESTDIR is empty staging dir without /bin/sh)
        try args.append("NO_INSTALL_CHROOT=yes");

        // Pass Axiom sysroot PATH and LOCALBASE through MAKE_ENV and CONFIGURE_ENV
        // This is critical: the ports framework (bsd.port.mk) uses these variables
        // to set up the environment for configure and build phases.
        //
        // The sysroot approach merges all dependency packages into a single directory,
        // allowing wrapper scripts (like autoconf-switch) to find related binaries.
        //
        // IMPORTANT: Only pass variables WITHOUT SPACES via MAKE_ENV/CONFIGURE_ENV.
        // Variables with spaces (like LDFLAGS with multiple -L flags) get shell-split
        // when the ports framework runs: env ${MAKE_ENV} ./configure
        // Instead, LDFLAGS/CPPFLAGS are set in the child process env_map below.
        if (build_env) |env| {
            // Use sysroot as LOCALBASE if available, otherwise fall back to /usr/local
            const localbase = if (env.sysroot.len > 0) env.sysroot else "/usr/local";

            // Only pass variables WITHOUT SPACES via MAKE_ENV/CONFIGURE_ENV
            // PATH and LOCALBASE are safe (no spaces in values)
            // LOCALBASE is critical for FreeBSD ports - tells them where to find libs/headers
            make_env_arg = try std.fmt.allocPrint(
                self.allocator,
                "MAKE_ENV+=PATH={s} LOCALBASE={s}",
                .{ env.path, localbase },
            );
            try args.append(make_env_arg.?);

            configure_env_arg = try std.fmt.allocPrint(
                self.allocator,
                "CONFIGURE_ENV+=PATH={s} LOCALBASE={s}",
                .{ env.path, localbase },
            );
            try args.append(configure_env_arg.?);

            std.debug.print("    [DEBUG] Passing to ports framework:\n", .{});
            std.debug.print("    [DEBUG]   MAKE_ENV+=PATH={s} LOCALBASE={s}\n", .{ env.path, localbase });
            std.debug.print("    [DEBUG]   CONFIGURE_ENV+=PATH={s} LOCALBASE={s}\n", .{ env.path, localbase });
            std.debug.print("    [DEBUG]   (LDFLAGS/CPPFLAGS set via process environment)\n", .{});
        }

        // Add DESTDIR if provided
        if (destdir) |dir| {
            destdir_arg = try std.fmt.allocPrint(self.allocator, "DESTDIR={s}", .{dir});
            try args.append(destdir_arg.?);
        }

        // Add job count for parallel builds
        jobs_arg = try std.fmt.allocPrint(self.allocator, "-j{d}", .{self.options.build_jobs});
        try args.append(jobs_arg.?);

        try args.append(target);

        var child = std.process.Child.init(args.items, self.allocator);

        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Pipe;

        // Set up custom environment if provided (includes Axiom store paths)
        var env_map: ?std.process.EnvMap = null;
        defer if (env_map) |*em| em.deinit();

        if (build_env) |env| {
            // Create environment map with PATH and LD_LIBRARY_PATH from Axiom store
            env_map = std.process.EnvMap.init(self.allocator);

            // Copy important environment variables from parent process
            if (std.posix.getenv("HOME")) |home| {
                try env_map.?.put("HOME", home);
            }
            if (std.posix.getenv("USER")) |user| {
                try env_map.?.put("USER", user);
            }
            if (std.posix.getenv("SHELL")) |shell| {
                try env_map.?.put("SHELL", shell);
            }
            if (std.posix.getenv("TERM")) |term| {
                try env_map.?.put("TERM", term);
            }
            if (std.posix.getenv("LANG")) |lang| {
                try env_map.?.put("LANG", lang);
            }

            // LOCALBASE is critical for FreeBSD ports - it's where ports look for dependencies
            // Use sysroot if available (contains all symlinked dependencies), otherwise /usr/local
            const localbase = if (env.sysroot.len > 0) env.sysroot else "/usr/local";
            try env_map.?.put("LOCALBASE", localbase);

            // Set custom PATH with sysroot bin directory first
            try env_map.?.put("PATH", env.path);
            try env_map.?.put("LD_LIBRARY_PATH", env.ld_library_path);

            // Set LDFLAGS and CPPFLAGS in environment for configure-time detection
            // This helps Perl Makefile.PL and other detection scripts find libraries
            // These MUST be set here (not via MAKE_ENV) because values contain spaces
            try env_map.?.put("LDFLAGS", env.ldflags);
            try env_map.?.put("CPPFLAGS", env.cppflags);

            // For Perl modules, also set LIBS and INC which ExtUtils::MakeMaker reads
            if (std.mem.indexOf(u8, origin, "/p5-") != null) {
                // LIBS needs -lintl for gettext support
                const libs_value = try std.fmt.allocPrint(
                    self.allocator,
                    "{s} -lintl",
                    .{env.ldflags},
                );
                defer self.allocator.free(libs_value);
                try env_map.?.put("LIBS", libs_value);
                try env_map.?.put("INC", env.cppflags);

                std.debug.print("    [DEBUG] Perl module env: LIBS={s}\n", .{libs_value});
                std.debug.print("    [DEBUG] Perl module env: INC={s}\n", .{env.cppflags});
            }

            // FreeBSD make needs these
            try env_map.?.put("MAKE", "make");
            try env_map.?.put("PORTSDIR", self.options.ports_tree);

            // Set the pointer on child
            child.env_map = &(env_map.?);

            if (self.options.verbose) {
                std.debug.print("  Build environment:\n", .{});
                std.debug.print("    LOCALBASE={s}\n", .{localbase});
                std.debug.print("    PATH={s}\n", .{env.path});
                std.debug.print("    LD_LIBRARY_PATH={s}\n", .{env.ld_library_path});
            }
        }

        try child.spawn();

        // Read stdout (contains compiler output including errors)
        var stdout_output: ?[]const u8 = null;
        if (child.stdout) |stdout_pipe| {
            const stdout_content = stdout_pipe.readToEndAlloc(self.allocator, 10 * 1024 * 1024) catch null;
            if (stdout_content) |content| {
                if (content.len > 0) {
                    stdout_output = content;
                } else {
                    self.allocator.free(content);
                }
            }
        }

        // Read stderr
        var stderr_output: ?[]const u8 = null;
        if (child.stderr) |stderr_pipe| {
            const stderr_content = stderr_pipe.readToEndAlloc(self.allocator, 1024 * 1024) catch null;
            if (stderr_content) |content| {
                if (content.len > 0) {
                    stderr_output = content;
                } else {
                    self.allocator.free(content);
                }
            }
        }

        const term = try child.wait();

        // In verbose mode, show stdout
        if (self.options.verbose) {
            if (stdout_output) |out| {
                std.debug.print("{s}", .{out});
            }
        }

        return MakeResult{
            .exit_code = term.Exited,
            .stdout = stdout_output,
            .stderr = stderr_output,
        };
    }

    /// Display build dependencies (user must build these first via separate ports-import calls)
    fn displayDependencies(self: *PortsMigrator, port_path: []const u8) !void {
        // Get BUILD_DEPENDS
        var build_args = [_][]const u8{ "make", "-C", port_path, "-V", "BUILD_DEPENDS" };
        var build_child = std.process.Child.init(&build_args, self.allocator);
        build_child.stdout_behavior = .Pipe;
        build_child.stderr_behavior = .Ignore;
        try build_child.spawn();

        var build_deps: ?[]const u8 = null;
        if (build_child.stdout) |stdout_pipe| {
            build_deps = stdout_pipe.readToEndAlloc(self.allocator, 1024 * 1024) catch null;
        }
        _ = try build_child.wait();

        // Get LIB_DEPENDS
        var lib_args = [_][]const u8{ "make", "-C", port_path, "-V", "LIB_DEPENDS" };
        var lib_child = std.process.Child.init(&lib_args, self.allocator);
        lib_child.stdout_behavior = .Pipe;
        lib_child.stderr_behavior = .Ignore;
        try lib_child.spawn();

        var lib_deps: ?[]const u8 = null;
        if (lib_child.stdout) |stdout_pipe| {
            lib_deps = stdout_pipe.readToEndAlloc(self.allocator, 1024 * 1024) catch null;
        }
        _ = try lib_child.wait();

        defer {
            if (build_deps) |d| self.allocator.free(d);
            if (lib_deps) |d| self.allocator.free(d);
        }

        // Parse dependencies and extract port origins (category/port format)
        var origins = std.ArrayList([]const u8).init(self.allocator);
        defer {
            for (origins.items) |o| self.allocator.free(o);
            origins.deinit();
        }

        // BUILD_DEPENDS format: "/path/to/file:category/port" or "command:category/port"
        if (build_deps) |deps| {
            const trimmed = std.mem.trim(u8, deps, " \t\n\r");
            if (trimmed.len > 0) {
                var dep_iter = std.mem.splitSequence(u8, trimmed, " ");
                while (dep_iter.next()) |dep| {
                    const dep_trimmed = std.mem.trim(u8, dep, " \t\n\r");
                    if (dep_trimmed.len == 0) continue;

                    if (std.mem.indexOf(u8, dep_trimmed, ":")) |colon_pos| {
                        const origin = dep_trimmed[colon_pos + 1 ..];
                        if (origin.len > 0 and std.mem.indexOf(u8, origin, "/") != null) {
                            // Check for duplicates
                            var found = false;
                            for (origins.items) |existing| {
                                if (std.mem.eql(u8, existing, origin)) {
                                    found = true;
                                    break;
                                }
                            }
                            if (!found) {
                                try origins.append(try self.allocator.dupe(u8, origin));
                            }
                        }
                    }
                }
            }
        }

        // LIB_DEPENDS format: "libname.so:category/port"
        if (lib_deps) |deps| {
            const trimmed = std.mem.trim(u8, deps, " \t\n\r");
            if (trimmed.len > 0) {
                var dep_iter = std.mem.splitSequence(u8, trimmed, " ");
                while (dep_iter.next()) |dep| {
                    const dep_trimmed = std.mem.trim(u8, dep, " \t\n\r");
                    if (dep_trimmed.len == 0) continue;

                    if (std.mem.indexOf(u8, dep_trimmed, ":")) |colon_pos| {
                        const origin = dep_trimmed[colon_pos + 1 ..];
                        if (origin.len > 0 and std.mem.indexOf(u8, origin, "/") != null) {
                            var found = false;
                            for (origins.items) |existing| {
                                if (std.mem.eql(u8, existing, origin)) {
                                    found = true;
                                    break;
                                }
                            }
                            if (!found) {
                                try origins.append(try self.allocator.dupe(u8, origin));
                            }
                        }
                    }
                }
            }
        }

        if (origins.items.len == 0) {
            std.debug.print("  Dependencies: none\n", .{});
            return;
        }

        std.debug.print("  Dependencies ({d} ports):\n", .{origins.items.len});
        for (origins.items) |origin| {
            std.debug.print("    - {s}\n", .{origin});
        }
        std.debug.print("  Note: Build these first if not already available on the system.\n", .{});
        std.debug.print("        e.g., axiom ports-import {s}\n", .{origins.items[0]});
    }

    /// Get direct dependencies for a port (returns list of port origins)
    fn getPortDependencies(self: *PortsMigrator, origin: []const u8) !std.ArrayList([]const u8) {
        const port_path = try std.fs.path.join(self.allocator, &[_][]const u8{
            self.options.ports_tree,
            origin,
        });
        defer self.allocator.free(port_path);

        var deps = std.ArrayList([]const u8).init(self.allocator);
        errdefer {
            for (deps.items) |d| self.allocator.free(d);
            deps.deinit();
        }

        // Get BUILD_DEPENDS, LIB_DEPENDS, RUN_DEPENDS
        const dep_vars = [_][]const u8{ "BUILD_DEPENDS", "LIB_DEPENDS", "RUN_DEPENDS" };

        for (dep_vars) |dep_var| {
            var args = [_][]const u8{ "make", "-C", port_path, "-V", dep_var };
            var child = std.process.Child.init(&args, self.allocator);
            child.stdout_behavior = .Pipe;
            child.stderr_behavior = .Ignore;

            child.spawn() catch continue;

            var dep_output: ?[]const u8 = null;
            if (child.stdout) |stdout_pipe| {
                dep_output = stdout_pipe.readToEndAlloc(self.allocator, 1024 * 1024) catch null;
            }
            _ = child.wait() catch continue;

            if (dep_output) |output| {
                defer self.allocator.free(output);
                const trimmed = std.mem.trim(u8, output, " \t\n\r");
                if (trimmed.len == 0) continue;

                var iter = std.mem.splitSequence(u8, trimmed, " ");
                while (iter.next()) |dep| {
                    const dep_trimmed = std.mem.trim(u8, dep, " \t\n\r");
                    if (dep_trimmed.len == 0) continue;

                    // Extract origin from "file:category/port" or "lib:category/port"
                    if (std.mem.indexOf(u8, dep_trimmed, ":")) |colon_pos| {
                        const dep_origin = dep_trimmed[colon_pos + 1 ..];
                        if (dep_origin.len > 0 and std.mem.indexOf(u8, dep_origin, "/") != null) {
                            // Check for duplicates
                            var found = false;
                            for (deps.items) |existing| {
                                if (std.mem.eql(u8, existing, dep_origin)) {
                                    found = true;
                                    break;
                                }
                            }
                            if (!found) {
                                try deps.append(try self.allocator.dupe(u8, dep_origin));
                            }
                        }
                    }
                }
            }
        }

        return deps;
    }

    /// Dependency graph node
    const DepNode = struct {
        origin: []const u8,
        deps: []const []const u8,
        depth: usize,
    };

    /// Build complete dependency tree for a port (recursive)
    /// Returns list of all dependencies in topological order (leaves first)
    pub fn resolveDependencyTree(self: *PortsMigrator, root_origin: []const u8) !std.ArrayList([]const u8) {
        // Use ArrayHashMap so we can iterate keys later to free them
        var visited = std.StringArrayHashMap(usize).init(self.allocator);
        defer {
            // Free all owned keys
            for (visited.keys()) |key| {
                self.allocator.free(key);
            }
            visited.deinit();
        }

        var result = std.ArrayList([]const u8).init(self.allocator);
        errdefer {
            for (result.items) |r| self.allocator.free(r);
            result.deinit();
        }

        // Track what we're currently visiting (for cycle detection)
        // Keys are borrowed from visited, so no need to free
        var visiting = std.StringHashMap(void).init(self.allocator);
        defer visiting.deinit();

        // Recursive depth-first traversal
        try self.visitDependency(root_origin, &visited, &visiting, &result, 0);

        // Sort by depth (deepest first = leaves first)
        const SortContext = struct {
            visited: *std.StringArrayHashMap(usize),
        };

        const ctx = SortContext{ .visited = &visited };
        std.mem.sort([]const u8, result.items, ctx, struct {
            fn lessThan(c: SortContext, a: []const u8, b: []const u8) bool {
                const depth_a = c.visited.get(a) orelse 0;
                const depth_b = c.visited.get(b) orelse 0;
                // Higher depth = deeper in tree = should come first (leaves)
                return depth_a > depth_b;
            }
        }.lessThan);

        return result;
    }

    /// Visit a dependency node (recursive DFS)
    fn visitDependency(
        self: *PortsMigrator,
        origin: []const u8,
        visited: *std.StringArrayHashMap(usize),
        visiting: *std.StringHashMap(void),
        result: *std.ArrayList([]const u8),
        depth: usize,
    ) !void {
        // Already fully visited?
        if (visited.get(origin)) |existing_depth| {
            // Update depth if we found a deeper path
            if (depth > existing_depth) {
                visited.putAssumeCapacity(origin, depth);
            }
            return;
        }

        // Currently visiting? (cycle detection)
        if (visiting.contains(origin)) {
            if (self.options.verbose) {
                std.debug.print("  Warning: Circular dependency detected at {s}, skipping\n", .{origin});
            }
            return;
        }

        // Dupe the origin string so we own it (for use as hashmap key)
        const owned_origin = try self.allocator.dupe(u8, origin);
        errdefer self.allocator.free(owned_origin);

        // Mark as currently visiting (borrow from owned_origin)
        try visiting.put(owned_origin, {});

        // Get direct dependencies
        var deps = self.getPortDependencies(origin) catch |err| {
            if (self.options.verbose) {
                std.debug.print("  Warning: Could not get dependencies for {s}: {s}\n", .{ origin, @errorName(err) });
            }
            _ = visiting.remove(owned_origin);
            self.allocator.free(owned_origin);
            return;
        };
        defer {
            for (deps.items) |d| self.allocator.free(d);
            deps.deinit();
        }

        // Visit each dependency first (depth-first)
        for (deps.items) |dep| {
            try self.visitDependency(dep, visited, visiting, result, depth + 1);
        }

        // Done visiting children
        _ = visiting.remove(owned_origin);

        // Mark as visited with depth (transfer ownership of owned_origin to visited map)
        try visited.put(owned_origin, depth);

        // Add to result (dupe again since result needs its own copy)
        try result.append(try self.allocator.dupe(u8, origin));
    }

    /// Migrate a port and all its dependencies
    /// Returns results for all ports in build order
    pub fn migrateWithDependencies(self: *PortsMigrator, origin: []const u8) !std.ArrayList(MigrationResult) {
        var results = std.ArrayList(MigrationResult).init(self.allocator);
        errdefer {
            for (results.items) |*r| r.deinit(self.allocator);
            results.deinit();
        }

        if (self.options.auto_deps) {
            // Resolve full dependency tree
            std.debug.print("Resolving dependency tree for {s}...\n", .{origin});

            var dep_tree = try self.resolveDependencyTree(origin);
            defer {
                for (dep_tree.items) |d| self.allocator.free(d);
                dep_tree.deinit();
            }

            if (dep_tree.items.len > 1) {
                std.debug.print("\nBuild order ({d} ports):\n", .{dep_tree.items.len});
                for (dep_tree.items, 0..) |dep, i| {
                    std.debug.print("  {d}. {s}\n", .{ i + 1, dep });
                }
                std.debug.print("\n", .{});
            }

            // Build each dependency in order
            for (dep_tree.items) |dep| {
                std.debug.print("\n" ++ "=" ** 60 ++ "\n", .{});
                std.debug.print("Processing: {s}\n", .{dep});
                std.debug.print("=" ** 60 ++ "\n", .{});

                // Temporarily disable auto_deps to avoid infinite recursion
                const saved_auto_deps = self.options.auto_deps;
                self.options.auto_deps = false;
                defer self.options.auto_deps = saved_auto_deps;

                const result = try self.migrate(dep);
                try results.append(result);

                // Stop on failure
                if (result.status == .failed) {
                    std.debug.print("Stopping due to failure in {s}\n", .{dep});
                    break;
                }
            }
        } else {
            // Just migrate the single port (no dependency resolution)
            const result = try self.migrate(origin);
            try results.append(result);
        }

        return results;
    }

    /// Import a built port into the Axiom store
    fn importPort(
        self: *PortsMigrator,
        metadata: *const PortMetadata,
        stage_dir: []const u8,
    ) !PackageId {
        std.debug.print("\n=== Importing to store: {s} ===\n", .{metadata.name});

        // Get the importer from options
        const importer = self.options.importer orelse {
            std.debug.print("Error: Importer not provided in options\n", .{});
            return PortsError.ImportFailed;
        };

        // Parse version
        const version = types.Version.parse(metadata.version) catch {
            std.debug.print("Error: Failed to parse version: {s}\n", .{metadata.version});
            return PortsError.ImportFailed;
        };

        // Create import options
        // Note: Ports builds are unsigned, so we allow unsigned imports
        const import_options = import_pkg.ImportOptions{
            .name = self.mapPortName(metadata.name),
            .version = version,
            .revision = metadata.revision,
            .description = metadata.comment,
            .license = if (metadata.license.len > 0) metadata.license else null,
            .dry_run = false,
            .auto_detect = false,
            .security = .{
                .allow_unsigned = true, // Ports builds don't have signatures
            },
        };

        // Find the actual package files (usually in usr/local under stage_dir)
        const pkg_root = try self.findPackageRoot(stage_dir);
        defer if (pkg_root.ptr != stage_dir.ptr) self.allocator.free(pkg_root);

        std.debug.print("  Package root: {s}\n", .{pkg_root});

        // Import the package
        const pkg_id = importer.import(
            import_pkg.ImportSource{ .directory = pkg_root },
            import_options,
        ) catch |err| {
            std.debug.print("Import error: {s}\n", .{@errorName(err)});
            return PortsError.ImportFailed;
        };

        std.debug.print("  ✓ Package imported: {s}@{}\n", .{ pkg_id.name, pkg_id.version });

        return pkg_id;
    }

    /// Find the actual package root directory (e.g., usr/local) in staged output
    fn findPackageRoot(self: *PortsMigrator, stage_dir: []const u8) ![]const u8 {
        // FreeBSD ports typically stage to DESTDIR/usr/local
        const usr_local = try std.fs.path.join(self.allocator, &[_][]const u8{ stage_dir, "usr", "local" });

        if (std.fs.cwd().access(usr_local, .{})) |_| {
            return usr_local;
        } else |_| {
            self.allocator.free(usr_local);
        }

        // Try just usr/
        const usr = try std.fs.path.join(self.allocator, &[_][]const u8{ stage_dir, "usr" });

        if (std.fs.cwd().access(usr, .{})) |_| {
            return usr;
        } else |_| {
            self.allocator.free(usr);
        }

        // Fall back to stage_dir itself
        return stage_dir;
    }

    /// Batch migrate multiple ports
    pub fn migrateMultiple(self: *PortsMigrator, origins: []const []const u8) ![]MigrationResult {
        var results = std.ArrayList(MigrationResult).init(self.allocator);

        for (origins) |origin| {
            const result = try self.migrate(origin);
            try results.append(result);
        }

        return results.toOwnedSlice();
    }

    /// Scan ports tree for all ports in a category
    pub fn scanCategory(self: *PortsMigrator, category: []const u8) ![][]const u8 {
        const cat_path = try std.fs.path.join(self.allocator, &[_][]const u8{
            self.options.ports_tree,
            category,
        });
        defer self.allocator.free(cat_path);

        var ports = std.ArrayList([]const u8).init(self.allocator);

        var dir = std.fs.cwd().openDir(cat_path, .{ .iterate = true }) catch {
            return ports.toOwnedSlice();
        };
        defer dir.close();

        var iter = dir.iterate();
        while (try iter.next()) |entry| {
            if (entry.kind == .directory and entry.name[0] != '.') {
                // Check if it's a valid port (has Makefile)
                const makefile_path = try std.fs.path.join(self.allocator, &[_][]const u8{
                    cat_path,
                    entry.name,
                    "Makefile",
                });
                defer self.allocator.free(makefile_path);

                if (std.fs.cwd().access(makefile_path, .{})) |_| {
                    const origin = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ category, entry.name });
                    try ports.append(origin);
                } else |_| {}
            }
        }

        return ports.toOwnedSlice();
    }

    // --- Internal helpers ---

    fn makeVar(self: *PortsMigrator, port_path: []const u8, varname: []const u8) ![]const u8 {
        const result = try self.makeVarOptional(port_path, varname);
        return result orelse PortsError.MissingRequiredField;
    }

    fn makeVarOptional(self: *PortsMigrator, port_path: []const u8, varname: []const u8) !?[]const u8 {
        const args = [_][]const u8{
            "make",
            "-C",
            port_path,
            "-V",
            varname,
        };

        var child = std.process.Child.init(&args, self.allocator);
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Ignore;

        try child.spawn();

        var stdout_buf: [8192]u8 = undefined;
        var total_read: usize = 0;

        if (child.stdout) |stdout| {
            while (true) {
                const n = stdout.read(stdout_buf[total_read..]) catch break;
                if (n == 0) break;
                total_read += n;
                if (total_read >= stdout_buf.len) break;
            }
        }

        _ = child.wait() catch {};

        if (total_read == 0) return null;

        // Trim trailing newline
        var end = total_read;
        while (end > 0 and (stdout_buf[end - 1] == '\n' or stdout_buf[end - 1] == '\r')) {
            end -= 1;
        }

        if (end == 0) return null;

        return try self.allocator.dupe(u8, stdout_buf[0..end]);
    }

    fn hasMakeVar(self: *PortsMigrator, port_path: []const u8, varname: []const u8) !bool {
        const result = try self.makeVarOptional(port_path, varname);
        if (result) |r| {
            self.allocator.free(r);
            return true;
        }
        return false;
    }

    fn splitWhitespace(self: *PortsMigrator, input: []const u8) ![]const []const u8 {
        var parts = std.ArrayList([]const u8).init(self.allocator);
        var iter = std.mem.tokenizeAny(u8, input, " \t\n\r");
        while (iter.next()) |part| {
            try parts.append(try self.allocator.dupe(u8, part));
        }
        return parts.toOwnedSlice();
    }

    fn readPkgDescr(self: *PortsMigrator, port_path: []const u8) ![]const u8 {
        const descr_path = try std.fs.path.join(self.allocator, &[_][]const u8{
            port_path,
            "pkg-descr",
        });
        defer self.allocator.free(descr_path);

        const file = std.fs.cwd().openFile(descr_path, .{}) catch {
            return try self.allocator.dupe(u8, "");
        };
        defer file.close();

        return file.readToEndAlloc(self.allocator, 65536) catch {
            return try self.allocator.dupe(u8, "");
        };
    }

    fn readDistinfoSha256(self: *PortsMigrator, port_path: []const u8) ![]const u8 {
        const distinfo_path = try std.fs.path.join(self.allocator, &[_][]const u8{
            port_path,
            "distinfo",
        });
        defer self.allocator.free(distinfo_path);

        const file = std.fs.cwd().openFile(distinfo_path, .{}) catch {
            return try self.allocator.dupe(u8, "");
        };
        defer file.close();

        const content = file.readToEndAlloc(self.allocator, 65536) catch {
            return try self.allocator.dupe(u8, "");
        };
        defer self.allocator.free(content);

        // Parse SHA256 line: SHA256 (filename) = hash
        var lines = std.mem.tokenizeScalar(u8, content, '\n');
        while (lines.next()) |line| {
            if (std.mem.startsWith(u8, line, "SHA256")) {
                // Find the hash after " = "
                if (std.mem.indexOf(u8, line, " = ")) |idx| {
                    return try self.allocator.dupe(u8, line[idx + 3 ..]);
                }
            }
        }

        return try self.allocator.dupe(u8, "");
    }

    fn parseDependencies(self: *PortsMigrator, port_path: []const u8, depvar: []const u8) ![]const PortDependency {
        const deps_str = try self.makeVarOptional(port_path, depvar) orelse return &[_]PortDependency{};
        defer self.allocator.free(deps_str);

        var deps = std.ArrayList(PortDependency).init(self.allocator);

        // Format: file:origin or lib.so:origin or pkg>=version:origin
        var iter = std.mem.tokenizeAny(u8, deps_str, " \t\n\r");
        while (iter.next()) |dep_spec| {
            if (std.mem.indexOf(u8, dep_spec, ":")) |colon_idx| {
                const file_or_pkg = dep_spec[0..colon_idx];
                const origin = dep_spec[colon_idx + 1 ..];

                // Extract package name from origin (last component)
                const pkg_name = std.fs.path.basename(origin);

                try deps.append(.{
                    .origin = try self.allocator.dupe(u8, origin),
                    .package = try self.allocator.dupe(u8, pkg_name),
                    .version = null, // TODO: parse version from pkg>=version
                    .file_or_lib = try self.allocator.dupe(u8, file_or_pkg),
                });
            }
        }

        return deps.toOwnedSlice();
    }

    fn parseOptions(self: *PortsMigrator, port_path: []const u8) ![]const PortOption {
        _ = self;
        _ = port_path;
        // TODO: Parse OPTIONS_DEFINE, OPTIONS_DEFAULT, etc.
        return &[_]PortOption{};
    }

    fn detectConfigureStyle(self: *PortsMigrator, uses: []const []const u8) ConfigureStyle {
        _ = self;
        for (uses) |u| {
            if (std.mem.startsWith(u8, u, "cmake")) return .cmake;
            if (std.mem.startsWith(u8, u, "meson")) return .meson;
            if (std.mem.startsWith(u8, u, "cargo")) return .cargo;
            if (std.mem.startsWith(u8, u, "go:")) return .go;
            if (std.mem.startsWith(u8, u, "python")) return .python;
            if (std.mem.startsWith(u8, u, "perl")) return .perl;
            if (std.mem.startsWith(u8, u, "ruby")) return .ruby;
            if (std.mem.startsWith(u8, u, "qmake")) return .qmake;
            if (std.mem.startsWith(u8, u, "scons")) return .scons;
            if (std.mem.startsWith(u8, u, "waf")) return .waf;
            if (std.mem.startsWith(u8, u, "autoreconf") or
                std.mem.startsWith(u8, u, "gmake") or
                std.mem.startsWith(u8, u, "libtool"))
            {
                return .gnu_configure;
            }
        }
        return .gnu_configure; // Default assumption
    }

    /// Map a ports origin like "devel/p5-Locale-gettext" or "lang/perl5.42"
    /// to the canonical Axiom package name used in the store.
    ///
    /// Rules in order:
    /// 1. Exact origin overrides (lang/perl5.42 → perl, devel/autoconf-switch → autoconf)
    /// 2. Perl core ports: perl5* → perl
    /// 3. Perl modules: p5-* → strip "p5-" prefix
    /// 4. Fallback: use the port name (last path component) as-is
    fn mapPortName(self: *PortsMigrator, origin: []const u8) []const u8 {
        _ = self; // May use self.options.name_mappings for additional overrides later

        // Compile-time map for exact origin overrides
        const overrides = std.StaticStringMap([]const u8).initComptime(.{
            // Perl core (explicit origins)
            .{ "lang/perl5.42", "perl" },
            .{ "lang/perl5.40", "perl" },
            .{ "lang/perl5.38", "perl" },
            .{ "lang/perl5.36", "perl" },

            // Autoconf switch installs tools under autoconf
            .{ "devel/autoconf-switch", "autoconf" },

            // gmake installs as 'make' not 'gmake'
            .{ "devel/gmake", "make" },
        });

        // 0. Check exact origin overrides
        if (overrides.get(origin)) |name| {
            return name;
        }

        // 1. Extract last path component: "category/name" → "name"
        const port_name = blk: {
            if (std.mem.lastIndexOfScalar(u8, origin, '/')) |idx| {
                break :blk origin[idx + 1 ..];
            } else {
                break :blk origin;
            }
        };

        // 2. Perl core ports: perl5, perl5.42, perl5XX → "perl"
        if (std.mem.startsWith(u8, port_name, "perl5")) {
            return "perl";
        }

        // 3. Perl modules: p5-* → strip "p5-" prefix
        if (std.mem.startsWith(u8, port_name, "p5-") and port_name.len > 3) {
            return port_name[3..]; // Skip "p5-"
        }

        // 4. Fallback: use the port name as-is
        return port_name;
    }

    /// Check if a port is a kernel module based on USES and categories
    fn isKernelModule(meta: *const PortMetadata) bool {
        // Check USES for kmod
        for (meta.uses) |u| {
            if (std.mem.eql(u8, u, "kmod") or std.mem.startsWith(u8, u, "kmod:")) {
                return true;
            }
        }

        // Check categories for kld (kernel loadable modules)
        for (meta.categories) |cat| {
            if (std.mem.eql(u8, cat, "kld")) {
                return true;
            }
        }

        return false;
    }

    /// Get current FreeBSD version for kernel compat (placeholder)
    fn getCurrentFreeBSDVersion(self: *PortsMigrator) u32 {
        _ = self;
        // In production, this would read from:
        // - make -V OSVERSION
        // - sysctl kern.osreldate
        // For now, return a placeholder value
        return 1502000; // FreeBSD 15.0-CURRENT
    }

    fn generateManifestYaml(self: *PortsMigrator, meta: *const PortMetadata, origin: []const u8) ![]const u8 {
        var output = std.ArrayList(u8).init(self.allocator);
        const writer = output.writer();

        try writer.writeAll("# Generated from FreeBSD port\n");
        try writer.writeAll("name: ");
        try writer.writeAll(self.mapPortName(meta.name));
        try writer.writeAll("\n");

        try writer.writeAll("version: \"");
        try writer.writeAll(meta.version);
        try writer.writeAll("\"\n");

        try writer.writeAll("revision: ");
        try std.fmt.format(writer, "{d}\n", .{meta.revision});

        try writer.writeAll("description: ");
        try writer.writeAll(meta.comment);
        try writer.writeAll("\n");

        if (meta.license.len > 0) {
            try writer.writeAll("license: ");
            try writer.writeAll(meta.license);
            try writer.writeAll("\n");
        }

        if (meta.www.len > 0) {
            try writer.writeAll("homepage: ");
            try writer.writeAll(meta.www);
            try writer.writeAll("\n");
        }

        if (meta.maintainer.len > 0) {
            try writer.writeAll("maintainer: ");
            try writer.writeAll(meta.maintainer);
            try writer.writeAll("\n");
        }

        // Origin (port path) - used to distinguish packages with same name from different ports
        try writer.writeAll("origin: ");
        try writer.writeAll(origin);
        try writer.writeAll("\n");

        // Provides
        try writer.writeAll("\nprovides:\n");
        try writer.writeAll("  - ");
        try writer.writeAll(meta.name);
        try writer.writeAll("\n");

        // Conflicts
        if (meta.conflicts.len > 0) {
            try writer.writeAll("\nconflicts:\n");
            for (meta.conflicts) |c| {
                try writer.writeAll("  - ");
                try writer.writeAll(c);
                try writer.writeAll("\n");
            }
        }

        // Kernel compatibility (for kmod packages)
        if (isKernelModule(meta)) {
            const freebsd_version = self.getCurrentFreeBSDVersion();
            // Set version range for current major version (e.g., 1500000-1509999 for 15.x)
            const major_min = (freebsd_version / 100000) * 100000;
            const major_max = major_min + 99999;

            try writer.writeAll("\nkernel:\n");
            try writer.writeAll("  kmod: true\n");
            try std.fmt.format(writer, "  freebsd_version_min: {d}\n", .{major_min});
            try std.fmt.format(writer, "  freebsd_version_max: {d}\n", .{major_max});
            try writer.writeAll("  # Note: kernel_idents left empty - compatible with any ident\n");
            try writer.writeAll("  # Add specific kernel idents if this kmod requires them:\n");
            try writer.writeAll("  # kernel_idents:\n");
            try writer.writeAll("  #   - \"GENERIC\"\n");
            try writer.writeAll("  #   - \"PGSD-GENERIC\"\n");
            try writer.writeAll("  require_exact_ident: false\n");
            try writer.writeAll("  # kld_names populated from port's installed .ko files:\n");
            try writer.writeAll("  kld_names:\n");
            try std.fmt.format(writer, "    - \"{s}.ko\"\n", .{meta.name});
        }

        return output.toOwnedSlice();
    }
};

/// Result of a single port migration
pub const MigrationResult = struct {
    origin: []const u8,
    status: MigrationStatus,
    manifest_path: ?[]const u8,
    axiom_package: ?[]const u8, // Package ID if imported
    warnings: std.ArrayList([]const u8),
    errors: std.ArrayList([]const u8),

    pub fn deinit(self: *MigrationResult, allocator: std.mem.Allocator) void {
        if (self.manifest_path) |p| allocator.free(p);
        if (self.axiom_package) |p| allocator.free(p);
        for (self.warnings.items) |w| allocator.free(w);
        self.warnings.deinit();
        for (self.errors.items) |e| allocator.free(e);
        self.errors.deinit();
    }
};

pub const MigrationStatus = enum {
    pending,
    generated,
    built,
    imported,
    failed,
    skipped,
};

/// Generate a migration report
pub fn generateReport(allocator: std.mem.Allocator, results: []const MigrationResult) ![]const u8 {
    var output = std.ArrayList(u8).init(allocator);
    const writer = output.writer();

    var generated: u32 = 0;
    var built: u32 = 0;
    var imported: u32 = 0;
    var failed: u32 = 0;
    var skipped: u32 = 0;

    for (results) |r| {
        switch (r.status) {
            .generated => generated += 1,
            .built => built += 1,
            .imported => imported += 1,
            .failed => failed += 1,
            .skipped => skipped += 1,
            .pending => {},
        }
    }

    try writer.writeAll("Ports Migration Report\n");
    try writer.writeAll("======================\n\n");

    try std.fmt.format(writer, "Total ports processed: {d}\n", .{results.len});
    try std.fmt.format(writer, "  Generated: {d}\n", .{generated});
    try std.fmt.format(writer, "  Built: {d}\n", .{built});
    try std.fmt.format(writer, "  Imported: {d}\n", .{imported});
    try std.fmt.format(writer, "  Failed: {d}\n", .{failed});
    try std.fmt.format(writer, "  Skipped: {d}\n", .{skipped});

    if (failed > 0) {
        try writer.writeAll("\nFailed ports:\n");
        for (results) |r| {
            if (r.status == .failed) {
                try std.fmt.format(writer, "  - {s}\n", .{r.origin});
                for (r.errors.items) |err| {
                    try std.fmt.format(writer, "      Error: {s}\n", .{err});
                }
            }
        }
    }

    return output.toOwnedSlice();
}
