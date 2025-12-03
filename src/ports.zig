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
        metadata.revision = std.fmt.parseInt(u32, try self.makeVarOptional(port_path, "PORTREVISION") orelse "0", 10) catch 0;
        metadata.epoch = std.fmt.parseInt(u32, try self.makeVarOptional(port_path, "PORTEPOCH") orelse "0", 10) catch 0;

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
        const manifest_yaml = try self.generateManifestYaml(&metadata);
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
                self.allocator.free(build_result.output_dir);
            }
        }

        return result;
    }

    /// Build result from port build
    const PortBuildResult = struct {
        output_dir: []const u8,
        success: bool,
    };

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
        _ = try self.runMakeTarget(port_path, "clean", null);

        // Step 2: Build the port
        std.debug.print("  Building...\n", .{});
        const build_exit = try self.runMakeTarget(port_path, "build", null);
        if (build_exit != 0) {
            std.debug.print("  Build failed with exit code: {d}\n", .{build_exit});
            return PortsError.BuildFailed;
        }

        // Step 3: Stage the installation
        std.debug.print("  Staging installation...\n", .{});
        const stage_exit = try self.runMakeTarget(port_path, "stage", stage_dir);
        if (stage_exit != 0) {
            std.debug.print("  Staging failed with exit code: {d}\n", .{stage_exit});
            return PortsError.BuildFailed;
        }

        std.debug.print("  Build completed successfully\n", .{});

        return PortBuildResult{
            .output_dir = stage_dir,
            .success = true,
        };
    }

    /// Run a make target in the port directory
    fn runMakeTarget(
        self: *PortsMigrator,
        port_path: []const u8,
        target: []const u8,
        destdir: ?[]const u8,
    ) !u8 {
        var args = std.ArrayList([]const u8).init(self.allocator);
        defer args.deinit();

        try args.append("make");
        try args.append("-C");
        try args.append(port_path);

        // Add DESTDIR if provided
        if (destdir) |dir| {
            const destdir_arg = try std.fmt.allocPrint(self.allocator, "DESTDIR={s}", .{dir});
            defer self.allocator.free(destdir_arg);
            try args.append(destdir_arg);
        }

        // Add job count for parallel builds
        const jobs_arg = try std.fmt.allocPrint(self.allocator, "-j{d}", .{self.options.build_jobs});
        defer self.allocator.free(jobs_arg);
        try args.append(jobs_arg);

        try args.append(target);

        var child = std.process.Child.init(args.items, self.allocator);
        if (!self.options.verbose) {
            child.stdout_behavior = .Ignore;
            child.stderr_behavior = .Ignore;
        }

        try child.spawn();
        const term = try child.wait();

        return term.Exited;
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
        const import_options = import_pkg.ImportOptions{
            .name = self.mapPortName(metadata.name),
            .version = version,
            .revision = metadata.revision,
            .description = metadata.comment,
            .license = if (metadata.license.len > 0) metadata.license else null,
            .dry_run = false,
            .auto_detect = false,
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

    fn mapPortName(self: *PortsMigrator, port_name: []const u8) []const u8 {
        for (self.options.name_mappings) |mapping| {
            if (std.mem.eql(u8, mapping.port_origin, port_name)) {
                return mapping.axiom_name;
            }
        }
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

    fn generateManifestYaml(self: *PortsMigrator, meta: *const PortMetadata) ![]const u8 {
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
