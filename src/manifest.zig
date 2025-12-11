const std = @import("std");
const types = @import("types.zig");
const service_mod = @import("service.zig");
const format_version = @import("format_version.zig");

const Version = types.Version;
const Dependency = types.Dependency;
const VersionConstraint = types.VersionConstraint;
const ServiceDeclaration = service_mod.ServiceDeclaration;
const FormatVersions = format_version.FormatVersions;
const FormatType = format_version.FormatType;

/// Virtual package relationship with optional version constraint
pub const VirtualPackage = struct {
    name: []const u8,
    constraint: ?VersionConstraint = null,
};

/// Feature flag definition for conditional compilation/dependencies
pub const Feature = struct {
    /// Feature name (e.g., "gui", "ssl", "debug")
    name: []const u8,

    /// Human-readable description
    description: ?[]const u8 = null,

    /// Dependencies required when this feature is enabled
    dependencies: []Dependency = &[_]Dependency{},

    /// Other features this feature implies (auto-enables)
    implies: []const []const u8 = &[_][]const u8{},

    /// Features that conflict with this one
    conflicts_with: []const []const u8 = &[_][]const u8{},

    /// Free allocated memory
    pub fn deinit(self: *Feature, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        if (self.description) |desc| {
            allocator.free(desc);
        }
        allocator.free(self.dependencies);
        for (self.implies) |imp| {
            allocator.free(imp);
        }
        allocator.free(self.implies);
        for (self.conflicts_with) |conf| {
            allocator.free(conf);
        }
        allocator.free(self.conflicts_with);
    }
};

/// Package output definition for selective installation (Phase 44)
/// Allows packages to define subsets of their files for different use cases
pub const PackageOutput = struct {
    /// Output name (e.g., "bin", "lib", "dev", "doc")
    name: []const u8,

    /// Human-readable description
    description: ?[]const u8 = null,

    /// Path patterns included in this output (glob patterns)
    paths: []const []const u8 = &[_][]const u8{},

    /// Other outputs this output depends on
    requires: []const []const u8 = &[_][]const u8{},

    /// Whether this output is included by default
    default: bool = true,

    /// Free allocated memory
    pub fn deinit(self: *PackageOutput, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        if (self.description) |desc| {
            allocator.free(desc);
        }
        for (self.paths) |p| {
            allocator.free(p);
        }
        allocator.free(self.paths);
        for (self.requires) |r| {
            allocator.free(r);
        }
        allocator.free(self.requires);
    }
};

/// Kernel module compatibility metadata
/// Used for packages that install .ko kernel modules
pub const KernelCompat = struct {
    /// True if this package installs kernel modules (.ko files)
    kmod: bool = false,

    /// Minimum compatible __FreeBSD_version (inclusive), null means no lower bound
    freebsd_version_min: ?u32 = null,

    /// Maximum compatible __FreeBSD_version (inclusive), null means no upper bound
    freebsd_version_max: ?u32 = null,

    /// List of kernel idents this package is compatible with (e.g., "PGSD-GENERIC")
    kernel_idents: []const []const u8 = &[_][]const u8{},

    /// If true, running kernel ident must match one of kernel_idents
    require_exact_ident: bool = false,

    /// Names of .ko files installed by this package
    kld_names: []const []const u8 = &[_][]const u8{},

    /// Validation errors for kernel compatibility metadata
    pub const ValidationError = error{
        /// freebsd_version_min is greater than freebsd_version_max
        VersionRangeInverted,
        /// require_exact_ident is true but kernel_idents is empty
        IdentRequiredButEmpty,
        /// kmod is false but kernel-specific fields are set
        NonKmodWithKernelFields,
    };

    /// Validate kernel compatibility metadata for logical consistency
    pub fn validate(self: KernelCompat) ValidationError!void {
        // Check that version range is valid
        if (self.freebsd_version_min != null and self.freebsd_version_max != null) {
            if (self.freebsd_version_min.? > self.freebsd_version_max.?) {
                return ValidationError.VersionRangeInverted;
            }
        }

        // Check that require_exact_ident has kernel_idents to match against
        if (self.require_exact_ident and self.kernel_idents.len == 0) {
            return ValidationError.IdentRequiredButEmpty;
        }

        // Warn (but don't error) if kmod is false but kernel fields are set
        // This is a soft validation - we just check for the most obvious case
        if (!self.kmod) {
            const has_version_constraint = self.freebsd_version_min != null or self.freebsd_version_max != null;
            const has_ident_constraint = self.require_exact_ident or self.kernel_idents.len > 0;
            if (has_version_constraint or has_ident_constraint) {
                return ValidationError.NonKmodWithKernelFields;
            }
        }
    }

    /// Free allocated memory
    pub fn deinit(self: *KernelCompat, allocator: std.mem.Allocator) void {
        for (self.kernel_idents) |ident| {
            allocator.free(ident);
        }
        allocator.free(self.kernel_idents);
        for (self.kld_names) |name| {
            allocator.free(name);
        }
        allocator.free(self.kld_names);
    }
};

/// Package manifest (manifest.yaml)
pub const Manifest = struct {
    /// Format version for this manifest file (e.g., "1.0")
    /// Used for compatibility checking and migrations
    format_version: ?[]const u8 = null,

    name: []const u8,
    version: Version,
    revision: u32,
    description: ?[]const u8 = null,
    license: ?[]const u8 = null,
    homepage: ?[]const u8 = null,
    maintainer: ?[]const u8 = null,
    tags: [][]const u8 = &[_][]const u8{},

    /// FreeBSD port origin (e.g., "devel/autoconf") - used to distinguish
    /// packages with the same name from different ports
    origin: ?[]const u8 = null,

    /// Virtual package names this package provides (e.g., "shell", "http-client")
    provides: [][]const u8 = &[_][]const u8{},

    /// Packages that cannot coexist with this one
    conflicts: []VirtualPackage = &[_]VirtualPackage{},

    /// Packages this one supersedes/replaces
    replaces: []VirtualPackage = &[_]VirtualPackage{},

    /// Kernel module compatibility (null for userland packages)
    kernel: ?KernelCompat = null,

    /// Services provided by this package (Phase 38)
    services: []ServiceDeclaration = &[_]ServiceDeclaration{},

    /// Feature flags supported by this package (Phase 43)
    features: []Feature = &[_]Feature{},

    /// Default features enabled when not explicitly specified
    default_features: [][]const u8 = &[_][]const u8{},

    /// Package outputs for selective installation (Phase 44)
    outputs: []PackageOutput = &[_]PackageOutput{},

    /// Parse manifest from YAML content
    ///
    /// YAML Subset Supported:
    /// ----------------------
    /// This is a minimal line-based YAML parser optimized for Axiom manifests.
    /// It does NOT support the full YAML specification.
    ///
    /// Supported features:
    /// - Single-line key: value pairs
    /// - Simple list items with "- item" syntax
    /// - One level of nesting (e.g., kernel: section)
    /// - Comments starting with #
    /// - Quoted values (quotes are stripped)
    ///
    /// NOT supported:
    /// - Multi-line strings (| or > syntax)
    /// - Nested arrays or complex structures
    /// - Escaped quotes within values
    /// - Flow syntax ({ } or [ ])
    /// - Anchors and aliases (&anchor, *alias)
    /// - Multiple documents (---)
    /// - Tags (!tag)
    ///
    /// Example of supported format:
    /// ```yaml
    /// name: mypackage
    /// version: 1.2.3
    /// description: A simple package
    /// tags:
    ///   - utility
    ///   - cli
    /// kernel:
    ///   kmod: true
    ///   freebsd_version_min: 1400000
    /// ```
    pub fn parse(allocator: std.mem.Allocator, yaml_content: []const u8) !Manifest {
        // Simple line-based YAML parser for our specific format
        // This is a minimal implementation - we can replace with proper YAML library later

        var manifest = Manifest{
            .name = undefined,
            .version = undefined,
            .revision = 0,
        };

        var lines = std.mem.splitScalar(u8, yaml_content, '\n');
        var tags = std.ArrayList([]const u8).init(allocator);
        defer tags.deinit();
        var provides_list = std.ArrayList([]const u8).init(allocator);
        defer provides_list.deinit();
        var conflicts_list = std.ArrayList(VirtualPackage).init(allocator);
        defer conflicts_list.deinit();
        var replaces_list = std.ArrayList(VirtualPackage).init(allocator);
        defer replaces_list.deinit();

        // Kernel compatibility fields
        var kernel_idents = std.ArrayList([]const u8).init(allocator);
        defer kernel_idents.deinit();
        var kld_names = std.ArrayList([]const u8).init(allocator);
        defer kld_names.deinit();
        var kernel_compat: ?KernelCompat = null;
        var in_kernel_section = false;

        const ListContext = enum {
            none,
            tags,
            provides,
            conflicts,
            replaces,
            kernel_idents,
            kld_names,
        };
        var list_context: ListContext = .none;

        while (lines.next()) |line| {
            const trimmed = std.mem.trim(u8, line, " \t\r");
            if (trimmed.len == 0) continue;
            if (std.mem.startsWith(u8, trimmed, "#")) continue;

            if (std.mem.startsWith(u8, trimmed, "- ")) {
                // List item
                const item = std.mem.trim(u8, trimmed[2..], " \t");
                switch (list_context) {
                    .tags => try tags.append(try allocator.dupe(u8, item)),
                    .provides => try provides_list.append(try allocator.dupe(u8, item)),
                    .conflicts => {
                        const vpkg = try parseVirtualPackage(allocator, item);
                        try conflicts_list.append(vpkg);
                    },
                    .replaces => {
                        const vpkg = try parseVirtualPackage(allocator, item);
                        try replaces_list.append(vpkg);
                    },
                    .kernel_idents => try kernel_idents.append(try allocator.dupe(u8, item)),
                    .kld_names => try kld_names.append(try allocator.dupe(u8, item)),
                    .none => {},
                }
                continue;
            }

            list_context = .none;

            var parts = std.mem.splitScalar(u8, trimmed, ':');
            const key = parts.next() orelse continue;
            const value_raw = parts.rest();
            const value = std.mem.trim(u8, value_raw, " \t");

            // Check if we're entering or leaving a section
            const is_indented = line.len > 0 and (line[0] == ' ' or line[0] == '\t');

            if (!is_indented and std.mem.eql(u8, key, "kernel")) {
                // Entering kernel section
                in_kernel_section = true;
                kernel_compat = KernelCompat{};
                continue;
            } else if (!is_indented and !std.mem.eql(u8, key, "kernel")) {
                // Top-level key, leaving kernel section
                in_kernel_section = false;
            }

            if (in_kernel_section) {
                // Parse kernel section fields
                if (std.mem.eql(u8, key, "kmod")) {
                    kernel_compat.?.kmod = std.mem.eql(u8, value, "true");
                } else if (std.mem.eql(u8, key, "freebsd_version_min")) {
                    kernel_compat.?.freebsd_version_min = try std.fmt.parseInt(u32, value, 10);
                } else if (std.mem.eql(u8, key, "freebsd_version_max")) {
                    kernel_compat.?.freebsd_version_max = try std.fmt.parseInt(u32, value, 10);
                } else if (std.mem.eql(u8, key, "require_exact_ident")) {
                    kernel_compat.?.require_exact_ident = std.mem.eql(u8, value, "true");
                } else if (std.mem.eql(u8, key, "kernel_idents")) {
                    list_context = .kernel_idents;
                } else if (std.mem.eql(u8, key, "kld_names")) {
                    list_context = .kld_names;
                }
            } else if (std.mem.eql(u8, key, "format_version")) {
                manifest.format_version = try allocator.dupe(u8, value);
            } else if (std.mem.eql(u8, key, "name")) {
                manifest.name = try allocator.dupe(u8, value);
            } else if (std.mem.eql(u8, key, "version")) {
                manifest.version = try Version.parse(value);
            } else if (std.mem.eql(u8, key, "revision")) {
                manifest.revision = try std.fmt.parseInt(u32, value, 10);
            } else if (std.mem.eql(u8, key, "description")) {
                manifest.description = try allocator.dupe(u8, value);
            } else if (std.mem.eql(u8, key, "license")) {
                manifest.license = try allocator.dupe(u8, value);
            } else if (std.mem.eql(u8, key, "homepage")) {
                manifest.homepage = try allocator.dupe(u8, value);
            } else if (std.mem.eql(u8, key, "maintainer")) {
                manifest.maintainer = try allocator.dupe(u8, value);
            } else if (std.mem.eql(u8, key, "origin")) {
                manifest.origin = try allocator.dupe(u8, value);
            } else if (std.mem.eql(u8, key, "tags")) {
                list_context = .tags;
            } else if (std.mem.eql(u8, key, "provides")) {
                list_context = .provides;
            } else if (std.mem.eql(u8, key, "conflicts")) {
                list_context = .conflicts;
            } else if (std.mem.eql(u8, key, "replaces")) {
                list_context = .replaces;
            }
        }

        manifest.tags = try tags.toOwnedSlice();
        manifest.provides = try provides_list.toOwnedSlice();
        manifest.conflicts = try conflicts_list.toOwnedSlice();
        manifest.replaces = try replaces_list.toOwnedSlice();

        // Finalize kernel compat if present
        if (kernel_compat) |*kc| {
            kc.kernel_idents = try kernel_idents.toOwnedSlice();
            kc.kld_names = try kld_names.toOwnedSlice();
            manifest.kernel = kc.*;
        }

        // Parse services section (Phase 38)
        manifest.services = service_mod.parseServiceDeclarations(allocator, yaml_content) catch &[_]ServiceDeclaration{};

        return manifest;
    }

    /// Validate manifest for required fields and format version compatibility
    pub fn validate(self: Manifest) !void {
        // Validate format version if present
        if (self.format_version) |fv| {
            format_version.validateVersion(.manifest, fv) catch |err| {
                return switch (err) {
                    format_version.VersionError.IncompatibleMajorVersion => error.IncompatibleFormatVersion,
                    format_version.VersionError.VersionTooNew => error.FormatVersionTooNew,
                    format_version.VersionError.InvalidVersion => error.InvalidFormatVersion,
                    else => error.InvalidFormatVersion,
                };
            };
        }

        if (self.name.len == 0) {
            return error.MissingName;
        }
        if (!isValidPackageName(self.name)) {
            return error.InvalidPackageName;
        }
    }

    /// Get the current format version string for writing manifests
    pub fn currentFormatVersion() []const u8 {
        return FormatVersions.manifest;
    }

    /// Free all allocated memory
    pub fn deinit(self: *Manifest, allocator: std.mem.Allocator) void {
        if (self.format_version) |fv| allocator.free(fv);
        allocator.free(self.name);
        if (self.description) |d| allocator.free(d);
        if (self.license) |l| allocator.free(l);
        if (self.homepage) |h| allocator.free(h);
        if (self.maintainer) |m| allocator.free(m);
        if (self.origin) |o| allocator.free(o);
        for (self.tags) |tag| {
            allocator.free(tag);
        }
        allocator.free(self.tags);
        for (self.provides) |p| {
            allocator.free(p);
        }
        allocator.free(self.provides);
        for (self.conflicts) |c| {
            allocator.free(c.name);
        }
        allocator.free(self.conflicts);
        for (self.replaces) |r| {
            allocator.free(r.name);
        }
        allocator.free(self.replaces);
        if (self.kernel) |*k| {
            var kernel_mut = k;
            kernel_mut.deinit(allocator);
        }
        for (self.services) |*svc| {
            var s = svc.*;
            s.deinit(allocator);
        }
        allocator.free(self.services);
    }

    /// Check if this package provides a virtual package
    pub fn providesVirtual(self: Manifest, virtual_name: []const u8) bool {
        for (self.provides) |p| {
            if (std.mem.eql(u8, p, virtual_name)) {
                return true;
            }
        }
        return false;
    }

    /// Check if this package conflicts with another package
    pub fn conflictsWith(self: Manifest, pkg_name: []const u8, pkg_version: ?Version) bool {
        for (self.conflicts) |c| {
            if (std.mem.eql(u8, c.name, pkg_name)) {
                if (c.constraint) |constraint| {
                    if (pkg_version) |ver| {
                        return constraint.satisfies(ver);
                    }
                }
                return true; // No constraint = conflicts with all versions
            }
        }
        return false;
    }

    /// Check if this package replaces another package
    pub fn replacesPackage(self: Manifest, pkg_name: []const u8, pkg_version: ?Version) bool {
        for (self.replaces) |r| {
            if (std.mem.eql(u8, r.name, pkg_name)) {
                if (r.constraint) |constraint| {
                    if (pkg_version) |ver| {
                        return constraint.satisfies(ver);
                    }
                }
                return true; // No constraint = replaces all versions
            }
        }
        return false;
    }

    /// Serialize manifest to YAML
    pub fn serialize(self: Manifest, allocator: std.mem.Allocator) ![]const u8 {
        var result = std.ArrayList(u8).init(allocator);
        defer result.deinit();
        const writer = result.writer();

        try writer.print("name: {s}\n", .{self.name});
        try writer.print("version: {}.{}.{}\n", .{ self.version.major, self.version.minor, self.version.patch });
        try writer.print("revision: {d}\n", .{self.revision});

        if (self.description) |d| try writer.print("description: {s}\n", .{d});
        if (self.license) |l| try writer.print("license: {s}\n", .{l});
        if (self.homepage) |h| try writer.print("homepage: {s}\n", .{h});
        if (self.maintainer) |m| try writer.print("maintainer: {s}\n", .{m});
        if (self.origin) |o| try writer.print("origin: {s}\n", .{o});

        if (self.tags.len > 0) {
            try writer.writeAll("tags:\n");
            for (self.tags) |tag| {
                try writer.print("  - {s}\n", .{tag});
            }
        }

        if (self.provides.len > 0) {
            try writer.writeAll("provides:\n");
            for (self.provides) |p| {
                try writer.print("  - {s}\n", .{p});
            }
        }

        if (self.conflicts.len > 0) {
            try writer.writeAll("conflicts:\n");
            for (self.conflicts) |c| {
                try writer.print("  - {s}", .{c.name});
                if (c.constraint) |constraint| {
                    try writeConstraint(writer, constraint);
                }
                try writer.writeAll("\n");
            }
        }

        if (self.replaces.len > 0) {
            try writer.writeAll("replaces:\n");
            for (self.replaces) |r| {
                try writer.print("  - {s}", .{r.name});
                if (r.constraint) |constraint| {
                    try writeConstraint(writer, constraint);
                }
                try writer.writeAll("\n");
            }
        }

        // Serialize kernel section if present
        if (self.kernel) |k| {
            try writer.writeAll("kernel:\n");
            try writer.print("  kmod: {s}\n", .{if (k.kmod) "true" else "false"});
            if (k.freebsd_version_min) |v| {
                try writer.print("  freebsd_version_min: {d}\n", .{v});
            }
            if (k.freebsd_version_max) |v| {
                try writer.print("  freebsd_version_max: {d}\n", .{v});
            }
            if (k.require_exact_ident) {
                try writer.writeAll("  require_exact_ident: true\n");
            }
            if (k.kernel_idents.len > 0) {
                try writer.writeAll("  kernel_idents:\n");
                for (k.kernel_idents) |ident| {
                    try writer.print("    - {s}\n", .{ident});
                }
            }
            if (k.kld_names.len > 0) {
                try writer.writeAll("  kld_names:\n");
                for (k.kld_names) |name| {
                    try writer.print("    - {s}\n", .{name});
                }
            }
        }

        return result.toOwnedSlice();
    }

    /// Check if this package is kernel-bound (installs kernel modules)
    pub fn isKernelBound(self: Manifest) bool {
        if (self.kernel) |k| {
            return k.kmod;
        }
        return false;
    }
};

/// Dependency manifest (deps.yaml)
pub const DependencyManifest = struct {
    dependencies: []Dependency,

    /// Parse dependency manifest from YAML content
    pub fn parse(allocator: std.mem.Allocator, yaml_content: []const u8) !DependencyManifest {
        var deps = std.ArrayList(Dependency).init(allocator);
        defer deps.deinit();

        var lines = std.mem.splitScalar(u8, yaml_content, '\n');
        
        var current_dep: ?struct {
            name: ?[]const u8 = null,
            version: ?[]const u8 = null,
            constraint_type: ?[]const u8 = null,
        } = null;

        while (lines.next()) |line| {
            const trimmed = std.mem.trim(u8, line, " \t\r");
            if (trimmed.len == 0) continue;
            if (std.mem.startsWith(u8, trimmed, "#")) continue;

            if (std.mem.startsWith(u8, trimmed, "- ")) {
                // New dependency, finalize previous one
                if (current_dep) |dep| {
                    if (dep.name) |name| {
                        const constraint = try parseConstraint(
                            allocator,
                            dep.version orelse "*",
                            dep.constraint_type orelse "any",
                        );
                        try deps.append(.{
                            .name = try allocator.dupe(u8, name),
                            .constraint = constraint,
                        });
                    }
                }
                current_dep = .{};
                continue;
            }

            if (current_dep == null) continue;

            var parts = std.mem.splitScalar(u8, trimmed, ':');
            const key = std.mem.trim(u8, parts.next() orelse continue, " \t");
            const value = std.mem.trim(u8, parts.rest(), " \t\"");

            if (std.mem.eql(u8, key, "name")) {
                current_dep.?.name = value;
            } else if (std.mem.eql(u8, key, "version")) {
                current_dep.?.version = value;
            } else if (std.mem.eql(u8, key, "constraint")) {
                current_dep.?.constraint_type = value;
            }
        }

        // Finalize last dependency
        if (current_dep) |dep| {
            if (dep.name) |name| {
                const constraint = try parseConstraint(
                    allocator,
                    dep.version orelse "*",
                    dep.constraint_type orelse "any",
                );
                try deps.append(.{
                    .name = try allocator.dupe(u8, name),
                    .constraint = constraint,
                });
            }
        }

        return DependencyManifest{
            .dependencies = try deps.toOwnedSlice(),
        };
    }

    /// Free all allocated memory
    pub fn deinit(self: *DependencyManifest, allocator: std.mem.Allocator) void {
        for (self.dependencies) |dep| {
            allocator.free(dep.name);
        }
        allocator.free(self.dependencies);
    }
};

/// Provenance information (provenance.yaml)
pub const Provenance = struct {
    build_time: i64,
    builder: []const u8,
    build_user: ?[]const u8 = null,
    source_url: ?[]const u8 = null,
    source_hash: ?[]const u8 = null,
    compiler: ?[]const u8 = null,
    compiler_version: ?[]const u8 = null,
    build_flags: [][]const u8 = &[_][]const u8{},

    /// Parse provenance from YAML content
    pub fn parse(allocator: std.mem.Allocator, yaml_content: []const u8) !Provenance {
        var prov = Provenance{
            .build_time = 0,
            .builder = undefined,
        };

        var lines = std.mem.splitScalar(u8, yaml_content, '\n');
        var flags = std.ArrayList([]const u8).init(allocator);
        defer flags.deinit();

        var in_flags = false;

        while (lines.next()) |line| {
            const trimmed = std.mem.trim(u8, line, " \t\r");
            if (trimmed.len == 0) continue;
            if (std.mem.startsWith(u8, trimmed, "#")) continue;

            if (std.mem.startsWith(u8, trimmed, "- ")) {
                if (in_flags) {
                    const flag = std.mem.trim(u8, trimmed[2..], " \t");
                    try flags.append(try allocator.dupe(u8, flag));
                }
                continue;
            }

            in_flags = false;

            var parts = std.mem.splitScalar(u8, trimmed, ':');
            const key = parts.next() orelse continue;
            const value = std.mem.trim(u8, parts.rest(), " \t");

            if (std.mem.eql(u8, key, "build_time")) {
                prov.build_time = try std.fmt.parseInt(i64, value, 10);
            } else if (std.mem.eql(u8, key, "builder")) {
                prov.builder = try allocator.dupe(u8, value);
            } else if (std.mem.eql(u8, key, "build_user")) {
                prov.build_user = try allocator.dupe(u8, value);
            } else if (std.mem.eql(u8, key, "source_url")) {
                prov.source_url = try allocator.dupe(u8, value);
            } else if (std.mem.eql(u8, key, "source_hash")) {
                prov.source_hash = try allocator.dupe(u8, value);
            } else if (std.mem.eql(u8, key, "compiler")) {
                prov.compiler = try allocator.dupe(u8, value);
            } else if (std.mem.eql(u8, key, "compiler_version")) {
                prov.compiler_version = try allocator.dupe(u8, value);
            } else if (std.mem.eql(u8, key, "build_flags")) {
                in_flags = true;
            }
        }

        prov.build_flags = try flags.toOwnedSlice();
        return prov;
    }

    /// Free all allocated memory
    pub fn deinit(self: *Provenance, allocator: std.mem.Allocator) void {
        allocator.free(self.builder);
        if (self.build_user) |u| allocator.free(u);
        if (self.source_url) |u| allocator.free(u);
        if (self.source_hash) |h| allocator.free(h);
        if (self.compiler) |c| allocator.free(c);
        if (self.compiler_version) |v| allocator.free(v);
        for (self.build_flags) |flag| {
            allocator.free(flag);
        }
        allocator.free(self.build_flags);
    }
};

/// Check if package name is valid
fn isValidPackageName(name: []const u8) bool {
    if (name.len == 0) return false;
    for (name) |c| {
        if (!std.ascii.isAlphanumeric(c) and c != '-' and c != '_' and c != '+') {
            return false;
        }
    }
    return true;
}

/// Parse version constraint from string and type
fn parseConstraint(
    allocator: std.mem.Allocator,
    version_str: []const u8,
    constraint_type: []const u8,
) !VersionConstraint {
    _ = allocator;
    
    if (std.mem.eql(u8, constraint_type, "any")) {
        return VersionConstraint{ .any = {} };
    } else if (std.mem.eql(u8, constraint_type, "exact")) {
        return VersionConstraint{ .exact = try Version.parse(version_str) };
    } else if (std.mem.eql(u8, constraint_type, "tilde")) {
        const v = try Version.parse(std.mem.trim(u8, version_str, "~"));
        return VersionConstraint{ .tilde = v };
    } else if (std.mem.eql(u8, constraint_type, "caret")) {
        const v = try Version.parse(std.mem.trim(u8, version_str, "^"));
        return VersionConstraint{ .caret = v };
    } else if (std.mem.eql(u8, constraint_type, "range")) {
        // Parse range like ">=1.2.0" or ">=1.0.0,<2.0.0"
        var min: ?Version = null;
        var max: ?Version = null;
        var min_inclusive = true;
        var max_inclusive = true;

        var parts = std.mem.splitScalar(u8, version_str, ',');
        while (parts.next()) |part| {
            const trimmed = std.mem.trim(u8, part, " \t");
            if (std.mem.startsWith(u8, trimmed, ">=")) {
                min = try Version.parse(trimmed[2..]);
                min_inclusive = true;
            } else if (std.mem.startsWith(u8, trimmed, ">")) {
                min = try Version.parse(trimmed[1..]);
                min_inclusive = false;
            } else if (std.mem.startsWith(u8, trimmed, "<=")) {
                max = try Version.parse(trimmed[2..]);
                max_inclusive = true;
            } else if (std.mem.startsWith(u8, trimmed, "<")) {
                max = try Version.parse(trimmed[1..]);
                max_inclusive = false;
            }
        }

        return VersionConstraint{ 
            .range = .{
                .min = min,
                .max = max,
                .min_inclusive = min_inclusive,
                .max_inclusive = max_inclusive,
            }
        };
    }

    return VersionConstraint{ .any = {} };
}

/// Parse a virtual package specification like "bash" or "bash>=5.0"
fn parseVirtualPackage(allocator: std.mem.Allocator, spec: []const u8) !VirtualPackage {
    // Check for version constraint operators
    const operators = [_][]const u8{ ">=", "<=", ">", "<", "~", "^", "=" };
    for (operators) |op| {
        if (std.mem.indexOf(u8, spec, op)) |idx| {
            const name = std.mem.trim(u8, spec[0..idx], " \t");
            const version_str = std.mem.trim(u8, spec[idx..], " \t");
            const constraint = try parseVersionSpec(version_str);
            return VirtualPackage{
                .name = try allocator.dupe(u8, name),
                .constraint = constraint,
            };
        }
    }

    // No version constraint, just the package name
    return VirtualPackage{
        .name = try allocator.dupe(u8, spec),
        .constraint = null,
    };
}

/// Parse a version specification like ">=5.0.0" or "~5.0"
fn parseVersionSpec(spec: []const u8) !VersionConstraint {
    if (std.mem.startsWith(u8, spec, ">=")) {
        const ver = try Version.parse(spec[2..]);
        return VersionConstraint{ .range = .{ .min = ver, .max = null, .min_inclusive = true, .max_inclusive = true } };
    } else if (std.mem.startsWith(u8, spec, ">")) {
        const ver = try Version.parse(spec[1..]);
        return VersionConstraint{ .range = .{ .min = ver, .max = null, .min_inclusive = false, .max_inclusive = true } };
    } else if (std.mem.startsWith(u8, spec, "<=")) {
        const ver = try Version.parse(spec[2..]);
        return VersionConstraint{ .range = .{ .min = null, .max = ver, .min_inclusive = true, .max_inclusive = true } };
    } else if (std.mem.startsWith(u8, spec, "<")) {
        const ver = try Version.parse(spec[1..]);
        return VersionConstraint{ .range = .{ .min = null, .max = ver, .min_inclusive = true, .max_inclusive = false } };
    } else if (std.mem.startsWith(u8, spec, "~")) {
        const ver = try Version.parse(spec[1..]);
        return VersionConstraint{ .tilde = ver };
    } else if (std.mem.startsWith(u8, spec, "^")) {
        const ver = try Version.parse(spec[1..]);
        return VersionConstraint{ .caret = ver };
    } else if (std.mem.startsWith(u8, spec, "=")) {
        const ver = try Version.parse(spec[1..]);
        return VersionConstraint{ .exact = ver };
    }
    return VersionConstraint{ .any = {} };
}

/// Write a version constraint to a writer
fn writeConstraint(writer: anytype, constraint: VersionConstraint) !void {
    switch (constraint) {
        .exact => |v| try writer.print("={}.{}.{}", .{ v.major, v.minor, v.patch }),
        .tilde => |v| try writer.print("~{}.{}.{}", .{ v.major, v.minor, v.patch }),
        .caret => |v| try writer.print("^{}.{}.{}", .{ v.major, v.minor, v.patch }),
        .any => {},
        .range => |r| {
            if (r.min) |min| {
                try writer.print("{s}{}.{}.{}", .{
                    if (r.min_inclusive) ">=" else ">",
                    min.major,
                    min.minor,
                    min.patch,
                });
            }
            if (r.max) |max| {
                if (r.min != null) try writer.writeAll(",");
                try writer.print("{s}{}.{}.{}", .{
                    if (r.max_inclusive) "<=" else "<",
                    max.major,
                    max.minor,
                    max.patch,
                });
            }
        },
    }
}

// Tests
test "Manifest.parse" {
    const allocator = std.testing.allocator;
    
    const yaml =
        \\name: bash
        \\version: 5.2.0
        \\revision: 1
        \\description: GNU Bourne Again Shell
        \\license: GPL-3.0
        \\
    ;

    var manifest = try Manifest.parse(allocator, yaml);
    defer manifest.deinit(allocator);

    try std.testing.expectEqualStrings("bash", manifest.name);
    try std.testing.expectEqual(@as(u32, 5), manifest.version.major);
    try std.testing.expectEqual(@as(u32, 1), manifest.revision);
}

test "DependencyManifest.parse" {
    const allocator = std.testing.allocator;

    const yaml =
        \\dependencies:
        \\  - name: readline
        \\    version: ">=8.0.0"
        \\    constraint: range
        \\  - name: ncurses
        \\    version: "~6.4"
        \\    constraint: tilde
        \\
    ;

    var deps = try DependencyManifest.parse(allocator, yaml);
    defer deps.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 2), deps.dependencies.len);
    try std.testing.expectEqualStrings("readline", deps.dependencies[0].name);
    try std.testing.expectEqualStrings("ncurses", deps.dependencies[1].name);
}

test "Manifest.parse with virtual packages" {
    const allocator = std.testing.allocator;

    const yaml =
        \\name: bash
        \\version: 5.2.0
        \\revision: 1
        \\description: GNU Bourne Again Shell
        \\provides:
        \\  - shell
        \\  - posix-shell
        \\conflicts:
        \\  - csh
        \\  - zsh<5.0.0
        \\replaces:
        \\  - sh
        \\
    ;

    var manifest = try Manifest.parse(allocator, yaml);
    defer manifest.deinit(allocator);

    try std.testing.expectEqualStrings("bash", manifest.name);
    try std.testing.expectEqual(@as(usize, 2), manifest.provides.len);
    try std.testing.expectEqualStrings("shell", manifest.provides[0]);
    try std.testing.expectEqualStrings("posix-shell", manifest.provides[1]);

    try std.testing.expectEqual(@as(usize, 2), manifest.conflicts.len);
    try std.testing.expectEqualStrings("csh", manifest.conflicts[0].name);
    try std.testing.expect(manifest.conflicts[0].constraint == null);
    try std.testing.expectEqualStrings("zsh", manifest.conflicts[1].name);
    try std.testing.expect(manifest.conflicts[1].constraint != null);

    try std.testing.expectEqual(@as(usize, 1), manifest.replaces.len);
    try std.testing.expectEqualStrings("sh", manifest.replaces[0].name);
}

test "Manifest.providesVirtual" {
    const allocator = std.testing.allocator;

    const yaml =
        \\name: bash
        \\version: 5.2.0
        \\revision: 1
        \\provides:
        \\  - shell
        \\  - posix-shell
        \\
    ;

    var manifest = try Manifest.parse(allocator, yaml);
    defer manifest.deinit(allocator);

    try std.testing.expect(manifest.providesVirtual("shell"));
    try std.testing.expect(manifest.providesVirtual("posix-shell"));
    try std.testing.expect(!manifest.providesVirtual("fish-shell"));
}

test "Manifest.conflictsWith" {
    const allocator = std.testing.allocator;

    const yaml =
        \\name: bash
        \\version: 5.2.0
        \\revision: 1
        \\conflicts:
        \\  - csh
        \\  - zsh<5.0.0
        \\
    ;

    var manifest = try Manifest.parse(allocator, yaml);
    defer manifest.deinit(allocator);

    // Conflicts with csh (any version)
    try std.testing.expect(manifest.conflictsWith("csh", null));
    try std.testing.expect(manifest.conflictsWith("csh", Version{ .major = 1, .minor = 0, .patch = 0 }));

    // Conflicts with zsh < 5.0.0
    try std.testing.expect(manifest.conflictsWith("zsh", Version{ .major = 4, .minor = 9, .patch = 0 }));
    try std.testing.expect(!manifest.conflictsWith("zsh", Version{ .major = 5, .minor = 0, .patch = 0 }));
    try std.testing.expect(!manifest.conflictsWith("zsh", Version{ .major = 5, .minor = 1, .patch = 0 }));

    // Does not conflict with fish
    try std.testing.expect(!manifest.conflictsWith("fish", null));
}

test "Manifest.serialize with virtual packages" {
    const allocator = std.testing.allocator;

    const yaml =
        \\name: bash
        \\version: 5.2.0
        \\revision: 1
        \\description: GNU Bourne Again Shell
        \\provides:
        \\  - shell
        \\conflicts:
        \\  - csh
        \\
    ;

    var manifest = try Manifest.parse(allocator, yaml);
    defer manifest.deinit(allocator);

    const serialized = try manifest.serialize(allocator);
    defer allocator.free(serialized);

    // Verify the serialized output contains expected content
    try std.testing.expect(std.mem.indexOf(u8, serialized, "name: bash") != null);
    try std.testing.expect(std.mem.indexOf(u8, serialized, "provides:") != null);
    try std.testing.expect(std.mem.indexOf(u8, serialized, "- shell") != null);
    try std.testing.expect(std.mem.indexOf(u8, serialized, "conflicts:") != null);
    try std.testing.expect(std.mem.indexOf(u8, serialized, "- csh") != null);
}
