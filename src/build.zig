const std = @import("std");
const zfs = @import("zfs.zig");
const types = @import("types.zig");
const store = @import("store.zig");
const manifest = @import("manifest.zig");
const import_pkg = @import("import.zig");

const ZfsHandle = zfs.ZfsHandle;
const PackageId = types.PackageId;
const PackageStore = store.PackageStore;
const Version = types.Version;
const Dependency = types.Dependency;
const VersionConstraint = types.VersionConstraint;
const Importer = import_pkg.Importer;

/// Build system errors
pub const BuildError = error{
    RecipeNotFound,
    InvalidRecipe,
    SourceFetchFailed,
    SandboxCreationFailed,
    DependencyNotFound,
    PhaseFailed,
    OutputCollectionFailed,
    ChecksumMismatch,
};

/// Source specification for a build
pub const Source = struct {
    url: ?[]const u8 = null,
    path: ?[]const u8 = null,
    sha256: ?[]const u8 = null,
    git_url: ?[]const u8 = null,
    git_ref: ?[]const u8 = null,

    pub fn deinit(self: *Source, allocator: std.mem.Allocator) void {
        if (self.url) |u| allocator.free(u);
        if (self.path) |p| allocator.free(p);
        if (self.sha256) |s| allocator.free(s);
        if (self.git_url) |g| allocator.free(g);
        if (self.git_ref) |r| allocator.free(r);
    }
};

/// A single build phase
pub const BuildPhase = struct {
    name: []const u8,
    command: []const u8,
    working_dir: ?[]const u8 = null,
    environment: ?std.StringHashMap([]const u8) = null,
    optional: bool = false,

    pub fn deinit(self: *BuildPhase, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.command);
        if (self.working_dir) |w| allocator.free(w);
        if (self.environment) |*env| {
            var iter = env.iterator();
            while (iter.next()) |entry| {
                allocator.free(entry.key_ptr.*);
                allocator.free(entry.value_ptr.*);
            }
            env.deinit();
        }
    }
};

/// Output configuration
pub const OutputConfig = struct {
    strip_binaries: bool = true,
    compress_man: bool = true,
    include_patterns: ?[]const []const u8 = null,
    exclude_patterns: ?[]const []const u8 = null,

    pub fn deinit(self: *OutputConfig, allocator: std.mem.Allocator) void {
        if (self.include_patterns) |patterns| {
            for (patterns) |p| allocator.free(p);
            allocator.free(patterns);
        }
        if (self.exclude_patterns) |patterns| {
            for (patterns) |p| allocator.free(p);
            allocator.free(patterns);
        }
    }
};

/// Build recipe
pub const BuildRecipe = struct {
    allocator: std.mem.Allocator,
    name: []const u8,
    version: Version,
    revision: u32 = 1,
    description: ?[]const u8 = null,
    license: ?[]const u8 = null,
    homepage: ?[]const u8 = null,
    source: Source,
    build_deps: std.ArrayList(Dependency),
    runtime_deps: std.ArrayList(Dependency),
    phases: std.ArrayList(BuildPhase),
    output: OutputConfig,

    pub fn init(allocator: std.mem.Allocator) BuildRecipe {
        return BuildRecipe{
            .allocator = allocator,
            .name = "",
            .version = Version{ .major = 0, .minor = 0, .patch = 0 },
            .source = Source{},
            .build_deps = std.ArrayList(Dependency).init(allocator),
            .runtime_deps = std.ArrayList(Dependency).init(allocator),
            .phases = std.ArrayList(BuildPhase).init(allocator),
            .output = OutputConfig{},
        };
    }

    pub fn deinit(self: *BuildRecipe) void {
        self.allocator.free(self.name);
        if (self.description) |d| self.allocator.free(d);
        if (self.license) |l| self.allocator.free(l);
        if (self.homepage) |h| self.allocator.free(h);
        self.source.deinit(self.allocator);

        for (self.build_deps.items) |*dep| {
            self.allocator.free(dep.name);
        }
        self.build_deps.deinit();

        for (self.runtime_deps.items) |*dep| {
            self.allocator.free(dep.name);
        }
        self.runtime_deps.deinit();

        for (self.phases.items) |*phase| {
            phase.deinit(self.allocator);
        }
        self.phases.deinit();

        self.output.deinit(self.allocator);
    }

    /// Parse a build recipe from YAML content
    pub fn parse(allocator: std.mem.Allocator, content: []const u8) !BuildRecipe {
        var recipe = BuildRecipe.init(allocator);
        errdefer recipe.deinit();

        var lines = std.mem.splitSequence(u8, content, "\n");
        var current_section: enum { none, source, build_deps, runtime_deps, phases, phase_env, output } = .none;
        var current_phase: ?*BuildPhase = null;
        var in_phase_block = false;
        var phase_indent: usize = 0;

        while (lines.next()) |line| {
            const trimmed = std.mem.trim(u8, line, " \t\r");
            if (trimmed.len == 0 or trimmed[0] == '#') continue;

            // Count leading spaces for indentation
            var indent: usize = 0;
            for (line) |c| {
                if (c == ' ') indent += 1 else if (c == '\t') indent += 2 else break;
            }

            // Top-level keys
            if (indent == 0) {
                current_section = .none;
                in_phase_block = false;
                current_phase = null;

                if (std.mem.startsWith(u8, trimmed, "name:")) {
                    recipe.name = try allocator.dupe(u8, std.mem.trim(u8, trimmed[5..], " \t\""));
                } else if (std.mem.startsWith(u8, trimmed, "version:")) {
                    const ver_str = std.mem.trim(u8, trimmed[8..], " \t\"");
                    recipe.version = try Version.parse(ver_str);
                } else if (std.mem.startsWith(u8, trimmed, "revision:")) {
                    const rev_str = std.mem.trim(u8, trimmed[9..], " \t");
                    recipe.revision = try std.fmt.parseInt(u32, rev_str, 10);
                } else if (std.mem.startsWith(u8, trimmed, "description:")) {
                    recipe.description = try allocator.dupe(u8, std.mem.trim(u8, trimmed[12..], " \t\""));
                } else if (std.mem.startsWith(u8, trimmed, "license:")) {
                    recipe.license = try allocator.dupe(u8, std.mem.trim(u8, trimmed[8..], " \t\""));
                } else if (std.mem.startsWith(u8, trimmed, "homepage:")) {
                    recipe.homepage = try allocator.dupe(u8, std.mem.trim(u8, trimmed[9..], " \t\""));
                } else if (std.mem.eql(u8, trimmed, "source:")) {
                    current_section = .source;
                } else if (std.mem.eql(u8, trimmed, "build_dependencies:")) {
                    current_section = .build_deps;
                } else if (std.mem.eql(u8, trimmed, "runtime_dependencies:")) {
                    current_section = .runtime_deps;
                } else if (std.mem.eql(u8, trimmed, "phases:")) {
                    current_section = .phases;
                } else if (std.mem.eql(u8, trimmed, "output:")) {
                    current_section = .output;
                }
                continue;
            }

            // Section content
            switch (current_section) {
                .source => {
                    if (std.mem.startsWith(u8, trimmed, "url:")) {
                        recipe.source.url = try allocator.dupe(u8, std.mem.trim(u8, trimmed[4..], " \t\""));
                    } else if (std.mem.startsWith(u8, trimmed, "path:")) {
                        recipe.source.path = try allocator.dupe(u8, std.mem.trim(u8, trimmed[5..], " \t\""));
                    } else if (std.mem.startsWith(u8, trimmed, "sha256:")) {
                        recipe.source.sha256 = try allocator.dupe(u8, std.mem.trim(u8, trimmed[7..], " \t\""));
                    } else if (std.mem.startsWith(u8, trimmed, "git:")) {
                        recipe.source.git_url = try allocator.dupe(u8, std.mem.trim(u8, trimmed[4..], " \t\""));
                    } else if (std.mem.startsWith(u8, trimmed, "ref:")) {
                        recipe.source.git_ref = try allocator.dupe(u8, std.mem.trim(u8, trimmed[4..], " \t\""));
                    }
                },
                .build_deps, .runtime_deps => {
                    if (std.mem.startsWith(u8, trimmed, "- name:")) {
                        const dep_name = try allocator.dupe(u8, std.mem.trim(u8, trimmed[7..], " \t\""));
                        const dep = Dependency{
                            .name = dep_name,
                            .constraint = VersionConstraint{ .any = {} },
                        };
                        if (current_section == .build_deps) {
                            try recipe.build_deps.append(dep);
                        } else {
                            try recipe.runtime_deps.append(dep);
                        }
                    }
                },
                .phases => {
                    // Phase definitions like "configure:", "build:", etc.
                    if (trimmed.len > 0 and trimmed[trimmed.len - 1] == ':' and indent <= 2) {
                        const phase_name = try allocator.dupe(u8, trimmed[0 .. trimmed.len - 1]);
                        const phase = BuildPhase{
                            .name = phase_name,
                            .command = "",
                        };
                        try recipe.phases.append(phase);
                        current_phase = &recipe.phases.items[recipe.phases.items.len - 1];
                        in_phase_block = true;
                        phase_indent = indent;
                    } else if (in_phase_block and current_phase != null) {
                        if (std.mem.startsWith(u8, trimmed, "command:")) {
                            const cmd = std.mem.trim(u8, trimmed[8..], " \t\"");
                            if (current_phase.?.command.len > 0) {
                                allocator.free(current_phase.?.command);
                            }
                            current_phase.?.command = try allocator.dupe(u8, cmd);
                        } else if (std.mem.startsWith(u8, trimmed, "optional:")) {
                            const val = std.mem.trim(u8, trimmed[9..], " \t");
                            current_phase.?.optional = std.mem.eql(u8, val, "true");
                        } else if (std.mem.startsWith(u8, trimmed, "working_dir:")) {
                            current_phase.?.working_dir = try allocator.dupe(u8, std.mem.trim(u8, trimmed[12..], " \t\""));
                        }
                    }
                },
                .output => {
                    if (std.mem.startsWith(u8, trimmed, "strip_binaries:")) {
                        const val = std.mem.trim(u8, trimmed[15..], " \t");
                        recipe.output.strip_binaries = std.mem.eql(u8, val, "true");
                    } else if (std.mem.startsWith(u8, trimmed, "compress_man:")) {
                        const val = std.mem.trim(u8, trimmed[13..], " \t");
                        recipe.output.compress_man = std.mem.eql(u8, val, "true");
                    }
                },
                else => {},
            }
        }

        // Verify required fields
        if (recipe.name.len == 0) {
            return BuildError.InvalidRecipe;
        }

        return recipe;
    }

    /// Load a build recipe from file
    pub fn loadFromFile(allocator: std.mem.Allocator, path: []const u8) !BuildRecipe {
        const file = std.fs.cwd().openFile(path, .{}) catch {
            return BuildError.RecipeNotFound;
        };
        defer file.close();

        const content = try file.readToEndAlloc(allocator, 10 * 1024 * 1024);
        defer allocator.free(content);

        return try parse(allocator, content);
    }
};

/// Build options
pub const BuildOptions = struct {
    jobs: u32 = 4,
    no_test: bool = false,
    dry_run: bool = false,
    keep_sandbox: bool = false,
    import_result: bool = true,
    verbose: bool = false,
};

/// Build sandbox for isolated builds
pub const BuildSandbox = struct {
    allocator: std.mem.Allocator,
    zfs_handle: *ZfsHandle,
    dataset: []const u8,
    mount_point: []const u8,
    source_dir: []const u8,
    output_dir: []const u8,
    env_vars: std.StringHashMap([]const u8),

    pub fn init(
        allocator: std.mem.Allocator,
        zfs_handle: *ZfsHandle,
        recipe: *const BuildRecipe,
    ) !BuildSandbox {
        const timestamp = std.time.timestamp();

        // Create sandbox dataset name
        const dataset = try std.fmt.allocPrint(
            allocator,
            "axiom/build/{s}-{d}",
            .{ recipe.name, timestamp },
        );
        errdefer allocator.free(dataset);

        // Create ZFS dataset for sandbox
        std.debug.print("Creating build sandbox: {s}\n", .{dataset});
        try zfs_handle.createDataset(allocator, dataset, null);

        // Get mount point
        const mount_point = try std.fmt.allocPrint(
            allocator,
            "/{s}",
            .{dataset},
        );
        errdefer allocator.free(mount_point);

        // Create directory structure
        const source_dir = try std.fs.path.join(allocator, &[_][]const u8{ mount_point, "src" });
        errdefer allocator.free(source_dir);

        const output_dir = try std.fs.path.join(allocator, &[_][]const u8{ mount_point, "output" });
        errdefer allocator.free(output_dir);

        try std.fs.cwd().makePath(source_dir);
        try std.fs.cwd().makePath(output_dir);

        // Set up environment variables
        var env_vars = std.StringHashMap([]const u8).init(allocator);
        try env_vars.put(try allocator.dupe(u8, "OUTPUT"), try allocator.dupe(u8, output_dir));
        try env_vars.put(try allocator.dupe(u8, "SRCDIR"), try allocator.dupe(u8, source_dir));
        try env_vars.put(try allocator.dupe(u8, "JOBS"), try std.fmt.allocPrint(allocator, "{d}", .{@as(u32, 4)}));

        return BuildSandbox{
            .allocator = allocator,
            .zfs_handle = zfs_handle,
            .dataset = dataset,
            .mount_point = mount_point,
            .source_dir = source_dir,
            .output_dir = output_dir,
            .env_vars = env_vars,
        };
    }

    pub fn deinit(self: *BuildSandbox) void {
        var iter = self.env_vars.iterator();
        while (iter.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.env_vars.deinit();
        self.allocator.free(self.source_dir);
        self.allocator.free(self.output_dir);
        self.allocator.free(self.mount_point);
        self.allocator.free(self.dataset);
    }

    /// Destroy the sandbox dataset
    pub fn destroy(self: *BuildSandbox) !void {
        std.debug.print("Destroying build sandbox: {s}\n", .{self.dataset});
        try self.zfs_handle.destroyDataset(self.allocator, self.dataset, true);
    }

    /// Set environment variable for builds
    pub fn setEnv(self: *BuildSandbox, key: []const u8, value: []const u8) !void {
        const key_copy = try self.allocator.dupe(u8, key);
        const value_copy = try self.allocator.dupe(u8, value);
        try self.env_vars.put(key_copy, value_copy);
    }

    /// Get the environment as a null-terminated array for spawn
    pub fn getEnvp(self: *BuildSandbox) ![]const [*:0]const u8 {
        var envp = std.ArrayList([*:0]const u8).init(self.allocator);
        errdefer envp.deinit();

        var iter = self.env_vars.iterator();
        while (iter.next()) |entry| {
            const env_str = try std.fmt.allocPrintZ(
                self.allocator,
                "{s}={s}",
                .{ entry.key_ptr.*, entry.value_ptr.* },
            );
            try envp.append(env_str.ptr);
        }

        return envp.toOwnedSlice();
    }
};

/// Package builder
pub const Builder = struct {
    allocator: std.mem.Allocator,
    zfs_handle: *ZfsHandle,
    store: *PackageStore,
    importer: *Importer,

    pub fn init(
        allocator: std.mem.Allocator,
        zfs_handle: *ZfsHandle,
        store_ptr: *PackageStore,
        importer: *Importer,
    ) Builder {
        return Builder{
            .allocator = allocator,
            .zfs_handle = zfs_handle,
            .store = store_ptr,
            .importer = importer,
        };
    }

    /// Build a package from a recipe
    pub fn build(self: *Builder, recipe: *BuildRecipe, options: BuildOptions) !PackageId {
        std.debug.print("\n=== Building {s} {d}.{d}.{d} ===\n\n", .{
            recipe.name,
            recipe.version.major,
            recipe.version.minor,
            recipe.version.patch,
        });

        if (options.dry_run) {
            try self.showBuildPlan(recipe, options);
            return PackageId{
                .name = recipe.name,
                .version = recipe.version,
                .revision = recipe.revision,
                .build_id = "dry-run",
            };
        }

        // Create build sandbox
        var sandbox = try BuildSandbox.init(self.allocator, self.zfs_handle, recipe);
        defer sandbox.deinit();
        defer {
            if (!options.keep_sandbox) {
                sandbox.destroy() catch |err| {
                    std.debug.print("Warning: Failed to destroy sandbox: {}\n", .{err});
                };
            }
        }

        // Set job count
        try sandbox.setEnv("JOBS", try std.fmt.allocPrint(self.allocator, "{d}", .{options.jobs}));

        // Inject build dependencies
        try self.injectDependencies(&sandbox, recipe.build_deps.items);

        // Fetch source
        try self.fetchSource(&sandbox, &recipe.source);

        // Execute build phases
        for (recipe.phases.items) |*phase| {
            // Skip test phase if --no-test
            if (options.no_test and std.mem.eql(u8, phase.name, "test")) {
                std.debug.print("Skipping test phase (--no-test)\n", .{});
                continue;
            }

            try self.executePhase(&sandbox, phase, options);
        }

        // Post-process output
        try self.postProcessOutput(&sandbox, &recipe.output);

        // Import result
        if (options.import_result) {
            return try self.importResult(&sandbox, recipe);
        }

        return PackageId{
            .name = recipe.name,
            .version = recipe.version,
            .revision = recipe.revision,
            .build_id = "not-imported",
        };
    }

    /// Show build plan without executing
    fn showBuildPlan(self: *Builder, recipe: *BuildRecipe, options: BuildOptions) !void {
        _ = self;

        std.debug.print("DRY RUN - Build plan for {s}:\n\n", .{recipe.name});

        std.debug.print("Source:\n", .{});
        if (recipe.source.url) |url| {
            std.debug.print("  URL: {s}\n", .{url});
        }
        if (recipe.source.path) |path| {
            std.debug.print("  Path: {s}\n", .{path});
        }
        if (recipe.source.git_url) |git| {
            std.debug.print("  Git: {s}\n", .{git});
            if (recipe.source.git_ref) |ref| {
                std.debug.print("  Ref: {s}\n", .{ref});
            }
        }

        std.debug.print("\nBuild dependencies:\n", .{});
        for (recipe.build_deps.items) |dep| {
            std.debug.print("  - {s}\n", .{dep.name});
        }

        std.debug.print("\nRuntime dependencies:\n", .{});
        for (recipe.runtime_deps.items) |dep| {
            std.debug.print("  - {s}\n", .{dep.name});
        }

        std.debug.print("\nBuild phases:\n", .{});
        for (recipe.phases.items) |phase| {
            if (options.no_test and std.mem.eql(u8, phase.name, "test")) {
                std.debug.print("  {s}: (skipped)\n", .{phase.name});
            } else {
                std.debug.print("  {s}: {s}\n", .{ phase.name, phase.command });
            }
        }

        std.debug.print("\nOutput settings:\n", .{});
        std.debug.print("  Strip binaries: {}\n", .{recipe.output.strip_binaries});
        std.debug.print("  Compress man pages: {}\n", .{recipe.output.compress_man});
    }

    /// Inject build dependencies into sandbox
    fn injectDependencies(self: *Builder, sandbox: *BuildSandbox, deps: []const Dependency) !void {
        _ = self;

        if (deps.len == 0) {
            std.debug.print("No build dependencies to inject\n", .{});
            return;
        }

        std.debug.print("Injecting {d} build dependencies...\n", .{deps.len});

        // Create deps directory in sandbox
        const deps_dir = try std.fs.path.join(sandbox.allocator, &[_][]const u8{ sandbox.mount_point, "deps" });
        defer sandbox.allocator.free(deps_dir);

        try std.fs.cwd().makePath(deps_dir);

        // Set PATH to include deps
        const deps_bin = try std.fs.path.join(sandbox.allocator, &[_][]const u8{ deps_dir, "bin" });
        defer sandbox.allocator.free(deps_bin);

        try std.fs.cwd().makePath(deps_bin);

        // Update PATH
        try sandbox.setEnv("PATH", try std.fmt.allocPrint(
            sandbox.allocator,
            "{s}:/usr/bin:/bin",
            .{deps_bin},
        ));

        // TODO: Actually link packages from store into deps directory
        // For now, just report what would be injected
        for (deps) |dep| {
            std.debug.print("  - {s}\n", .{dep.name});
        }
    }

    /// Fetch source into sandbox
    fn fetchSource(self: *Builder, sandbox: *BuildSandbox, source: *const Source) !void {
        std.debug.print("Fetching source...\n", .{});

        if (source.url) |url| {
            try self.fetchUrl(sandbox, url, source.sha256);
        } else if (source.path) |path| {
            try self.copyLocalSource(sandbox, path);
        } else if (source.git_url) |git_url| {
            try self.cloneGit(sandbox, git_url, source.git_ref);
        } else {
            std.debug.print("Warning: No source specified\n", .{});
        }
    }

    /// Fetch source from URL
    fn fetchUrl(self: *Builder, sandbox: *BuildSandbox, url: []const u8, expected_sha256: ?[]const u8) !void {
        std.debug.print("  Downloading: {s}\n", .{url});

        // Determine filename from URL
        const filename = std.fs.path.basename(url);
        const download_path = try std.fs.path.join(self.allocator, &[_][]const u8{ sandbox.source_dir, filename });
        defer self.allocator.free(download_path);

        // Use curl/wget to download
        var child = std.process.Child.init(
            &[_][]const u8{ "curl", "-L", "-o", download_path, url },
            self.allocator,
        );
        child.stderr_behavior = .Pipe;

        try child.spawn();
        const stderr = try child.stderr.?.readToEndAlloc(self.allocator, 1024 * 1024);
        defer self.allocator.free(stderr);

        const term = try child.wait();

        if (term.Exited != 0) {
            std.debug.print("Download failed: {s}\n", .{stderr});
            return BuildError.SourceFetchFailed;
        }

        // Verify checksum if provided
        if (expected_sha256) |expected| {
            std.debug.print("  Verifying SHA256...\n", .{});

            var sha_child = std.process.Child.init(
                &[_][]const u8{ "sha256sum", download_path },
                self.allocator,
            );
            sha_child.stdout_behavior = .Pipe;

            try sha_child.spawn();
            const stdout = try sha_child.stdout.?.readToEndAlloc(self.allocator, 1024);
            defer self.allocator.free(stdout);
            _ = try sha_child.wait();

            // Parse hash from output (format: "hash  filename")
            if (std.mem.indexOf(u8, stdout, " ")) |space_idx| {
                const actual = stdout[0..space_idx];
                if (!std.mem.eql(u8, actual, expected)) {
                    std.debug.print("  Checksum mismatch!\n", .{});
                    std.debug.print("    Expected: {s}\n", .{expected});
                    std.debug.print("    Actual:   {s}\n", .{actual});
                    return BuildError.ChecksumMismatch;
                }
            }
            std.debug.print("  Checksum verified\n", .{});
        }

        // Extract if tarball
        if (std.mem.endsWith(u8, filename, ".tar.gz") or
            std.mem.endsWith(u8, filename, ".tgz") or
            std.mem.endsWith(u8, filename, ".tar.xz") or
            std.mem.endsWith(u8, filename, ".tar.bz2") or
            std.mem.endsWith(u8, filename, ".tar"))
        {
            std.debug.print("  Extracting...\n", .{});

            var tar_child = std.process.Child.init(
                &[_][]const u8{ "tar", "-xf", download_path, "-C", sandbox.source_dir },
                self.allocator,
            );

            try tar_child.spawn();
            _ = try tar_child.wait();
        }
    }

    /// Copy local source
    fn copyLocalSource(self: *Builder, sandbox: *BuildSandbox, path: []const u8) !void {
        std.debug.print("  Copying from: {s}\n", .{path});

        var child = std.process.Child.init(
            &[_][]const u8{ "cp", "-r", path, sandbox.source_dir },
            self.allocator,
        );

        try child.spawn();
        _ = try child.wait();
    }

    /// Clone git repository
    fn cloneGit(self: *Builder, sandbox: *BuildSandbox, git_url: []const u8, git_ref: ?[]const u8) !void {
        std.debug.print("  Cloning: {s}\n", .{git_url});

        var args = std.ArrayList([]const u8).init(self.allocator);
        defer args.deinit();

        try args.append("git");
        try args.append("clone");
        if (git_ref) |ref| {
            try args.append("--branch");
            try args.append(ref);
        }
        try args.append("--depth");
        try args.append("1");
        try args.append(git_url);
        try args.append(sandbox.source_dir);

        var child = std.process.Child.init(args.items, self.allocator);

        try child.spawn();
        const term = try child.wait();

        if (term.Exited != 0) {
            return BuildError.SourceFetchFailed;
        }
    }

    /// Execute a build phase
    fn executePhase(self: *Builder, sandbox: *BuildSandbox, phase: *const BuildPhase, options: BuildOptions) !void {
        std.debug.print("\n--- Phase: {s} ---\n", .{phase.name});
        std.debug.print("Command: {s}\n", .{phase.command});

        // Find the source subdirectory (first directory in source_dir)
        var work_dir = sandbox.source_dir;

        var dir = std.fs.cwd().openDir(sandbox.source_dir, .{ .iterate = true }) catch {
            work_dir = sandbox.source_dir;
            return;
        };
        defer dir.close();

        var iter = dir.iterate();
        while (try iter.next()) |entry| {
            if (entry.kind == .directory) {
                work_dir = try std.fs.path.join(self.allocator, &[_][]const u8{ sandbox.source_dir, entry.name });
                break;
            }
        }
        defer if (work_dir.ptr != sandbox.source_dir.ptr) self.allocator.free(work_dir);

        // Use custom working directory if specified
        const actual_work_dir = phase.working_dir orelse work_dir;

        if (options.verbose) {
            std.debug.print("Working directory: {s}\n", .{actual_work_dir});
        }

        // Prepare environment
        var env_map = try std.process.getEnvMap(self.allocator);
        defer env_map.deinit();

        // Add sandbox environment variables
        var env_iter = sandbox.env_vars.iterator();
        while (env_iter.next()) |entry| {
            try env_map.put(entry.key_ptr.*, entry.value_ptr.*);
        }

        // Add phase-specific environment
        if (phase.environment) |phase_env| {
            var phase_iter = phase_env.iterator();
            while (phase_iter.next()) |entry| {
                try env_map.put(entry.key_ptr.*, entry.value_ptr.*);
            }
        }

        // Execute command via shell
        var child = std.process.Child.init(
            &[_][]const u8{ "/bin/sh", "-c", phase.command },
            self.allocator,
        );
        child.cwd = actual_work_dir;
        child.env_map = &env_map;

        try child.spawn();
        const term = try child.wait();

        if (term.Exited != 0) {
            if (phase.optional) {
                std.debug.print("Phase {s} failed (optional, continuing)\n", .{phase.name});
            } else {
                std.debug.print("Phase {s} failed with exit code {d}\n", .{ phase.name, term.Exited });
                return BuildError.PhaseFailed;
            }
        } else {
            std.debug.print("Phase {s} completed successfully\n", .{phase.name});
        }
    }

    /// Post-process build output
    fn postProcessOutput(self: *Builder, sandbox: *BuildSandbox, output_config: *const OutputConfig) !void {
        std.debug.print("\nPost-processing output...\n", .{});

        // Strip binaries if requested
        if (output_config.strip_binaries) {
            const bin_dir = try std.fs.path.join(self.allocator, &[_][]const u8{ sandbox.output_dir, "bin" });
            defer self.allocator.free(bin_dir);

            // Check if bin directory exists
            if (std.fs.cwd().access(bin_dir, .{})) |_| {
                std.debug.print("  Stripping binaries...\n", .{});

                var child = std.process.Child.init(
                    &[_][]const u8{ "find", bin_dir, "-type", "f", "-executable", "-exec", "strip", "{}", ";" },
                    self.allocator,
                );
                try child.spawn();
                _ = try child.wait();
            } else |_| {}
        }

        // Compress man pages if requested
        if (output_config.compress_man) {
            const man_dir = try std.fs.path.join(self.allocator, &[_][]const u8{ sandbox.output_dir, "share", "man" });
            defer self.allocator.free(man_dir);

            if (std.fs.cwd().access(man_dir, .{})) |_| {
                std.debug.print("  Compressing man pages...\n", .{});

                var child = std.process.Child.init(
                    &[_][]const u8{ "find", man_dir, "-type", "f", "-name", "*.1", "-exec", "gzip", "-9", "{}", ";" },
                    self.allocator,
                );
                try child.spawn();
                _ = try child.wait();
            } else |_| {}
        }
    }

    /// Import build result into package store
    fn importResult(self: *Builder, sandbox: *BuildSandbox, recipe: *BuildRecipe) !PackageId {
        std.debug.print("\nImporting build result...\n", .{});

        const import_options = import_pkg.ImportOptions{
            .name = recipe.name,
            .version = recipe.version,
            .revision = recipe.revision,
            .description = recipe.description,
            .license = recipe.license,
            .dry_run = false,
            .auto_detect = false,
        };

        return try self.importer.import(
            import_pkg.ImportSource{ .directory = sandbox.output_dir },
            import_options,
        );
    }
};
