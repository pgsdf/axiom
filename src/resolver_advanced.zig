const std = @import("std");
const types = @import("types.zig");
const store = @import("store.zig");
const profile_mod = @import("profile.zig");
const manifest_mod = @import("manifest.zig");
const sat_resolver = @import("sat_resolver.zig");

const Allocator = std.mem.Allocator;
const Version = types.Version;
const VersionConstraint = types.VersionConstraint;
const Dependency = types.Dependency;
const PackageId = types.PackageId;
const PackageStore = store.PackageStore;
const Profile = profile_mod.Profile;
const Preference = profile_mod.Preference;
const Pin = profile_mod.Pin;
const Manifest = manifest_mod.Manifest;
const Feature = manifest_mod.Feature;
const SATResolver = sat_resolver.SATResolver;

// =============================================================================
// Virtual Provider Resolution
// =============================================================================

/// A provider that can satisfy a virtual package dependency
pub const VirtualProvider = struct {
    /// Package that provides the virtual
    package_id: PackageId,

    /// Name of the virtual being provided
    virtual_name: []const u8,

    /// Priority (higher = preferred)
    priority: i32 = 0,
};

/// Index of all virtual providers in the store
pub const VirtualProviderIndex = struct {
    allocator: Allocator,

    /// Maps virtual name -> list of providers
    providers: std.StringHashMap(std.ArrayList(VirtualProvider)),

    pub fn init(allocator: Allocator) VirtualProviderIndex {
        return .{
            .allocator = allocator,
            .providers = std.StringHashMap(std.ArrayList(VirtualProvider)).empty,
        };
    }

    pub fn deinit(self: *VirtualProviderIndex) void {
        var iter = self.providers.valueIterator();
        while (iter.next()) |list| {
            list.deinit(self.allocator);
        }
        self.providers.deinit();
    }

    /// Build index from package store
    pub fn buildFromStore(self: *VirtualProviderIndex, pkg_store: *PackageStore) !void {
        const packages = try pkg_store.listPackages();
        defer {
            for (packages) |pkg| {
                self.allocator.free(pkg.name);
                self.allocator.free(pkg.build_id);
            }
            self.allocator.free(packages);
        }

        for (packages) |pkg| {
            // Get package metadata which includes manifest
            var metadata = pkg_store.getPackage(pkg) catch continue;
            defer {
                metadata.manifest.deinit(self.allocator);
                self.allocator.free(metadata.dataset_path);
            }

            for (metadata.manifest.provides) |virtual_name| {
                try self.addProvider(virtual_name, pkg, 0);
            }
        }
    }

    /// Add a provider for a virtual
    pub fn addProvider(self: *VirtualProviderIndex, virtual_name: []const u8, pkg_id: PackageId, priority: i32) !void {
        const gop = try self.providers.getOrPut(virtual_name);
        if (!gop.found_existing) {
            gop.value_ptr.* = .empty;
        }

        try gop.value_ptr.append(self.allocator, .{
            .package_id = pkg_id,
            .virtual_name = virtual_name,
            .priority = priority,
        });
    }

    /// Get all providers for a virtual
    pub fn getProviders(self: *VirtualProviderIndex, virtual_name: []const u8) ?[]const VirtualProvider {
        if (self.providers.get(virtual_name)) |list| {
            return list.items;
        }
        return null;
    }

    /// Check if a virtual is provided by any package
    pub fn hasProviders(self: *VirtualProviderIndex, virtual_name: []const u8) bool {
        return self.providers.contains(virtual_name);
    }
};

// =============================================================================
// Feature Flag Resolution
// =============================================================================

/// Resolved feature configuration for a package
pub const ResolvedFeatures = struct {
    /// Package this applies to
    package_name: []const u8,

    /// Enabled features
    enabled: std.StringHashMap(void),

    /// Additional dependencies from enabled features
    feature_deps: std.ArrayList(Dependency),

    allocator: Allocator,

    pub fn init(allocator: Allocator, package_name: []const u8) ResolvedFeatures {
        return .{
            .allocator = allocator,
            .package_name = package_name,
            .enabled = std.StringHashMap(void).init(allocator),
            .feature_deps = std.ArrayList(Dependency).empty,
        };
    }

    pub fn deinit(self: *ResolvedFeatures) void {
        self.enabled.deinit();
        self.feature_deps.deinit(self.allocator);
    }

    /// Enable a feature
    pub fn enableFeature(self: *ResolvedFeatures, feature_name: []const u8) !void {
        try self.enabled.put(feature_name, {});
    }

    /// Check if a feature is enabled
    pub fn isEnabled(self: *ResolvedFeatures, feature_name: []const u8) bool {
        return self.enabled.contains(feature_name);
    }
};

/// Feature resolver for handling feature flags
pub const FeatureResolver = struct {
    allocator: Allocator,

    /// Per-package resolved features
    package_features: std.StringHashMap(ResolvedFeatures),

    pub fn init(allocator: Allocator) FeatureResolver {
        return .{
            .allocator = allocator,
            .package_features = std.StringHashMap(ResolvedFeatures).init(allocator),
        };
    }

    pub fn deinit(self: *FeatureResolver) void {
        var iter = self.package_features.valueIterator();
        while (iter.next()) |rf| {
            rf.deinit();
        }
        self.package_features.deinit();
    }

    /// Resolve features for a package given manifest and request
    pub fn resolveFeatures(
        self: *FeatureResolver,
        manifest: *const Manifest,
        requested_features: []const []const u8,
        disabled_features: []const []const u8,
    ) !*ResolvedFeatures {
        const gop = try self.package_features.getOrPut(manifest.name);
        if (!gop.found_existing) {
            gop.value_ptr.* = ResolvedFeatures.init(self.allocator, manifest.name);
        }

        var resolved = gop.value_ptr;

        // Start with default features
        for (manifest.default_features) |default_feat| {
            // Skip if explicitly disabled
            var is_disabled = false;
            for (disabled_features) |disabled| {
                if (std.mem.eql(u8, default_feat, disabled)) {
                    is_disabled = true;
                    break;
                }
            }
            if (!is_disabled) {
                try resolved.enableFeature(default_feat);
            }
        }

        // Add explicitly requested features
        for (requested_features) |feat| {
            try resolved.enableFeature(feat);
        }

        // Process implies relationships (transitive closure)
        var changed = true;
        while (changed) {
            changed = false;
            for (manifest.features) |feature| {
                if (resolved.isEnabled(feature.name)) {
                    for (feature.implies) |implied| {
                        if (!resolved.isEnabled(implied)) {
                            try resolved.enableFeature(implied);
                            changed = true;
                        }
                    }
                }
            }
        }

        // Collect dependencies from enabled features
        for (manifest.features) |feature| {
            if (resolved.isEnabled(feature.name)) {
                for (feature.dependencies) |dep| {
                    try resolved.feature_deps.append(self.allocator, dep);
                }
            }
        }

        return resolved;
    }

    /// Check for feature conflicts
    pub fn checkConflicts(self: *FeatureResolver, manifest: *const Manifest) !?[]const u8 {
        const resolved = self.package_features.get(manifest.name) orelse return null;

        for (manifest.features) |feature| {
            if (resolved.isEnabled(feature.name)) {
                for (feature.conflicts_with) |conflict| {
                    if (resolved.isEnabled(conflict)) {
                        return feature.name;
                    }
                }
            }
        }

        return null;
    }
};

// =============================================================================
// Dependency Chain Explanation (why-depends)
// =============================================================================

/// A step in a dependency chain
pub const DependencyStep = struct {
    /// Package at this step
    package: PackageId,

    /// Dependency that led to the next step (null for root)
    dependency: ?Dependency = null,

    /// Reason for this dependency
    reason: Reason = .direct,

    pub const Reason = enum {
        direct,      // Directly requested
        dependency,  // Required by another package
        virtual,     // Provides a virtual
        feature,     // Required by a feature
    };
};

/// Explains why a package is in the resolution
pub const DependencyExplanation = struct {
    allocator: Allocator,

    /// The package being explained
    target: PackageId,

    /// All paths from root packages to this target
    paths: std.ArrayList(std.ArrayList(DependencyStep)),

    pub fn init(allocator: Allocator, target: PackageId) DependencyExplanation {
        return .{
            .allocator = allocator,
            .target = target,
            .paths = std.ArrayList(std.ArrayList(DependencyStep)).empty,
        };
    }

    pub fn deinit(self: *DependencyExplanation) void {
        for (self.paths.items) |*path| {
            path.deinit(self.allocator);
        }
        self.paths.deinit(self.allocator);
    }

    /// Add a dependency path
    pub fn addPath(self: *DependencyExplanation, steps: []const DependencyStep) !void {
        var path: std.ArrayList(DependencyStep) = .empty;
        try path.appendSlice(self.allocator, steps);
        try self.paths.append(self.allocator, path);
    }

    /// Format explanation for display
    pub fn format(self: *DependencyExplanation, writer: anytype) !void {
        try writer.print("Package {s} {f} is required because:\n", .{
            self.target.name,
            self.target.version,
        });

        for (self.paths.items, 0..) |path, i| {
            try writer.print("\n  Path {d}:\n", .{i + 1});
            for (path.items, 0..) |step, j| {
                const indent = "    " ** (j + 1);
                switch (step.reason) {
                    .direct => try writer.print("{s}{s} {f} (directly requested)\n", .{
                        indent,
                        step.package.name,
                        step.package.version,
                    }),
                    .dependency => try writer.print("{s}{s} {f} (dependency of previous)\n", .{
                        indent,
                        step.package.name,
                        step.package.version,
                    }),
                    .virtual => try writer.print("{s}{s} {f} (provides virtual)\n", .{
                        indent,
                        step.package.name,
                        step.package.version,
                    }),
                    .feature => try writer.print("{s}{s} {f} (required by feature)\n", .{
                        indent,
                        step.package.name,
                        step.package.version,
                    }),
                }
            }
        }
    }
};

// =============================================================================
// Preference and Pin Handling
// =============================================================================

/// Handles version preferences and pins
pub const PreferenceHandler = struct {
    allocator: Allocator,

    /// Version pins (exact version requirements)
    pins: std.StringHashMap(Pin),

    /// Version preferences (soft constraints)
    preferences: std.StringHashMap(Preference),

    pub fn init(allocator: Allocator) PreferenceHandler {
        return .{
            .allocator = allocator,
            .pins = std.StringHashMap(Pin).init(allocator),
            .preferences = std.StringHashMap(Preference).init(allocator),
        };
    }

    pub fn deinit(self: *PreferenceHandler) void {
        self.pins.deinit();
        self.preferences.deinit();
    }

    /// Load preferences and pins from profile
    pub fn loadFromProfile(self: *PreferenceHandler, prof: *const Profile) !void {
        for (prof.pins) |pin| {
            try self.pins.put(pin.name, pin);
        }
        for (prof.preferences) |pref| {
            try self.preferences.put(pref.name, pref);
        }
    }

    /// Get pin for a package
    pub fn getPin(self: *PreferenceHandler, package_name: []const u8) ?*const Pin {
        return self.pins.getPtr(package_name);
    }

    /// Get preference for a package
    pub fn getPreference(self: *PreferenceHandler, package_name: []const u8) ?*const Preference {
        return self.preferences.getPtr(package_name);
    }

    /// Calculate weight for a version based on preferences
    pub fn calculateWeight(self: *PreferenceHandler, package_name: []const u8, version: Version) i32 {
        const pref = self.preferences.get(package_name) orelse return 0;

        var weight: i32 = 0;

        // Check if version matches prefer pattern
        if (pref.prefer) |prefer_pattern| {
            if (matchesPattern(version, prefer_pattern)) {
                weight += pref.weight;
            }
        }

        // Check if version matches avoid pattern
        if (pref.avoid) |avoid_pattern| {
            if (matchesPattern(version, avoid_pattern)) {
                weight -= pref.weight;
            }
        }

        return weight;
    }

    /// Check if a version matches a pattern like "3.11.*"
    fn matchesPattern(version: Version, pattern: []const u8) bool {
        // Simple pattern matching: "X.Y.*" or "X.*" or exact "X.Y.Z"
        var parts = std.mem.splitScalar(u8, pattern, '.');

        // Major version
        const major_str = parts.next() orelse return false;
        if (std.mem.eql(u8, major_str, "*")) return true;
        const major = std.fmt.parseInt(u32, major_str, 10) catch return false;
        if (version.major != major) return false;

        // Minor version
        const minor_str = parts.next() orelse return true; // "X" matches X.*
        if (std.mem.eql(u8, minor_str, "*")) return true;
        const minor = std.fmt.parseInt(u32, minor_str, 10) catch return false;
        if (version.minor != minor) return false;

        // Patch version
        const patch_str = parts.next() orelse return true; // "X.Y" matches X.Y.*
        if (std.mem.eql(u8, patch_str, "*")) return true;
        const patch = std.fmt.parseInt(u32, patch_str, 10) catch return false;
        if (version.patch != patch) return false;

        return true;
    }
};

// =============================================================================
// Advanced Resolver (combines all features)
// =============================================================================

/// Advanced resolver with support for virtuals, features, preferences
pub const AdvancedResolver = struct {
    allocator: Allocator,

    /// Base SAT resolver
    sat_resolver: SATResolver,

    /// Virtual provider index
    virtual_index: VirtualProviderIndex,

    /// Feature resolver
    feature_resolver: FeatureResolver,

    /// Preference handler
    preference_handler: PreferenceHandler,

    /// Package store reference
    pkg_store: *PackageStore,

    pub fn init(allocator: Allocator, pkg_store: *PackageStore) AdvancedResolver {
        return .{
            .allocator = allocator,
            .sat_resolver = SATResolver.empty,
            .virtual_index = VirtualProviderIndex.empty,
            .feature_resolver = FeatureResolver.empty,
            .preference_handler = PreferenceHandler.empty,
            .pkg_store = pkg_store,
        };
    }

    pub fn deinit(self: *AdvancedResolver) void {
        self.sat_resolver.deinit();
        self.virtual_index.deinit();
        self.feature_resolver.deinit();
        self.preference_handler.deinit();
    }

    /// Build virtual provider index from store
    pub fn buildVirtualIndex(self: *AdvancedResolver) !void {
        try self.virtual_index.buildFromStore(self.pkg_store);
    }

    /// Load preferences from profile
    pub fn loadPreferences(self: *AdvancedResolver, prof: *const Profile) !void {
        try self.preference_handler.loadFromProfile(prof);
    }

    /// Get alternatives for a virtual package
    pub fn getAlternatives(self: *AdvancedResolver, virtual_name: []const u8) ?[]const VirtualProvider {
        return self.virtual_index.getProviders(virtual_name);
    }

    /// Check if a name is a virtual package
    pub fn isVirtual(self: *AdvancedResolver, name: []const u8) bool {
        return self.virtual_index.hasProviders(name);
    }

    /// Explain why a package is in the resolution
    pub fn explainDependency(
        self: *AdvancedResolver,
        target: PackageId,
        resolved: []const PackageId,
        direct_requests: []const []const u8,
    ) !DependencyExplanation {
        var explanation = DependencyExplanation.init(self.allocator, target);

        // Build dependency graph from resolved packages
        // Then find all paths from direct requests to target
        // This is a simplified implementation

        // Check if target is directly requested
        for (direct_requests) |req| {
            if (std.mem.eql(u8, req, target.name)) {
                var path: std.ArrayList(DependencyStep) = .empty;
                try path.append(self.allocator, .{
                    .package = target,
                    .reason = .direct,
                });
                try explanation.paths.append(self.allocator, path);
            }
        }

        // For indirect dependencies, we'd need to trace the dependency graph
        // This is a placeholder for the full implementation
        _ = resolved;

        return explanation;
    }
};

// =============================================================================
// Tests
// =============================================================================

test "PreferenceHandler.matchesPattern" {
    const v311 = Version{ .major = 3, .minor = 11, .patch = 0 };
    const v312 = Version{ .major = 3, .minor = 12, .patch = 0 };

    try std.testing.expect(PreferenceHandler.matchesPattern(v311, "3.11.*"));
    try std.testing.expect(!PreferenceHandler.matchesPattern(v312, "3.11.*"));
    try std.testing.expect(PreferenceHandler.matchesPattern(v311, "3.*"));
    try std.testing.expect(PreferenceHandler.matchesPattern(v312, "3.*"));
    try std.testing.expect(!PreferenceHandler.matchesPattern(v311, "2.*"));
}

test "VirtualProviderIndex" {
    const _allocator = std.testing.allocator;
    var index = VirtualProviderIndex.empty;
    defer index.deinit();

    const pkg1 = PackageId{
        .name = "openssl",
        .version = .{ .major = 3, .minor = 0, .patch = 0 },
        .revision = 1,
        .build_id = "abc123",
    };

    try index.addProvider("ssl-library", pkg1, 0);
    try index.addProvider("crypto-library", pkg1, 0);

    try std.testing.expect(index.hasProviders("ssl-library"));
    try std.testing.expect(index.hasProviders("crypto-library"));
    try std.testing.expect(!index.hasProviders("nonexistent"));

    const providers = index.getProviders("ssl-library").?;
    try std.testing.expectEqual(@as(usize, 1), providers.len);
}

test "FeatureResolver.basic" {
    const _allocator = std.testing.allocator;
    var resolver = FeatureResolver.empty;
    defer resolver.deinit();

    // Mock manifest with features
    const manifest = Manifest{
        .name = "test-pkg",
        .version = .{ .major = 1, .minor = 0, .patch = 0 },
        .revision = 1,
        .default_features = &[_][]const u8{"ssl"},
        .features = &[_]Feature{},
    };

    const requested = &[_][]const u8{"gui"};
    const disabled = &[_][]const u8{};

    const resolved = try resolver.resolveFeatures(&manifest, requested, disabled);
    try std.testing.expect(resolved.isEnabled("ssl"));
    try std.testing.expect(resolved.isEnabled("gui"));
}
