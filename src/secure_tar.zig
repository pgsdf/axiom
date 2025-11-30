const std = @import("std");

/// Secure tar extraction with hardened defaults
/// Prevents path traversal, symlink escapes, and other archive-based attacks
pub const SecureTarExtractor = struct {
    allocator: std.mem.Allocator,
    extraction_root: []const u8,
    options: ExtractOptions,
    /// Statistics about extraction
    stats: ExtractionStats = .{},

    /// Extraction options with secure defaults
    pub const ExtractOptions = struct {
        /// Allow symlinks in the archive (default: true, but validated)
        allow_symlinks: bool = true,
        /// Allow absolute paths (default: false - security risk)
        allow_absolute_paths: bool = false,
        /// Allow parent directory references (default: false - path traversal)
        allow_parent_refs: bool = false,
        /// Maximum path length (default: 1024)
        max_path_length: usize = 1024,
        /// Maximum file size in bytes (default: 1GB)
        max_file_size: u64 = 1024 * 1024 * 1024,
        /// Maximum total extracted size in bytes (default: 10GB)
        max_total_size: u64 = 10 * 1024 * 1024 * 1024,
        /// Permission mask to apply (default: 0o755 for dirs, 0o644 for files)
        dir_permission_mask: u32 = 0o755,
        file_permission_mask: u32 = 0o644,
        /// Strip setuid/setgid bits (default: true)
        strip_setuid: bool = true,
        /// Strip sticky bit (default: true)
        strip_sticky: bool = true,
    };

    /// Statistics gathered during extraction
    pub const ExtractionStats = struct {
        files_extracted: usize = 0,
        directories_created: usize = 0,
        symlinks_created: usize = 0,
        bytes_extracted: u64 = 0,
        paths_rejected: usize = 0,
        permissions_modified: usize = 0,
    };

    /// Errors that can occur during secure extraction
    pub const ExtractionError = error{
        /// Path contains parent directory reference (..)
        PathTraversal,
        /// Path is absolute (starts with /)
        AbsolutePath,
        /// Symlink target escapes extraction root
        SymlinkEscape,
        /// Path exceeds maximum length
        PathTooLong,
        /// Filename contains invalid characters (NUL, control chars)
        InvalidFilename,
        /// File size exceeds maximum
        FileTooLarge,
        /// Total extraction size exceeds maximum
        TotalSizeTooLarge,
        /// Archive is malformed
        MalformedArchive,
        /// I/O error during extraction
        IoError,
        /// Allocation failed
        OutOfMemory,
    };

    /// Initialize a secure tar extractor
    pub fn init(
        allocator: std.mem.Allocator,
        extraction_root: []const u8,
        options: ExtractOptions,
    ) SecureTarExtractor {
        return .{
            .allocator = allocator,
            .extraction_root = extraction_root,
            .options = options,
            .stats = .{},
        };
    }

    /// Extract a tar archive from a file path
    pub fn extractFromPath(self: *SecureTarExtractor, tar_path: []const u8) !void {
        const file = std.fs.cwd().openFile(tar_path, .{}) catch |err| {
            std.debug.print("SecureTarExtractor: Failed to open {s}: {}\n", .{ tar_path, err });
            return ExtractionError.IoError;
        };
        defer file.close();

        try self.extractFromFile(file);
    }

    /// Extract a tar archive from a file handle
    pub fn extractFromFile(self: *SecureTarExtractor, file: std.fs.File) !void {
        // Get file reader
        var reader = file.reader();

        // Detect and handle compression
        // Read magic bytes to detect compression type
        var magic: [6]u8 = undefined;
        const bytes_read = reader.readAll(&magic) catch |err| {
            std.debug.print("SecureTarExtractor: Failed to read magic bytes: {}\n", .{err});
            return ExtractionError.IoError;
        };

        // Seek back to start
        file.seekTo(0) catch |err| {
            std.debug.print("SecureTarExtractor: Failed to seek: {}\n", .{err});
            return ExtractionError.IoError;
        };

        if (bytes_read >= 2 and magic[0] == 0x1f and magic[1] == 0x8b) {
            // gzip compressed
            try self.extractGzip(file);
        } else if (bytes_read >= 6 and std.mem.eql(u8, magic[0..6], &[_]u8{ 0xfd, '7', 'z', 'X', 'Z', 0x00 })) {
            // xz compressed
            try self.extractXz(file);
        } else if (bytes_read >= 4 and magic[0] == 0x28 and magic[1] == 0xb5 and magic[2] == 0x2f and magic[3] == 0xfd) {
            // zstd compressed
            try self.extractZstd(file);
        } else {
            // Assume uncompressed tar
            try self.extractTar(file.reader());
        }
    }

    /// Extract gzip-compressed tar
    fn extractGzip(self: *SecureTarExtractor, file: std.fs.File) !void {
        var decompress = std.compress.gzip.decompressor(file.reader());
        try self.extractTar(decompress.reader());
    }

    /// Extract xz-compressed tar
    fn extractXz(self: *SecureTarExtractor, file: std.fs.File) !void {
        var decompress = std.compress.xz.decompress(self.allocator, file.reader()) catch |err| {
            std.debug.print("SecureTarExtractor: XZ decompression init failed: {}\n", .{err});
            return ExtractionError.MalformedArchive;
        };
        defer decompress.deinit();
        try self.extractTar(decompress.reader());
    }

    /// Extract zstd-compressed tar
    fn extractZstd(self: *SecureTarExtractor, file: std.fs.File) !void {
        var decompress = std.compress.zstd.decompressor(file.reader(), .{});
        try self.extractTar(decompress.reader());
    }

    /// Extract from a tar reader using std.tar.iterator
    fn extractTar(self: *SecureTarExtractor, reader: anytype) !void {
        // Allocate buffers for tar iterator
        var file_name_buffer: [std.fs.max_path_bytes]u8 = undefined;
        var link_name_buffer: [std.fs.max_path_bytes]u8 = undefined;

        var tar_iter = std.tar.iterator(reader, .{
            .file_name_buffer = &file_name_buffer,
            .link_name_buffer = &link_name_buffer,
            .diagnostics = null,
        });

        while (true) {
            const entry = tar_iter.next() catch |err| {
                std.debug.print("SecureTarExtractor: Tar iteration error: {}\n", .{err});
                return ExtractionError.MalformedArchive;
            };

            if (entry == null) break;
            const file_entry = entry.?;

            // Validate and extract the entry
            try self.processEntry(file_entry);
        }
    }

    /// Process a single tar entry with security validation
    fn processEntry(self: *SecureTarExtractor, entry: anytype) !void {
        // Get the file name
        const name = entry.name;

        // Validate the path
        const validated_path = try self.validatePath(name);
        defer self.allocator.free(validated_path);

        // Build full extraction path
        const full_path = try std.fs.path.join(self.allocator, &[_][]const u8{ self.extraction_root, validated_path });
        defer self.allocator.free(full_path);

        // Process based on file type
        switch (entry.kind) {
            .file => try self.extractRegularFile(entry, full_path),
            .directory => try self.extractDirectory(full_path),
            .sym_link => try self.extractSymlink(entry, full_path, validated_path),
        }
    }

    /// Extract a regular file
    fn extractRegularFile(
        self: *SecureTarExtractor,
        entry: anytype,
        full_path: []const u8,
    ) !void {
        // Check file size
        if (entry.size > self.options.max_file_size) {
            std.debug.print("SecureTarExtractor: File too large: {d} bytes\n", .{entry.size});
            return ExtractionError.FileTooLarge;
        }

        // Check total size
        if (self.stats.bytes_extracted + entry.size > self.options.max_total_size) {
            std.debug.print("SecureTarExtractor: Total extraction size exceeded\n", .{});
            return ExtractionError.TotalSizeTooLarge;
        }

        // Ensure parent directory exists
        if (std.fs.path.dirname(full_path)) |parent| {
            std.fs.cwd().makePath(parent) catch |err| {
                std.debug.print("SecureTarExtractor: Failed to create parent dir: {}\n", .{err});
                return ExtractionError.IoError;
            };
        }

        // Create the file
        const file = std.fs.cwd().createFile(full_path, .{}) catch |err| {
            std.debug.print("SecureTarExtractor: Failed to create file {s}: {}\n", .{ full_path, err });
            return ExtractionError.IoError;
        };
        defer file.close();

        // Write file contents directly using tar entry's writeAll method
        entry.writeAll(file.writer()) catch |err| {
            std.debug.print("SecureTarExtractor: Write error: {}\n", .{err});
            return ExtractionError.IoError;
        };
        const bytes_written = entry.size;

        // Apply permissions
        try self.applyFilePermissions(full_path, entry.mode);

        self.stats.files_extracted += 1;
        self.stats.bytes_extracted += bytes_written;
    }

    /// Extract a directory
    fn extractDirectory(self: *SecureTarExtractor, full_path: []const u8) !void {
        std.fs.cwd().makePath(full_path) catch |err| {
            // Ignore if directory already exists
            if (err != error.PathAlreadyExists) {
                std.debug.print("SecureTarExtractor: Failed to create directory {s}: {}\n", .{ full_path, err });
                return ExtractionError.IoError;
            }
        };

        self.stats.directories_created += 1;
    }

    /// Extract a symbolic link with validation
    fn extractSymlink(
        self: *SecureTarExtractor,
        entry: anytype,
        full_path: []const u8,
        validated_path: []const u8,
    ) !void {
        if (!self.options.allow_symlinks) {
            self.stats.paths_rejected += 1;
            return; // Silently skip
        }

        const link_target = entry.link_name;
        if (link_target.len == 0) {
            std.debug.print("SecureTarExtractor: Symlink without target\n", .{});
            return ExtractionError.MalformedArchive;
        }

        // Validate symlink target doesn't escape extraction root
        try self.validateSymlinkTarget(validated_path, link_target);

        // Ensure parent directory exists
        if (std.fs.path.dirname(full_path)) |parent| {
            std.fs.cwd().makePath(parent) catch |err| {
                std.debug.print("SecureTarExtractor: Failed to create parent dir: {}\n", .{err});
                return ExtractionError.IoError;
            };
        }

        // Create symlink
        std.posix.symlink(link_target, full_path) catch |err| {
            std.debug.print("SecureTarExtractor: Failed to create symlink: {}\n", .{err});
            return ExtractionError.IoError;
        };

        self.stats.symlinks_created += 1;
    }

    /// Validate a path from the archive
    /// Returns the sanitized path or an error
    pub fn validatePath(self: *SecureTarExtractor, path: []const u8) ![]const u8 {
        // Check for empty path
        if (path.len == 0) {
            return ExtractionError.InvalidFilename;
        }

        // Check for NUL bytes
        if (std.mem.indexOfScalar(u8, path, 0) != null) {
            self.stats.paths_rejected += 1;
            std.debug.print("SecureTarExtractor: Path contains NUL byte\n", .{});
            return ExtractionError.InvalidFilename;
        }

        // Check path length
        if (path.len > self.options.max_path_length) {
            self.stats.paths_rejected += 1;
            std.debug.print("SecureTarExtractor: Path too long: {d} bytes\n", .{path.len});
            return ExtractionError.PathTooLong;
        }

        // Check for absolute paths
        if (path[0] == '/') {
            if (!self.options.allow_absolute_paths) {
                self.stats.paths_rejected += 1;
                std.debug.print("SecureTarExtractor: Absolute path rejected: {s}\n", .{path});
                return ExtractionError.AbsolutePath;
            }
        }

        // Check for control characters (except for path separators)
        for (path) |c| {
            if (c < 32 and c != '\t') {
                self.stats.paths_rejected += 1;
                std.debug.print("SecureTarExtractor: Path contains control character\n", .{});
                return ExtractionError.InvalidFilename;
            }
        }

        // Check for parent directory references
        var iter = std.mem.splitScalar(u8, path, '/');
        var normalized_parts = std.ArrayList([]const u8).init(self.allocator);
        defer normalized_parts.deinit();

        while (iter.next()) |component| {
            if (component.len == 0) continue; // Skip empty components (double slashes)

            if (std.mem.eql(u8, component, ".")) {
                continue; // Skip current directory references
            }

            if (std.mem.eql(u8, component, "..")) {
                if (!self.options.allow_parent_refs) {
                    self.stats.paths_rejected += 1;
                    std.debug.print("SecureTarExtractor: Path traversal rejected: {s}\n", .{path});
                    return ExtractionError.PathTraversal;
                }
                // If parent refs are allowed, still don't let them escape root
                if (normalized_parts.items.len > 0) {
                    _ = normalized_parts.pop();
                } else {
                    // Would escape root
                    self.stats.paths_rejected += 1;
                    return ExtractionError.PathTraversal;
                }
            } else {
                try normalized_parts.append(component);
            }
        }

        // Build normalized path
        if (normalized_parts.items.len == 0) {
            return try self.allocator.dupe(u8, ".");
        }

        // Calculate total length needed
        var total_len: usize = 0;
        for (normalized_parts.items) |part| {
            total_len += part.len + 1; // +1 for separator
        }
        total_len -= 1; // No trailing separator

        var result = try self.allocator.alloc(u8, total_len);
        var pos: usize = 0;
        for (normalized_parts.items, 0..) |part, i| {
            @memcpy(result[pos..][0..part.len], part);
            pos += part.len;
            if (i < normalized_parts.items.len - 1) {
                result[pos] = '/';
                pos += 1;
            }
        }

        return result;
    }

    /// Validate that a symlink target doesn't escape the extraction root
    pub fn validateSymlinkTarget(
        self: *SecureTarExtractor,
        link_location: []const u8,
        target: []const u8,
    ) !void {
        // Get the directory containing the symlink
        const link_dir = std.fs.path.dirname(link_location) orelse "";

        // Resolve the target relative to the link location
        var resolved_parts = std.ArrayList([]const u8).init(self.allocator);
        defer resolved_parts.deinit();

        // Start with link directory components
        var dir_iter = std.mem.splitScalar(u8, link_dir, '/');
        while (dir_iter.next()) |component| {
            if (component.len > 0 and !std.mem.eql(u8, component, ".")) {
                try resolved_parts.append(component);
            }
        }

        // Process target path
        var target_iter = std.mem.splitScalar(u8, target, '/');
        while (target_iter.next()) |component| {
            if (component.len == 0 or std.mem.eql(u8, component, ".")) {
                continue;
            }

            if (std.mem.eql(u8, component, "..")) {
                if (resolved_parts.items.len == 0) {
                    // Would escape extraction root
                    self.stats.paths_rejected += 1;
                    std.debug.print("SecureTarExtractor: Symlink escape detected: {s} -> {s}\n", .{ link_location, target });
                    return ExtractionError.SymlinkEscape;
                }
                _ = resolved_parts.pop();
            } else {
                try resolved_parts.append(component);
            }
        }

        // If target is absolute, reject unless allowed
        if (target.len > 0 and target[0] == '/') {
            if (!self.options.allow_absolute_paths) {
                self.stats.paths_rejected += 1;
                std.debug.print("SecureTarExtractor: Absolute symlink target rejected: {s}\n", .{target});
                return ExtractionError.SymlinkEscape;
            }
        }
    }

    /// Apply file permissions with security hardening
    fn applyFilePermissions(self: *SecureTarExtractor, path: []const u8, original_mode: u32) !void {
        var mode = original_mode;
        var modified = false;

        // Strip setuid bit (4000)
        if (self.options.strip_setuid and (mode & 0o4000) != 0) {
            mode &= ~@as(u32, 0o4000);
            modified = true;
            std.debug.print("SecureTarExtractor: Stripped setuid from {s}\n", .{path});
        }

        // Strip setgid bit (2000)
        if (self.options.strip_setuid and (mode & 0o2000) != 0) {
            mode &= ~@as(u32, 0o2000);
            modified = true;
            std.debug.print("SecureTarExtractor: Stripped setgid from {s}\n", .{path});
        }

        // Strip sticky bit (1000)
        if (self.options.strip_sticky and (mode & 0o1000) != 0) {
            mode &= ~@as(u32, 0o1000);
            modified = true;
        }

        // Apply permission mask
        const stat_result = std.fs.cwd().statFile(path) catch return;
        const is_directory = stat_result.kind == .directory;

        const mask = if (is_directory)
            self.options.dir_permission_mask
        else
            self.options.file_permission_mask;

        mode = mode & mask;

        // Actually set the permissions
        const cpath = std.fs.cwd().realpathAlloc(self.allocator, path) catch return;
        defer self.allocator.free(cpath);

        // Use chmod via posix
        const fd = std.fs.cwd().openFile(path, .{ .mode = .read_only }) catch return;
        defer fd.close();
        fd.chmod(@truncate(mode)) catch |err| {
            std.debug.print("SecureTarExtractor: Failed to set permissions on {s}: {}\n", .{ path, err });
            return;
        };

        if (modified) {
            self.stats.permissions_modified += 1;
        }
    }

    /// Get extraction statistics
    pub fn getStats(self: *const SecureTarExtractor) ExtractionStats {
        return self.stats;
    }

    /// Reset extraction statistics
    pub fn resetStats(self: *SecureTarExtractor) void {
        self.stats = .{};
    }
};

/// Convenience function to extract with default secure options
pub fn extractSecure(
    allocator: std.mem.Allocator,
    tar_path: []const u8,
    extraction_root: []const u8,
) !SecureTarExtractor.ExtractionStats {
    var extractor = SecureTarExtractor.init(allocator, extraction_root, .{});
    try extractor.extractFromPath(tar_path);
    return extractor.getStats();
}

/// Convenience function to extract with custom options
pub fn extractWithOptions(
    allocator: std.mem.Allocator,
    tar_path: []const u8,
    extraction_root: []const u8,
    options: SecureTarExtractor.ExtractOptions,
) !SecureTarExtractor.ExtractionStats {
    var extractor = SecureTarExtractor.init(allocator, extraction_root, options);
    try extractor.extractFromPath(tar_path);
    return extractor.getStats();
}

// ============================================================================
// Tests
// ============================================================================

test "validatePath.rejects_parent_refs" {
    var extractor = SecureTarExtractor.init(
        std.testing.allocator,
        "/tmp/test",
        .{},
    );

    // Should reject path with ..
    const result = extractor.validatePath("foo/../../../etc/passwd");
    try std.testing.expectError(SecureTarExtractor.ExtractionError.PathTraversal, result);

    // Should reject .. at start
    const result2 = extractor.validatePath("../etc/passwd");
    try std.testing.expectError(SecureTarExtractor.ExtractionError.PathTraversal, result2);
}

test "validatePath.rejects_absolute_paths" {
    var extractor = SecureTarExtractor.init(
        std.testing.allocator,
        "/tmp/test",
        .{},
    );

    const result = extractor.validatePath("/etc/passwd");
    try std.testing.expectError(SecureTarExtractor.ExtractionError.AbsolutePath, result);
}

test "validatePath.rejects_nul_bytes" {
    var extractor = SecureTarExtractor.init(
        std.testing.allocator,
        "/tmp/test",
        .{},
    );

    const result = extractor.validatePath("foo\x00bar");
    try std.testing.expectError(SecureTarExtractor.ExtractionError.InvalidFilename, result);
}

test "validatePath.rejects_long_paths" {
    var extractor = SecureTarExtractor.init(
        std.testing.allocator,
        "/tmp/test",
        .{ .max_path_length = 10 },
    );

    const result = extractor.validatePath("this/is/a/very/long/path");
    try std.testing.expectError(SecureTarExtractor.ExtractionError.PathTooLong, result);
}

test "validatePath.normalizes_paths" {
    var extractor = SecureTarExtractor.init(
        std.testing.allocator,
        "/tmp/test",
        .{},
    );

    // Should normalize ./foo to foo
    const result1 = try extractor.validatePath("./foo/bar");
    defer std.testing.allocator.free(result1);
    try std.testing.expectEqualStrings("foo/bar", result1);

    // Should normalize foo//bar to foo/bar
    const result2 = try extractor.validatePath("foo//bar");
    defer std.testing.allocator.free(result2);
    try std.testing.expectEqualStrings("foo/bar", result2);
}

test "validateSymlinkTarget.rejects_escape" {
    var extractor = SecureTarExtractor.init(
        std.testing.allocator,
        "/tmp/test",
        .{},
    );

    // Symlink from foo/link -> ../../etc/passwd should be rejected
    const result = extractor.validateSymlinkTarget("foo/link", "../../etc/passwd");
    try std.testing.expectError(SecureTarExtractor.ExtractionError.SymlinkEscape, result);

    // Symlink from deep/nested/link -> ../../../etc/passwd should be rejected
    const result2 = extractor.validateSymlinkTarget("deep/nested/link", "../../../etc/passwd");
    try std.testing.expectError(SecureTarExtractor.ExtractionError.SymlinkEscape, result2);
}

test "validateSymlinkTarget.allows_safe_targets" {
    var extractor = SecureTarExtractor.init(
        std.testing.allocator,
        "/tmp/test",
        .{},
    );

    // Symlink from foo/link -> bar should be allowed
    try extractor.validateSymlinkTarget("foo/link", "bar");

    // Symlink from foo/link -> ../bar should be allowed (stays in root)
    try extractor.validateSymlinkTarget("foo/link", "../bar");

    // Symlink from deep/nested/link -> ../../other should be allowed
    try extractor.validateSymlinkTarget("deep/nested/link", "../../other");
}

test "validatePath.rejects_control_chars" {
    var extractor = SecureTarExtractor.init(
        std.testing.allocator,
        "/tmp/test",
        .{},
    );

    // Should reject paths with control characters
    const result = extractor.validatePath("foo\x01bar");
    try std.testing.expectError(SecureTarExtractor.ExtractionError.InvalidFilename, result);
}
