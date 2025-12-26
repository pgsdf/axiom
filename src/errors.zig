// ============================================================================
// Phase 52: Unified Error Handling Module
// ============================================================================
//
// This module provides consistent error handling patterns across all Axiom
// modules, eliminating silent error swallowing while maintaining operational
// continuity for non-critical failures.
//
// Usage:
//   const errors = @import("errors.zig");
//
//   // For non-critical cleanup that can fail silently but should be logged
//   std.fs.deleteTreeAbsolute(tmp_dir) catch |err| {
//       errors.logNonCritical(@src(), err, "cleanup temp directory", tmp_dir);
//   };
//
//   // For critical operations that should be propagated
//   try errors.wrapError(@src(), someOperation(), "operation description");
//

const std = @import("std");

/// Error severity levels for classification
pub const Severity = enum {
    /// Informational - operation succeeded but with notes
    info,
    /// Warning - operation succeeded but may indicate issues
    warning,
    /// Error - operation failed but recovery may be possible
    err,
    /// Critical - operation failed, immediate attention needed
    critical,

    pub fn toString(self: Severity) []const u8 {
        return switch (self) {
            .info => "INFO",
            .warning => "WARN",
            .err => "ERROR",
            .critical => "CRITICAL",
        };
    }

    pub fn toLogLevel(self: Severity) std.log.Level {
        return switch (self) {
            .info => .info,
            .warning => .warn,
            .err => .err,
            .critical => .err,
        };
    }
};

/// Error categories for grouping related errors
pub const Category = enum {
    /// ZFS dataset operations
    zfs,
    /// Package store operations
    store,
    /// Package import operations
    import_op,
    /// Environment realization
    realization,
    /// Dependency resolution
    resolution,
    /// Network/cache operations
    network,
    /// Permission/security
    permission,
    /// File system cleanup
    cleanup,
    /// Service management
    service,
    /// Configuration
    config,
    /// Build operations
    build,
    /// General I/O
    io,

    pub fn toString(self: Category) []const u8 {
        return switch (self) {
            .zfs => "ZFS",
            .store => "Store",
            .import_op => "Import",
            .realization => "Realization",
            .resolution => "Resolution",
            .network => "Network",
            .permission => "Permission",
            .cleanup => "Cleanup",
            .service => "Service",
            .config => "Config",
            .build => "Build",
            .io => "I/O",
        };
    }
};

/// Extended error context with source location
pub const ErrorInfo = struct {
    category: Category,
    severity: Severity,
    operation: []const u8,
    resource: ?[]const u8,
    source_file: []const u8,
    source_line: u32,
    source_fn: []const u8,

    pub fn format(
        self: ErrorInfo,
        writer: anytype,
    ) !void {
        try writer.print("[{s}] {s}:{d} in {s}: {s}", .{
            self.category.toString(),
            self.source_file,
            self.source_line,
            self.source_fn,
            self.operation,
        });
        if (self.resource) |res| {
            try writer.print(" ({s})", .{res});
        }
    }
};

// ============================================================================
// Non-Critical Error Logging
// ============================================================================
// These functions are used for operations that can fail without affecting
// the overall operation, such as cleanup tasks, optional features, etc.
// The errors are logged but not propagated.

/// Log a non-critical error that occurs during cleanup operations.
/// Use this for operations like deleting temp files that shouldn't fail the main operation.
pub fn logNonCritical(
    comptime src: std.builtin.SourceLocation,
    err: anyerror,
    operation: []const u8,
    resource: ?[]const u8,
) void {
    const info = ErrorInfo{
        .category = .cleanup,
        .severity = .warning,
        .operation = operation,
        .resource = resource,
        .source_file = src.file,
        .source_line = src.line,
        .source_fn = src.fn_name,
    };
    std.log.warn("{f}: {} (non-critical, continuing)", .{ info, err });
}

/// Log a non-critical error with a specific category
pub fn logNonCriticalWithCategory(
    comptime src: std.builtin.SourceLocation,
    err: anyerror,
    category: Category,
    operation: []const u8,
    resource: ?[]const u8,
) void {
    const info = ErrorInfo{
        .category = category,
        .severity = .warning,
        .operation = operation,
        .resource = resource,
        .source_file = src.file,
        .source_line = src.line,
        .source_fn = src.fn_name,
    };
    std.log.warn("{f}: {} (non-critical, continuing)", .{ info, err });
}

/// Log an error during process cleanup (waiting on child processes)
pub fn logProcessCleanup(
    comptime src: std.builtin.SourceLocation,
    err: anyerror,
    process_desc: ?[]const u8,
) void {
    const info = ErrorInfo{
        .category = .cleanup,
        .severity = .warning,
        .operation = "wait on child process",
        .resource = process_desc,
        .source_file = src.file,
        .source_line = src.line,
        .source_fn = src.fn_name,
    };
    std.log.warn("{f}: {} (process cleanup, continuing)", .{ info, err });
}

/// Log an error during file/directory cleanup
pub fn logFileCleanup(
    comptime src: std.builtin.SourceLocation,
    err: anyerror,
    path: []const u8,
) void {
    const info = ErrorInfo{
        .category = .cleanup,
        .severity = .info,
        .operation = "cleanup file/directory",
        .resource = path,
        .source_file = src.file,
        .source_line = src.line,
        .source_fn = src.fn_name,
    };
    std.log.debug("{f}: {} (cleanup, continuing)", .{ info, err });
}

/// Log an error during directory creation that may already exist
pub fn logMkdirBestEffort(
    comptime src: std.builtin.SourceLocation,
    err: anyerror,
    path: []const u8,
) void {
    // PathAlreadyExists is expected in many cases
    if (err == error.PathAlreadyExists) {
        return;
    }
    const info = ErrorInfo{
        .category = .io,
        .severity = .warning,
        .operation = "create directory",
        .resource = path,
        .source_file = src.file,
        .source_line = src.line,
        .source_fn = src.fn_name,
    };
    std.log.warn("{f}: {} (best effort, continuing)", .{ info, err });
}

/// Log an error when loading optional configuration
pub fn logConfigLoadOptional(
    comptime src: std.builtin.SourceLocation,
    err: anyerror,
    config_path: []const u8,
) void {
    // FileNotFound is expected for optional configs
    if (err == error.FileNotFound) {
        std.log.debug("Optional config not found: {s}", .{config_path});
        return;
    }
    const info = ErrorInfo{
        .category = .config,
        .severity = .warning,
        .operation = "load optional config",
        .resource = config_path,
        .source_file = src.file,
        .source_line = src.line,
        .source_fn = src.fn_name,
    };
    std.log.warn("{f}: {}", .{ info, err });
}

/// Log an error during ZFS dataset cleanup
pub fn logZfsCleanup(
    comptime src: std.builtin.SourceLocation,
    err: anyerror,
    dataset: []const u8,
) void {
    const info = ErrorInfo{
        .category = .zfs,
        .severity = .warning,
        .operation = "cleanup dataset",
        .resource = dataset,
        .source_file = src.file,
        .source_line = src.line,
        .source_fn = src.fn_name,
    };
    std.log.warn("{f}: {} (cleanup, continuing)", .{ info, err });
}

/// Log an error during service operations
pub fn logServiceOp(
    comptime src: std.builtin.SourceLocation,
    err: anyerror,
    operation: []const u8,
    service_name: []const u8,
) void {
    const info = ErrorInfo{
        .category = .service,
        .severity = .warning,
        .operation = operation,
        .resource = service_name,
        .source_file = src.file,
        .source_line = src.line,
        .source_fn = src.fn_name,
    };
    std.log.warn("{f}: {} (service op, continuing)", .{ info, err });
}

/// Log an error during trust store operations
pub fn logTrustStoreOp(
    comptime src: std.builtin.SourceLocation,
    err: anyerror,
    operation: []const u8,
) void {
    const info = ErrorInfo{
        .category = .permission,
        .severity = .warning,
        .operation = operation,
        .resource = null,
        .source_file = src.file,
        .source_line = src.line,
        .source_fn = src.fn_name,
    };
    std.log.warn("{f}: {} (trust store, continuing)", .{ info, err });
}

/// Log an error during logging/audit operations (meta-logging)
pub fn logLoggingError(
    comptime src: std.builtin.SourceLocation,
    err: anyerror,
    operation: []const u8,
) void {
    // Use stderr directly to avoid potential recursion
    const stderr_file = std.fs.File.stderr();
    var stderr_buf: [4096]u8 = undefined;
    const stderr = stderr_file.writer(&stderr_buf);
    stderr.print("[WARN] {s}:{d} in {s}: {s}: {}\n", .{
        src.file,
        src.line,
        src.fn_name,
        operation,
        err,
    }) catch {};
}

/// Log an error during output formatting operations
pub fn logFormatError(
    comptime src: std.builtin.SourceLocation,
    err: anyerror,
) void {
    const info = ErrorInfo{
        .category = .io,
        .severity = .warning,
        .operation = "format output",
        .resource = null,
        .source_file = src.file,
        .source_line = src.line,
        .source_fn = src.fn_name,
    };
    std.log.warn("{f}: {}", .{ info, err });
}

/// Log an error during data collection (non-critical append)
pub fn logCollectionError(
    comptime src: std.builtin.SourceLocation,
    err: anyerror,
    operation: []const u8,
) void {
    const info = ErrorInfo{
        .category = .io,
        .severity = .warning,
        .operation = operation,
        .resource = null,
        .source_file = src.file,
        .source_line = src.line,
        .source_fn = src.fn_name,
    };
    std.log.warn("{f}: {} (collection, continuing)", .{ info, err });
}

/// Log an error during hex parsing operations
pub fn logParseError(
    comptime src: std.builtin.SourceLocation,
    err: anyerror,
    operation: []const u8,
) void {
    const info = ErrorInfo{
        .category = .io,
        .severity = .warning,
        .operation = operation,
        .resource = null,
        .source_file = src.file,
        .source_line = src.line,
        .source_fn = src.fn_name,
    };
    std.log.warn("{f}: {} (parse, continuing)", .{ info, err });
}

// ============================================================================
// Error Wrapping for Critical Operations
// ============================================================================

/// Wrap an error with additional context for debugging
pub fn wrapError(
    comptime src: std.builtin.SourceLocation,
    result: anytype,
    operation: []const u8,
) @TypeOf(result) {
    if (result) |value| {
        return value;
    } else |err| {
        std.log.err("{s}:{d} in {s}: {s} failed: {}", .{
            src.file,
            src.line,
            src.fn_name,
            operation,
            err,
        });
        return err;
    }
}

// ============================================================================
// C Interop Error Checking
// ============================================================================

/// Check a C library return value and log if non-zero
pub fn checkCReturn(
    comptime src: std.builtin.SourceLocation,
    ret: c_int,
    operation: []const u8,
) void {
    if (ret != 0) {
        std.log.warn("{s}:{d} in {s}: C call '{s}' returned {d}", .{
            src.file,
            src.line,
            src.fn_name,
            operation,
            ret,
        });
    }
}

/// Check a C library return value, returning an error if non-zero
pub fn checkCReturnError(
    comptime src: std.builtin.SourceLocation,
    ret: c_int,
    operation: []const u8,
) !void {
    if (ret != 0) {
        std.log.err("{s}:{d} in {s}: C call '{s}' returned {d}", .{
            src.file,
            src.line,
            src.fn_name,
            operation,
            ret,
        });
        return error.CInteropFailed;
    }
}

// ============================================================================
// Unified Axiom Error Type
// ============================================================================
// Re-export the main error types for convenience

pub const AxiomError = error{
    // Security errors
    SecurityViolation,
    PathTraversal,
    SymlinkEscape,
    CommandInjection,

    // Store errors
    StoreCorrupted,
    StoreVersionMismatch,
    PackageNotFound,
    PackageCorrupted,
    ManifestInvalid,

    // Import errors
    ImportInterrupted,
    ImportHashMismatch,
    ImportSignatureInvalid,

    // Realization errors
    RealizationConflict,
    RealizationInterrupted,
    EnvironmentCorrupted,

    // Resolution errors
    DependencyConflict,
    UnsatisfiableDependency,
    CyclicDependency,

    // ZFS errors
    ZfsOperationFailed,
    DatasetNotFound,
    DatasetExists,
    PoolNotAvailable,

    // Network errors
    NetworkError,
    CacheUnreachable,
    FetchTimeout,

    // Permission errors
    PermissionDenied,
    InsufficientPrivileges,

    // C interop errors
    CInteropFailed,

    // Cleanup errors (usually non-fatal)
    CleanupFailed,
};

// ============================================================================
// Tests
// ============================================================================

test "error logging does not panic" {
    const src = @src();

    // Test that logging functions don't panic
    logNonCritical(src, error.FileNotFound, "test operation", "test resource");
    logNonCriticalWithCategory(src, error.OutOfMemory, .store, "test op", null);
    logProcessCleanup(src, error.BrokenPipe, "test process");
    logFileCleanup(src, error.AccessDenied, "/tmp/test");
    logMkdirBestEffort(src, error.PathAlreadyExists, "/tmp/existing");
    logConfigLoadOptional(src, error.FileNotFound, "/etc/test.yaml");
    logZfsCleanup(src, error.PermissionDenied, "zroot/test");
    logServiceOp(src, error.ProcessNotFound, "stop", "test-service");
    logTrustStoreOp(src, error.FileNotFound, "load");
    logLoggingError(src, error.NoSpaceLeft, "write audit log");
    logFormatError(src, error.OutOfMemory);
    logCollectionError(src, error.OutOfMemory, "append to list");
    logParseError(src, error.InvalidCharacter, "parse hex string");
}

test "checkCReturn logs non-zero values" {
    checkCReturn(@src(), 0, "successful_call");
    checkCReturn(@src(), -1, "failed_call");
}

test "ErrorInfo format" {
    const info = ErrorInfo{
        .category = .zfs,
        .severity = .err,
        .operation = "create dataset",
        .resource = "zroot/test",
        .source_file = "test.zig",
        .source_line = 42,
        .source_fn = "testFn",
    };

    var buf: [256]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    try std.fmt.format(stream.writer(), "{f}", .{info});
    const result = stream.getWritten();

    try std.testing.expect(std.mem.indexOf(u8, result, "ZFS") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "test.zig") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "create dataset") != null);
}
