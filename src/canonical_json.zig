const std = @import("std");
const Allocator = std.mem.Allocator;

/// Canonical JSON serializer following RFC 8785 (JCS - JSON Canonicalization Scheme)
///
/// Guarantees:
/// - UTF-8 encoded output
/// - Lexicographically sorted object keys
/// - No insignificant whitespace
/// - Normalized number formats (no leading zeros, no trailing zeros after decimal)
/// - Consistent string escaping
///
/// This is the ONLY format used for hashing and signing in Lockbox.
pub const CanonicalJson = struct {
    allocator: Allocator,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return .{ .allocator = allocator };
    }

    /// Serialize a value to canonical JSON
    pub fn serialize(self: *Self, value: JsonValue) ![]u8 {
        var buffer: std.ArrayList(u8) = .empty;
        errdefer buffer.deinit(self.allocator);
        try self.writeValue(&buffer, value);
        return buffer.toOwnedSlice(self.allocator);
    }

    fn writeValue(self: *Self, buffer: *std.ArrayList(u8), value: JsonValue) !void {
        switch (value) {
            .null => try buffer.appendSlice(self.allocator, "null"),
            .bool => |b| try buffer.appendSlice(self.allocator, if (b) "true" else "false"),
            .integer => |i| {
                var num_buf: [32]u8 = undefined;
                const num_str = std.fmt.bufPrint(&num_buf, "{d}", .{i}) catch unreachable;
                try buffer.appendSlice(self.allocator, num_str);
            },
            .string => |s| try self.writeString(buffer, s),
            .array => |arr| try self.writeArray(buffer, arr),
            .object => |obj| try self.writeObject(buffer, obj),
        }
    }

    fn writeString(self: *Self, buffer: *std.ArrayList(u8), s: []const u8) !void {
        try buffer.append(self.allocator, '"');

        for (s) |c| {
            switch (c) {
                '"' => try buffer.appendSlice(self.allocator, "\\\""),
                '\\' => try buffer.appendSlice(self.allocator, "\\\\"),
                '\n' => try buffer.appendSlice(self.allocator, "\\n"),
                '\r' => try buffer.appendSlice(self.allocator, "\\r"),
                '\t' => try buffer.appendSlice(self.allocator, "\\t"),
                0x08 => try buffer.appendSlice(self.allocator, "\\b"), // backspace
                0x0C => try buffer.appendSlice(self.allocator, "\\f"), // form feed
                else => {
                    if (c < 0x20) {
                        // Control characters as \uXXXX
                        var escape_buf: [6]u8 = undefined;
                        _ = std.fmt.bufPrint(&escape_buf, "\\u{X:0>4}", .{c}) catch unreachable;
                        try buffer.appendSlice(self.allocator, &escape_buf);
                    } else {
                        try buffer.append(self.allocator, c);
                    }
                },
            }
        }

        try buffer.append(self.allocator, '"');
    }

    fn writeArray(self: *Self, buffer: *std.ArrayList(u8), arr: []const JsonValue) !void {
        try buffer.append(self.allocator, '[');

        for (arr, 0..) |item, i| {
            if (i > 0) try buffer.append(self.allocator, ',');
            try self.writeValue(buffer, item);
        }

        try buffer.append(self.allocator, ']');
    }

    fn writeObject(self: *Self, buffer: *std.ArrayList(u8), obj: []const JsonKeyValue) !void {
        // Sort keys lexicographically for canonical output
        const sorted = try self.allocator.alloc(JsonKeyValue, obj.len);
        defer self.allocator.free(sorted);
        @memcpy(sorted, obj);

        std.mem.sort(JsonKeyValue, sorted, {}, struct {
            fn lessThan(_: void, a: JsonKeyValue, b: JsonKeyValue) bool {
                return std.mem.lessThan(u8, a.key, b.key);
            }
        }.lessThan);

        try buffer.append(self.allocator, '{');

        for (sorted, 0..) |kv, i| {
            if (i > 0) try buffer.append(self.allocator, ',');
            try self.writeString(buffer, kv.key);
            try buffer.append(self.allocator, ':');
            try self.writeValue(buffer, kv.value);
        }

        try buffer.append(self.allocator, '}');
    }

    /// Compute SHA-256 hash of canonical JSON
    pub fn computeHash(self: *Self, value: JsonValue) ![64]u8 {
        const json = try self.serialize(value);
        defer self.allocator.free(json);

        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(json);

        var hash: [32]u8 = undefined;
        hasher.final(&hash);

        var hex: [64]u8 = undefined;
        _ = std.fmt.bufPrint(&hex, "{x}", .{std.fmt.fmtSliceHexLower(&hash)}) catch unreachable;
        return hex;
    }
};

/// JSON value types for canonical serialization
pub const JsonValue = union(enum) {
    null: void,
    bool: bool,
    integer: i64,
    string: []const u8,
    array: []const JsonValue,
    object: []const JsonKeyValue,

    /// Create a null value
    pub fn nullValue() JsonValue {
        return .{ .null = {} };
    }

    /// Create a boolean value
    pub fn boolean(b: bool) JsonValue {
        return .{ .bool = b };
    }

    /// Create an integer value
    pub fn int(i: i64) JsonValue {
        return .{ .integer = i };
    }

    /// Create a string value
    pub fn str(s: []const u8) JsonValue {
        return .{ .string = s };
    }

    /// Create an array value
    pub fn arr(items: []const JsonValue) JsonValue {
        return .{ .array = items };
    }

    /// Create an object value
    pub fn obj(pairs: []const JsonKeyValue) JsonValue {
        return .{ .object = pairs };
    }
};

/// Key-value pair for JSON objects
pub const JsonKeyValue = struct {
    key: []const u8,
    value: JsonValue,

    pub fn init(key: []const u8, value: JsonValue) JsonKeyValue {
        return .{ .key = key, .value = value };
    }
};

/// Builder for constructing JSON objects programmatically
pub const JsonObjectBuilder = struct {
    allocator: Allocator,
    pairs: std.ArrayList(JsonKeyValue),

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return .{
            .allocator = allocator,
            .pairs = .empty,
        };
    }

    pub fn deinit(self: *Self) void {
        self.pairs.deinit(self.allocator);
    }

    pub fn put(self: *Self, key: []const u8, value: JsonValue) !void {
        try self.pairs.append(self.allocator, .{ .key = key, .value = value });
    }

    pub fn putString(self: *Self, key: []const u8, value: []const u8) !void {
        try self.put(key, JsonValue.str(value));
    }

    pub fn putInt(self: *Self, key: []const u8, value: i64) !void {
        try self.put(key, JsonValue.int(value));
    }

    pub fn putBool(self: *Self, key: []const u8, value: bool) !void {
        try self.put(key, JsonValue.boolean(value));
    }

    pub fn putNull(self: *Self, key: []const u8) !void {
        try self.put(key, JsonValue.nullValue());
    }

    pub fn build(self: *Self) JsonValue {
        return JsonValue.obj(self.pairs.items);
    }

    /// Build and return owned slice (caller must free)
    pub fn buildOwned(self: *Self) ![]const JsonKeyValue {
        return self.pairs.toOwnedSlice(self.allocator);
    }
};

/// Builder for constructing JSON arrays programmatically
pub const JsonArrayBuilder = struct {
    allocator: Allocator,
    items: std.ArrayList(JsonValue),

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return .{
            .allocator = allocator,
            .items = .empty,
        };
    }

    pub fn deinit(self: *Self) void {
        self.items.deinit(self.allocator);
    }

    pub fn append(self: *Self, value: JsonValue) !void {
        try self.items.append(self.allocator, value);
    }

    pub fn appendString(self: *Self, value: []const u8) !void {
        try self.append(JsonValue.str(value));
    }

    pub fn appendInt(self: *Self, value: i64) !void {
        try self.append(JsonValue.int(value));
    }

    pub fn build(self: *Self) JsonValue {
        return JsonValue.arr(self.items.items);
    }

    pub fn buildOwned(self: *Self) ![]const JsonValue {
        return self.items.toOwnedSlice(self.allocator);
    }
};

// ============================================================================
// Tests
// ============================================================================

test "CanonicalJson: null value" {
    var cj = CanonicalJson.init(std.testing.allocator);
    const json = try cj.serialize(JsonValue.nullValue());
    defer std.testing.allocator.free(json);
    try std.testing.expectEqualStrings("null", json);
}

test "CanonicalJson: boolean values" {
    var cj = CanonicalJson.init(std.testing.allocator);

    const true_json = try cj.serialize(JsonValue.boolean(true));
    defer std.testing.allocator.free(true_json);
    try std.testing.expectEqualStrings("true", true_json);

    const false_json = try cj.serialize(JsonValue.boolean(false));
    defer std.testing.allocator.free(false_json);
    try std.testing.expectEqualStrings("false", false_json);
}

test "CanonicalJson: integer values" {
    var cj = CanonicalJson.init(std.testing.allocator);

    const pos = try cj.serialize(JsonValue.int(42));
    defer std.testing.allocator.free(pos);
    try std.testing.expectEqualStrings("42", pos);

    const neg = try cj.serialize(JsonValue.int(-123));
    defer std.testing.allocator.free(neg);
    try std.testing.expectEqualStrings("-123", neg);

    const zero = try cj.serialize(JsonValue.int(0));
    defer std.testing.allocator.free(zero);
    try std.testing.expectEqualStrings("0", zero);
}

test "CanonicalJson: string escaping" {
    var cj = CanonicalJson.init(std.testing.allocator);

    const simple = try cj.serialize(JsonValue.str("hello"));
    defer std.testing.allocator.free(simple);
    try std.testing.expectEqualStrings("\"hello\"", simple);

    const with_quotes = try cj.serialize(JsonValue.str("say \"hi\""));
    defer std.testing.allocator.free(with_quotes);
    try std.testing.expectEqualStrings("\"say \\\"hi\\\"\"", with_quotes);

    const with_newline = try cj.serialize(JsonValue.str("line1\nline2"));
    defer std.testing.allocator.free(with_newline);
    try std.testing.expectEqualStrings("\"line1\\nline2\"", with_newline);
}

test "CanonicalJson: empty array" {
    var cj = CanonicalJson.init(std.testing.allocator);
    const json = try cj.serialize(JsonValue.arr(&[_]JsonValue{}));
    defer std.testing.allocator.free(json);
    try std.testing.expectEqualStrings("[]", json);
}

test "CanonicalJson: array with values" {
    var cj = CanonicalJson.init(std.testing.allocator);
    const json = try cj.serialize(JsonValue.arr(&[_]JsonValue{
        JsonValue.int(1),
        JsonValue.int(2),
        JsonValue.int(3),
    }));
    defer std.testing.allocator.free(json);
    try std.testing.expectEqualStrings("[1,2,3]", json);
}

test "CanonicalJson: empty object" {
    var cj = CanonicalJson.init(std.testing.allocator);
    const json = try cj.serialize(JsonValue.obj(&[_]JsonKeyValue{}));
    defer std.testing.allocator.free(json);
    try std.testing.expectEqualStrings("{}", json);
}

test "CanonicalJson: object with sorted keys" {
    var cj = CanonicalJson.init(std.testing.allocator);

    // Keys are intentionally out of order to test sorting
    const json = try cj.serialize(JsonValue.obj(&[_]JsonKeyValue{
        JsonKeyValue.init("zebra", JsonValue.int(3)),
        JsonKeyValue.init("apple", JsonValue.int(1)),
        JsonKeyValue.init("mango", JsonValue.int(2)),
    }));
    defer std.testing.allocator.free(json);

    // Keys must be sorted lexicographically
    try std.testing.expectEqualStrings("{\"apple\":1,\"mango\":2,\"zebra\":3}", json);
}

test "CanonicalJson: nested object" {
    var cj = CanonicalJson.init(std.testing.allocator);

    const inner = JsonValue.obj(&[_]JsonKeyValue{
        JsonKeyValue.init("b", JsonValue.int(2)),
        JsonKeyValue.init("a", JsonValue.int(1)),
    });

    const json = try cj.serialize(JsonValue.obj(&[_]JsonKeyValue{
        JsonKeyValue.init("outer", inner),
    }));
    defer std.testing.allocator.free(json);

    try std.testing.expectEqualStrings("{\"outer\":{\"a\":1,\"b\":2}}", json);
}

test "CanonicalJson: hash determinism" {
    var cj = CanonicalJson.init(std.testing.allocator);

    const value = JsonValue.obj(&[_]JsonKeyValue{
        JsonKeyValue.init("name", JsonValue.str("test")),
        JsonKeyValue.init("version", JsonValue.str("1.0.0")),
    });

    const hash1 = try cj.computeHash(value);
    const hash2 = try cj.computeHash(value);

    // Same input must produce identical hash
    try std.testing.expectEqualStrings(&hash1, &hash2);
}

test "CanonicalJson: hash uniqueness" {
    var cj = CanonicalJson.init(std.testing.allocator);

    const value1 = JsonValue.obj(&[_]JsonKeyValue{
        JsonKeyValue.init("name", JsonValue.str("test1")),
    });

    const value2 = JsonValue.obj(&[_]JsonKeyValue{
        JsonKeyValue.init("name", JsonValue.str("test2")),
    });

    const hash1 = try cj.computeHash(value1);
    const hash2 = try cj.computeHash(value2);

    // Different input must produce different hash
    try std.testing.expect(!std.mem.eql(u8, &hash1, &hash2));
}

test "JsonObjectBuilder" {
    var builder = JsonObjectBuilder.init(std.testing.allocator);
    defer builder.deinit();

    try builder.putString("name", "artifact");
    try builder.putInt("size", 1024);
    try builder.putBool("signed", true);

    var cj = CanonicalJson.init(std.testing.allocator);
    const json = try cj.serialize(builder.build());
    defer std.testing.allocator.free(json);

    // Keys sorted alphabetically
    try std.testing.expectEqualStrings("{\"name\":\"artifact\",\"signed\":true,\"size\":1024}", json);
}

test "JsonArrayBuilder" {
    var builder = JsonArrayBuilder.init(std.testing.allocator);
    defer builder.deinit();

    try builder.appendString("a");
    try builder.appendString("b");
    try builder.appendInt(42);

    var cj = CanonicalJson.init(std.testing.allocator);
    const json = try cj.serialize(builder.build());
    defer std.testing.allocator.free(json);

    try std.testing.expectEqualStrings("[\"a\",\"b\",42]", json);
}

test "CanonicalJson: no whitespace" {
    var cj = CanonicalJson.init(std.testing.allocator);

    const complex = JsonValue.obj(&[_]JsonKeyValue{
        JsonKeyValue.init("items", JsonValue.arr(&[_]JsonValue{
            JsonValue.obj(&[_]JsonKeyValue{
                JsonKeyValue.init("id", JsonValue.int(1)),
            }),
        })),
    });

    const json = try cj.serialize(complex);
    defer std.testing.allocator.free(json);

    // No spaces, tabs, or newlines
    for (json) |c| {
        try std.testing.expect(c != ' ');
        try std.testing.expect(c != '\t');
        try std.testing.expect(c != '\n');
    }
}
