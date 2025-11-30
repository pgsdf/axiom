const std = @import("std");
const signature = @import("signature.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("Axiom Signature Verification - Phase 15 Test\n", .{});
    std.debug.print("=============================================\n\n", .{});

    // Test 1: Key generation
    std.debug.print("1. Key Generation\n", .{});
    std.debug.print("-----------------\n", .{});

    const key_pair = signature.KeyPair.generate();
    const key_id = try key_pair.keyId(allocator);
    defer allocator.free(key_id);

    std.debug.print("  Generated key pair\n", .{});
    std.debug.print("  Key ID: {s}\n", .{key_id});
    std.debug.print("  Public key: {s}...\n", .{std.fmt.fmtSliceHexLower(key_pair.public_key[0..16])});

    // Test 2: Trust store
    std.debug.print("\n2. Trust Store\n", .{});
    std.debug.print("--------------\n", .{});

    var trust_store = signature.TrustStore.init(allocator, "/tmp/axiom-test-trust.toml");
    defer trust_store.deinit();

    // Add key to trust store
    const pub_key = signature.PublicKey{
        .key_id = key_id,
        .key_data = key_pair.public_key,
        .owner = "Test User",
        .email = "test@example.com",
        .created = std.time.timestamp(),
    };

    try trust_store.addKey(pub_key);
    std.debug.print("  Added key to trust store\n", .{});

    // Trust the key
    try trust_store.trustKey(key_id);
    std.debug.print("  Trusted key: {s}\n", .{key_id});

    // Check trust
    const is_trusted = trust_store.isKeyTrusted(key_id);
    std.debug.print("  Key trusted: {}\n", .{is_trusted});

    // Save trust store
    try trust_store.save();
    std.debug.print("  Trust store saved\n", .{});

    // Test 3: Create test package and sign it
    std.debug.print("\n3. Package Signing\n", .{});
    std.debug.print("------------------\n", .{});

    // Create test package directory
    const test_pkg = "/tmp/axiom-sig-test-pkg";
    std.fs.cwd().deleteTree(test_pkg) catch {};
    try std.fs.cwd().makePath(test_pkg ++ "/bin");

    // Create test files
    {
        const file1 = try std.fs.cwd().createFile(test_pkg ++ "/README.txt", .{});
        defer file1.close();
        try file1.writeAll("Test package for signature verification\n");
    }
    {
        const file2 = try std.fs.cwd().createFile(test_pkg ++ "/bin/test", .{});
        defer file2.close();
        try file2.writeAll("#!/bin/sh\necho 'Hello'\n");
    }

    std.debug.print("  Created test package: {s}\n", .{test_pkg});

    // Sign the package
    var signer = signature.Signer.init(allocator, key_pair, "Test Signer <test@example.com>");
    var sig = try signer.signPackage(test_pkg);
    defer sig.deinit(allocator);

    std.debug.print("  Package signed\n", .{});
    std.debug.print("  Files in signature: {d}\n", .{sig.files.len});

    // Save signature
    const sig_yaml = try sig.toYaml(allocator);
    defer allocator.free(sig_yaml);

    {
        const sig_file = try std.fs.cwd().createFile(test_pkg ++ "/manifest.sig", .{});
        defer sig_file.close();
        try sig_file.writeAll(sig_yaml);
    }
    std.debug.print("  Signature saved to manifest.sig\n", .{});

    // Print signature
    std.debug.print("\n  Signature YAML:\n", .{});
    var lines = std.mem.splitSequence(u8, sig_yaml, "\n");
    var line_count: usize = 0;
    while (lines.next()) |line| {
        if (line_count < 10) {
            std.debug.print("    {s}\n", .{line});
        } else if (line_count == 10) {
            std.debug.print("    ...\n", .{});
        }
        line_count += 1;
    }

    // Test 4: Verify package
    std.debug.print("\n4. Package Verification\n", .{});
    std.debug.print("-----------------------\n", .{});

    var verifier = signature.Verifier.init(allocator, &trust_store, .strict);
    const result = try verifier.verifyPackage(test_pkg);

    std.debug.print("  Verification result:\n", .{});
    std.debug.print("    Valid: {}\n", .{result.valid});
    std.debug.print("    Key trusted: {}\n", .{result.key_trusted});
    if (result.key_id) |kid| std.debug.print("    Key ID: {s}\n", .{kid});
    if (result.signer) |s| std.debug.print("    Signer: {s}\n", .{s});
    std.debug.print("    Files verified: {d}\n", .{result.files_verified});
    std.debug.print("    Files failed: {d}\n", .{result.files_failed});
    if (result.error_message) |msg| std.debug.print("    Error: {s}\n", .{msg});

    // Free result strings
    if (result.key_id) |kid| allocator.free(kid);
    if (result.signer) |s| allocator.free(s);

    // Test 5: Tamper with package and verify again
    std.debug.print("\n5. Tamper Detection\n", .{});
    std.debug.print("-------------------\n", .{});

    // Modify a file
    {
        const file = try std.fs.cwd().createFile(test_pkg ++ "/README.txt", .{});
        defer file.close();
        try file.writeAll("TAMPERED CONTENT!\n");
    }
    std.debug.print("  Modified README.txt\n", .{});

    const tamper_result = try verifier.verifyPackage(test_pkg);

    std.debug.print("  Verification after tampering:\n", .{});
    std.debug.print("    Valid: {}\n", .{tamper_result.valid});
    std.debug.print("    Files verified: {d}\n", .{tamper_result.files_verified});
    std.debug.print("    Files failed: {d}\n", .{tamper_result.files_failed});

    if (tamper_result.key_id) |kid| allocator.free(kid);
    if (tamper_result.signer) |s| allocator.free(s);

    // Test 6: Export and import public key
    std.debug.print("\n6. Key Export/Import\n", .{});
    std.debug.print("--------------------\n", .{});

    const export_path = "/tmp/axiom-test-key.pub";
    try signature.exportPublicKey(allocator, pub_key, export_path);
    std.debug.print("  Exported public key to: {s}\n", .{export_path});

    var imported_key = try signature.importPublicKey(allocator, export_path);
    defer imported_key.deinit(allocator);

    std.debug.print("  Imported key ID: {s}\n", .{imported_key.key_id});
    std.debug.print("  Keys match: {}\n", .{std.mem.eql(u8, &pub_key.key_data, &imported_key.key_data)});

    // Cleanup
    std.debug.print("\n7. Cleanup\n", .{});
    std.debug.print("----------\n", .{});

    std.fs.cwd().deleteTree(test_pkg) catch {};
    std.fs.cwd().deleteFile("/tmp/axiom-test-trust.toml") catch {};
    std.fs.cwd().deleteFile(export_path) catch {};
    std.debug.print("  Cleaned up test files\n", .{});

    std.debug.print("\n✓ Signature verification test completed successfully!\n", .{});
}
