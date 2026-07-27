const std = @import("std");

const EncryptedPart = struct {
    var_name: []const u8,
    encrypted: []const u8,
};

fn randomVarName(allocator: std.mem.Allocator, rng: std.Random) ![]const u8 {
    const alphanumeric = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    const rest_len = rng.intRangeAtMost(usize, 4, 9);
    const name = try allocator.alloc(u8, rest_len + 1);
    errdefer allocator.free(name);

    name[0] = rng.intRangeAtMost(u8, 'a', 'z');

    for (name[1..]) |*c| {
        const idx = rng.intRangeLessThan(usize, 0, alphanumeric.len);
        c.* = alphanumeric[idx];
    }

    return name;
}

fn xorEncrypt(allocator: std.mem.Allocator, input: []const u8, key: []const u8) ![]const u8 {
    if (key.len == 0) return error.EmptyKey;

    const encrypted = try allocator.alloc(u8, input.len);
    defer allocator.free(encrypted);

    for (input, 0..) |byte, i| {
        encrypted[i] = byte ^ key[i % key.len];
    }

    const encoder = std.base64.standard.Encoder;
    const encoded_len = encoder.calcSize(encrypted.len);
    const encoded = try allocator.alloc(u8, encoded_len);
    _ = encoder.encode(encoded, encrypted);

    return encoded;
}

fn xorDecrypt(allocator: std.mem.Allocator, input: []const u8, key: []const u8) ![]const u8 {
    if (key.len == 0) return error.EmptyKey;

    const decoder = std.base64.standard.Decoder;
    const decoded_len = try decoder.calcSizeForSlice(input);
    const decoded = try allocator.alloc(u8, decoded_len);
    defer allocator.free(decoded);

    _ = try decoder.decode(decoded, input);

    const result = try allocator.alloc(u8, decoded.len);
    for (decoded, 0..) |byte, i| {
        result[i] = byte ^ key[i % key.len];
    }

    if (!std.unicode.utf8ValidateSlice(result)) {
        allocator.free(result);
        return error.InvalidUtf8;
    }

    return result;
}

fn splitUrl(allocator: std.mem.Allocator, rng: std.Random, url: []const u8) !std.ArrayList([]const u8) {
    if (url.len == 0) return error.EmptyUrl;

    const num_parts = rng.intRangeAtMost(usize, 3, 5);

    var parts: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (parts.items) |item| allocator.free(item);
        parts.deinit(allocator);
    }

    var start: usize = 0;

    var i: usize = 0;
    while (i < num_parts - 1) : (i += 1) {
        const min_part_len = url.len / num_parts / 2;
        const max_part_len = url.len / num_parts;

        const lower = @max(min_part_len, 1);
        const upper = @max(max_part_len, lower);

        const part_len = rng.intRangeAtMost(usize, lower, upper);

        if (start + part_len <= url.len) {
            const part = try allocator.dupe(u8, url[start .. start + part_len]);
            try parts.append(allocator, part);
            start += part_len;
        }
    }

    if (start < url.len) {
        const last_part = try allocator.dupe(u8, url[start..]);
        try parts.append(allocator, last_part);
    }

    return parts;
}

fn encryptionAlgorithm(
    allocator: std.mem.Allocator,
    rng: std.Random,
    url: []const u8,
    key: []const u8,
) !struct { parts: std.ArrayList(EncryptedPart), code: []const u8 } {
    var split_parts = try splitUrl(allocator, rng, url);
    defer {
        for (split_parts.items) |item| allocator.free(item);
        split_parts.deinit(allocator);
    }

    var encrypted_parts: std.ArrayList(EncryptedPart) = .empty;
    errdefer {
        for (encrypted_parts.items) |item| {
            allocator.free(item.var_name);
            allocator.free(item.encrypted);
        }
        encrypted_parts.deinit(allocator);
    }

    var code_builder: std.ArrayList(u8) = .empty;
    errdefer code_builder.deinit(allocator);

    for (split_parts.items) |part| {
        const var_name = try randomVarName(allocator, rng);
        errdefer allocator.free(var_name);

        const encrypted = try xorEncrypt(allocator, part, key);
        errdefer allocator.free(encrypted);

        try encrypted_parts.append(allocator, .{
            .var_name = var_name,
            .encrypted = encrypted,
        });

        const line = try std.fmt.allocPrint(allocator, "let {s} = \"{s}\";\n", .{ var_name, encrypted });
        defer allocator.free(line);
        try code_builder.appendSlice(allocator, line);
    }

    const code = try code_builder.toOwnedSlice(allocator);

    return .{
        .parts = encrypted_parts,
        .code = code,
    };
}

fn decryptionAlgorithm(
    allocator: std.mem.Allocator,
    encrypted_parts: []const EncryptedPart,
    key: []const u8,
) !struct { url: []const u8, code: []const u8 } {
    var code_builder: std.ArrayList(u8) = .empty;
    errdefer code_builder.deinit(allocator);

    var decrypted_parts: std.ArrayList([]const u8) = .empty;
    defer {
        for (decrypted_parts.items) |item| allocator.free(item);
        decrypted_parts.deinit(allocator);
    }

    for (encrypted_parts) |part| {
        const decrypted = try xorDecrypt(allocator, part.encrypted, key);
        errdefer allocator.free(decrypted);
        try decrypted_parts.append(allocator, decrypted);

        const line = try std.fmt.allocPrint(allocator, "let decrypted_{s} = xor_decrypt({s}, \"{s}\");\n", .{
            part.var_name,
            part.var_name,
            key,
        });
        defer allocator.free(line);
        try code_builder.appendSlice(allocator, line);
    }

    // Build format template: "{}{}{}..."
    var template_builder: std.ArrayList(u8) = .empty;
    defer template_builder.deinit(allocator);
    for (decrypted_parts.items) |_| {
        try template_builder.appendSlice(allocator, "{}");
    }

    // Build argument list: decrypted_a, decrypted_b, decrypted_c
    var args_builder: std.ArrayList(u8) = .empty;
    defer args_builder.deinit(allocator);
    for (encrypted_parts, 0..) |part, idx| {
        if (idx > 0) try args_builder.appendSlice(allocator, ", ");
        const arg = try std.fmt.allocPrint(allocator, "decrypted_{s}", .{part.var_name});
        defer allocator.free(arg);
        try args_builder.appendSlice(allocator, arg);
    }

    const final_line = try std.fmt.allocPrint(allocator, "let final_url = format!(\"{s}\", {s});\n", .{
        template_builder.items,
        args_builder.items,
    });
    defer allocator.free(final_line);
    try code_builder.appendSlice(allocator, final_line);

    // Reconstruct final URL
    var url_builder: std.ArrayList(u8) = .empty;
    errdefer url_builder.deinit(allocator);
    for (decrypted_parts.items) |part| {
        try url_builder.appendSlice(allocator, part);
    }

    const code = try code_builder.toOwnedSlice(allocator);
    errdefer allocator.free(code);

    const url = try url_builder.toOwnedSlice(allocator);

    return .{
        .url = url,
        .code = code,
    };
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;

    var seed: u64 = undefined;
    init.io.random(std.mem.asBytes(&seed));
    var prng = std.Random.DefaultPrng.init(seed);
    const rng = prng.random();

    const url = "https://testsite.com/files/malicious.exe";
    const key = "M@lWaREiwV_iMsCooL";

    var enc_result = try encryptionAlgorithm(allocator, rng, url, key);
    defer {
        for (enc_result.parts.items) |item| {
            allocator.free(item.var_name);
            allocator.free(item.encrypted);
        }
        enc_result.parts.deinit(allocator);
        allocator.free(enc_result.code);
    }

    std.debug.print("Encrypted parts code:\n{s}\n", .{enc_result.code});

    const dec_result = try decryptionAlgorithm(allocator, enc_result.parts.items, key);
    defer {
        allocator.free(dec_result.url);
        allocator.free(dec_result.code);
    }

    std.debug.print("Decryption code:\n{s}\n", .{dec_result.code});
    std.debug.print("Decrypted URL: {s}\n", .{dec_result.url});
}
