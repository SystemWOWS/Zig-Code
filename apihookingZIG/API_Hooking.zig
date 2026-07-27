const std = @import("std");

pub const panic = std.debug.no_panic;

const DWORD = std.os.windows.DWORD;
const ULONG = std.os.windows.DWORD;
const HANDLE = std.os.windows.HANDLE;
const BOOL = std.os.windows.BOOL;
const HWND = ?*anyopaque;
const LPCSTR = [*:0]const u8;
const LPCWSTR = [*:0]const u16;
const NTSTATUS = u32;
const SIZE_T = usize;

const STATUS_SUCCESS: NTSTATUS = 0;

const PAGE_EXECUTE_READWRITE: ULONG = 0x40;
const MB_OK: DWORD = 0x00000000;
const MB_ICONINFORMATION: DWORD = 0x00000040;

const NtCurrentProcess: HANDLE = @ptrFromInt(@as(usize, @bitCast(@as(isize, -1))));

extern "user32" fn MessageBoxA(
    hWnd: HWND,
    lpText: LPCSTR,
    lpCaption: LPCSTR,
    uType: DWORD,
) callconv(.winapi) i32;

extern "user32" fn MessageBoxW(
    hWnd: HWND,
    lpText: LPCWSTR,
    lpCaption: LPCWSTR,
    uType: DWORD,
) callconv(.winapi) i32;

const TH32CS_SNAPTHREAD: DWORD = 0x00000004;
const THREAD_SUSPEND_RESUME: DWORD = 0x0002;
const INVALID_HANDLE_VALUE: HANDLE = @ptrFromInt(@as(usize, @bitCast(@as(isize, -1))));

const THREADENTRY32 = extern struct {
    dwSize: DWORD,
    cntUsage: DWORD,
    th32ThreadID: DWORD,
    th32OwnerProcessID: DWORD,
    tpBasePri: i32,
    tpDeltaPri: i32,
    dwFlags: DWORD,
};

fn current_pid() DWORD {
    return asm volatile ("mov %%gs:0x40, %[p]"
        : [p] "=r" (-> DWORD),
    );
}

fn current_tid() DWORD {
    return asm volatile ("mov %%gs:0x48, %[t]"
        : [t] "=r" (-> DWORD),
    );
}

const LIST_ENTRY = extern struct {
    Flink: *LIST_ENTRY,
    Blink: *LIST_ENTRY,
};

const UNICODE_STRING = extern struct {
    Length: u16,
    MaximumLength: u16,
    _pad: u32 = 0,
    Buffer: ?*u16,
};

const PEB_LDR_DATA = extern struct {
    Length: u32,
    Initialized: u32,
    SsHandle: ?*anyopaque,
    InLoadOrderModuleList: LIST_ENTRY,
    InMemoryOrderModuleList: LIST_ENTRY,
    InInitializationOrderModuleList: LIST_ENTRY,
};

const PEB = extern struct {
    InheritedAddressSpace: u8,
    ReadImageFileExecOptions: u8,
    BeingDebugged: u8,
    BitField: u8,
    Mutant: ?*anyopaque,
    ImageBaseAddress: ?*anyopaque,
    Ldr: *PEB_LDR_DATA,
};

const LDR_DATA_TABLE_ENTRY = extern struct {
    InLoadOrderLinks: LIST_ENTRY,
    InMemoryOrderLinks: LIST_ENTRY,
    InInitializationOrderLinks: LIST_ENTRY,
    DllBase: ?*anyopaque,
    EntryPoint: ?*anyopaque,
    SizeOfImage: u32,
    FullDllName: UNICODE_STRING,
    BaseDllName: UNICODE_STRING,
};

fn get_peb() *PEB {
    return asm volatile ("mov %%gs:0x60, %[peb]"
        : [peb] "=r" (-> *PEB),
    );
}

fn rd_u8(addr: usize) u8 {
    const p: [*]const u8 = @ptrFromInt(addr);
    return p[0];
}

fn rd_u16(addr: usize) u16 {
    const p: [*]const u8 = @ptrFromInt(addr);
    return @as(u16, p[0]) | (@as(u16, p[1]) << 8);
}

fn rd_u32(addr: usize) u32 {
    const p: [*]const u8 = @ptrFromInt(addr);
    return @as(u32, p[0]) |
        (@as(u32, p[1]) << 8) |
        (@as(u32, p[2]) << 16) |
        (@as(u32, p[3]) << 24);
}

fn get_module_base(name_lower: []const u8) ?*anyopaque {
    const ldr = get_peb().Ldr;
    var entry = ldr.InMemoryOrderModuleList.Flink;
    const head: *LIST_ENTRY = &ldr.InMemoryOrderModuleList;

    while (entry != head) {
        const ldr_entry: *LDR_DATA_TABLE_ENTRY = @fieldParentPtr("InMemoryOrderLinks", entry);
        const base_name = &ldr_entry.BaseDllName;
        if (base_name.Buffer) |buf_raw| {
            const buf: [*]u16 = @ptrCast(buf_raw);
            const len: usize = base_name.Length / 2;
            if (len == name_lower.len) {
                var match = true;
                var i: usize = 0;
                while (i < len) : (i += 1) {
                    const c = std.ascii.toLower(@intCast(buf[i] & 0xFF));
                    if (c != name_lower[i]) {
                        match = false;
                        break;
                    }
                }
                if (match) return ldr_entry.DllBase;
            }
        }
        entry = entry.Flink;
    }
    return null;
}

fn get_export_address(base: *anyopaque, func_name: []const u8) ?*anyopaque {
    const base_addr = @intFromPtr(base);

    const e_lfanew = rd_u32(base_addr + 0x3C);
    const opt_hdr = base_addr + e_lfanew + 4 + 20;
    const export_rva = rd_u32(opt_hdr + 0x70);
    const export_size = rd_u32(opt_hdr + 0x74);
    if (export_rva == 0) return null;

    const export_dir = base_addr + export_rva;
    const num_names = rd_u32(export_dir + 0x18);
    const funcs_rva = rd_u32(export_dir + 0x1C);
    const names_rva = rd_u32(export_dir + 0x20);
    const ords_rva = rd_u32(export_dir + 0x24);
    if (num_names == 0) return null;

    const names = base_addr + names_rva;
    const funcs = base_addr + funcs_rva;
    const ords = base_addr + ords_rva;

    var i: u32 = 0;
    while (i < num_names) : (i += 1) {
        const name_rva = rd_u32(names + @as(usize, i) * 4);
        if (ascii_streq(base_addr + name_rva, func_name)) {
            const ord = rd_u16(ords + @as(usize, i) * 2);
            const func_rva = rd_u32(funcs + @as(usize, ord) * 4);
            if (func_rva >= export_rva and func_rva < export_rva + export_size) {
                return null;
            }
            return @ptrFromInt(base_addr + func_rva);
        }
    }
    return null;
}

fn ascii_streq(name_addr: usize, target: []const u8) bool {
    const p: [*]const u8 = @ptrFromInt(name_addr);
    var i: usize = 0;
    while (i < target.len) : (i += 1) {
        if (p[i] == 0) return false;
        if (p[i] != target[i]) return false;
    }
    return p[target.len] == 0;
}

const STUB_SIG = [_]u8{ 0x4C, 0x8B, 0xD1, 0xB8 };
const STUB_SCAN_LIMIT: usize = 0x500;

fn matches_sig(addr: usize) bool {
    const p: [*]const u8 = @ptrFromInt(addr);
    for (STUB_SIG, 0..) |b, i| if (p[i] != b) return false;
    return true;
}

fn resolve_ssn(stub_addr: usize) ?u32 {
    if (matches_sig(stub_addr)) {
        return rd_u32(stub_addr + 4);
    }

    var skipped: u32 = 0;
    var off: usize = 1;
    while (off + 8 <= STUB_SCAN_LIMIT) : (off += 1) {
        if (matches_sig(stub_addr + off)) {
            skipped += 1;
            const found_ssn = rd_u32(stub_addr + off + 4);
            const candidate = found_ssn -% skipped;
            if (candidate < 0x1000) return candidate;
        }
    }
    return null;
}

fn syscall2(ssn: u32, arg1: usize, arg2: usize) NTSTATUS {
    return asm volatile (
        \\mov %[a1], %%rcx
        \\mov %%rcx, %%r10
        \\mov %[ssn], %%eax
        \\mov %[a2], %%rdx
        \\syscall
        : [ret] "={eax}" (-> NTSTATUS),
        : [ssn] "r" (ssn),
          [a1] "r" (arg1),
          [a2] "r" (arg2),
        : .{ .rax = true, .rcx = true, .rdx = true, .r10 = true, .r11 = true, .memory = true });
}

fn nt_protect_virtual_memory(
    ssn: u32,
    process: usize,
    base: *usize,
    size: *usize,
    new_protect: ULONG,
    old_protect: *ULONG,
) NTSTATUS {
    return asm volatile (
        \\mov %[p], %%rcx
        \\mov %%rcx, %%r10
        \\mov %[ssn], %%eax
        \\mov %[b], %%rdx
        \\mov %[s], %%r8
        \\mov %[n], %%r9
        \\sub $0x38, %%rsp
        \\mov %[o], 0x28(%%rsp)
        \\syscall
        \\add $0x38, %%rsp
        : [ret] "={eax}" (-> NTSTATUS),
        : [ssn] "r" (ssn),
          [p] "r" (process),
          [b] "r" (@intFromPtr(base)),
          [s] "r" (@intFromPtr(size)),
          [n] "r" (@as(u64, new_protect)),
          [o] "r" (@intFromPtr(old_protect)),
        : .{ .rax = true, .rcx = true, .rdx = true, .r8 = true, .r9 = true, .r10 = true, .r11 = true, .memory = true });
}

const Imports = struct {
    ntdll_base: *anyopaque,
    user32_base: *anyopaque,
    nt_protect_ssn: u32,
    nt_suspend_thread_ssn: u32,
    nt_resume_thread_ssn: u32,
    message_box_a: *anyopaque,
    create_toolhelp32_snapshot: *const fn (DWORD, DWORD) callconv(.winapi) HANDLE,
    thread32_first: *const fn (HANDLE, *THREADENTRY32) callconv(.winapi) BOOL,
    thread32_next: *const fn (HANDLE, *THREADENTRY32) callconv(.winapi) BOOL,
    open_thread: *const fn (DWORD, BOOL, DWORD) callconv(.winapi) ?HANDLE,
    close_handle: *const fn (HANDLE) callconv(.winapi) BOOL,
    current_pid: DWORD,
    current_tid: DWORD,
};

fn resolve_imports() ?Imports {
    const ntdll_base = get_module_base("ntdll.dll") orelse return null;
    const user32_base = get_module_base("user32.dll") orelse return null;

    const nt_protect = get_export_address(ntdll_base, "NtProtectVirtualMemory") orelse return null;
    const nt_suspend = get_export_address(ntdll_base, "NtSuspendThread") orelse return null;
    const nt_resume = get_export_address(ntdll_base, "NtResumeThread") orelse return null;

    const nt_protect_ssn = resolve_ssn(@intFromPtr(nt_protect)) orelse return null;
    const nt_suspend_ssn = resolve_ssn(@intFromPtr(nt_suspend)) orelse return null;
    const nt_resume_ssn = resolve_ssn(@intFromPtr(nt_resume)) orelse return null;

    const message_box_a = get_export_address(user32_base, "MessageBoxA") orelse return null;

    const kernel32_base = get_module_base("kernel32.dll") orelse return null;
    const create_snap = get_export_address(kernel32_base, "CreateToolhelp32Snapshot") orelse return null;
    const t32first = get_export_address(kernel32_base, "Thread32First") orelse return null;
    const t32next = get_export_address(kernel32_base, "Thread32Next") orelse return null;
    const open_thread = get_export_address(kernel32_base, "OpenThread") orelse return null;
    const close_handle = get_export_address(kernel32_base, "CloseHandle") orelse return null;

    return .{
        .ntdll_base = ntdll_base,
        .user32_base = user32_base,
        .nt_protect_ssn = nt_protect_ssn,
        .nt_suspend_thread_ssn = nt_suspend_ssn,
        .nt_resume_thread_ssn = nt_resume_ssn,
        .message_box_a = message_box_a,
        .create_toolhelp32_snapshot = @ptrCast(@alignCast(create_snap)),
        .thread32_first = @ptrCast(@alignCast(t32first)),
        .thread32_next = @ptrCast(@alignCast(t32next)),
        .open_thread = @ptrCast(@alignCast(open_thread)),
        .close_handle = @ptrCast(@alignCast(close_handle)),
        .current_pid = current_pid(),
        .current_tid = current_tid(),
    };
}

const INTERCEPTOR_SIZE: usize = 14;

const ApiInterceptor = struct {
    target_function: ?[*]u8,
    replacement_function: ?*anyopaque,
    original_code: [INTERCEPTOR_SIZE]u8,
    original_protection: ULONG,

    fn init() ApiInterceptor {
        return .{
            .target_function = null,
            .replacement_function = null,
            .original_code = [_]u8{0} ** INTERCEPTOR_SIZE,
            .original_protection = 0,
        };
    }
};

fn setup_interceptor(
    imp: *const Imports,
    target_function: *anyopaque,
    replacement_function: *anyopaque,
    ic: *ApiInterceptor,
) bool {
    ic.target_function = @ptrCast(target_function);
    ic.replacement_function = replacement_function;

    const t: [*]u8 = @ptrCast(target_function);

    if (t[0] == 0xFF and t[1] == 0x25) {
        std.debug.print("[!] Target prologue already patched (FF 25 ...) — aborting\n", .{});
        return false;
    }

    @memcpy(ic.original_code[0..], t[0..INTERCEPTOR_SIZE]);

    var base: usize = @intFromPtr(target_function);
    var region_size: usize = INTERCEPTOR_SIZE;
    var old_prot: ULONG = 0;
    const status = nt_protect_virtual_memory(
        imp.nt_protect_ssn,
        @intFromPtr(NtCurrentProcess),
        &base,
        &region_size,
        PAGE_EXECUTE_READWRITE,
        &old_prot,
    );
    if (status != STATUS_SUCCESS) {
        std.debug.print("[!] NtProtectVirtualMemory failed: 0x{X}\n", .{status});
        return false;
    }
    ic.original_protection = old_prot;
    return true;
}

var g_suspended: [128]?HANDLE = [_]?HANDLE{null} ** 128;
var g_suspended_count: usize = 0;

fn suspend_other_threads(imp: *const Imports) void {
    g_suspended_count = 0;
    const snap = imp.create_toolhelp32_snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    defer _ = imp.close_handle(snap);

    var te: THREADENTRY32 = .{
        .dwSize = @sizeOf(THREADENTRY32),
        .cntUsage = 0,
        .th32ThreadID = 0,
        .th32OwnerProcessID = 0,
        .tpBasePri = 0,
        .tpDeltaPri = 0,
        .dwFlags = 0,
    };
    if (imp.thread32_first(snap, &te) == .FALSE) return;
    while (true) {
        if (te.th32OwnerProcessID == imp.current_pid and te.th32ThreadID != imp.current_tid) {
            const h = imp.open_thread(THREAD_SUSPEND_RESUME, .FALSE, te.th32ThreadID);
            if (h) |handle| {
                if (g_suspended_count < g_suspended.len) {
                    _ = syscall2(imp.nt_suspend_thread_ssn, @intFromPtr(handle), 0);
                    g_suspended[g_suspended_count] = handle;
                    g_suspended_count += 1;
                } else {
                    _ = imp.close_handle(handle);
                }
            }
        }
        if (imp.thread32_next(snap, &te) == .FALSE) break;
    }
}

fn resume_other_threads(imp: *const Imports) void {
    var i: usize = 0;
    while (i < g_suspended_count) : (i += 1) {
        if (g_suspended[i]) |handle| {
            _ = syscall2(imp.nt_resume_thread_ssn, @intFromPtr(handle), 0);
            _ = imp.close_handle(handle);
            g_suspended[i] = null;
        }
    }
    g_suspended_count = 0;
}

fn activate_interceptor(imp: *const Imports, ic: *ApiInterceptor) bool {
    const target = ic.target_function orelse return false;
    const replacement = ic.replacement_function orelse return false;

    suspend_other_threads(imp);

    const jmp_prefix = [6]u8{ 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 };
    const addr: u64 = @intFromPtr(replacement);
    const addr_bytes: [8]u8 = @bitCast(addr);
    @memcpy(target[6..14], addr_bytes[0..]);
    @memcpy(target[0..6], &jmp_prefix);

    resume_other_threads(imp);
    return true;
}

fn deactivate_interceptor(imp: *const Imports, ic: *ApiInterceptor) bool {
    const target = ic.target_function orelse return false;

    suspend_other_threads(imp);
    @memcpy(target[0..INTERCEPTOR_SIZE], ic.original_code[0..]);
    resume_other_threads(imp);

    var base: usize = @intFromPtr(target);
    var region_size: usize = INTERCEPTOR_SIZE;
    var old_prot: ULONG = 0;
    _ = nt_protect_virtual_memory(
        imp.nt_protect_ssn,
        @intFromPtr(NtCurrentProcess),
        &base,
        &region_size,
        ic.original_protection,
        &old_prot,
    );

    ic.target_function = null;
    ic.replacement_function = null;
    @memset(ic.original_code[0..], 0);
    ic.original_protection = 0;
    return true;
}

fn custom_dialog(
    hwnd: HWND,
    lp_text: LPCSTR,
    lp_caption: LPCSTR,
    u_type: DWORD,
) callconv(.winapi) i32 {
    const text = std.mem.span(lp_text);
    const caption = std.mem.span(lp_caption);

    std.debug.print("[INFO] Dialog Parameters:\n", .{});
    std.debug.print("\tText:    {s}\n", .{text});
    std.debug.print("\tCaption: {s}\n", .{caption});

    const new_text_u8 = "sw64 Is a Good Guy";
    const new_caption_u8 = "System Dialog";

    var new_text_w = [_]u16{0} ** (new_text_u8.len + 1);
    var new_caption_w = [_]u16{0} ** (new_caption_u8.len + 1);

    for (new_text_u8, 0..) |c, i| new_text_w[i] = c;
    for (new_caption_u8, 0..) |c, i| new_caption_w[i] = c;

    return MessageBoxW(
        hwnd,
        @ptrCast(&new_text_w),
        @ptrCast(&new_caption_w),
        u_type,
    );
}

pub fn main() void {
    const imp = resolve_imports() orelse {
        std.debug.print("[ERROR] PEB / syscall resolution failed\n", .{});
        return;
    };
    std.debug.print(
        "[INFO] SSNs: NtProtectVirtualMemory={x} NtSuspendThread={x} NtResumeThread={x}  pid={d} tid={d}\n",
        .{ imp.nt_protect_ssn, imp.nt_suspend_thread_ssn, imp.nt_resume_thread_ssn, imp.current_pid, imp.current_tid },
    );

    var ic = ApiInterceptor.init();
    if (!setup_interceptor(&imp, imp.message_box_a, @ptrCast(@constCast(&custom_dialog)), &ic)) {
        std.debug.print("[ERROR] Interceptor setup failed\n", .{});
        return;
    }

    _ = MessageBoxA(null, "Testing system", "System info", MB_OK | MB_ICONINFORMATION);

    std.debug.print("[INFO] Activating API Interceptor...\n", .{});
    if (!activate_interceptor(&imp, &ic)) {
        std.debug.print("[ERROR] Interceptor activation failed\n", .{});
        return;
    }
    std.debug.print("[INFO] Interceptor activated\n", .{});

    _ = MessageBoxA(null, "Sw64 Is Bad Guy...", "System Info", MB_OK | MB_ICONINFORMATION);

    std.debug.print("[INFO] Deactivating API interceptor...\n", .{});
    if (!deactivate_interceptor(&imp, &ic)) {
        std.debug.print("[ERROR] Interceptor deactivation failed\n", .{});
        return;
    }
    std.debug.print("[INFO] Interceptor deactivated\n", .{});

    _ = MessageBoxA(null, "System Restored", "System Info", MB_OK | MB_ICONINFORMATION);

    std.debug.print("[INFO] PoC Demonstrated Successfully\n", .{});
}
