//
// API Hooking Via Trampoline: Zig Port (hardened)
//
// Inline trampoline hook on MessageBoxA in user32.dll. The hooked call is
// redirected to custom_dialog, which logs params and forwards to MessageBoxW
// with modified text.
//
// Build:  zig build            (-> zig-out/bin/Api_Hooking.exe)
//
// What this build implements from the original TODO list:
//
//   [1] VirtualProtect replaced with a direct NtProtectVirtualMemory syscall.
//   [2] GetModuleHandleA / GetProcAddress removed from the IAT — modules and
//       exports are resolved by walking the PEB (Ldr.InMemoryOrderModuleList)
//       and parsing each module's PE export table.
//   [3] The first bytes of the target are checked for an existing FF 25 ...
//       inline hook before we snapshot the prologue, so we don't capture an
//       EDR's trampoline bytes as our "original" code.
//   [4] Trampoline write is bracketed by suspending every OTHER thread in the
//       process (Toolhelp32 enumerate + NtSuspendThread per TID != current,
//       direct syscalls) and resuming after — closes the TOCTOU window where
//       the target is half-patched, without NtSuspendProcess self-deadlocking
//       the caller.
//   [5] SSNs are resolved at runtime with a HellsGate/HalosGate scan over the
//       ntdll stub bytes, so the build is not pinned to one OS version's SSN.
//   [6] std panic chain is replaced with std.debug.no_panic (just @trap), and
//       the build defaults to ReleaseSmall with exe.strip = true to drop the
//       DWARF/PDB sections CAPA pattern-matches on.
//   [7] Freestanding (-target x86_64-windows-none) is left as a build-option
//       exercise — it drops the CRT/.TLS sections but requires a hand-rolled
//       entry point and is incompatible with std.os.windows as used here.
//

const std = @import("std");

// Kill the std panic/crypto/process chain that drags in base64/RC4/XOR
// signatures. no_panic just traps; no formatted I/O on panic.
pub const panic = std.debug.no_panic;

// ---------------------------------------------------------------------------
// Win32 types
// ---------------------------------------------------------------------------

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

// (HANDLE)-1 == NtCurrentProcess
const NtCurrentProcess: HANDLE = @ptrFromInt(@as(usize, @bitCast(@as(isize, -1))));

// MessageBoxA (the hook target) and MessageBoxW (called from the hook body)
// stay as ordinary IAT imports — we legitimately call them. Everything else
// (module/export resolution, memory protection, thread suspension) is done
// without going through the IAT.

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

// ---------------------------------------------------------------------------
// Thread enumeration (for atomic trampoline patching without self-deadlock)
// ---------------------------------------------------------------------------

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

// Current process/thread IDs read straight from the TEB (gs:0x40 / gs:0x48),
// i.e. TEB.ClientId.UniqueProcess / UniqueThread — no kernel32 imports needed.
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

// ---------------------------------------------------------------------------
// PEB / Ldr / PE structures (x64)
// ---------------------------------------------------------------------------

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
    return asm volatile (
        "mov %%gs:0x60, %[peb]"
        : [peb] "=r" (-> *PEB),
    );
}

// ---------------------------------------------------------------------------
// Little-endian byte readers (avoid alignment faults on PE fields)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// PEB walk — find a loaded module's DllBase by lowercased base name
// ---------------------------------------------------------------------------

fn get_module_base(name_lower: []const u8) ?*anyopaque {
    const ldr = get_peb().Ldr;
    var entry = ldr.InMemoryOrderModuleList.Flink;
    const head: *LIST_ENTRY = &ldr.InMemoryOrderModuleList;

    while (entry != head) {
        const ldr_entry: *LDR_DATA_TABLE_ENTRY = @fieldParentPtr("InMemoryOrderLinks", entry);
        const base_name = &ldr_entry.BaseDllName;
        if (base_name.Buffer) |buf_raw| {
            const buf: [*]u16 = @ptrCast(buf_raw);
            const len: usize = base_name.Length / 2; // bytes -> UTF-16 chars
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

// ---------------------------------------------------------------------------
// PE export table walk — resolve an export by (case-sensitive) name
// ---------------------------------------------------------------------------

fn get_export_address(base: *anyopaque, func_name: []const u8) ?*anyopaque {
    const base_addr = @intFromPtr(base);

    const e_lfanew = rd_u32(base_addr + 0x3C);
    const opt_hdr = base_addr + e_lfanew + 4 + 20; // skip signature + file header
    const export_rva = rd_u32(opt_hdr + 0x70); // DataDirectory[0].VirtualAddress
    const export_size = rd_u32(opt_hdr + 0x74); // DataDirectory[0].Size
    if (export_rva == 0) return null;

    const export_dir = base_addr + export_rva;
    const num_names = rd_u32(export_dir + 0x18);
    const funcs_rva = rd_u32(export_dir + 0x1C); // AddressOfFunctions
    const names_rva = rd_u32(export_dir + 0x20); // AddressOfNames
    const ords_rva = rd_u32(export_dir + 0x24); // AddressOfNameOrdinals
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
            // Forwarder RVAs point inside the export directory; skip them.
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

// ---------------------------------------------------------------------------
// HellsGate / HalosGate — resolve an Nt* syscall SSN from its ntdll stub
// ---------------------------------------------------------------------------
//
// Win10/11 ntdll syscall stubs start with:
//     4C 8B D1          mov r10, rcx
//     B8 <ssn:u32>      mov eax, SSN
// If the stub is hooked (e.g. an EDR patched the prologue with a JMP), the
// signature won't match. We then scan forward for the next intact stub and
// back-derive the original SSN by counting how many stubs we skipped.

const STUB_SIG = [_]u8{ 0x4C, 0x8B, 0xD1, 0xB8 };
const STUB_SCAN_LIMIT: usize = 0x500;

fn matches_sig(addr: usize) bool {
    const p: [*]const u8 = @ptrFromInt(addr);
    for (STUB_SIG, 0..) |b, i| if (p[i] != b) return false;
    return true;
}

fn resolve_ssn(stub_addr: usize) ?u32 {
    // HellsGate: target stub intact.
    if (matches_sig(stub_addr)) {
        return rd_u32(stub_addr + 4);
    }

    // HalosGate: scan forward for an intact stub, back-derive SSN.
    var skipped: u32 = 0;
    var off: usize = 1;
    while (off + 8 <= STUB_SCAN_LIMIT) : (off += 1) {
        if (matches_sig(stub_addr + off)) {
            skipped += 1;
            const found_ssn = rd_u32(stub_addr + off + 4);
            const candidate = found_ssn -% skipped;
            // Syscall numbers on Win10/11 x64 are small positive values.
            if (candidate < 0x1000) return candidate;
        }
    }
    return null;
}

// ---------------------------------------------------------------------------
// Direct syscall stubs
// ---------------------------------------------------------------------------

// 2-arg syscall (NtSuspendThread / NtResumeThread). The 2nd arg
// (PreviousSuspendCount*) may be NULL.
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

// NtProtectVirtualMemory(ProcessHandle, *BaseAddress, *RegionSize, NewProtect,//                        *OldProtect) — 5th arg goes on the user stack at
// [rsp+0x28] per the x64 syscall ABI.
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
          [p]   "r" (process),
          [b]   "r" (@intFromPtr(base)),
          [s]   "r" (@intFromPtr(size)),
          [n]   "r" (@as(u64, new_protect)),
          [o]   "r" (@intFromPtr(old_protect)),
        : .{ .rax = true, .rcx = true, .rdx = true, .r8 = true, .r9 = true, .r10 = true, .r11 = true, .memory = true });
}

// ---------------------------------------------------------------------------
// Resolved imports + SSNs (populated once in main)
// ---------------------------------------------------------------------------

const Imports = struct {
    ntdll_base: *anyopaque,
    user32_base: *anyopaque,
    nt_protect_ssn: u32,
    nt_suspend_thread_ssn: u32,
    nt_resume_thread_ssn: u32,
    message_box_a: *anyopaque,
    // kernel32 exports (resolved via PEB, called through function pointers so
    // GetModuleHandleA/GetProcAddress stay out of the IAT).
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

    // kernel32 thread-enumeration exports, resolved the same PEB/PE way.
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

// ---------------------------------------------------------------------------
// Interceptor
// ---------------------------------------------------------------------------

// 64-bit trampoline: 6 bytes JMP [RIP+0] + 8 bytes absolute address = 14 bytes
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

// setup_interceptor — snapshot the prologue, check it isn't already hooked,
// and flip memory to PAGE_EXECUTE_READWRITE via a direct syscall.
fn setup_interceptor(
    imp: *const Imports,
    target_function: *anyopaque,
    replacement_function: *anyopaque,
    ic: *ApiInterceptor,
) bool {
    ic.target_function = @ptrCast(target_function);
    ic.replacement_function = replacement_function;

    const t: [*]u8 = @ptrCast(target_function);

    // [3] existing-hook check: an EDR inline hook typically starts FF 25 ...
    if (t[0] == 0xFF and t[1] == 0x25) {
        std.debug.print("[!] Target prologue already patched (FF 25 ...) — aborting\n", .{});
        return false;
    }

    // Snapshot original bytes.
    @memcpy(ic.original_code[0..], t[0..INTERCEPTOR_SIZE]);

    // [1] NtProtectVirtualMemory via direct syscall.
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

// [4] Atomicity: suspend every OTHER thread in this process, patch, resume.
// NtSuspendProcess self-deadlocks the caller, so we enumerate threads via
// Toolhelp32 and NtSuspendThread each TID != current. Handles are stashed for
// the matching resume.
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

// activate_interceptor — suspend sibling threads, write the trampoline, resume.
fn activate_interceptor(imp: *const Imports, ic: *ApiInterceptor) bool {
    const target = ic.target_function orelse return false;
    const replacement = ic.replacement_function orelse return false;

    // [4] close the TOCTOU window on the patch.
    suspend_other_threads(imp);

    const jmp_prefix = [6]u8{ 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 };
    const addr: u64 = @intFromPtr(replacement);
    const addr_bytes: [8]u8 = @bitCast(addr);
    @memcpy(target[6..14], addr_bytes[0..]);
    @memcpy(target[0..6], &jmp_prefix);

    resume_other_threads(imp);
    return true;
}

// deactivate_interceptor — restore prologue + protection, clear the struct.
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

// ---------------------------------------------------------------------------
// Hook body — must match MessageBoxA's calling convention exactly
// ---------------------------------------------------------------------------

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

    // UTF-16LE replacement strings (null-terminated).
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

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

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

    // 1. Before hook — normal dialog.
    _ = MessageBoxA(null, "Testing system", "System info", MB_OK | MB_ICONINFORMATION);

    // 2. Activate.
    std.debug.print("[INFO] Activating API Interceptor...\n", .{});
    if (!activate_interceptor(&imp, &ic)) {
        std.debug.print("[ERROR] Interceptor activation failed\n", .{});
        return;
    }
    std.debug.print("[INFO] Interceptor activated\n", .{});

    // 3. While hooked — redirected to custom_dialog.
    _ = MessageBoxA(null, "Sw64 Is Bad Guy...", "System Info", MB_OK | MB_ICONINFORMATION);

    // 4. Deactivate.
    std.debug.print("[INFO] Deactivating API interceptor...\n", .{});
    if (!deactivate_interceptor(&imp, &ic)) {
        std.debug.print("[ERROR] Interceptor deactivation failed\n", .{});
        return;
    }
    std.debug.print("[INFO] Interceptor deactivated\n", .{});

    // 5. After hook — normal dialog again.
    _ = MessageBoxA(null, "System Restored", "System Info", MB_OK | MB_ICONINFORMATION);

    std.debug.print("[INFO] PoC Demonstrated Successfully\n", .{});
}
