# Zig API Hooking Demo

Zig proof-of-concept for inline API hooking on Windows x64.
It patches `MessageBoxA` with a trampoline and redirects execution to a custom handler.

## Layout

- `API_Hooking.zig` — main hooking implementation
- `build.zig` — Zig build script

## Requirements

- Zig `0.16.0` (or compatible)
- Windows x64

## Build

```powershell
zig build
```

Binary output: `zig-out/bin/Api_Hooking.exe`

## Credits

- https://git.smukx.site/smukx/Rust-for-Malware-Development/src/branch/main/Api_Hooking
- https://github.com/ZeroMemoryEx/TrampHook
- https://www.ired.team/offensive-security/code-injection-process-injection/how-to-hook-windows-api-using-c++
- https://www.packtpub.com/en-us/product/mastering-malware-analysis-9781789610789/chapter/inspecting-process-injection-and-api-hooking-6/section/inline-api-hooking-with-trampoline-ch06lvl1sec86

## Notes

- Low-level research/demo project.
- Uses direct syscalls and runtime export resolution.
- Use only in environments where you have explicit authorization.
