# Zig API Hooking Demo

This repository contains a Zig proof-of-concept for inline API hooking on Windows x64.
It patches `MessageBoxA` with a trampoline and redirects execution to a custom handler.

## Project Layout

- `apihookingZIG/API_Hooking.zig`: main hooking implementation
- `apihookingZIG/build.zig`: standard Zig build entrypoint
- `apihookingZIG/buildforapi.zig`: build configuration used by `build.zig`

## Requirements

- Zig `0.16.0` (or compatible)
- Windows x64

## Build

From `apihookingZIG`:

```powershell
zig build
```

The binary is produced at `apihookingZIG/zig-out/bin/Api_Hooking.exe`.


## Credits
https://git.smukx.site/smukx/Rust-for-Malware-Development/src/branch/main/Api_Hooking
https://github.com/ZeroMemoryEx/TrampHook
https://www.ired.team/offensive-security/code-injection-process-injection/how-to-hook-windows-api-using-c++
https://www.packtpub.com/en-us/product/mastering-malware-analysis-9781789610789/chapter/inspecting-process-injection-and-api-hooking-6/section/inline-api-hooking-with-trampoline-ch06lvl1sec86

## Notes

- This is a low-level research/demo project.
- It uses direct syscalls and runtime export resolution techniques.
- Use only in environments where you have explicit authorization.
- i'm new to zig :)
