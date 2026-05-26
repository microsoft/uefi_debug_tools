# EfiSymComposition

A WinDbg Target Composition component that resolves and loads symbols for
UEFI ELF images during a debug session.

## Purpose

This module is a runtime dependency of the [UEFI Debugger Extension](../UefiDbgExt/readme.md).
It is loaded by `uefiext` to enable symbol resolution for UEFI binaries and
is not intended to be invoked directly by users.

It ships alongside `uefiext.dll` in the release bundle produced by the
[Build UEFI Debug Extension](https://github.com/microsoft/uefi_debug_tools/actions/workflows/Build-UefiExt.yaml)
workflow, so installing `uefiext` per its readme also installs this component.

## Building

Requires Visual Studio 2022 with the Windows SDK. The `Microsoft.Debugging.TargetModel.SDK`
NuGet package must be restored before building.

```powershell
nuget restore EfiSymComposition\packages.config -PackagesDirectory EfiSymComposition\packages
msbuild EfiSymComposition\EfiSymComposition.vcxproj -property:Configuration=Release -property:Platform=x64
```

Supported platforms: `x64`, `ARM64`.
