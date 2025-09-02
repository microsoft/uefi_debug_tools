
# UEFI Debugger Extension

[![Build UEFI Debug Extension](https://github.com/microsoft/uefi_debug_tools/actions/workflows/Build-UefiExt.yaml/badge.svg)](https://github.com/microsoft/uefi_debug_tools/actions/workflows/Build-UefiExt.yaml)

This folder contains the source for the UEFI debugger extension. This provides
functionality within windbg for debugging the UEFI environment. Using the UEFI
extension requires that Windbgx has access to the symbol files for the target
UEFI code.

The most recent compiled version of this binary can be found as a build artifact
in the [debug extension workflow](https://github.com/microsoft/uefi_debug_tools/actions/workflows/Build-UefiExt.yaml).

## Compiling

Windbg debugger extensions need to be compiled with the Visual Studio build tools.
Visual Studio 2022 is recommended. The easiest way to compile is to use the Developer
Command Prompt that comes with the Visual Studio tools installation. In the command
prompt, navigate to the folder and run `msbuild`.

```powershell
    msbuild -property:Configuration=Release -property:Platform=x64
```

The project can also be loaded and built in Visual Studio using the solution
file. This project requires the Windows SDK and the Windows Driver Kit.

## Installing the Extension

Debugger extensions can be loaded into windbg several ways. The easiest is to download
the module into a default path folder. This can be done with the below commands.
Note that the architecture is the architecture of the host machine running Windbg,
not the device being debugged.

__Installing for X64 Host__:

```powershell
Invoke-WebRequest -Uri "https://github.com/microsoft/uefi_debug_tools/releases/latest/download/uefiext_x64.zip" -OutFile "$env:TEMP\uefiext.zip"; Expand-Archive "$env:TEMP\uefiext.zip" -DestinationPath "$env:TEMP\uefiext" -Force; Copy-Item "$env:TEMP\uefiext\uefiext.dll" -Destination "C:\Users\$Env:UserName\AppData\Local\DBG\EngineExtensions\UefiExt.dll"
```

__Installing for ARM64 Host__:

```powershell
Invoke-WebRequest -Uri "https://github.com/microsoft/uefi_debug_tools/releases/latest/download/uefiext_arm64.zip" -OutFile "$env:TEMP\uefiext.zip"; Expand-Archive "$env:TEMP\uefiext.zip" -DestinationPath "$env:TEMP\uefiext" -Force; Copy-Item "$env:TEMP\uefiext\uefiext.dll" -Destination "C:\Users\$Env:UserName\AppData\Local\DBG\EngineExtensions\UefiExt.dll"
```

`!uefiext` commands should now be available in windbg.

### Manual Install

If you want to manually load the extension, this can be done with the .load
command. Though this will not persist across windbg sessions.

```console
    .load <path to uefiext.dll>
```

The second is to place the DLL in the windbg application folder, or another
place in windbg's extpath which can be enumerating using the .extpath command.
This will make the extension available to all future windbg sessions.

```text
    e.g. C:\Users\<user>\AppData\Local\dbg\EngineExtensions
```

For more information about loading debugger extensions see the
[Microsoft documentation page](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/loading-debugger-extension-dlls).

## Using the Extension

Once the extension is loaded into windbg, you can use it by running any of its
commands. To see its commands, use the help command to get started.

```console
    !uefiext.help
```

One particularly useful instruction will be the `!uefiext.findall` instruction
to load the needed modules.

## Automatic Initialization

It is advised to configure `!uefiext.init` as a startup action in
Settings->Debugging Settings->Startup. This will attempt to detect a UEFI environment
and automatically resolve initial symbols when connecting. This will do nothing
when debugging other environments.

![Windbgx Extension Startup](docs/res/windbgx_startup.png)

## Design

Windbg debug extensions allow for programmatic decoding and outputting of data
from to debugger. The UEFI debug extension is designed to help with
finding, parsing, and changing data in the UEFI environment more accessible from
the debugger.

Because UEFI has various environments, SEC, DXE, MM, the extension has a concept
of the current running environment. This can be manually set using `!uefiext.setenv`.
This environment should be used to change the operation of various routines based
on the current context. For example, enumerating the hobs or loaded modules is
done differently in DXE then it is in MM. At the time of writing this, most functions
are only implemented in DXE, but this environment should always be checked before
accessing environment specific information.

## Creating new commands

New commands can be exported by added them to the exports in uefiext.def. New
commands should also be added to the help command in uefiext.cpp. For reference
on how to write debugger extension code, see the [Microsoft API Docs](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/debugger-engine-and-extension-apis).

## Copyright

Copyright (C) Microsoft Corporation. All rights reserved.

SPDX-License-Identifier: MIT
