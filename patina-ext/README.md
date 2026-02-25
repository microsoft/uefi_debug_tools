# PatinaExt

A javascript WinDbg extension providing type models and scripts for inspecting Patina specific structures. Visualizers
are automatically used by the debugger when looking at a symbol with the appopriate type signature. Scripts/functions
are registered as funciton aliases, making them available via the debugger command line.

While the javascript extension is standalone, the `UefiDbgExt` DLL wraps it as a way provide a unified interface via
`!uefiext.<cmd>`. This means that the `UefiDbgExt` will automatically load the javascript extension when
`!uefiext.init` is run, and will pass through commands from the DLL to the script (e.g. calling `!uefiext.gcd` calls
`!__gcd`).

By default, compilation and usage of this extension is managed via the `UefiDbgExt` DLL; review the
[UefiDbgExt Documentation](https://github.com/microsoft/uefi_debug_tools/blob/main/UefiDbgExt/readme.md) for a unified
experience.

## Layout

The extension follows a clean, modular architecture organized into two main directories: (1) `\commands` and
(2) `\visualizers`.

[patina-ext\src\index.ts](patina-ext/src/index.ts) serves as the main entry point for the extension. When the extension
is loaded, this file is responsible for:

- Registering all function aliases for commands via `Commands.getCommands()`
- Registering all type visualizers via `Visualizers.getRegistrations()`
- Providing the main initialization function (`__patina_ext_init`) that sets up global variables and performs
  environment detection

The `initializeScript()` function orchestrates the registration of all extension functionality by combining commands
and visualizers into a single array that WinDbg processes during extension loading.

### Commands

The [commands](patina-ext/src/commands) directory contains all interactive commands that users can execute from the
debugger command line. Each command is implemented as a function and registered as a function alias through
`host.functionAlias()`.

- [commands/index.ts](patina-ext/src/commands/index.ts) acts as the central registry, providing a `getCommands()`
  function that returns all available command function aliases
- Commands use uncommon names prefixed with `__` (e.g., `__gcd`) to avoid conflicts with existing debugger commands
- The namespace pattern allows for easy organization and future expansion of command functionality

### Visualizers

The [visualizers](patina-ext/src/visualizers) directory contains type-specific visualizers that automatically enhance
the display of Patina data structures in the debugger. These visualizers are automatically invoked by WinDbg when
inspecting symbols with matching type signatures.

- [visualizers/index.ts](patina-ext/src/visualizers/index.ts) serves as the central registry, providing a
  `getRegistrations()` function that returns all type signature registrations
- Individual visualizer files like [gcd.ts](patina-ext/src/visualizers/gcd.ts) and
  [collections.ts](patina-ext/src/visualizers/collections.ts) contain specialized visualizers for different
  Patina data types
- Each visualizer is implemented as a class and registered via `host.typeSignatureRegistration()` to automatically
  activate when the appropriate type is encountered

This modular organization ensures clean separation of concerns, making the codebase maintainable and allowing for easy
addition of new commands and visualizers without affecting existing functionality.

## Development

When developing the extension, developers may opt to directly call the function aliases provided by the extension
rather than relying on the `UefiDbgExt` DLL command wrapper. This means two things:

1. Compiling the javascript extension
2. Loading and unloading via `.scriptload` / `.scriptunload`
3. Executing function aliases (e.g. `!__gcd` rather than `!uefiext.gcd`)

### Compilation

The javascript extension utilized `npm` for dependency management and compilation as noted below. The `deploy` step
below simply moves the compiled javascript extension to "C:/Users/$Env:UserName/AppData/Local/DBG/EngineExtensions/".

1. `> cd patina-ext`
2. `> npm install`
3. `> npm run build`
4. `> npm run deploy`

### Function Wrapping

Javascript extensions do not have a way to scope commands like the DLL's do (e.g. we cannot do `!uefiext.<cmd>`) as
they simply register function aliases. Due to this, it is important to use uncommon names to ensure there is no
conflict (e.g. `!__gcd` instead of `!gcd`). We then wrap the function alias call in a `UefiDbgExt` DLL command,
providing a unified experience through `!uefiext.<cmd>`. For an example, please refer to the `__gcd` method in
`patina-ext/src/commands/index.ts` and it's wrapper in `UefiDbgExt/patina.cpp`.

1. Create the new function.
1. Register the function alias via `host.functionAlias()`.
1. Define a wrapper function in `UefiDbgExt\patina.cpp` that calls the provided function alias.
1. Update `uefiext.def` with the new function export.

### Standalone Usage

Load the script:

`> .scriptload <Workspace>\patina-ext\dist\PatinaExt.js`

Call the function aliases directly:

`> !__gcd`

It can later be unloaded (necessary if loading a new version):

`> .scriptunload <workspace>\patina-ext\dist\PatinaExt.js`
