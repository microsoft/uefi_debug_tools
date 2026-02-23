# PatinaExt

A javascript WinDbg extension providing type models and scripts for inspecting Patina specific structures. Visualizers
are automatically used by the debugger when looking at a symbol with the appopriate type signature. As for the scripts,
they are automatically made available via the debugger command line.

While the javascript extension is standalone, the `UefiDbgExt` DLL wraps it as a way provide a unified interface via
`!uefiext.<cmd>`. This means that the `UefiDbgExt` will automatically load the javascript extension (via
`!uefiext.init`) and will pass through commands from the DLL to the script (e.g. calling `!uefiext.gcd` simply calls
`!gcd`).

## Development

When developing the extension, developers should opt to directly call scripts, rather than relying on the `UefiDbgExt`
DLL command wrapper. This means two things:

1. Manually loading and unloading via `.scriptload` / `.scriptunload`
2. Manually calling function aliases (e.g. `!gcd` rather than `!uefiext.gcd`)

### Compilation

As this is a javascript / typescript project, npm is needed.

1. `> cd patina-ext`
2. `> npm run build`

### Usage

To load the extension, you must manually execute the `.scriptload` command:

`> .scriptload <Workspace>\patina-ext\dist\PatinaExt.js`
`> .scriptunload <workspace>\patina-ext\dist\PatinaExt.js`

To use aliases, you must manually call them:

`> !gcd`
