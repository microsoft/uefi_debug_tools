# PatinaExt

A javascript WinDbg extension providing type models and scripts for inspecting Patina specific structures.

# Setup and Usage

As this is a javascript project, `npm` is necessary.

## Compilation

1. `> cd patina-ext`
2. `> npx tsc`

## Usage (From Debugger)

1. `> .scriptload <Workspace>\patina-ext\dist\PatinaExt.js`
2. `> !memory_blocks`
