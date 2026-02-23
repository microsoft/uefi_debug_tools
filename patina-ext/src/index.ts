// The main entry point for the Patina Extension.
//
// This file defines the `WinDbgExtension` specific methods for initializing the extension, as well as the single
// function alias used to fully initialize the extension by setting the global variables.
//
// Copyright (c) Microsoft Corporation.
// SPDX-License-Identifier: BSD-2-Clause-Patent

/// <reference path="global.ts" />
/// <reference path="util.ts" />
/// <reference path="visualizers/index.ts" />
/// <reference path="commands/index.ts" />

declare const host: any;

// Returns an array of all registrations provided by the extension, including visualizers and commands.
function initializeScript(): any[] {
    return [
       new host.functionAlias(initialize, "__patina_ext_init"),
        ...Visualizers.getRegistrations(),
        ...Commands.getCommands(),
    ];
}

// Perform environment detection and initialization of global variables used across the extension
function initialize() {
    globalThis.APP_VERSION = "0.1.0";
    globalThis.ENVIRONMENT = Environment.DXE;
    globalThis.PATINA_MODULE = null;

    // Check if we're running with a Patina DXE Core. If we are not, this reduces the functionality of the extension.
    if (monitorCommand("ExdiDbgType")[0] === "UEFI") {
        const output = monitorCommand("?")[0];
        if (output.includes("Rust Debugger") || output.includes("Patina Debugger")) {
            globalThis.ENVIRONMENT = Environment.PATINA;
            // We know the GCD symbol path exists in the Patina environment, so we can directly query it to find the module name.
            globalThis.PATINA_MODULE = getModule("patina_dxe_core::GCD");
        }
    }

    host.diagnostics.debugLog(`App Version: ${APP_VERSION}\n`);
    host.diagnostics.debugLog(`Environment: ${Environment[ENVIRONMENT]}\n`);
    host.diagnostics.debugLog(`Patina Core: ${PATINA_MODULE}\n`);
}
