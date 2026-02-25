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
function initialize(): string {
  globalThis.APP_VERSION = "0.1.0";
  globalThis.PATINA_MODULE = getModule("patina_dxe_core::GCD");
  if (!globalThis.PATINA_MODULE) {
    return "Failed to locate Patina module.";
  }
  return "Patina extension initialized.";
}
