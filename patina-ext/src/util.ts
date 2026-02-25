// A namespace for utility functions used throughout the extension.
//
// Copyright (c) Microsoft Corporation.
// SPDX-License-Identifier: BSD-2-Clause-Patent

// Returns the module name that contains the specified symbol, or null if not found.
//
// Calling `host.getModuleSymbol` requires loading the module, which can be expensive. `ignore_deffered` allows
// skipping modules that are marked as deferred, e.g. not yet loaded.
function getModule(
  name: string,
  ignore_deferred: boolean = true,
): string | null {
  const modules = host.namespace.Debugger.Utility.Control.ExecuteCommand("lm");

  for (const line of [...modules].reverse()) {
    if (ignore_deferred && line.includes("deferred")) {
      continue;
    }

    // Line format:
    // 00000000`7e8e8000 00000000`7eab4000   qemu_q35_dxe_core C (private pdb symbols)  ...
    const parts = line.trim().split(/\s+/);
    if (parts.length >= 3) {
      const moduleName = parts[2];
      host.diagnostics.debugLog(`Checking module: ${moduleName}\n`);

      try {
        // getModuleSymbol will throw if the symbol is not found in the module
        host.getModuleSymbol(moduleName, name);
        return moduleName;
      } catch (e: any) {
        continue;
      }
    }
  }

  return null;
}

// Utility function to inspect an object and log its properties and their types
function inspectObject(obj: any, objName = "object") {
  host.diagnostics.debugLog(`\n=== Inspecting ${objName} ===\n`);

  try {
    const props = Object.getOwnPropertyNames(obj);
    host.diagnostics.debugLog(`Properties (${props.length}):\n`);

    for (const prop of props) {
      try {
        const value = obj[prop];
        const type = typeof value;

        if (type === "function") {
          host.diagnostics.debugLog(`  ${prop}(): [function]\n`);
        } else {
          host.diagnostics.debugLog(`  ${prop}: ${value} [${type}]\n`);
        }
      } catch (e: any) {
        host.diagnostics.debugLog(`  ${prop}: [Error: ${e.message}]\n`);
      }
    }
  } catch (e: any) {
    host.diagnostics.debugLog(`Error inspecting object: ${e.message}\n`);
  }

  host.diagnostics.debugLog(`=== End ${objName} ===\n\n`);
}

// Utility function to execute a monitor command and return the output as an array of strings
function monitorCommand(command: string): string[] {
  const cmd = `!uefiext.monitor ${command}`;
  return host.namespace.Debugger.Utility.Control.ExecuteCommand(cmd);
}
