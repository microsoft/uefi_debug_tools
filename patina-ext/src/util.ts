// A namespace for utility functions used throughout the extension.
//
// Copyright (c) Microsoft Corporation.
// SPDX-License-Identifier: BSD-2-Clause-Patent

// Returns a static symbol by name and returns it as a host object.
//
// Returns null if the symbol or module is not found
function getStatic(name: string): any | null {
    const module = getModule(name);

    if (!module) {
        return null;
    }

    return host.getModuleSymbol(module, name);
}

// Returns the module name that contains the specified symbol, or null if not found
function getModule(name: string): string | null {
    const line = host.namespace.Debugger.Utility.Control.ExecuteCommand(`x *!${name}`)[0];

    if (!line) {
        return null;
    }

    return line.split(" ")[1].split("!")[0];
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
                
                if (type === 'function') {
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
