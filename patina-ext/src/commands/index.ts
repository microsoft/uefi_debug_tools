namespace Commands {
    export function getCommands(): any[] {
        return [
            new host.functionAlias(__memory_blocks, "memory_blocks"),
        ];
    }
}

function __memory_blocks() {
    // Resolve the module name dynamically, then build a direct dx path
    let module = getModule("patina_dxe_core::GCD");

    if (!module) {
        host.diagnostics.debugLog("Could not find module for patina_dxe_core::GCD\n");
        return;
    }

    const query = [
        `${module}!patina_dxe_core::GCD.memory.data.memory_blocks.nodes`,
        `.Select(n => new {`,
        `  tag = n.tag_str(),`,
        `  memory_type = n.memory_type,`,
        `  base_address = n.base_address,`,
        `  end = n.base_address + n.length,`,
        `  length = n.length,`,
        `  attributes = n.attributes,`,
        `  capabilities = n.capabilities`,
        `})`,
    ].join("");

    return host.namespace.Debugger.Utility.Control.ExecuteCommand(
        `dx -r1 -g ${query}`, false
    );
}