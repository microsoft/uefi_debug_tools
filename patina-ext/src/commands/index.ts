// A namespace for all commands provided by the extension.
//
// Each command is implemented as a function and registered as a function alias via `host.functionAlias`. The
// `getCommands` function is the only externally visible part of this namespace and is consumed by the extension's
// initialization code to register all commands at once.
//
// For better organization, commands may be grouped into sub-namespaces within the `Commands` namespace, but this is not required.
//
// Copyright (c) Microsoft Corporation.
// SPDX-License-Identifier: BSD-2-Clause-Patent
namespace Commands {
  /// Returns all function aliases for commands in this namespace, including those in sub-namespaces.
  export function getCommands(): any[] {
    return [new host.functionAlias(__gcd, "__gcd")];
  }
}

// A function alias used by the extension to provide Patina GCD interaction.
//
// This function currently has the following subcommands:
//   - memory: Dump the GCD memory map with details about each memory block.
//   - io: Dump the GCD I/O map with details about each I/O block.
//   - help: Show a help message describing the available subcommands and their usage.
function __gcd(cmd: any) {
  if (globalThis.PATINA_MODULE === null) {
    host.diagnostics.debugLog("Patina Core module not found.\n");
    return;
  }
  const module = globalThis.PATINA_MODULE;

  if (cmd === "memory") {
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
      `dx -r1 -g ${query}`,
      false,
    );
  } else if (cmd === "io") {
    const query = [
      `${module}!patina_dxe_core::GCD.io.data.io_blocks.nodes`,
      `.Select(n => new {`,
      `  tag = n.tag_str(),`,
      `  io_type = n.io_type,`,
      `  base_address = n.base_address,`,
      `  end = n.base_address + n.length,`,
      `  length = n.length`,
      `})`,
    ].join("");

    return host.namespace.Debugger.Utility.Control.ExecuteCommand(
      `dx -r1 -g ${query}`,
      false,
    );
  } else {
    host.diagnostics.debugLog(
      "Help for gcd command:\n" +
        "\nBasic Commands:\n" +
        "  memory    - Dump the GCD memory map with details about each memory block.\n" +
        "  io        - Dump the GCD I/O map with details about each I/O block.\n" +
        "  help      - Show this help message.\n" +
        "\nExample Usage:\n" +
        '  !gcd "memory"\n' +
        '  !gcd "io"\n' +
        '  !gcd "help"\n',
    );
    return;
  }
}
