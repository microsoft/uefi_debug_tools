/*++

    Copyright (c) Microsoft Corporation.

    SPDX-License-Identifier: BSD-2-Clause-Patent

Module Name:

    memory.cpp

Abstract:

    This file contains command forwarders to the Patina javascript extension.

--*/

#include "uefiext.h"
#include <string>
#include <sstream>

//
// *******************************************************  Helper Functions
//

/**
 * Builds a command string with quoted arguments from a space-separated argument string.
 *
 *
 * @param baseCommand The base command name (e.g., "!gcd")
 * @param args Space-separated arguments to be quoted and appended
 * @return Complete command string with quoted arguments
 */
std::string
BuildQuotedCommand (
  const std::string  &baseCommand,
  PCSTR              args
  )
{
  std::string  command = baseCommand;

  if (args && *args) {
    std::string         argsStr (args);
    std::istringstream  iss (argsStr);
    std::string         token;

    // Parse each argument and wrap in quotes
    while (iss >> token) {
      command += " \"" + token + "\"";
    }
  }

  return command;
}

//
// *******************************************************  External Functions
//

HRESULT CALLBACK
patinainit (
  PDEBUG_CLIENT4  Client,
  PCSTR           args
  )
{
  std::string  Output;
  HRESULT      hr = S_OK;

  INIT_API ();

  Output = ExecuteCommandWithOutput (Client, ".scriptload PatinaExt.js");
  if (Output.find ("JavaScript script successfully loaded") == std::string::npos) {
    dprintf ("Failed to load PatinaExt.js\n");
    hr = E_FAIL;
    goto Cleanup;
  }

  Output = ExecuteCommandWithOutput (Client, "!__patina_ext_init");
  if (Output.find ("Patina extension initialized.") == std::string::npos) {
    dprintf ("Failed to initialize Patina extension\n");
    hr = E_FAIL;
    goto Cleanup;
  }

  gPatinaExtLoaded = TRUE;

Cleanup:
  EXIT_API ();
  return hr;
}
