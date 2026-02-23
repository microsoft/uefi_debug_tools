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
gcd (
  PDEBUG_CLIENT4  Client,
  PCSTR           args
  )
{
  INIT_API ();

  if (gUefiEnv == PATINA) {
    // Build command string with quoted arguments
    std::string  command = BuildQuotedCommand ("!__gcd", args);

    g_ExtControl->Execute (
                    DEBUG_OUTCTL_ALL_CLIENTS,
                    command.c_str (),
                    DEBUG_EXECUTE_DEFAULT
                    );
    // Forward the command to the Patina extension.
  } else {
    dprintf ("Not supported for this environment!\n");
    return ERROR_NOT_SUPPORTED;
  }

  EXIT_API ();
  return S_OK;
}
