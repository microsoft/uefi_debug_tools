/*++

Copyright (c) Microsoft Corporation.

SPDX-License-Identifier: BSD-2-Clause-Patent

Module Name:

    uefiext.cpp

Abstract:

    This file contains core UEFI debug commands.

--*/

#include "uefiext.h"
#include <vector>

UEFI_ENV  gUefiEnv         = DXE;
BOOL      gPatinaExtLoaded = FALSE;
ULONG     g_TargetMachine;

HRESULT
NotifyOnTargetAccessible (
  PDEBUG_CONTROL  Control
  )
{
  //
  // Attempt to determine what environment the debugger is in.
  //

  return S_OK;
}

const struct _DML_COLOR_MAP {
  CHAR     *Bg;
  CHAR     *Fg;
  ULONG    Mask;
} DmlColorMap[ColorMax] = {
  { "normbg", "normfg",  DEBUG_OUTPUT_NORMAL  }, // Normal
  { "verbbg", "verbfg",  DEBUG_OUTPUT_VERBOSE }, // Verbose
  { "warnbg", "warnfg",  DEBUG_OUTPUT_WARNING }, // Warning
  { "errbg",  "errfg",   DEBUG_OUTPUT_ERROR   }, // Error
  { "subbg",  "subfg",   DEBUG_OUTPUT_NORMAL  }, // Subdued
  { "normbg", "srccmnt", DEBUG_OUTPUT_NORMAL  }, // Header
  { "empbg",  "emphfg",  DEBUG_OUTPUT_NORMAL  }, // Emphasized
  { "normbg", "changed", DEBUG_OUTPUT_NORMAL  }, // Changed
};

VOID
PrintDml (
  __in PRINTF_DML_COLOR  Color,
  __in PCSTR             Format,
  ...
  )

/*++

Routine Description:

    This routine prints a string with DML markup to the debugger, optionally
    encoding the string with the given color information.

Arguments:

    Color - A color of type PRINTF_DML_COLOR. Certain colors, such as Verbose,
            Warning, and Error are given special handling by the debugger.

    Format - Format string.

    ... - Additional arguments to support the format string.

Return Value:

    None.

--*/
{
  va_list  Args;
  ULONG    Mask;

  va_start (Args, Format);
  Mask = DEBUG_OUTPUT_NORMAL;

  if ((Color > Normal) && (Color < ColorMax)) {
    Mask = DmlColorMap[Color].Mask;
    g_ExtControl->ControlledOutput (
                    DEBUG_OUTCTL_AMBIENT_DML,
                    Mask,
                    "<col fg=\"%s\" bg=\"%s\">",
                    DmlColorMap[Color].Fg,
                    DmlColorMap[Color].Bg
                    );
  }

  g_ExtControl->ControlledOutputVaList (
                  DEBUG_OUTCTL_AMBIENT_DML,
                  Mask,
                  Format,
                  Args
                  );

  if ((Color > Normal) && (Color < ColorMax)) {
    g_ExtControl->ControlledOutput (
                    DEBUG_OUTCTL_AMBIENT_DML,
                    Mask,
                    "</col>"
                    );
  }

  va_end (Args);
}

HRESULT CALLBACK
setenv (
  PDEBUG_CLIENT4  Client,
  PCSTR           args
  )
{
  INIT_API ();

  if (_stricmp (args, "PEI") == 0) {
    gUefiEnv = PEI;
  } else if (_stricmp (args, "DXE") == 0) {
    gUefiEnv = DXE;
  } else if (_stricmp (args, "MM") == 0) {
    gUefiEnv = MM;
  } else if (_stricmp (args, "patina") == 0) {
    gUefiEnv = PATINA;
  } else {
    dprintf ("Unknown environment type! Supported types: PEI, DXE, MM, patina\n");
  }

  EXIT_API ();
  return S_OK;
}

HRESULT CALLBACK
help (
  PDEBUG_CLIENT4  Client,
  PCSTR           args
  )
{
  INIT_API ();

  UNREFERENCED_PARAMETER (args);

  dprintf (
    "Help for uefiext.dll\n"
    "\nBasic Commands:\n"
    "  help                - Shows this help\n"
    "  init                - Detects and initializes windbg for debugging UEFI.\n"
    "  setenv              - Set the extensions environment mode\n"
    "\nModule Discovery:\n"
    "  findall             - Attempts to detect environment and load all modules\n"
    "  findmodule          - Find the currently running module\n"
    "  elf                 - Dumps the headers of an ELF image\n"
    "\nData Parsing:\n"
    "  memorymap           - Prints the current memory map\n"
    "  hobs                - Enumerates the hand off blocks\n"
    "  protocols           - Lists the protocols from the protocol list.\n"
    "  pt                  - Dumps the page tables for a given address\n"
    "  handles             - Prints the handles list.\n"
    "  linkedlist          - Parses a UEFI style linked list of entries.\n"
    "  efierror            - Translates an EFI error code.\n"
    "  advlog              - Prints the advanced logger memory log.\n"
    );

  // Only show Patina-specific commands if the extension is loaded
  if (gPatinaExtLoaded) {
    dprintf ("  gcd                 - Commands for dumping GCD information (Patina Only).\n");
  }

  dprintf (
    "\nUEFI Debugger:\n"
    "  info                - Queries information about the UEFI debugger\n"
    "  monitor             - Sends direct monitor commands\n"
    "  modulebreak         - Sets a break on load for the provided module. e.g. 'shell'\n"
    "  readmsr             - Reads a MSR value (x86 only)\n"
    "  reboot              - Reboots the system\n"
    );

  EXIT_API ();

  return S_OK;
}

HRESULT CALLBACK
uefiext_init (
  PDEBUG_CLIENT4  Client,
  PCSTR           args
  )
{
  ULONG        TargetClass = 0;
  ULONG        TargetQual  = 0;
  ULONG        Mask;
  std::string  Output;

  INIT_API ();

  UNREFERENCED_PARAMETER (args);

  dprintf ("Initializing UEFI Debugger Extension\n");
  g_ExtControl->GetDebuggeeType (&TargetClass, &TargetQual);
  if ((TargetClass == DEBUG_CLASS_KERNEL) && (TargetQual == DEBUG_KERNEL_EXDI_DRIVER)) {
    // Enabled the verbose flag in the output mask. This is required for .exdicmd
    // output.
    Client->GetOutputMask (&Mask);
    Client->SetOutputMask (Mask | DEBUG_OUTPUT_VERBOSE);

    if ((Status = g_ExtControl->GetActualProcessorType (&g_TargetMachine)) != S_OK) {
      return S_FALSE;
    }

    if ((Status = Client->QueryInterface (__uuidof (IDebugRegisters), (void **)&g_ExtRegisters)) != S_OK) {
      return S_FALSE;
    }

    Output = MonitorCommandWithOutput (Client, "ExdiDbgType", 0);

    // Don't run !monitor ? on QEMU targets, this causes a confusion between WinDbg and QEMU and we get
    // corrupted memory reads. It also isn't needed
    if (Output.find ("UEFI") != std::string::npos) {
      // Detect if this is a UEFI software debugger.
      Output = MonitorCommandWithOutput (Client, "?", 0);
      if ((Output.find ("Rust Debugger") != std::string::npos) ||
          (Output.find ("Patina Debugger") != std::string::npos))
      {
        dprintf ("Patina Debugger detected.\n");
        gUefiEnv = PATINA;
      } else if (Output.find ("DXE UEFI Debugger") != std::string::npos) {
        dprintf ("DXE UEFI Debugger detected.\n");
        gUefiEnv = DXE;
      } else {
        dprintf ("Unknown environment, assuming DXE. Unexpected state, update UefiExt.\n");
        gUefiEnv = DXE;
      }
    } else {
      dprintf ("Non-UEFI debug environment detected, defaulting to DXE\n");
      gUefiEnv = DXE;
    }

    dprintf ("Scanning for images.\n");
    if ((gUefiEnv == DXE) || (gUefiEnv == PATINA)) {
      g_ExtControl->Execute (
                      DEBUG_OUTCTL_ALL_CLIENTS,
                      "!uefiext.findall",
                      DEBUG_EXECUTE_DEFAULT
                      );
    } else {
      g_ExtControl->Execute (
                      DEBUG_OUTCTL_ALL_CLIENTS,
                      "!uefiext.findmodule",
                      DEBUG_EXECUTE_DEFAULT
                      );
    }

    if (gUefiEnv == PATINA) {
      INIT_API (); // The other extension commands may call `EXIT_API()`, so we need to re-initialize.
      g_ExtControl->Execute (
                      DEBUG_OUTCTL_THIS_CLIENT,
                      "!uefiext.patinainit",
                      DEBUG_EXECUTE_DEFAULT
                      );
      dprintf ("Patina extension loaded: %s\n", gPatinaExtLoaded ? "Yes" : "No");
    }
  }

  EXIT_API ();

  return S_OK;
}

// Used to capture output from debugger commands
std::vector<std::string>  mResponses = { };

class OutputCallbacks : public IDebugOutputCallbacks {
public:

  STDMETHOD (QueryInterface)(THIS_ REFIID InterfaceId, PVOID *Interface) {
    if (InterfaceId == __uuidof (IDebugOutputCallbacks)) {
      *Interface = (IDebugOutputCallbacks *)this;
      AddRef ();
      return S_OK;
    } else {
      *Interface = NULL;
      return E_NOINTERFACE;
    }
  }

  STDMETHOD_ (ULONG, AddRef)(THIS) {
    return 1;
  }

  STDMETHOD_ (ULONG, Release)(THIS) {
    return 1;
  }

  STDMETHOD (Output)(THIS_ ULONG Mask, PCSTR Text) {
    mResponses.push_back (std::string (Text));
    return S_OK;
  }
};

OutputCallbacks  mOutputCallback;

std::string
ExecuteCommandWithOutput (
  PDEBUG_CLIENT4  Client,
  PCSTR           Command
  )
{
  PDEBUG_OUTPUT_CALLBACKS  Callbacks;
  std::string              Output;

  mResponses.clear ();

  Client->GetOutputCallbacks (&Callbacks);
  Client->SetOutputCallbacks (&mOutputCallback);
  g_ExtControl->Execute (
                  DEBUG_OUTCTL_THIS_CLIENT,
                  Command,
                  DEBUG_EXECUTE_DEFAULT
                  );
  Client->SetOutputCallbacks (Callbacks);

  for (const auto &str : mResponses) {
    Output += str;
  }

  return Output;
}

std::string
MonitorCommandWithOutput (
  PDEBUG_CLIENT4  Client,
  PCSTR           MonitorCommand,
  ULONG           Offset
  )
{
  CHAR         Command[512];
  std::string  Output;
  ULONG        Mask;
  PCSTR        Preamble = "Target command response: ";
  PCSTR        Ending   = "exdiCmd:";
  PCSTR        Ok       = "OK\n";

  if (Offset == 0 ) {
    sprintf_s (Command, sizeof (Command), ".exdicmd target:0:%s", MonitorCommand);
  } else {
    sprintf_s (Command, sizeof (Command), ".exdicmd target:0:O[%d] %s", Offset, MonitorCommand);
  }

  Client->GetOutputMask (&Mask);
  Client->SetOutputMask (Mask | DEBUG_OUTPUT_VERBOSE);
  Output = ExecuteCommandWithOutput (Client, Command);
  Client->SetOutputMask (Mask);

  // Clean up the output.
  size_t  PreamblePos = Output.find (Preamble);

  if (PreamblePos != std::string::npos) {
    Output = Output.substr (PreamblePos + strlen (Preamble));
  }

  size_t  EndingPos = Output.find (Ending);

  if (EndingPos != std::string::npos) {
    Output = Output.substr (0, EndingPos);
  }

  // If it has the OK string appended to the end, remove it
  size_t  OkLen = strlen (Ok);

  if (Output.length () > OkLen) {
    if (Output.compare (Output.length () - OkLen, OkLen, Ok) == 0) {
      Output.replace (Output.length () - OkLen, OkLen, "\n");
    }
  }

  return Output;
}

VOID
BreakFromRunning (
  VOID
  )
{
  IDebugClient    *DebugClient;
  PDEBUG_CONTROL  DebugControl;

  //
  // Running findall refresh makes many assumptions about the target state
  // which may lead to reading bad data if incorrect. Therefore, restrict
  // this functionality to Patina environment for safety.
  //

  if (PATINA != gUefiEnv) {
    return;
  }

  if (DebugCreate (__uuidof (IDebugClient), (void **)&DebugClient) == S_OK) {
    if (DebugClient->QueryInterface (__uuidof (IDebugControl), (void **)&DebugControl) == S_OK) {
      DebugControl->Execute (
                      DEBUG_OUTCTL_LOG_ONLY,
                      "!uefiext.findall -r",
                      DEBUG_EXECUTE_DEFAULT
                      );

      DebugControl->Release ();
    }

    DebugClient->Release ();
  }
}
