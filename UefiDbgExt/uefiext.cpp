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

// Command help information structure
typedef struct _COMMAND_HELP_INFO {
  PCSTR    Name;
  PCSTR    ShortDescription;
  PCSTR    LongDescription;
  PCSTR    Usage;
  PCSTR    Parameters;
} COMMAND_HELP_INFO;

static const COMMAND_HELP_INFO  CommandHelpTable[] = {
  // Basic Commands
  {
    "help",
    "Shows this help",
    "Displays help information for available commands. When called with a\n"
    "  command name, shows detailed information about that specific command.",
    "!help [command]",
    "  command  (optional) - Name of the command to get detailed help for.\n"
    "                        If omitted, shows the list of all commands."
  },
  {
    "init",
    "Detects and initializes windbg for debugging UEFI.",
    "Initializes the UEFI debugger extension. Detects the target environment\n"
    "  (PEI, DXE, MM, or Patina) and configures the debugger appropriately.\n"
    "  Also scans for and loads module symbols.",
    "!init",
    "  (none)"
  },
  {
    "setenv",
    "Set the extensions environment mode",
    "Manually sets the UEFI environment mode. This affects how other commands\n"
    "  interpret data structures and locate symbols.",
    "!setenv <environment>",
    "  environment  (required) - One of: PEI, DXE, MM, patina"
  },
  // Module Discovery
  {
    "findall",
    "Attempts to detect environment and load all modules",
    "Finds the system table and debug image info table, then loads symbols\n"
    "  for all modules listed in the debug table. Only supported in DXE and\n"
    "  Patina environments.",
    "!findall [-r]",
    "  -r  (optional) - Refresh mode. Uses cached table addresses instead of\n"
    "                   rescanning for them."
  },
  {
    "findmodule",
    "Find the currently running module",
    "Searches backwards from the given address (or current instruction pointer)\n"
    "  to find a PE/COFF image header and loads symbols for that module.",
    "!findmodule [address]",
    "  address  (optional) - Address within the module to find. Defaults to @$ip."
  },
  {
    "elf",
    "Dumps the headers of an ELF image",
    "Parses and displays the headers of an ELF format image at the specified\n"
    "  address.",
    "!elf <address>",
    "  address  (required) - Base address of the ELF image."
  },
  // Data Parsing
  {
    "memorymap",
    "Prints the current DXE system memory map",
    "Enumerates and displays the gMemoryMap entries including address ranges,\n"
    "  attributes, and memory types. Also shows memory usage summary by type.\n"
    "  Only supported in DXE environment.",
    "!memorymap",
    "  (none)"
  },
  {
    "hobs",
    "Enumerates the hand off blocks",
    "Walks the HOB (Hand-Off Block) list and displays each HOB entry with its\n"
    "  type, length, and address. Provides DML links to view HOB details.\n"
    "  Only supported in DXE environment.",
    "!hobs [address]",
    "  address  (optional) - Address of the HOB list. If omitted, attempts to\n"
    "                        find the HOB list from system configuration tables."
  },
  {
    "protocols",
    "Lists the protocols from the protocol list.",
    "Enumerates all protocols registered in the protocol database. Displays\n"
    "  protocol GUIDs with DML links to view protocol interfaces and notify\n"
    "  handlers.",
    "!protocols",
    "  (none)"
  },
  {
    "pt",
    "Dumps the page tables for a given address",
    "Walks the page table hierarchy to show how a virtual address is translated.\n"
    "  Displays each level of the page table with flags and physical addresses.\n"
    "  Supports x64 and ARM64 architectures.",
    "!pt [-i] <VA> [PageTableRoot]",
    "  -i             (optional) - Ignore the self map, use to read an uninstalled\n"
    "                              page table or to only check identity mappings.\n"
    "  VA             (required) - Virtual address to look up.\n"
    "  PageTableRoot  (optional) - Page table root address. Use this to specify an\n"
    "                              not installed page table. Defaults to the installed\n"
    "                              page table root (CR3/TTBR0_EL2)."
  },
  {
    "handles",
    "Prints the handles list.",
    "Enumerates all handles in the UEFI handle database. Displays each handle\n"
    "  with DML links to view handle details and associated protocols.",
    "!handles",
    "  (none)"
  },
  {
    "linkedlist",
    "Parses a UEFI style linked list of entries.",
    "Walks a doubly-linked list and displays each entry using the debugger's\n"
    "  dt command. Useful for debugging custom linked list structures.",
    "!linkedlist <ListHead> <Type> <LinkField>",
    "  ListHead   (required) - Address of the list head (LIST_ENTRY).\n"
    "  Type       (required) - Type name of the structure containing the link.\n"
    "  LinkField  (required) - Name of the LIST_ENTRY field within the structure."
  },
  {
    "efierror",
    "Translates an EFI error code.",
    "Converts a UEFI status code (EFI_STATUS) to its symbolic name, such as\n"
    "  EFI_SUCCESS, EFI_NOT_FOUND, EFI_INVALID_PARAMETER, etc.",
    "!efierror <code>",
    "  code  (required) - EFI status code value (in hex or decimal)."
  },
  {
    "advlog",
    "Prints the advanced logger memory log.",
    "Reads and displays the Advanced Logger buffer contents. Supports reading\n"
    "  the last N bytes of the log for large buffers.",
    "!advlog [-t[bytes]] [address]",
    "  -t[bytes]  (optional) - Show only the tail (last portion) of the log.\n"
    "                          Optionally specify byte count (default: 0x1000).\n"
    "                          Example: -t4096 shows last 4096 bytes.\n"
    "  address    (optional) - Address of ADVANCED_LOGGER_INFO structure.\n"
    "                          If omitted, attempts to find mLoggerInfo symbol."
  },
  {
    "gcd",
    "Commands for dumping GCD information.",
    "Displays the Global Coherency Domain (GCD) memory space map. Shows base\n"
    "  and end addresses, capabilities, attributes, and memory type for each\n"
    "  GCD entry. In Patina environment, forwards to the JavaScript extension.",
    "!gcd [audit]",
    "  audit  (optional) - Filter out entries with skip attributes set."
  },
  // UEFI Debugger
  {
    "info",
    "Queries information about the UEFI debugger",
    "Sends the '?' command to the UEFI debugger monitor and displays the\n"
    "  response. Shows debugger type, version, and capabilities.",
    "!info",
    "  (none)"
  },
  {
    "loadcore",
    "Loads a new Patina DXE Core to execute",
    "Loads and transfers control to a new DXE core binary. Only supported in\n"
    "  the Patina environment. The image is compressed and sent to the target.",
    "!loadcore [/nogo] <ImagePath>",
    "  /nogo      (optional) - Load the core but do not resume execution.\n"
    "  ImagePath  (required) - File path to the DXE core PE image to load."
  },
  {
    "monitor",
    "Sends direct monitor commands",
    "Sends a command string directly to the UEFI debugger monitor interface.\n"
    "  Used for low-level debugger interaction and commands not exposed as\n"
    "  extension commands.",
    "!monitor <command>",
    "  command  (required) - The monitor command string to execute. Running\n"
    "                        '!monitor help' will list available monitor commands."
  },
  {
    "modulebreak",
    "Sets a break on load for the provided module.",
    "Configures the debugger to break when a module with the specified name\n"
    "  is loaded. Useful for debugging early module initialization."
    "  Run !findall after hitting this breakpoint to load symbols for the module.",
    "!modulebreak <modulename>",
    "  modulename  (required) - Name of the module to break on (e.g., 'Shell')."
  },
  {
    "readmsr",
    "Reads a MSR value (x86 only)",
    "Reads a Model Specific Register and displays its value. Only supported\n"
    "  on x86/x64 targets.",
    "!readmsr <index>",
    "  index  (required) - MSR index in hexadecimal (e.g., 0x1A0 for IA32_MISC_ENABLE)."
  },
  {
    "reboot",
    "Reboots the system",
    "Initiates a system reboot. Unloads all symbols and continues execution\n"
    "  with the reboot flag set.",
    "!reboot",
    "  (none)"
  },
  // End marker
  { NULL, NULL, NULL, NULL, NULL }
};

static VOID
PrintCommandHelp (
  PCSTR  CommandName
  )
{
  const COMMAND_HELP_INFO  *Cmd;

  for (Cmd = CommandHelpTable; Cmd->Name != NULL; Cmd++) {
    if (_stricmp (CommandName, Cmd->Name) == 0) {
      dprintf ("\n%s - %s\n", Cmd->Name, Cmd->ShortDescription);
      dprintf ("\nDescription:\n  %s\n", Cmd->LongDescription);
      dprintf ("\nUsage:\n  %s\n", Cmd->Usage);
      dprintf ("\nParameters:\n%s\n", Cmd->Parameters);
      return;
    }
  }

  dprintf ("Unknown command: %s\n", CommandName);
  dprintf ("Use !help to see a list of available commands.\n");
}

HRESULT CALLBACK
help (
  PDEBUG_CLIENT4  Client,
  PCSTR           args
  )
{
  INIT_API ();

  // Skip leading whitespace
  while (*args == ' ' || *args == '\t') {
    args++;
  }

  // If a command name was provided, show detailed help for that command
  if (*args != '\0') {
    PrintCommandHelp (args);
    EXIT_API ();
    return S_OK;
  }

  dprintf (
    "Help for uefiext.dll\n"
    "  Use '!help <command>' for detailed information about a specific command.\n"
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
    dprintf ("  gcd                 - Commands for dumping GCD information.\n");
  }

  dprintf (
    "\nUEFI Debugger:\n"
    "  info                - Queries information about the UEFI debugger\n"
    "  loadcore            - Loads a new Patina DXE Core to execute\n"
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
