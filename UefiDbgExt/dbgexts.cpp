/*++

    Copyright (c) Microsoft Corporation.

    SPDX-License-Identifier: BSD-2-Clause-Patent

Module Name:

    dbgexts.cpp

Abstract:

    This file contains the generic routines and initialization code
    for the debugger extensions dll.

--*/

#include "dbgexts.h"
#include <strsafe.h>

PDEBUG_CLIENT4    g_ExtClient;
PDEBUG_CONTROL    g_ExtControl;
PDEBUG_SYMBOLS2   g_ExtSymbols;
PDEBUG_REGISTERS  g_ExtRegisters;

WINDBG_EXTENSION_APIS  ExtensionApis;

ULONG               TargetMachine;
BOOL                Connected;
UefiEventCallbacks  g_EventCallbacks;
IDebugClient        *g_EventClient = NULL;

extern ULONG64  gSystemTableAddr;
extern ULONG64  gDebugTableAddr;

// Queries for all debugger interfaces.
extern "C" HRESULT
ExtQuery (
  PDEBUG_CLIENT4  Client
  )
{
  HRESULT  Status;

  if ((Status = Client->QueryInterface (
                          __uuidof (IDebugControl),
                          (void **)&g_ExtControl
                          )) != S_OK)
  {
    goto Fail;
  }

  if ((Status = Client->QueryInterface (
                          __uuidof (IDebugSymbols2),
                          (void **)&g_ExtSymbols
                          )) != S_OK)
  {
    goto Fail;
  }

  g_ExtClient = Client;

  return S_OK;

Fail:
  ExtRelease ();
  return Status;
}

// Cleans up all debugger interfaces.
void
ExtRelease (
  void
  )
{
  g_ExtClient = NULL;
  EXT_RELEASE (g_ExtControl);
  EXT_RELEASE (g_ExtSymbols);
}

// Normal output.
void __cdecl
ExtOut (
  PCSTR  Format,
  ...
  )
{
  va_list  Args;

  va_start (Args, Format);
  g_ExtControl->OutputVaList (DEBUG_OUTPUT_NORMAL, Format, Args);
  va_end (Args);
}

// Error output.
void __cdecl
ExtErr (
  PCSTR  Format,
  ...
  )
{
  va_list  Args;

  va_start (Args, Format);
  g_ExtControl->OutputVaList (DEBUG_OUTPUT_ERROR, Format, Args);
  va_end (Args);
}

// Warning output.
void __cdecl
ExtWarn (
  PCSTR  Format,
  ...
  )
{
  va_list  Args;

  va_start (Args, Format);
  g_ExtControl->OutputVaList (DEBUG_OUTPUT_WARNING, Format, Args);
  va_end (Args);
}

extern "C"
HRESULT
CALLBACK
DebugExtensionInitialize (
  PULONG  Version,
  PULONG  Flags
  )
{
  IDebugClient    *DebugClient;
  PDEBUG_CONTROL  DebugControl;
  HRESULT         Hr;

  *Version = DEBUG_EXTENSION_VERSION (1, 0);
  *Flags   = 0;
  Hr       = S_OK;

  if ((Hr = DebugCreate (
              __uuidof (IDebugClient),
              (void **)&DebugClient
              )) != S_OK)
  {
    return Hr;
  }

  if ((Hr = DebugClient->QueryInterface (
                           __uuidof (IDebugControl),
                           (void **)&DebugControl
                           )) == S_OK)
  {
    //
    // Get the windbg-style extension APIS
    //
    ExtensionApis.nSize = sizeof (ExtensionApis);
    Hr                  = DebugControl->GetWindbgExtensionApis64 (&ExtensionApis);

    DebugControl->Release ();
  }

  DebugClient->Release ();
  return Hr;
}

//
// UefiEventCallbacks implementation
//

STDMETHODIMP
UefiEventCallbacks::QueryInterface (
  THIS_
  _In_ REFIID  InterfaceId,
  _Out_ PVOID  *Interface
  )
{
  *Interface = NULL;

  if (IsEqualIID (InterfaceId, __uuidof (IUnknown)) ||
      IsEqualIID (InterfaceId, __uuidof (IDebugEventCallbacks)))
  {
    *Interface = (IDebugEventCallbacks *)this;
    AddRef ();
    return S_OK;
  }

  return E_NOINTERFACE;
}

STDMETHODIMP_ (ULONG)
UefiEventCallbacks::AddRef (
                      THIS
                      ) {
  // This class is a global singleton, so no reference counting needed
  return 1;
}

STDMETHODIMP_ (ULONG)
UefiEventCallbacks::Release (
                      THIS
                      ) {
  // This class is a global singleton, so no reference counting needed
  return 0;
}

STDMETHODIMP
UefiEventCallbacks::GetInterestMask (
  THIS_
  _Out_ PULONG  Mask
  )
{
  // We're only interested in engine state changes to detect execution status changes
  *Mask = DEBUG_EVENT_CHANGE_ENGINE_STATE;
  return S_OK;
}

STDMETHODIMP
UefiEventCallbacks::Breakpoint (
  THIS_
  _In_ PDEBUG_BREAKPOINT  Bp
  )
{
  UNREFERENCED_PARAMETER (Bp);
  return DEBUG_STATUS_NO_CHANGE;
}

STDMETHODIMP
UefiEventCallbacks::Exception (
  THIS_
  _In_ PEXCEPTION_RECORD64  Exception,
  _In_ ULONG                FirstChance
  )
{
  UNREFERENCED_PARAMETER (Exception);
  UNREFERENCED_PARAMETER (FirstChance);
  return DEBUG_STATUS_NO_CHANGE;
}

STDMETHODIMP
UefiEventCallbacks::CreateThread (
  THIS_
  _In_ ULONG64  Handle,
  _In_ ULONG64  DataOffset,
  _In_ ULONG64  StartOffset
  )
{
  UNREFERENCED_PARAMETER (Handle);
  UNREFERENCED_PARAMETER (DataOffset);
  UNREFERENCED_PARAMETER (StartOffset);
  return DEBUG_STATUS_NO_CHANGE;
}

STDMETHODIMP
UefiEventCallbacks::ExitThread (
  THIS_
  _In_ ULONG  ExitCode
  )
{
  UNREFERENCED_PARAMETER (ExitCode);
  return DEBUG_STATUS_NO_CHANGE;
}

STDMETHODIMP
UefiEventCallbacks::CreateProcess (
  THIS_
  _In_ ULONG64    ImageFileHandle,
  _In_ ULONG64    Handle,
  _In_ ULONG64    BaseOffset,
  _In_ ULONG      ModuleSize,
  _In_opt_ PCSTR  ModuleName,
  _In_opt_ PCSTR  ImageName,
  _In_ ULONG      CheckSum,
  _In_ ULONG      TimeDateStamp,
  _In_ ULONG64    InitialThreadHandle,
  _In_ ULONG64    ThreadDataOffset,
  _In_ ULONG64    StartOffset
  )
{
  UNREFERENCED_PARAMETER (ImageFileHandle);
  UNREFERENCED_PARAMETER (Handle);
  UNREFERENCED_PARAMETER (BaseOffset);
  UNREFERENCED_PARAMETER (ModuleSize);
  UNREFERENCED_PARAMETER (ModuleName);
  UNREFERENCED_PARAMETER (ImageName);
  UNREFERENCED_PARAMETER (CheckSum);
  UNREFERENCED_PARAMETER (TimeDateStamp);
  UNREFERENCED_PARAMETER (InitialThreadHandle);
  UNREFERENCED_PARAMETER (ThreadDataOffset);
  UNREFERENCED_PARAMETER (StartOffset);
  return DEBUG_STATUS_NO_CHANGE;
}

STDMETHODIMP
UefiEventCallbacks::ExitProcess (
  THIS_
  _In_ ULONG  ExitCode
  )
{
  UNREFERENCED_PARAMETER (ExitCode);
  return DEBUG_STATUS_NO_CHANGE;
}

STDMETHODIMP
UefiEventCallbacks::LoadModule (
  THIS_
  _In_ ULONG64    ImageFileHandle,
  _In_ ULONG64    BaseOffset,
  _In_ ULONG      ModuleSize,
  _In_opt_ PCSTR  ModuleName,
  _In_opt_ PCSTR  ImageName,
  _In_ ULONG      CheckSum,
  _In_ ULONG      TimeDateStamp
  )
{
  UNREFERENCED_PARAMETER (ImageFileHandle);
  UNREFERENCED_PARAMETER (BaseOffset);
  UNREFERENCED_PARAMETER (ModuleSize);
  UNREFERENCED_PARAMETER (ModuleName);
  UNREFERENCED_PARAMETER (ImageName);
  UNREFERENCED_PARAMETER (CheckSum);
  UNREFERENCED_PARAMETER (TimeDateStamp);
  return DEBUG_STATUS_NO_CHANGE;
}

STDMETHODIMP
UefiEventCallbacks::UnloadModule (
  THIS_
  _In_opt_ PCSTR  ImageBaseName,
  _In_ ULONG64    BaseOffset
  )
{
  UNREFERENCED_PARAMETER (ImageBaseName);
  UNREFERENCED_PARAMETER (BaseOffset);
  return DEBUG_STATUS_NO_CHANGE;
}

STDMETHODIMP
UefiEventCallbacks::SystemError (
  THIS_
  _In_ ULONG  Error,
  _In_ ULONG  Level
  )
{
  UNREFERENCED_PARAMETER (Error);
  UNREFERENCED_PARAMETER (Level);
  return DEBUG_STATUS_NO_CHANGE;
}

STDMETHODIMP
UefiEventCallbacks::SessionStatus (
  THIS_
  _In_ ULONG  Status
  )
{
  UNREFERENCED_PARAMETER (Status);
  return DEBUG_STATUS_NO_CHANGE;
}

STDMETHODIMP
UefiEventCallbacks::ChangeDebuggeeState (
  THIS_
  _In_ ULONG    Flags,
  _In_ ULONG64  Argument
  )
{
  UNREFERENCED_PARAMETER (Flags);
  UNREFERENCED_PARAMETER (Argument);
  return DEBUG_STATUS_NO_CHANGE;
}

STDMETHODIMP
UefiEventCallbacks::ChangeEngineState (
  THIS_
  _In_ ULONG    Flags,
  _In_ ULONG64  Argument
  )
{
  static BOOLEAN  LastGo = FALSE;

  if (Flags & DEBUG_CES_EXECUTION_STATUS) {
    if (Argument == DEBUG_STATUS_GO) {
      LastGo = TRUE;
    } else if ((Argument == DEBUG_STATUS_BREAK) && LastGo) {
      LastGo = FALSE;
      BreakFromRunning ();
    }
  }

  return S_OK;
}

STDMETHODIMP
UefiEventCallbacks::ChangeSymbolState (
  THIS_
  _In_ ULONG    Flags,
  _In_ ULONG64  Argument
  )
{
  UNREFERENCED_PARAMETER (Flags);
  UNREFERENCED_PARAMETER (Argument);
  return S_OK;
}

extern "C"
void
CALLBACK
DebugExtensionNotify (
  ULONG    Notify,
  ULONG64  Argument
  )
{
  UNREFERENCED_PARAMETER (Argument);

  //
  // The first time we actually connect to a target
  //

  if ((Notify == DEBUG_NOTIFY_SESSION_ACCESSIBLE) && (!Connected)) {
    IDebugClient    *DebugClient;
    HRESULT         Hr;
    PDEBUG_CONTROL  DebugControl;

    if ((Hr = DebugCreate (
                __uuidof (IDebugClient),
                (void **)&DebugClient
                )) == S_OK)
    {
      //
      // Get the architecture type.
      //

      if ((Hr = DebugClient->QueryInterface (
                               __uuidof (IDebugControl),
                               (void **)&DebugControl
                               )) == S_OK)
      {
        if ((Hr = DebugControl->GetActualProcessorType (
                                  &TargetMachine
                                  )) == S_OK)
        {
          Connected = TRUE;
        }

        NotifyOnTargetAccessible (DebugControl);

        DebugControl->Release ();
      }

      //
      // Register event callbacks to get notified on every break
      // Keep the client reference for unregistration later
      //
      if (g_EventClient == NULL) {
        g_EventClient = DebugClient;
        g_EventClient->AddRef ();
        g_EventClient->SetEventCallbacks (&g_EventCallbacks);
      }

      DebugClient->Release ();
    }
  }

  if (Notify == DEBUG_NOTIFY_SESSION_INACTIVE) {
    Connected        = FALSE;
    TargetMachine    = 0;
    gSystemTableAddr = 0;
    gDebugTableAddr  = 0;
  }

  return;
}

extern "C"
void
CALLBACK
DebugExtensionUninitialize (
  void
  )
{
  //
  // Unregister event callbacks before unloading
  //
  if (g_EventClient != NULL) {
    g_EventClient->SetEventCallbacks (NULL);
    g_EventClient->Release ();
    g_EventClient = NULL;
  }

  return;
}

extern "C"
HRESULT
CALLBACK
KnownStructOutput (
  _In_ ULONG Flag,
  _In_ ULONG64 Address,
  _In_ PSTR StructName,
  _Out_writes_opt_ (*BufferSize) PSTR Buffer,
  _Inout_opt_ _When_ (Flag == DEBUG_KNOWN_STRUCT_GET_NAMES, _Notnull_) _When_ (Flag == DEBUG_KNOWN_STRUCT_GET_SINGLE_LINE_OUTPUT, _Notnull_) PULONG BufferSize
  )
{
  const char  *KnownStructs[] = { "_LARGE_INTEGER", "_SYSTEMTIME", NULL };
  HRESULT     Hr              = S_OK;

  if ((Flag == DEBUG_KNOWN_STRUCT_GET_NAMES) && (Buffer != NULL) && (BufferSize != NULL)) {
    //
    // Return names of known structs in multi string
    //
    ULONG  SizeRemaining = *BufferSize, SizeNeeded = 0, Length;
    PCHAR  CopyAt = Buffer;

    for (ULONG i = 0; KnownStructs[i] != NULL; i++) {
      if ((SizeRemaining > (Length = (ULONG)strlen (KnownStructs[i]) + 1)) &&
          (Hr == S_OK))
      {
        Hr = StringCbCopy (CopyAt, SizeRemaining, KnownStructs[i]);

        SizeRemaining -= Length;
        CopyAt        += Length;
      } else {
        Hr = S_FALSE;
      }

      SizeNeeded += Length;
    }

    if ((SizeRemaining > 0) && (Hr == S_OK)) {
      // Terminate multistring and return size copied
      *CopyAt = 0;
    } else {
      Hr = S_FALSE;
    }

    // return size copied
    *BufferSize = SizeNeeded+1;
  } else if ((Flag == DEBUG_KNOWN_STRUCT_GET_SINGLE_LINE_OUTPUT) && (Buffer != NULL) && (BufferSize != NULL)) {
    if (!strcmp (StructName, KnownStructs[0])) {
      ULONG64  Data;
      ULONG    ret;

      if (ReadMemory (Address, &Data, sizeof (Data), &ret)) {
        Hr = StringCbPrintf (Buffer, *BufferSize, " { %lx`%lx }", (ULONG)(Data >> 32), (ULONG)Data);
      } else {
        Hr = E_INVALIDARG;
      }
    } else if (!strcmp (StructName, KnownStructs[1])) {
      SYSTEMTIME  Data;
      ULONG       ret;

      if (ReadMemory (Address, &Data, sizeof (Data), &ret)) {
        Hr = StringCbPrintf (
               Buffer,
               *BufferSize,
               " { %02lu:%02lu:%02lu %02lu/%02lu/%04lu }",
               Data.wHour,
               Data.wMinute,
               Data.wSecond,
               Data.wMonth,
               Data.wDay,
               Data.wYear
               );
      } else {
        Hr = E_INVALIDARG;
      }
    } else {
      Hr = E_INVALIDARG;
    }
  } else if (Flag == DEBUG_KNOWN_STRUCT_SUPPRESS_TYPE_NAME) {
    if (!strcmp (StructName, KnownStructs[0])) {
      // Do not print type name for KnownStructs[0]
      Hr = S_OK;
    } else {
      // Print the type name
      Hr = S_FALSE;
    }

    if (Buffer) {
      Buffer[0] = 0;
    }
  } else {
    Hr = E_INVALIDARG;
  }

  return Hr;
}

extern "C"
HRESULT
_EFN_Analyze (
  _In_ PDEBUG_CLIENT4             Client,
  _In_ FA_EXTENSION_PLUGIN_PHASE  CallPhase,
  _In_ PDEBUG_FAILURE_ANALYSIS2   pAnalysis
  )
{
  INIT_API ();

  // Analysis tags
  #define FA_TAG_SAMPLE_PLUGIN_DEBUG_TEXT  0xA0000000

  ExtOut ("DbgExts Analysis Phase: %lx\n", CallPhase);
  switch (CallPhase) {
    case FA_PLUGIN_STACK_ANALYSIS:
      pAnalysis->SetString (
                   (FA_TAG)FA_TAG_SAMPLE_PLUGIN_DEBUG_TEXT,
                   "Sample custom analyzer was run for this analysis.\n"
                   );
      break;
    case FA_PLUGIN_POST_BUCKETING:
      PFA_ENTRY  Entry;

      //
      // Set default bucket if folowup module in dbgeng
      //
      if (((Entry = pAnalysis->Get (DEBUG_FLR_MODULE_NAME)) != NULL) &&
          !strcmp (FA_ENTRY_DATA (PSTR, Entry), "dbgeng"))
      {
        pAnalysis->SetString (DEBUG_FLR_DEFAULT_BUCKET_ID, "AV_IN_DEBUGGER");
      }

      break;
    default:
      // do nothing
      EXIT_API ();
      return S_OK;
  }

  UNREFERENCED_PARAMETER (pAnalysis);

  EXIT_API ();
  return S_OK;
}
