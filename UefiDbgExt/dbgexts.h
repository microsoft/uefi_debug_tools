/*++

    Copyright (c) Microsoft Corporation.

    SPDX-License-Identifier: BSD-2-Clause-Patent

Module Name:

    dbgexts.h

--*/

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <vector>

#include "uefispec.h"

//
// Define KDEXT_64BIT to make all wdbgexts APIs recognize 64 bit addresses
// It is recommended for extensions to use 64 bit headers from wdbgexts so
// the extensions could support 64 bit targets.
//
#define KDEXT_64BIT
#include <wdbgexts.h>
#include <dbgeng.h>

#pragma warning(disable:4201) // nonstandard extension used : nameless struct
#include <extsfns.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum _PRINTF_DML_COLOR {
  Normal,
  Verbose,
  Warning,
  Err,
  Subdued,
  Header,
  Emphasized,
  Changed,
  ColorMax
} PRINTF_DML_COLOR, *PPRINTF_DML_COLOR;

//
// Event callbacks class for break notifications
//
class UefiEventCallbacks : public IDebugEventCallbacks
{
public:
  // IUnknown
  STDMETHOD (QueryInterface)(
    THIS_
    _In_ REFIID InterfaceId,
    _Out_ PVOID *Interface
    );
  STDMETHOD_ (ULONG, AddRef)(THIS);
  STDMETHOD_ (ULONG, Release)(THIS);

  // IDebugEventCallbacks
  STDMETHOD (GetInterestMask)(
    THIS_
    _Out_ PULONG Mask
    );
  STDMETHOD (Breakpoint)(
    THIS_
    _In_ PDEBUG_BREAKPOINT Bp
    );
  STDMETHOD (Exception)(
    THIS_
    _In_ PEXCEPTION_RECORD64 Exception,
    _In_ ULONG FirstChance
    );
  STDMETHOD (CreateThread)(
    THIS_
    _In_ ULONG64 Handle,
    _In_ ULONG64 DataOffset,
    _In_ ULONG64 StartOffset
    );
  STDMETHOD (ExitThread)(
    THIS_
    _In_ ULONG ExitCode
    );
  STDMETHOD (CreateProcess)(
    THIS_
    _In_ ULONG64 ImageFileHandle,
    _In_ ULONG64 Handle,
    _In_ ULONG64 BaseOffset,
    _In_ ULONG ModuleSize,
    _In_opt_ PCSTR ModuleName,
    _In_opt_ PCSTR ImageName,
    _In_ ULONG CheckSum,
    _In_ ULONG TimeDateStamp,
    _In_ ULONG64 InitialThreadHandle,
    _In_ ULONG64 ThreadDataOffset,
    _In_ ULONG64 StartOffset
    );
  STDMETHOD (ExitProcess)(
    THIS_
    _In_ ULONG ExitCode
    );
  STDMETHOD (LoadModule)(
    THIS_
    _In_ ULONG64 ImageFileHandle,
    _In_ ULONG64 BaseOffset,
    _In_ ULONG ModuleSize,
    _In_opt_ PCSTR ModuleName,
    _In_opt_ PCSTR ImageName,
    _In_ ULONG CheckSum,
    _In_ ULONG TimeDateStamp
    );
  STDMETHOD (UnloadModule)(
    THIS_
    _In_opt_ PCSTR ImageBaseName,
    _In_ ULONG64 BaseOffset
    );
  STDMETHOD (SystemError)(
    THIS_
    _In_ ULONG Error,
    _In_ ULONG Level
    );
  STDMETHOD (SessionStatus)(
    THIS_
    _In_ ULONG Status
    );
  STDMETHOD (ChangeDebuggeeState)(
    THIS_
    _In_ ULONG Flags,
    _In_ ULONG64 Argument
    );
  STDMETHOD (ChangeEngineState)(
    THIS_
    _In_ ULONG Flags,
    _In_ ULONG64 Argument
    );
  STDMETHOD (ChangeSymbolState)(
    THIS_
    _In_ ULONG Flags,
    _In_ ULONG64 Argument
    );
};

VOID
PrintDml (
  __in PRINTF_DML_COLOR  Mask,
  __in PCSTR             Format,
  ...
  );

#define INIT_API()                             \
    HRESULT Status;                            \
    if ((Status = ExtQuery(Client)) != S_OK) return Status;

#define EXT_RELEASE(Unk) \
    ((Unk) != NULL ? ((Unk)->Release(), (Unk) = NULL) : NULL)

#define EXIT_API  ExtRelease

// Global variables initialized by query.
extern PDEBUG_CLIENT4    g_ExtClient;
extern PDEBUG_CONTROL    g_ExtControl;
extern PDEBUG_SYMBOLS2   g_ExtSymbols;
extern PDEBUG_REGISTERS  g_ExtRegisters;
extern ULONG             g_TargetMachine;

extern BOOL   Connected;
extern ULONG  TargetMachine;

HRESULT
ExtQuery (
  PDEBUG_CLIENT4  Client
  );

void
ExtRelease (
  void
  );

HRESULT
NotifyOnTargetAccessible (
  PDEBUG_CONTROL  Control
  );

VOID
BreakFromRunning (
  VOID
  );

#ifdef __cplusplus
}
#endif
