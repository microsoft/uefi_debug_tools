//**************************************************************************
//
// EfiSymComposition.h
//
// Main header for the Symbol Locator WinDbg extension. This extension
// provides a LocateSymbolsForImage callback to intercept symbol resolution.
//
//**************************************************************************
//
// Copyright (c) Microsoft Corporation.  All rights reserved.
//
//**************************************************************************

#ifndef __EFISYMCOMPOSITION_H__
#define __EFISYMCOMPOSITION_H__

#include <windows.h>
#include <memory>
#include <functional>
#include <string>
#include <map>
#include <vector>
#include <algorithm>

#include <wrl.h>
#include <wrl/client.h>
#include <wrl/implements.h>
#include <wrl/module.h>

#define KDEXT_64BIT
#include <dbgeng.h>
#include <dbgmodel.h>
// #include <DbgServices.h>
#include "DbgServicesUpdated.h" // TEMP until DbgServices.h is updated
#include <DbgServicesBridgeClient.h>

#include <initguid.h>
DEFINE_GUID(DEBUG_COMPONENT_ELFIMAGE_SYMBOLPROVIDER, 0x21381683, 0x766b, 0x4eed, 0xb8, 0xee, 0x5a, 0x21, 0x5b, 0xd8, 0x51, 0xcd);

using namespace Microsoft::WRL;

#define IfFailedReturn(EXPR) do { HRESULT __hr = (EXPR); if (FAILED(__hr)) { return __hr; } } while (false, false)

namespace Debugger
{
namespace TargetComposition
{
namespace Services
{
namespace EFIEfiSymComposition
{

class EFIEfiSymCompositionProvider;

} // EfiSymComposition
} // Services
} // TargetComposition
} // Debugger

// Global verbose flag for logging control
extern bool g_VerboseLogging;

// Logging macros
#define LOG(ctrl, ...) { if (ctrl) { (ctrl)->Output(DEBUG_OUTPUT_SYMBOLS, __VA_ARGS__); } }
#define LOG_VERBOSE(ctrl, ...) { if (g_VerboseLogging && ctrl) { (ctrl)->Output(DEBUG_OUTPUT_SYMBOLS, __VA_ARGS__); } }

// Helper function to find symbol file and call ElfBinComposition's OpenSymbols
BOOLEAN LoadEfiSymbols(ULONG64 BaseAddress, PCSTR FilePath, _COM_Outptr_ ISvcSymbolSet **ppSymbolSet, _In_ ISvcSymbolProvider2 *spSymbolProvider2, _In_opt_ IDebugClient *pDebugClient, _In_opt_ PVOID pBldIdData, _In_ SIZE_T bldIdSize);

#include "EfiSymCompositionService.h"

#endif // __EFISYMCOMPOSITION_H__
