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
#include <DbgServices.h>
#include <DbgServicesBridgeClient.h>

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

BOOLEAN LoadEfiSymbols (ULONG64 BaseAddress, PCSTR FilePath, _COM_Outptr_ ISvcSymbolSet **ppSymbolSet);

#include "EfiSymCompositionService.h"

#endif // __EFISYMCOMPOSITION_H__
