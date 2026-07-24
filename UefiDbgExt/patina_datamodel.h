/*++

    Copyright (c) Microsoft Corporation.

    SPDX-License-Identifier: BSD-2-Clause-Patent

Module Name:

    patina_datamodel.h

Abstract:

    Native (C++) Debugger Data Model visualizers for Patina types, replacing the JavaScript visualizers. Provides
    `dx` decoding and tree iteration for the GCD red-black trees and their block enums.

--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

//
// Acquires the data model interfaces and registers the Patina type visualizers. Called from
// DebugExtensionInitialize. Returns S_OK on success; failure leaves the classic (wdbgexts) commands unaffected.
//
HRESULT
PatinaDataModelInitialize (
  void
  );

//
// Unregisters the Patina type visualizers and releases the data model interfaces. Called from
// DebugExtensionUninitialize.
//
void
PatinaDataModelUninitialize (
  void
  );

#ifdef __cplusplus
}
#endif
