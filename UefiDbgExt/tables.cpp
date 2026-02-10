/*++

Copyright (c) Microsoft Corporation.

SPDX-License-Identifier: BSD-2-Clause-Patent

Module Name:

    tables.cpp

Abstract:

    This file contains debug commands enumerating EFI tables.

--*/

#include "uefiext.h"

GUID  TableGuids[] = EFI_TABLE_GUIDS;

ULONG64
GetTableAddress (
  EFI_TABLE  Table
  )
{
  ULONG64  StPtrAddr;
  ULONG64  SystemTableAddr;
  ULONG64  NumTables;
  ULONG64  ConfigTables;
  ULONG64  TableAddr;
  ULONG64  Result;
  ULONG64  ConfigTableSize;
  GUID     TableGuid;
  ULONG64  i;

  if (gUefiEnv == DXE) {
    StPtrAddr = GetExpression ("gST");
    if (StPtrAddr == NULL) {
      dprintf ("Failed to find global system table!\n");
      return 0;
    }

    if (!ReadPointer (StPtrAddr, &SystemTableAddr)) {
      dprintf ("Failed to find global system table!\n");
      return 0;
    }

    GetFieldValue (SystemTableAddr, "EFI_SYSTEM_TABLE", "NumberOfTableEntries", NumTables);
    GetFieldValue (SystemTableAddr, "EFI_SYSTEM_TABLE", "ConfigurationTable", ConfigTables);
    ConfigTableSize = GetTypeSize ("EFI_CONFIGURATION_TABLE");

    //
    // Check the number of tables in case something is wrong.
    //

    if (NumTables > 100) {
      dprintf ("Found too many system tables! (%lld) \n", NumTables);
      return 0;
    }

    for (i = 0; i < NumTables; i++) {
      TableAddr = ConfigTables + (i * ConfigTableSize);
      GetFieldValue (TableAddr, "EFI_CONFIGURATION_TABLE", "VendorGuid", TableGuid);
      if (TableGuid == TableGuids[Table]) {
        GetFieldValue (TableAddr, "EFI_CONFIGURATION_TABLE", "VendorTable", Result);
        return Result;
      }
    }
  } else {
    dprintf ("Not supported for this environment!\n");
  }

  return 0;
}

ULONG64
FindConfigTable (
  IN  ULONG64     SystemTableAddr,
  IN  const GUID  *TableGuid
  )
{
  EFI_SYSTEM_TABLE  SystemTable;
  ULONG             BytesRead = 0;

  // Read the EFI_SYSTEM_TABLE structure from the provided address
  if (!ReadMemory (SystemTableAddr, &SystemTable, sizeof (SystemTable), &BytesRead) || (BytesRead != sizeof (SystemTable))) {
    return 0;
  }

  // Iterate through the configuration tables to find the debug image info table
  ULONG64  ConfigTableAddr = (ULONG64)SystemTable.ConfigurationTable;

  for (UINT64 i = 0; i < SystemTable.NumberOfTableEntries; i++) {
    EFI_CONFIGURATION_TABLE  CurrentTable;
    if (!ReadMemory (ConfigTableAddr + (i * sizeof (EFI_CONFIGURATION_TABLE)), &CurrentTable, sizeof (CurrentTable), &BytesRead) || (BytesRead != sizeof (CurrentTable))) {
      return 0;
    }

    if (memcmp (&CurrentTable.VendorGuid, TableGuid, sizeof (GUID)) == 0) {
      return (ULONG64)CurrentTable.VendorTable;
    }
  }

  return 0;
}

ULONG64
FindSystemTable (
  VOID
  )

{
  ULONG64  SystemPtrAddr = NULL;

  if (gUefiEnv == DXE) {
    SystemPtrAddr = GetExpression ("mDebugTable");
    if (!ReadPointer (SystemPtrAddr, &SystemPtrAddr)) {
      dprintf ("Failed to read memory at %llx to get system table from ptr\n", SystemPtrAddr);
      return 0;
    }
  } else if (gUefiEnv == PATINA) {
    PSTR  Response = MonitorCommandWithOutput (g_ExtClient, "system_table_ptr", 0);
    SystemPtrAddr = strtoull (Response, NULL, 16);

    if (SystemPtrAddr == 0) {
      // if we didn't get the monitor command response, we will try to read the system table pointer from the core
      // which may work, if we already have loaded the core symbols. If not, we will fail gracefully. This would be the
      // case for the QEMU debugger, where we don't have the monitor command available, but we do have the
      // system table pointer symbols loaded.
      SystemPtrAddr = GetExpression ("patina_dxe_core::config_tables::debug_image_info_table::DBG_SYSTEM_TABLE_POINTER_ADDRESS");
      if (!ReadPointer (SystemPtrAddr, &SystemPtrAddr)) {
        dprintf ("Failed to read memory at %llx to get system table from ptr\n", SystemPtrAddr);
        return 0;
      }
    }
  }

  if (SystemPtrAddr == NULL) {
    // TODO: Add a flag to indicate whether we should scan memory for the system table pointer and then make the
    // scanning better, maybe binary search (though has issues). For now, C DXE has parity with before, Rust has
    // two cases, we don't have the monitor command yet, but that is only true at the initial breakpoint (gets set up
    // very soon after that, before other modules are loaded, so we have already succeeded) or we are in an older Rust
    // core that doesn't support the monitor command
    return 0;

    /*
    // Locate the system table pointer, which is allocated on a 4MB boundary near the top of memory
    // with signature EFI_SYSTEM_TABLE_SIGNATURE       SIGNATURE_64 ('I','B','I',' ','S','Y','S','T')
    // and the EFI_SYSTEM_TABLE structure.
    SystemPtrAddr = 0x80000000; // Start at the top of memory, well, as far as we want to go. This is pretty lazy, but it takes a long time to search the entire memory space.
    while (SystemPtrAddr >= 0x400000) { // Stop at 4MB boundary
      if (!ReadPointer(SystemPtrAddr, &Signature)) {
        SystemPtrAddr -= 0x400000; // Move to the next 4MB boundary
        continue;
      }

      if (Signature == SystemTableSignature) {
        dprintf("Found EFI_SYSTEM_TABLE_SIGNATURE at %llx\n", SystemPtrAddr);
        break;
      }

      SystemPtrAddr -= 0x400000; // Move to the next 4MB boundary
    }

    if (SystemPtrAddr < 0x400000) {
      dprintf("Failed to locate EFI_SYSTEM_TABLE_SIGNATURE!\n");
      return ERROR_NOT_FOUND;
    }
    */
  } else {
    // Check the signature at the system table pointer address
    ULONG64  Signature = 0;
    if (!ReadPointer (SystemPtrAddr, &Signature)) {
      dprintf ("Failed to read memory at %llx to get system table signature\n", SystemPtrAddr);
      return 0;
    }

    if (Signature != SYSTEM_TABLE_SIGNATURE) {
      dprintf ("Couldn't find EFI_SYSTEM_TABLE_SIGNATURE %llx at %llx, found %llx instead\n", SYSTEM_TABLE_SIGNATURE, SystemPtrAddr, Signature);
      return 0;
    }
  }

  // move past the signature to get the EFI_SYSTEM_TABLE structure
  SystemPtrAddr += sizeof (UINT64);

  ULONG64  SystemTableAddr = 0;

  if (!ReadPointer (SystemPtrAddr, &SystemTableAddr)) {
    dprintf ("Failed to read the system table address at %llx!\n", SystemPtrAddr);
    return 0;
  }

  return SystemTableAddr;
}
