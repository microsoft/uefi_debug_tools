/*++

    Copyright (c) Microsoft Corporation.

    SPDX-License-Identifier: BSD-2-Clause-Patent

Module Name:

    modules.cpp

Abstract:

    This file contains debug commands for enumerating UEFI modules and their
    symbols.

--*/

#include "uefiext.h"
#include <winnt.h>
#include <vector>
#include <cstring>

const GUID  gDebugImageInfoTableGuid = EFI_DEBUG_IMAGE_INFO_TABLE_GUID;

ULONG64  gSystemTableAddr = 0;
ULONG64  gDebugTableAddr  = 0;

VOID
LoadCompositionExtensions (
  )
{
  static BOOLEAN  Loaded = FALSE;

  if (!Loaded) {
    dprintf ("Loading target composition extensions.\n");
    g_ExtControl->Execute (
                    DEBUG_OUTCTL_THIS_CLIENT,
                    ".load ELFBinComposition",
                    DEBUG_EXECUTE_DEFAULT
                    );

    //
    // TODO: Load additional target composition binaries when completed.
    //

    Loaded = TRUE;
  }
}

BOOLEAN
ReloadModuleFromPeDebug (
  ULONG64  Address
  )
{
  ULONG                               BytesRead;
  IMAGE_DOS_HEADER                    DosHeader;
  ULONG64                             NtHeadersAddr;
  IMAGE_NT_HEADERS64                  NtHeaders64;
  UINT32                              DebugDirRVA;
  UINT32                              DebugDirSize;
  UINT32                              ImageSize;
  ULONG                               NumEntries;
  ULONG64                             DebugDirAddr;
  std::vector<IMAGE_DEBUG_DIRECTORY>  DebugEntries;
  ULONG                               i;
  IMAGE_DEBUG_DIRECTORY               *Entry;
  ULONG64                             CvAddr;
  CHAR                                Signature[5];
  ULONG                               CvHeaderSize;
  ULONG64                             PdbPathAddr;
  CHAR                                PdbPath[1024];
  ULONG                               SizeToRead;
  CHAR                                *basename;
  CHAR                                *p;
  CHAR                                ModuleName[256];
  CHAR                                *dot;
  CHAR                                EfiName[256];
  CHAR                                Command[512];

  BytesRead = 0;

  // Read DOS header
  if (!ReadMemory (Address, &DosHeader, sizeof (DosHeader), &BytesRead) || (BytesRead != sizeof (DosHeader))) {
    dprintf ("Failed to read DOS header at %llx\n", Address);
    return false;
  }

  if (DosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
    dprintf ("Invalid DOS header magic at %llx\n", Address);
    return false;
  }

  // Read NT headers
  NtHeadersAddr = Address + DosHeader.e_lfanew;
  NtHeaders64   = { 0 };

  if (!ReadMemory (NtHeadersAddr, &NtHeaders64, sizeof (NtHeaders64), &BytesRead)) {
    dprintf ("Failed to read NT headers at %llx\n", NtHeadersAddr);
    return false;
  }

  // Ensure this is a 64-bit optional header
  if (NtHeaders64.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
    dprintf ("Not a 64-bit PE image at %llx\n", Address);
    return false;
  }

  // Determine Debug Directory RVA and size and image size from 64-bit OptionalHeader
  DebugDirRVA  = NtHeaders64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;
  DebugDirSize = NtHeaders64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;
  ImageSize    = NtHeaders64.OptionalHeader.SizeOfImage;

  if ((DebugDirRVA == 0) || (DebugDirSize == 0)) {
    dprintf ("No debug directory in PE image at %llx\n", Address);
    return false;
  }

  // Read debug directory entries
  NumEntries   = DebugDirSize / sizeof (IMAGE_DEBUG_DIRECTORY);
  DebugDirAddr = Address + DebugDirRVA;
  DebugEntries.resize (NumEntries);
  if (!ReadMemory (DebugDirAddr, DebugEntries.data (), DebugDirSize, &BytesRead) || (BytesRead != DebugDirSize)) {
    dprintf ("Failed to read debug directory at %llx\n", DebugDirAddr);
    return false;
  }

  // Look for CodeView entry
  for (i = 0; i < NumEntries; i++) {
    Entry = &DebugEntries[i];
    if (Entry->Type == IMAGE_DEBUG_TYPE_CODEVIEW) {
      CvAddr = 0;
      // If AddressOfRawData appears to be an absolute VA within the loaded image range, use it directly.
      if ((Entry->AddressOfRawData != 0) && (Entry->AddressOfRawData >= Address) && (Entry->AddressOfRawData < (Address + (ULONG64)NtHeaders64.OptionalHeader.SizeOfImage))) {
        CvAddr = Entry->AddressOfRawData;
      } else if (Entry->AddressOfRawData != 0) {
        // Treat as relative
        CvAddr = Address + Entry->AddressOfRawData;
      } else if (Entry->PointerToRawData != 0) {
        // Treat PointerToRawData as file offset mapped into memory at image base
        CvAddr = Address + Entry->PointerToRawData;
      } else {
        dprintf ("Debug entry has no raw data address for %llx\n", Address);
        continue;
      }

      // Read the CodeView signature
      memset (Signature, 0, sizeof (Signature));
      if (!ReadMemory (CvAddr, Signature, 4, &BytesRead) || (BytesRead != 4)) {
        continue;
      }

      CvHeaderSize = 0;
      if (strncmp (Signature, "RSDS", 4) == 0) {
        CvHeaderSize = 24;
      } else if (strncmp (Signature, "NB10", 4) == 0) {
        CvHeaderSize = 16;
      } else {
        dprintf ("Unsupported CodeView signature '%c%c%c%c' at %llx\n", Signature[0], Signature[1], Signature[2], Signature[3], CvAddr);
        continue;
      }

      PdbPathAddr = CvAddr + CvHeaderSize;

      // Read PDB path using the size from the debug directory
      memset (PdbPath, 0, sizeof (PdbPath));
      if ((Entry->SizeOfData != 0) && (Entry->SizeOfData > CvHeaderSize)) {
        ULONG64  Rem = Entry->SizeOfData - CvHeaderSize;
        SizeToRead = (ULONG)((Rem < (sizeof (PdbPath) - 1)) ? Rem : (sizeof (PdbPath) - 1));
      } else {
        SizeToRead = (ULONG)(sizeof (PdbPath) - 1);
      }

      if (!ReadMemory (PdbPathAddr, PdbPath, SizeToRead, &BytesRead) || (BytesRead == 0)) {
        dprintf ("Failed to read PDB path at %llx (size %lu)\n", PdbPathAddr, SizeToRead);
        continue;
      }

      // Ensure null termination even if partial read
      PdbPath[(BytesRead < (sizeof (PdbPath) - 1)) ? BytesRead : (sizeof (PdbPath) - 1)] = '\0';

      // Check for the .dll extension. This indicates that this is a GenFW converted module.
      // To load symbols for these, we need to load the compositions extensions.
      if (strstr (PdbPath, ".dll") != NULL) {
        LoadCompositionExtensions ();
      }

      // Extract the filename from the path
      basename = PdbPath;
      p        = PdbPath;
      while (*p) {
        if ((*p == '\\') || (*p == '/')) {
          basename = p + 1;
        }

        p++;
      }

      // Remove extension
      memset (ModuleName, 0, sizeof (ModuleName));
      strncpy_s (ModuleName, sizeof (ModuleName), basename, _TRUNCATE);
      dot = strrchr (ModuleName, '.');
      if (dot) {
        *dot = '\0';
      }

      // Add a .efi extension, this is needed for the way symbols are resolved
      // for GenFW converted modules.
      memset (EfiName, 0, sizeof (EfiName));
      sprintf_s (EfiName, sizeof (EfiName), "%s.efi", ModuleName);

      // Build .reload command. Include size if we have one.
      if (ImageSize != 0) {
        sprintf_s (Command, sizeof (Command), ".reload %s=%I64x,%I32x", EfiName, Address, ImageSize);
      } else {
        sprintf_s (Command, sizeof (Command), ".reload %s=%I64x", EfiName, Address);
      }

      g_ExtControl->Execute (DEBUG_OUTCTL_THIS_CLIENT, Command, DEBUG_EXECUTE_DEFAULT);
      return true;
    }
  }

  dprintf ("Failed to locate CodeView PDB path at %llx\n", Address);
  return false;
}

HRESULT
FindModuleBackwards (
  ULONG64  Address
  )
{
  ULONG64        MinAddress;
  CHAR           Command[512];
  ULONG64        MaxSize;
  ULONG32        Check;
  CONST ULONG32  Magic    = 0x5A4D;     // MZ
  CONST ULONG32  ElfMagic = 0x464C457F; // 0x7F_ELF
  ULONG          BytesRead;
  HRESULT        Result;
  ULONG64        Base;

  MaxSize = 0x400000;   // 4 Mb
  Address = PAGE_ALIGN_DOWN (Address);
  if (Address > MaxSize) {
    MinAddress = Address - MaxSize;
  } else {
    MinAddress = 0;
  }

  // Check this hasn't already be loaded.
  Result = g_ExtSymbols->GetModuleByOffset (Address, 0, NULL, &Base);
  if (Result == S_OK) {
    dprintf ("Already loaded module at %llx\n", Base);
    return Result;
  }

  Result = ERROR_NOT_FOUND;
  for ( ; Address >= MinAddress; Address -= PAGE_SIZE) {
    Check = 0;
    ReadMemory (Address, &Check, sizeof (Check), &BytesRead);
    if (BytesRead != sizeof (Check)) {
      break;
    }

    if ((Check & 0xFFFF) == Magic) {
      dprintf ("Found PE/COFF image at %llx\n", Address);

      // First try to treat this as a PE/COFF image and reload using debug info (CodeView/PDB)
      if (ReloadModuleFromPeDebug (Address)) {
        Result = S_OK;
        break;
      }

      // If that fails, see if imgscan can find it.
      dprintf ("Falling back to .imgscan for module at %llx\n", Address);
      sprintf_s (&Command[0], sizeof (Command), ".imgscan /l /r %I64x %I64x", Address, Address + 0xFFF);
      g_ExtControl->Execute (
                      DEBUG_OUTCTL_THIS_CLIENT,
                      &Command[0],
                      DEBUG_EXECUTE_DEFAULT
                      );

      Result = S_OK;
      break;
    } else if (Check == ElfMagic) {
      dprintf ("Found ELF image at %llx. ELF images not yet supported.\n", Address);

      Result = S_OK;
      break;
    }
  }

  return Result;
}

HRESULT
loadmodules (
  ULONG64  DebugTableAddr,
  BOOLEAN  Refresh
  )
{
  ULONG  BytesRead = 0;

  //
  // TODO: Add support for PEI & MM
  //

  if (DebugTableAddr == 0) {
    dprintf ("Bad debug table address!\n");
    return ERROR_INVALID_PARAMETER;
  }

  // Read the debug image info table header
  EFI_DEBUG_IMAGE_INFO_TABLE_HEADER  DebugImageInfoTableHeader;

  if (!ReadMemory (DebugTableAddr, &DebugImageInfoTableHeader, sizeof (DebugImageInfoTableHeader), &BytesRead) || (BytesRead != sizeof (DebugImageInfoTableHeader))) {
    dprintf ("Failed to read EFI_DEBUG_IMAGE_INFO_TABLE_HEADER at %llx\n", DebugTableAddr);
    return ERROR_NOT_FOUND;
  }

  // If there is an update in progress, the table cannot be trusted. Abort.
  if (DebugImageInfoTableHeader.UpdateStatus & EFI_DEBUG_IMAGE_INFO_UPDATE_IN_PROGRESS) {
    dprintf ("Debug image info table update in progress. Try again later.\n");
    return ERROR_BUSY;
  }

  //
  // Clear the modified flag if needed. If the this is a refresh and the modify flag is not set, exit early.
  //

  if (DebugImageInfoTableHeader.UpdateStatus & EFI_DEBUG_IMAGE_INFO_TABLE_MODIFIED) {
    UINT32  NewStatus = DebugImageInfoTableHeader.UpdateStatus & (~EFI_DEBUG_IMAGE_INFO_TABLE_MODIFIED);
    if (!WriteMemory (DebugTableAddr + offsetof (EFI_DEBUG_IMAGE_INFO_TABLE_HEADER, UpdateStatus), &NewStatus, sizeof (NewStatus), &BytesRead) || (BytesRead != sizeof (NewStatus))) {
      dprintf ("Failed to clear modified flag in EFI_DEBUG_IMAGE_INFO_TABLE_HEADER at %llx\n", DebugTableAddr);
    }
  } else if (Refresh) {
    dprintf ("No modifications to debug table.\n");
    return S_OK;
  }

  if ((DebugImageInfoTableHeader.EfiDebugImageInfoTable == NULL) ||
      (DebugImageInfoTableHeader.TableSize == 0))
  {
    dprintf ("Debug image info table is empty!\n");
    return ERROR_NOT_FOUND;
  }

  // Iterate through the debug image info table entries
  for (ULONG Index = 0; Index < DebugImageInfoTableHeader.TableSize; Index++) {
    ULONG64  EntryAddr = (ULONG64)DebugImageInfoTableHeader.EfiDebugImageInfoTable + (Index * sizeof (EFI_DEBUG_IMAGE_INFO));
    ULONG64  NormalImageAddr;
    if (!ReadMemory (EntryAddr, &NormalImageAddr, sizeof (NormalImageAddr), &BytesRead) || (BytesRead != sizeof (NormalImageAddr))) {
      dprintf ("Failed to read debug image info entry at index %lu\n", Index);
      continue;
    }

    if (NormalImageAddr == NULL) {
      dprintf ("Skipping missing normal image info at index %lu\n", Index);
      continue;
    }

    ULONG64  LoadedImageProtocolAddr;
    if (!ReadMemory (NormalImageAddr + offsetof (EFI_DEBUG_IMAGE_INFO_NORMAL, LoadedImageProtocolInstance), &LoadedImageProtocolAddr, sizeof (LoadedImageProtocolAddr), &BytesRead) || (BytesRead != sizeof (LoadedImageProtocolAddr))) {
      dprintf ("Failed to read loaded image protocol instance at index %lu\n", Index);
      continue;
    }

    if (LoadedImageProtocolAddr == NULL) {
      dprintf ("Skipping missing loaded image protocol at index %lu\n", Index);
      continue;
    }

    UINT64  ImageBase;
    if (!ReadMemory (LoadedImageProtocolAddr + offsetof (EFI_LOADED_IMAGE_PROTOCOL, ImageBase), &ImageBase, sizeof (ImageBase), &BytesRead) || (BytesRead != sizeof (ImageBase))) {
      dprintf ("Failed to read image base at index %lu\n", Index);
      continue;
    }

    // Check if the module is already loaded
    ULONG64  Base;
    if ((g_ExtSymbols->GetModuleByOffset (ImageBase, 0, NULL, &Base) == S_OK) && (ImageBase == Base)) {
      dprintf ("Module at %llx is already loaded\n", ImageBase);
      continue;
    }

    dprintf ("Loading module at %llx\n", ImageBase);

    if (!ReloadModuleFromPeDebug (ImageBase)) {
      // If ReloadModuleFromPeDebug fails, fall back to .imgscan
      CHAR  Command[512];
      sprintf_s (Command, sizeof (Command), ".imgscan /l /r %I64x (%I64x + 0xFFF)", ImageBase, ImageBase);
      g_ExtControl->Execute (
                      DEBUG_OUTCTL_THIS_CLIENT,
                      Command,
                      DEBUG_EXECUTE_DEFAULT
                      );
    }
  }

  return S_OK;
}

HRESULT CALLBACK
findmodule (
  PDEBUG_CLIENT4  Client,
  PCSTR           args
  )
{
  ULONG64  Address;
  HRESULT  Result;

  INIT_API ();

  if (strlen (args) == 0) {
    args = "@$ip";
  }

  Address = GetExpression (args);
  if ((Address == 0) || (Address == (-1))) {
    dprintf ("Invalid address!\n");
    dprintf ("Usage: !uefiext.findmodule [Address]\n");
    return ERROR_INVALID_PARAMETER;
  }

  Result = FindModuleBackwards (Address);

  EXIT_API ();
  return Result;
}

HRESULT CALLBACK
findall (
  PDEBUG_CLIENT4  Client,
  PCSTR           args
  )
{
  ULONG    BytesRead   = 0;
  BOOLEAN  RefreshMode = FALSE;
  HRESULT  Result;

  INIT_API ();

  if ((gUefiEnv != DXE) && (gUefiEnv != PATINA)) {
    dprintf ("Only supported for DXE and Rust!\n");
    return ERROR_NOT_SUPPORTED;
  }

  // Check for refresh flag
  if (strstr (args, "-r") != NULL) {
    RefreshMode = TRUE;
  }

  // Only use the cached table addresses in refresh mode
  if (!RefreshMode) {
    gSystemTableAddr = 0;
    gDebugTableAddr  = 0;
  }

  if (gSystemTableAddr == 0) {
    //
    // Finding the system table may require finding and loading the core first.
    //

    FindModuleBackwards (GetExpression ("@$ip"));
    g_ExtControl->Execute (
                    DEBUG_OUTCTL_THIS_CLIENT,
                    "ld *ore*",
                    DEBUG_EXECUTE_DEFAULT
                    );

    gSystemTableAddr = FindSystemTable ();
  } else {
    dprintf ("Using cached system table address %llx\n", gSystemTableAddr);
  }

  if (gSystemTableAddr == 0) {
    dprintf ("System table not found. May not be initialized yet.\n");
    return ERROR_NOT_FOUND;
  }

  //
  // Load all the other modules using the debug table.
  //

  if (gDebugTableAddr == 0) {
    gDebugTableAddr = FindConfigTable (gSystemTableAddr, &gDebugImageInfoTableGuid);
    if (gDebugTableAddr == 0) {
      dprintf ("Failed to locate EFI_DEBUG_IMAGE_INFO_TABLE_HEADER in configuration tables\n");
      return ERROR_NOT_FOUND;
    }
  } else {
    dprintf ("Using cached debug table address %llx\n", gDebugTableAddr);
  }

  Result = loadmodules (gDebugTableAddr, RefreshMode);

  EXIT_API ();
  return Result;
}
