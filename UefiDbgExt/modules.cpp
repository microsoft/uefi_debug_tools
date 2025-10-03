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

VOID
LoadCompositionExtensions (
  )
{
  static BOOLEAN  Loaded = FALSE;

  if (!Loaded) {
    dprintf ("Loading target composition extensions.\n");
    g_ExtControl->Execute (
                    DEBUG_OUTCTL_ALL_CLIENTS,
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
  ULONG             BytesRead = 0;
  IMAGE_DOS_HEADER  DosHeader;

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
  ULONG64             NtHeadersAddr = Address + DosHeader.e_lfanew;
  IMAGE_NT_HEADERS64  NtHeaders64   = { 0 };

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
  UINT32  DebugDirRVA  = NtHeaders64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;
  UINT32  DebugDirSize = NtHeaders64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;
  UINT32  ImageSize    = NtHeaders64.OptionalHeader.SizeOfImage;

  if ((DebugDirRVA == 0) || (DebugDirSize == 0)) {
    dprintf ("No debug directory in PE image at %llx\n", Address);
    return false;
  }

  // Read debug directory entries
  ULONG                               NumEntries   = DebugDirSize / sizeof (IMAGE_DEBUG_DIRECTORY);
  ULONG64                             DebugDirAddr = Address + DebugDirRVA;
  std::vector<IMAGE_DEBUG_DIRECTORY>  DebugEntries;

  DebugEntries.resize (NumEntries);
  if (!ReadMemory (DebugDirAddr, DebugEntries.data (), DebugDirSize, &BytesRead) || (BytesRead != DebugDirSize)) {
    dprintf ("Failed to read debug directory at %llx\n", DebugDirAddr);
    return false;
  }

  // Look for CodeView entry
  for (ULONG i = 0; i < NumEntries; i++) {
    IMAGE_DEBUG_DIRECTORY  &Entry = DebugEntries[i];
    if (Entry.Type == IMAGE_DEBUG_TYPE_CODEVIEW) {
      ULONG64  CvAddr = 0;
      // If AddressOfRawData appears to be an absolute VA within the loaded image range, use it directly.
      if ((Entry.AddressOfRawData != 0) && (Entry.AddressOfRawData >= Address) && (Entry.AddressOfRawData < (Address + (ULONG64)NtHeaders64.OptionalHeader.SizeOfImage))) {
        CvAddr = Entry.AddressOfRawData;
      } else if (Entry.AddressOfRawData != 0) {
        // Treat as relative
        CvAddr = Address + Entry.AddressOfRawData;
      } else if (Entry.PointerToRawData != 0) {
        // Treat PointerToRawData as file offset mapped into memory at image base
        CvAddr = Address + Entry.PointerToRawData;
      } else {
        dprintf ("Debug entry has no raw data address for %llx\n", Address);
        continue;
      }

      // Read the CodeView signature
      CHAR  Signature[5] = { 0 };
      if (!ReadMemory (CvAddr, Signature, 4, &BytesRead) || (BytesRead != 4)) {
        continue;
      }

      ULONG  CvHeaderSize = 0;
      if (strncmp (Signature, "RSDS", 4) == 0) {
        CvHeaderSize = 24;
      } else if (strncmp (Signature, "NB10", 4) == 0) {
        CvHeaderSize = 16;
      } else {
        dprintf ("Unsupported CodeView signature '%c%c%c%c' at %llx\n", Signature[0], Signature[1], Signature[2], Signature[3], CvAddr);
        continue;
      }

      ULONG64  PdbPathAddr = CvAddr + CvHeaderSize;

      // Read PDB path using the size from the debug directory
      CHAR   PdbPath[1024] = { 0 };
      ULONG  SizeToRead;
      if ((Entry.SizeOfData != 0) && (Entry.SizeOfData > CvHeaderSize)) {
        ULONG64  Rem = Entry.SizeOfData - CvHeaderSize;
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
      CHAR  *basename = PdbPath;
      CHAR  *p        = PdbPath;
      while (*p) {
        if ((*p == '\\') || (*p == '/')) {
          basename = p + 1;
        }

        p++;
      }

      // Remove extension
      CHAR  ModuleName[256] = { 0 };
      strncpy_s (ModuleName, sizeof (ModuleName), basename, _TRUNCATE);
      CHAR  *dot = strrchr (ModuleName, '.');
      if (dot) {
        *dot = '\0';
      }

      // Add a .efi extension, this is needed for the way symbols are resolved
      // for GenFW converted modules.
      CHAR  EfiName[256] = { 0 };
      sprintf_s (EfiName, sizeof (EfiName), "%s.efi", ModuleName);

      // Build .reload command. Include size if we have one.
      CHAR  Command[512];
      if (ImageSize != 0) {
        sprintf_s (Command, sizeof (Command), ".reload %s=%I64x,%I32x", EfiName, Address, ImageSize);
      } else {
        sprintf_s (Command, sizeof (Command), ".reload %s=%I64x", EfiName, Address);
      }

      g_ExtControl->Execute (DEBUG_OUTCTL_ALL_CLIENTS, Command, DEBUG_EXECUTE_DEFAULT);
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
                      DEBUG_OUTCTL_ALL_CLIENTS,
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
  ULONG64  SystemTableAddr
  )
{
  UINT32                       TableSize;
  ULONG64                      Table;
  EFI_DEBUG_IMAGE_INFO         *Entry;
  EFI_DEBUG_IMAGE_INFO_NORMAL  *NormalImage;
  EFI_LOADED_IMAGE_PROTOCOL    *ImageProtocol;
  UINT64                       ImageBase;
  ULONG                        Index;
  CHAR                         Command[512];
  ULONG64                      Base;
  ULONG                        BytesRead = 0;

  //
  // TODO: Add support for PEI & MM
  //

  EFI_SYSTEM_TABLE                   SystemTable;
  EFI_CONFIGURATION_TABLE            *ConfigTable;
  GUID                               DebugImageInfoTableGuid    = EFI_DEBUG_IMAGE_INFO_TABLE_GUID;
  EFI_DEBUG_IMAGE_INFO_TABLE_HEADER  *DebugImageInfoTableHeader = NULL;

  // Read the EFI_SYSTEM_TABLE structure from the provided address
  if (!ReadMemory (SystemTableAddr, &SystemTable, sizeof (SystemTable), &BytesRead) || (BytesRead != sizeof (SystemTable))) {
    dprintf ("Failed to read EFI_SYSTEM_TABLE at %llx\n", SystemTableAddr);
    return ERROR_NOT_FOUND;
  }

  // Iterate through the configuration tables to find the debug image info table
  ConfigTable = SystemTable.ConfigurationTable;
  for (UINT64 i = 0; i < SystemTable.NumberOfTableEntries; i++) {
    EFI_CONFIGURATION_TABLE  CurrentTable;
    if (!ReadMemory ((ULONG64)&ConfigTable[i], &CurrentTable, sizeof (CurrentTable), &BytesRead) || (BytesRead != sizeof (CurrentTable))) {
      dprintf ("Failed to read configuration table entry at index %llu\n", i);
      continue;
    }

    if (memcmp (&CurrentTable.VendorGuid, &DebugImageInfoTableGuid, sizeof (GUID)) == 0) {
      DebugImageInfoTableHeader = (EFI_DEBUG_IMAGE_INFO_TABLE_HEADER *)CurrentTable.VendorTable;
      break;
    }
  }

  if (DebugImageInfoTableHeader == NULL) {
    dprintf ("Failed to locate EFI_DEBUG_IMAGE_INFO_TABLE_HEADER in configuration tables\n");
    return ERROR_NOT_FOUND;
  }

  // Read the debug image info table header
  if (!ReadMemory ((ULONG64)&DebugImageInfoTableHeader->TableSize, &TableSize, sizeof (TableSize), &BytesRead) || (BytesRead != sizeof (TableSize))) {
    dprintf ("Failed to read EFI_DEBUG_IMAGE_INFO_TABLE_HEADER at %llx\n", (ULONG64)DebugImageInfoTableHeader);
    return ERROR_NOT_FOUND;
  }

  if (!ReadMemory ((ULONG64)&DebugImageInfoTableHeader->EfiDebugImageInfoTable, &Table, sizeof (Table), &BytesRead) || (BytesRead != sizeof (Table))) {
    dprintf ("Failed to read EfiDebugImageInfoTable pointer\n");
    return ERROR_NOT_FOUND;
  }

  if ((Table == NULL) || (TableSize == 0)) {
    dprintf ("Debug image info table is empty!\n");
    return ERROR_NOT_FOUND;
  }

  // Iterate through the debug image info table entries
  for (Index = 0; Index < TableSize; Index++) {
    Entry = (EFI_DEBUG_IMAGE_INFO *)(Table + (Index * sizeof (EFI_DEBUG_IMAGE_INFO)));
    if (!ReadMemory ((ULONG64)&Entry->NormalImage, &NormalImage, sizeof (NormalImage), &BytesRead) || (BytesRead != sizeof (NormalImage))) {
      dprintf ("Failed to read debug image info entry at index %lu\n", Index);
      continue;
    }

    if (NormalImage == NULL) {
      dprintf ("Skipping missing normal image info at index %lu\n", Index);
      continue;
    }

    if (!ReadMemory ((ULONG64)&NormalImage->LoadedImageProtocolInstance, &ImageProtocol, sizeof (ImageProtocol), &BytesRead) || (BytesRead != sizeof (ImageProtocol))) {
      dprintf ("Failed to read loaded image protocol instance at index %lu\n", Index);
      continue;
    }

    if (ImageProtocol == NULL) {
      dprintf ("Skipping missing loaded image protocol at index %lu\n", Index);
      continue;
    }

    if (!ReadMemory ((ULONG64)&ImageProtocol->ImageBase, &ImageBase, sizeof (ImageBase), &BytesRead) || (BytesRead != sizeof (ImageBase))) {
      dprintf ("Failed to read image base at index %lu\n", Index);
      continue;
    }

    // Check if the module is already loaded
    if ((g_ExtSymbols->GetModuleByOffset (ImageBase, 0, NULL, &Base) == S_OK) && (ImageBase == Base)) {
      dprintf ("Module at %llx is already loaded\n", ImageBase);
      continue;
    }

    dprintf ("Loading module at %llx\n", ImageBase);
    if (!ReloadModuleFromPeDebug (ImageBase)) {
      // If ReloadModuleFromPeDebug fails, fall back to .imgscan
      sprintf_s (Command, sizeof (Command), ".imgscan /l /r %I64x (%I64x + 0xFFF)", ImageBase, ImageBase);
      g_ExtControl->Execute (
                      DEBUG_OUTCTL_ALL_CLIENTS,
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
  HRESULT  Result;
  ULONG64  SystemPtrAddr;
  ULONG64  SystemTableAddr;
  ULONG64  Signature            = 0;
  ULONG    BytesRead            = 0;
  ULONG64  SystemTableSignature = (('I') | (static_cast<ULONG64>('B') << 8) | (static_cast<ULONG64>('I') << 16) | (static_cast<ULONG64>(' ') << 24) | (static_cast<ULONG64>('S') << 32) | (static_cast<ULONG64>('Y') << 40) | (static_cast<ULONG64>('S') << 48) | (static_cast<ULONG64>('T') << 56));
  PSTR     Response;

  INIT_API ();

  if ((gUefiEnv != DXE) && (gUefiEnv != RUST)) {
    dprintf ("Only supported for DXE and Rust!\n");
    return ERROR_NOT_SUPPORTED;
  }

  //
  // First find the current module. We only do this to see if we are in the core to find the system table pointer
  // symbols. If we are not in the core, we will ask the monitor for the system table pointer address, failing that
  // we will scan memory for the EFI_SYSTEM_TABLE_SIGNATURE, per UEFI spec. The C DXE environment does not have the
  // monitor command, so relies on the core symbols having been loaded at the initial breakpoint (or us being broken
  // into the core now)
  //

  FindModuleBackwards (GetExpression ("@$ip"));

  g_ExtControl->Execute (
                  DEBUG_OUTCTL_ALL_CLIENTS,
                  "ld *ore*",
                  DEBUG_EXECUTE_DEFAULT
                  );

  //
  // Find the system table pointer, which we may not find if we are not in the core module
  //

  if (gUefiEnv == DXE) {
    SystemPtrAddr = GetExpression ("mDebugTable");
    if (!ReadPointer (SystemPtrAddr, &SystemPtrAddr)) {
      dprintf ("Failed to read memory at %llx to get system table from ptr\n", SystemPtrAddr);
      return ERROR_NOT_FOUND;
    }
  } else if (gUefiEnv == RUST) {
    Response      = MonitorCommandWithOutput (Client, "system_table_ptr", 0);
    SystemPtrAddr = strtoull (Response, NULL, 16);

    if (SystemPtrAddr == 0) {
      // if we didn't get the monitor command response, we will try to read the system table pointer from the core
      // which may work, if we already have loaded the core symbols. If not, we will fail gracefully. This would be the
      // case for the QEMU debugger, where we don't have the monitor command available, but we do have the
      // system table pointer symbols loaded.
      SystemPtrAddr = GetExpression ("patina_dxe_core::config_tables::debug_image_info_table::DBG_SYSTEM_TABLE_POINTER_ADDRESS");
      if (!ReadPointer (SystemPtrAddr, &SystemPtrAddr)) {
        dprintf ("Failed to read memory at %llx to get system table from ptr\n", SystemPtrAddr);
        return ERROR_NOT_FOUND;
      }
    }
  }

  if (SystemPtrAddr == NULL) {
    // TODO: Add a flag to indicate whether we should scan memory for the system table pointer and then make the
    // scanning better, maybe binary search (though has issues). For now, C DXE has parity with before, Rust has
    // two cases, we don't have the monitor command yet, but that is only true at the initial breakpoint (gets set up
    // very soon after that, before other modules are loaded, so we have already succeeded) or we are in an older Rust
    // core that doesn't support the monitor command
    return ERROR_NOT_FOUND;

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
    if (!ReadPointer (SystemPtrAddr, &Signature)) {
      dprintf ("Failed to read memory at %llx to get system table signature\n", SystemPtrAddr);
      return ERROR_NOT_FOUND;
    }

    if (Signature != SystemTableSignature) {
      dprintf ("Couldn't find EFI_SYSTEM_TABLE_SIGNATURE %llx at %llx, found %llx instead\n", SystemTableSignature, SystemPtrAddr, Signature);
      return ERROR_NOT_FOUND;
    }
  }

  // move past the signature to get the EFI_SYSTEM_TABLE structure
  SystemPtrAddr += sizeof (UINT64);

  if (!ReadPointer (SystemPtrAddr, &SystemTableAddr)) {
    dprintf ("Failed to find the system table!\n");
    return ERROR_NOT_FOUND;
  }

  //
  // Load all the other modules.
  //

  Result = loadmodules (SystemTableAddr);

  EXIT_API ();
  return S_OK;
}

#pragma pack (push, 1)
typedef struct _ELF_HEADER_64 {
  unsigned char    e_ident[16]; // 0x74 + ELF
  UINT16           e_type;
  UINT16           e_machine;
  UINT32           e_version;
  UINT64           e_entry;
  UINT64           e_phoff;
  UINT64           e_shoff;
  UINT32           e_flags;
  UINT16           e_ehsize;
  UINT16           e_phentsize;
  UINT16           e_phnum;
  UINT16           e_shentsize;
  UINT16           e_shnum;
  UINT16           e_shstrndx;
} ELF_HEADER_64;
C_ASSERT (sizeof (ELF_HEADER_64) == 64);

typedef struct _ELF_SECTION_64 {
  UINT32    sh_name;
  UINT16    e_type;
  UINT16    e_machine;
  UINT32    e_version;
  UINT64    e_entry;
  UINT64    e_phoff;
  UINT64    e_shoff;
  UINT32    e_flags;
  UINT16    e_ehsize;
  UINT16    e_phentsize;
  UINT16    e_phnum;
  UINT16    e_shentsize;
  UINT16    e_shnum;
  UINT16    e_shstrndx;
} ELF_SECTION_64;

#pragma pack (pop)

HRESULT CALLBACK
elf (
  PDEBUG_CLIENT4  Client,
  PCSTR           args
  )
{
  ULONG64         Address;
  ELF_HEADER_64   Header = { 0 };
  ELF_SECTION_64  *Section;
  ULONG           BytesRead = 0;

  INIT_API ();

  if (strlen (args) == 0) {
    dprintf ("Usage: !uefiext.elf [Address]\n");
    return ERROR_INVALID_PARAMETER;
  }

  Address = GetExpression (args);
  if ((Address == 0) || (Address == (-1))) {
    dprintf ("Invalid address!\n");
    dprintf ("Usage: !uefiext.elf [Address]\n");
    return ERROR_INVALID_PARAMETER;
  }

  ReadMemory (Address, &Header, sizeof (Header), &BytesRead);
  if (BytesRead != sizeof (Header)) {
    dprintf ("Failed to read header!\n");
    return ERROR_BAD_ARGUMENTS;
  }

  if ((Header.e_ident[0] != 0x7F) || (Header.e_ident[1] != 'E') || (Header.e_ident[2] != 'L') || (Header.e_ident[3] != 'F')) {
    dprintf ("Invalid ELF header! Magic did not match.\n");
    return ERROR_INVALID_DATA;
  }

  dprintf ("ELF Header @ %llx\n", Address);
  dprintf ("------------------------------------\n");
  dprintf ("Type                     0x%x\n", Header.e_type);
  dprintf ("Machine                  0x%x\n", Header.e_machine);
  dprintf ("Version                  0x%x\n", Header.e_version);
  dprintf ("Entry                    0x%llx\n", Header.e_entry);
  dprintf ("Program Table Offset     0x%llx\n", Header.e_phoff);
  dprintf ("Section Table Offset     0x%llx\n", Header.e_shoff);
  dprintf ("Flags                    0x%x\n", Header.e_flags);
  dprintf ("Header Size              0x%x\n", Header.e_ehsize);
  dprintf ("Program Header Size      0x%x\n", Header.e_phentsize);
  dprintf ("Program Header Num       0x%x\n", Header.e_phnum);
  dprintf ("Section Header Size      0x%x\n", Header.e_shentsize);
  dprintf ("Section Header Num       0x%x\n", Header.e_shnum);
  dprintf ("Section Names Index      0x%x\n", Header.e_shstrndx);
  dprintf ("------------------------------------\n\n");

  // Print sections.
  Section = (ELF_SECTION_64 *)(Address + Header.e_phoff);

  EXIT_API ();
  return S_OK;
}
