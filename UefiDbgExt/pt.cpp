#include "uefiext.h"

#define FLAG_IGNORE_SELFMAP  0x1

#define INVALID_PFN  (~0ULL)

//
// ---------------------------------------------------------- AMD64 Definitions
//

#define X64_PAGE_SHIFT  12

#define PTE_PER_PAGE_X64  512
#define PDE_PER_PAGE_X64  512
#define PPE_PER_PAGE_X64  512
#define PXE_PER_PAGE_X64  512
#define PLE_PER_PAGE_X64  512

#define PTI_SHIFT_X64  12
#define PDI_SHIFT_X64  21
#define PPI_SHIFT_X64  30
#define PXI_SHIFT_X64  39
#define PLI_SHIFT_X64  48

#define PTI_MASK_X64  (PTE_PER_PAGE_X64 - 1)
#define PDI_MASK_X64  (PDE_PER_PAGE_X64 - 1)
#define PPI_MASK_X64  (PPE_PER_PAGE_X64 - 1)
#define PXI_MASK_X64  (PXE_PER_PAGE_X64 - 1)
#define PLI_MASK_X64  (PLE_PER_PAGE_X64 - 1)

#define GetPleOffsetX64(va)  ((ULONG)(((ULONG64)(va) >> PLI_SHIFT_X64) & PLI_MASK_X64))
#define GetPxeOffsetX64(va)  ((ULONG)(((ULONG64)(va) >> PXI_SHIFT_X64) & PXI_MASK_X64))
#define GetPpeOffsetX64(va)  ((ULONG)(((ULONG64)(va) >> PPI_SHIFT_X64) & PPI_MASK_X64))
#define GetPdeOffsetX64(va)  ((ULONG)(((ULONG64)(va) >> PDI_SHIFT_X64) & PDI_MASK_X64))
#define GetPteOffsetX64(va)  ((ULONG)(((ULONG64)(va) >> PTI_SHIFT_X64) & PTI_MASK_X64))

typedef struct _HARDWARE_PTE_X64 {
  union {
    struct {
      ULONG64    Valid           : 1;
      ULONG64    Write           : 1;
      ULONG64    Owner           : 1;
      ULONG64    WriteThrough    : 1;
      ULONG64    CacheDisable    : 1;
      ULONG64    Accessed        : 1;
      ULONG64    Dirty           : 1;
      ULONG64    LargePage       : 1;
      ULONG64    Global          : 1;
      ULONG64    reserved0       : 3;
      ULONG64    PageFrameNumber : 40;
      ULONG64    reserved1       : 11;
      ULONG64    NoExecute       : 1;
    };

    ULONG64    AsULong64;
  };
} HARDWARE_PTE_X64, *PHARDWARE_PTE_X64;

#define PTE_SHIFT_X64          3
#define TABLE_DECODE_BITS_X64  9
#define VA_BITS_X64(LEVELS)  ((LEVELS) == 5 ? 57 : 48)
#define VA_MASK_X64(LEVELS)  (((ULONG64)1 << VA_BITS_X64(LEVELS)) - 1)

#undef PTI_SHIFT
#define PTI_SHIFT(LEVELS)  (X64_PAGE_SHIFT + TABLE_DECODE_BITS_X64 * (LEVELS))

//
// ---------------------------------------------------------- ARM64 Definitions
//

#define ARM64_PAGE_SHIFT  12

#define PTE_PER_PAGE_ARM64  512
#define PDE_PER_PAGE_ARM64  512
#define PPE_PER_PAGE_ARM64  512
#define PXE_PER_PAGE_ARM64  512

#define PTE_SHIFT_ARM64  3
#define PTI_SHIFT_ARM64  12
#define PDI_SHIFT_ARM64  21
#define PPI_SHIFT_ARM64  30
#define PXI_SHIFT_ARM64  39

#define PPI_MASK_ARM64  (PPE_PER_PAGE_ARM64 - 1)
#define PXI_MASK_ARM64  (PXE_PER_PAGE_ARM64 - 1)

#define GetPxeOffsetARM64(va)  ((ULONG)(((ULONG64)(va) >> PXI_SHIFT_ARM64) & PXI_MASK_ARM64))
#define GetPpeOffsetARM64(va)  ((ULONG)(((ULONG64)(va) >> PPI_SHIFT_ARM64) & PPI_MASK_ARM64))
#define GetPdeOffsetARM64(va)  ((ULONG)(((ULONG64)(va) >> PDI_SHIFT_ARM64) & (PDE_PER_PAGE_ARM64 - 1)))
#define GetPteOffsetARM64(va)  ((ULONG)(((ULONG64)(va) >> PTI_SHIFT_ARM64) & (PTE_PER_PAGE_ARM64 - 1)))

#define VA_BITS_ARM64  48
#define VA_MASK_ARM64  (((ULONG64)1 << VA_BITS_ARM64) - 1)

#define ARM64_TCR_T0SZ_MASK   0x3f
#define ARM64_TCR_T1SZ_MASK   0x00000000003f0000ULL
#define ARM64_TCR_T0SZ_SHIFT  0
#define ARM64_TCR_T1SZ_SHIFT  16
#define ARM64_TCR_TG1_MASK    0x00000000c0000000ULL
#define ARM64_TCR_TG0_MASK    0x000000000000c000ULL

typedef struct _HARDWARE_PTE_ARM64 {
  union {
    struct {
      ULONGLONG    Valid               : 1;
      ULONGLONG    NotLargePage        : 1;     // ARM Large page bit is inverted !
      ULONGLONG    CacheType           : 3;     // Lower 2 bits for cache type encoding
      ULONGLONG    NonSecure           : 1;
      ULONGLONG    AccessPermissions   : 2;
      ULONGLONG    Shareability        : 2;
      ULONGLONG    Accessed            : 1;
      ULONGLONG    NonGlobal           : 1;
      ULONGLONG    PageFrameNumber     : 38;
      ULONGLONG    GuardedPage         : 1;
      ULONGLONG    DirtyBitModifer     : 1;
      ULONGLONG    ContiguousBit       : 1;
      ULONGLONG    PrivilegedNoExecute : 1;
      ULONGLONG    UserNoExecute       : 1;
      ULONGLONG    Reserved            : 4;
      ULONGLONG    PxnTable            : 1;
      ULONGLONG    UxnTable            : 1;
      ULONGLONG    ApTable             : 2;
      ULONGLONG    NsTable             : 1;
    };

    ULONG64    AsULong64;
  };
} HARDWARE_PTE_ARM64, *PHARDWARE_PTE_ARM64;

/*

Attr<n>[7:4] Meaning
0000              Device memory. See encoding of Attr<n>[3:0] for the type of Device memory.
00RW, RW not 00   Normal memory, Outer Write-Through Transient
0100              Normal memory, Outer Non-cacheable
01RW, RW not 00   Normal memory, Outer Write-Back Transient
10RW              Normal memory, Outer Write-Through Non-transient
11RW              Normal memory, Outer Write-Back Non-transient

Attr<n>[3:0] Meaning when Attr<n>[7:4] is 0000              Meaning when Attr<n>[7:4] is not 0000
0000              Device-nGnRnE memory                        UNPREDICTABLE
00RW, RW not 00   UNPREDICTABLE                               Normal Memory, Inner Write-through transient
0100              Device-nGnRE memory                         Normal memory, Inner Non-cacheable
01RW, RW not 00   UNPREDICTABLE                               Normal Memory, Inner Write-back transient
1000              Device-nGRE memory                          Normal Memory, Inner Write-through non-transient (RW=00)
10RW, RW not 00   UNPREDICTABLE                               Normal Memory, Inner Write-through non-transient
1100              Device-GRE memory                           Normal Memory, Inner Write-back non-transient (RW=00)
11RW, RW not 00   UNPREDICTABLE                               Normal Memory, Inner Write-back non-transient

*/

typedef struct _MAIR_ATTR {
  UINT8    Attribute;
  PCSTR    Description;
} MAIR_ATTR, *PMAIR_ATTR;

#define UNPREDICTABLE_MEMORY                       "UNPREDICTABLE"
#define DEVICE_MEMORY                              "Device memory"
#define NORMAL_MEMORY_WRITE_THROUGH_TRANSIENT      "Write-Through Transient"
#define NORMAL_MEMORY_NON_CACHABLE                 "Non-cacheable"
#define NORMAL_MEMORY_WRITE_BACK_TRANSIENT         "Write-Back Transient"
#define NORMAL_MEMORY_WRITE_THROUGH_NON_TRANSIENT  "Write-Through Non-transient"
#define NORMAL_MEMORY_WRITE_BACK_NON_TRANSIENT     "Write-Back Non-transient"

#define MAKE_ATTR(_a, _b)  ((_a << 2) | _b)

//
// Outer Attributes
//

MAIR_ATTR  MairAttr7_4[] = {
  { MAKE_ATTR (0x0, 0x0), DEVICE_MEMORY                             },
  { MAKE_ATTR (0x0, 0x1), NORMAL_MEMORY_WRITE_THROUGH_TRANSIENT     },
  { MAKE_ATTR (0x0, 0x2), NORMAL_MEMORY_WRITE_THROUGH_TRANSIENT     },
  { MAKE_ATTR (0x0, 0x3), NORMAL_MEMORY_WRITE_THROUGH_TRANSIENT     },
  { MAKE_ATTR (0x1, 0x0), NORMAL_MEMORY_NON_CACHABLE                },
  { MAKE_ATTR (0x1, 0x1), NORMAL_MEMORY_WRITE_BACK_TRANSIENT        },
  { MAKE_ATTR (0x1, 0x2), NORMAL_MEMORY_WRITE_BACK_TRANSIENT        },
  { MAKE_ATTR (0x1, 0x3), NORMAL_MEMORY_WRITE_BACK_TRANSIENT        },
  { MAKE_ATTR (0x2, 0x0), NORMAL_MEMORY_WRITE_THROUGH_NON_TRANSIENT },
  { MAKE_ATTR (0x2, 0x1), NORMAL_MEMORY_WRITE_THROUGH_NON_TRANSIENT },
  { MAKE_ATTR (0x2, 0x2), NORMAL_MEMORY_WRITE_THROUGH_NON_TRANSIENT },
  { MAKE_ATTR (0x2, 0x3), NORMAL_MEMORY_WRITE_THROUGH_NON_TRANSIENT },
  { MAKE_ATTR (0x3, 0x0), NORMAL_MEMORY_WRITE_BACK_NON_TRANSIENT    },
  { MAKE_ATTR (0x3, 0x1), NORMAL_MEMORY_WRITE_BACK_NON_TRANSIENT    },
  { MAKE_ATTR (0x3, 0x2), NORMAL_MEMORY_WRITE_BACK_NON_TRANSIENT    },
  { MAKE_ATTR (0x3, 0x3), NORMAL_MEMORY_WRITE_BACK_NON_TRANSIENT    }
};

//
// Inner attributes.
//

MAIR_ATTR  MairAttr3_0[] = {
  { MAKE_ATTR (0x0, 0x0), UNPREDICTABLE_MEMORY                      },
  { MAKE_ATTR (0x0, 0x1), NORMAL_MEMORY_WRITE_THROUGH_TRANSIENT     },
  { MAKE_ATTR (0x0, 0x2), NORMAL_MEMORY_WRITE_THROUGH_TRANSIENT     },
  { MAKE_ATTR (0x0, 0x3), NORMAL_MEMORY_WRITE_THROUGH_TRANSIENT     },
  { MAKE_ATTR (0x1, 0x0), NORMAL_MEMORY_NON_CACHABLE                },
  { MAKE_ATTR (0x1, 0x1), NORMAL_MEMORY_WRITE_BACK_TRANSIENT        },
  { MAKE_ATTR (0x1, 0x2), NORMAL_MEMORY_WRITE_BACK_TRANSIENT        },
  { MAKE_ATTR (0x1, 0x3), NORMAL_MEMORY_WRITE_BACK_TRANSIENT        },
  { MAKE_ATTR (0x2, 0x0), NORMAL_MEMORY_WRITE_THROUGH_NON_TRANSIENT },
  { MAKE_ATTR (0x2, 0x1), NORMAL_MEMORY_WRITE_THROUGH_NON_TRANSIENT },
  { MAKE_ATTR (0x2, 0x2), NORMAL_MEMORY_WRITE_THROUGH_NON_TRANSIENT },
  { MAKE_ATTR (0x2, 0x3), NORMAL_MEMORY_WRITE_THROUGH_NON_TRANSIENT },
  { MAKE_ATTR (0x3, 0x0), NORMAL_MEMORY_WRITE_BACK_NON_TRANSIENT    },
  { MAKE_ATTR (0x3, 0x1), NORMAL_MEMORY_WRITE_BACK_NON_TRANSIENT    },
  { MAKE_ATTR (0x3, 0x2), NORMAL_MEMORY_WRITE_BACK_NON_TRANSIENT    },
  { MAKE_ATTR (0x3, 0x3), NORMAL_MEMORY_WRITE_BACK_NON_TRANSIENT    }
};

MAIR_ATTR  MairAttr3_0_DeviceMemory[] = {
  { MAKE_ATTR (0x0, 0x0), "Device-nGnRnE" },
  { MAKE_ATTR (0x1, 0x0), "Device-nGnRE"  },
  { MAKE_ATTR (0x2, 0x0), "Device-nGRE"   },
  { MAKE_ATTR (0x3, 0x0), "Device-GRE"    },
};

//
// ---------------------------------------------------------- Utility Functions
//

std::string
GetArm64SharabilityForPte (
  _In_ PHARDWARE_PTE_ARM64  Pte,
  _In_ ULONG                Level
  )
{
  UCHAR  Sharability;
  PCSTR  Description;

  UNREFERENCED_PARAMETER (Level);

  Sharability = Pte->Shareability;

  switch (Sharability) {
    case 0:
      Description = "None";
      break;
    case 2:
      Description = "Outer";
      break;
    case 3:
      Description = "Inner";
      break;
    default:
      Description = "Reserved";
      break;
  }

  return Format ("%s", Description);
}

BOOLEAN
IsPageWritable (
  _In_ PHARDWARE_PTE_ARM64  Pte
  )
{
  // Read Only sets this field to 2
  return (BOOLEAN)Pte->AccessPermissions == 0x0;
}

template<class T>
VOID
DisplayPte (
  __in T      Pte,
  __in ULONG  Level = -1
  )
{
  dprintf ("Contains %016I64x ", Pte->AsULong64);
  dprintf (
    " %c%c%c%c%c%c%c%c%c%c",
    Pte->Global ? 'G' : '-',
    Pte->LargePage ? 'L' : '-',
    Pte->Dirty ? 'D' : '-',
    Pte->Accessed ? 'A' : '-',
    Pte->CacheDisable ? 'N' : '-',
    Pte->WriteThrough ? 'T' : '-',
    Pte->Owner ? 'U' : 'K',
    Pte->Write ? 'W' : 'R',
    Pte->NoExecute ? '-' : 'E',
    Pte->Valid ? 'V' : '-'
    );
}

VOID
DisplayPte (
  __in PHARDWARE_PTE_ARM64  Pte,
  __in ULONG                Level = -1
  )
{
  dprintf ("Contains %016I64x ", Pte->AsULong64);
  dprintf (
    " %c%c%c%c%c%c%c%c",

    Pte->NonGlobal ? '_' : 'G',
    Pte->NotLargePage ? '_' : 'L',
    IsPageWritable (Pte) ? 'W' : 'R',
    '_',
    '_',
    Pte->Accessed ? 'A' : '_',
    Pte->UserNoExecute ? 'X' : 'E', // In the EL2 translation scheme UXN is the XN bit and is the only execute permission bit
    Pte->Valid ? 'V' : '-'
    );

  dprintf (" Share: %s", GetArm64SharabilityForPte (Pte, Level).c_str ());
}

VOID
DisplayHardwarePte (
  __in PSTR     Name,
  __in ULONG64  Address,
  __in BOOLEAN  Virtual         = FALSE,
  __in ULONG64  PhysicalAddress = (ULONG64)-1,
  __in ULONG64  TableAddress    = (ULONG64)-1
  )
{
  PrintDml (Normal, " %3s @ ", Name);

  if (Virtual == FALSE) {
    PrintDml (
      Normal,
      "#"
      "<exec cmd=\"!uefiext.pt %s\">"
      "%s</exec> ",
      FormatAddress (Address).c_str (),
      FormatAddress (Address).c_str ()
      );
  } else {
    std::string  SetBreakPoint = Format (
                                   "<altlink name=\"BreakOnWrite\" cmd=\"ba w4 %s;ba w4 %s\">",
                                   FormatAddress (Address).c_str (),
                                   FormatAddress (Address + 4).c_str ()
                                   );

    PrintDml (
      Normal,
      " "
      "<exec cmd=\"!uefiext.pt %s\">%s"
      "%s</exec> ",
      FormatAddress (Address).c_str (),
      SetBreakPoint.c_str (),
      FormatAddress (Address).c_str ()
      );

    // print the PA at the entry, not the start of the table
    ULONG64 Offset = Address & 0xFFF;

    PrintDml (
      Normal,
      " PA %s ",
      FormatAddress (TableAddress + Offset).c_str ()
      );
  }
}

template<class T>
BOOLEAN
IsLargePage (
  __in T  Pte
  )
{
  return (Pte->LargePage != 0);
}

BOOLEAN
IsLargePage (
  __in PHARDWARE_PTE_ARM64  Pte
  )
{
  return (Pte->NotLargePage == 0);
}

ULONG64
GetCr3Value (
  VOID
  )
{
  return GetRegisterValue ("cr3");
}

ULONG
GetCr0Value (
  VOID
  )
{
  return (ULONG)GetRegisterValue ("cr0");
}

ULONG
GetPageTableLevels (
  _In_ ULONG  TargetMachine
  )
{
  ULONG    Cr0;
  ULONG    PagingLevels;
  ULONG64  PhysicalAddress;

  PagingLevels    = 0;
  PhysicalAddress = 0;
  switch (TargetMachine) {
    case IMAGE_FILE_MACHINE_AMD64:
      //
      // By default, obtain the paging level from the hardware. Follow
      // the recipe for determining whether five-level paging is enabled.
      //

      PagingLevels = 4;
      Cr0          = (ULONG)GetRegisterValue ("cr0");

      // TODO: Refer EFER to determine if 5 level paging
      break;
    case IMAGE_FILE_MACHINE_ARM64:
      PagingLevels = 4;
      VerbOut ("Assuming %d level page table\n", PagingLevels);

      // TODO: Read regs to determine

      break;
  }

  return PagingLevels;
}

BOOLEAN
ParseRegsForReg (
  _In_ PCSTR     Regs,
  _In_ PCSTR     RegName,
  _Out_ ULONG64  *Value
  )
{
  std::string  SearchStr = Format ("%s: ", RegName);
  PCSTR        RegPos    = NULL;

  if (Value == NULL) {
    return FALSE;
  }

  RegPos = strstr (Regs, SearchStr.c_str ());
  if (RegPos != NULL) {
    RegPos += SearchStr.length ();
    *Value  = strtoull (RegPos, NULL, 16);
  }

  return (RegPos != NULL);
}

ULONG64
GetPageTableRoot (
  _In_ PDEBUG_CLIENT4  Client,
  _In_ ULONG64         UserRoot,
  _Out_opt_ PULONG     Levels,
  _Inout_ PULONG64     VirtualAddress = NULL
  )
{
  ULONG64  Root;
  PCSTR    Regs;

  Root = 0;

  if (UserRoot == 0) {
    switch (g_TargetMachine) {
      case IMAGE_FILE_MACHINE_AMD64:
        Root = (GetCr3Value () & ~((1 << 12) - 1));
        break;
      case IMAGE_FILE_MACHINE_ARM64:
      {
        Regs = MonitorCommandWithOutput (Client, Format ("arch regs").c_str (), 0);
        if (ParseRegsForReg (Regs, "ttbr0_el2", &Root)) {
          break;
        }

        dprintf ("Failed to get PageTableRoot from ttbr0_el2 register\n");
        goto Exit;
      }
    }
  } else {
    dprintf ("Using user provider PageTableRoot\n");
    Root = UserRoot;
  }

  if (Levels != NULL) {
    *Levels = GetPageTableLevels (g_TargetMachine);
  }

Exit:
  return Root;
}

template<class T>
BOOLEAN
ReadPte (
  __in ULONG64  Address,
  __out T       *Pte,
  __in BOOLEAN  Virtual = FALSE
  )
{
  ULONG  ByteCount;

  ZeroMemory (Pte, sizeof (*Pte));
  ByteCount = 0;
  if (Virtual == FALSE) {
    ReadPhysical (Address, Pte, sizeof (*Pte), &ByteCount);
  } else {
    ReadMemory (Address, Pte, sizeof (*Pte), &ByteCount);
  }

  if (ByteCount != sizeof (*Pte)) {
    dprintf ("Failed to read %s%p\n", (Virtual ? "" : "#"), Address);
    return FALSE;
  } else {
    return TRUE;
  }
}

VOID
DisplayPhysicalAddress (
  __in ULONG64  PhysicalAddress,
  __in ULONG64  VirtualAddress,
  __in PCSTR    CacheType
  )
{
  PCSTR  OneToOne = "";

  if (PhysicalAddress == VirtualAddress) {
    OneToOne = "- IdentityMapping";
  }

  PrintDml (
    Normal,
    " PA  @ #<exec cmd=\"!uefiext.pt %s\">%s</exec> %s - %s",
    FormatAddress (PhysicalAddress).c_str (),
    FormatAddress (PhysicalAddress).c_str (),
    OneToOne,
    CacheType
    );

  dprintf ("\n");
}

VOID
DisplayRoot (
  __in ULONG64  PhysicalAddress
  )
{
  dprintf ("Root @ #%s\n", FormatAddress (PhysicalAddress).c_str ());
}

#define X64_PTE_BASE(SelfMapIndex)  (0xFFFF000000000000 | (SelfMapIndex << 39))
#define X64_PDE_BASE(SelfMapIndex)  (0xFFFF000000000000 | (SelfMapIndex << 39) | (SelfMapIndex << 30))
#define X64_PPE_BASE(SelfMapIndex)  (0xFFFF000000000000 | (SelfMapIndex << 39) | (SelfMapIndex << 30) | (SelfMapIndex << 21))
#define X64_PXE_BASE(SelfMapIndex)  (0xFFFF000000000000 | (SelfMapIndex << 39) | (SelfMapIndex << 30) | (SelfMapIndex << 21) | (SelfMapIndex << 12))
#define X64_PLE_BASE(SelfMapIndex)  (0xFFFF000000000000 | (SelfMapIndex << 39) | (SelfMapIndex << 30) | (SelfMapIndex << 21) | (SelfMapIndex << 12) | (SelfMapIndex << 3))

ULONG64
GetPteAddressX64 (
  _In_ ULONG64  Va,
  _In_ ULONG    PagingLevels,
  _In_ ULONG64  SelfMapIndex
  )
{
  return (((((ULONG64)(Va) & VA_MASK_X64 (PagingLevels)) >> PTI_SHIFT (0)) << PTE_SHIFT_X64) + X64_PTE_BASE (SelfMapIndex));
}

ULONG64
GetPdeAddressX64 (
  _In_ ULONG64  Va,
  _In_ ULONG    PagingLevels,
  _In_ ULONG64  SelfMapIndex
  )
{
  return (((((ULONG64)(Va) & VA_MASK_X64 (PagingLevels)) >> PTI_SHIFT (1)) << PTE_SHIFT_X64) + X64_PDE_BASE (SelfMapIndex));
}

ULONG64
GetPpeAddressX64 (
  _In_ ULONG64  Va,
  _In_ ULONG    PagingLevels,
  _In_ ULONG64  SelfMapIndex
  )
{
  return (((((ULONG64)(Va) & VA_MASK_X64 (PagingLevels)) >> PTI_SHIFT (2)) << PTE_SHIFT_X64) + X64_PPE_BASE (SelfMapIndex));
}

ULONG64
GetPxeAddressX64 (
  _In_ ULONG64  Va,
  _In_ ULONG    PagingLevels,
  _In_ ULONG64  SelfMapIndex
  )
{
  return (((((ULONG64)(Va) & VA_MASK_X64 (PagingLevels)) >> PTI_SHIFT (3)) << PTE_SHIFT_X64) +  X64_PXE_BASE (SelfMapIndex));
}

ULONG64
GetPleAddressX64 (
  _In_ ULONG64  Va,
  _In_ ULONG    PagingLevels,
  _In_ ULONG64  SelfMapIndex
  )
{
  return (((((ULONG64)(Va) & VA_MASK_X64 (PagingLevels)) >> PTI_SHIFT (4)) << PTE_SHIFT_X64) +  X64_PLE_BASE (SelfMapIndex));
}

VOID
DumpPteX64 (
  __in PDEBUG_CLIENT4  Client,
  __in ULONG64         Address,
  __in ULONG64         UserRoot,
  __in ULONG64         Flags
  )
{
  ULONG             Levels;
  ULONG             PleOffset;
  ULONG             PxeOffset;
  ULONG             PpeOffset;
  ULONG             PdeOffset;
  ULONG             PteOffset;
  ULONG             PageOffset;
  HARDWARE_PTE_X64  Pte;
  ULONG64           PteAddress;
  ULONG64           PhysicalAddress;
  ULONG64           PageFrameIndex;
  ULONG64           SelfMapIndex = 512;
  LONG              TestIndex    = 511;
  ULONG64           TableAddress;
  PCSTR             CacheType;

  //
  // Get page table root and paging levels.
  //

  PhysicalAddress = GetPageTableRoot (Client, UserRoot, &Levels);
  if (PhysicalAddress == 0) {
    dprintf ("PageTableRoot is NULL\n");
    return;
  }

  if ((Levels != 4) && (Levels != 5)) {
    dprintf ("Paging level is invalid for x64: %u\n", Levels);
    return;
  }

  if (Flags & FLAG_IGNORE_SELFMAP) {
    dprintf ("Ignoring self map\n");
  } else {
    // Search backwards for self-mapped PTE.
    //
    for ( ; TestIndex >= 0; TestIndex--) {
      ReadPte (PhysicalAddress + (TestIndex * 8), &Pte);
      if ((Pte.PageFrameNumber << X64_PAGE_SHIFT) == PhysicalAddress) {
        SelfMapIndex = TestIndex;
        dprintf ("Self-mapped PTE found at index 0x%x, using self map\n", SelfMapIndex);
        break;
      }
    }
  }

  PleOffset = 0;
  PxeOffset = GetPxeOffsetX64 (Address);
  PpeOffset = GetPpeOffsetX64 (Address);
  PdeOffset = GetPdeOffsetX64 (Address);
  PteOffset = GetPteOffsetX64 (Address);

  PageOffset = ((ULONG)(Address << 20)) >> 20;

  if (Levels != 5) {
    dprintf (
      "VA: %s %03x %03x %03x %03x %03x\n",
      FormatAddress (Address).c_str (),
      PxeOffset,
      PpeOffset,
      PdeOffset,
      PteOffset,
      PageOffset
      );
  } else {
    PleOffset = GetPleOffsetX64 (Address);
    dprintf (
      "VA: %s %03x %03x %03x %03x %03x %03x\n",
      FormatAddress (Address).c_str (),
      PleOffset,
      PxeOffset,
      PpeOffset,
      PdeOffset,
      PteOffset,
      PageOffset
      );
  }

  // the first PA of the page table is the root
  TableAddress = PhysicalAddress;

  if (SelfMapIndex != 512) {
    if (Levels == 5) {
      PteAddress = GetPleAddressX64 (Address, Levels, SelfMapIndex);
      ReadPte (PteAddress, &Pte, TRUE);
      DisplayHardwarePte ("Ple", PteAddress, TRUE, Pte.PageFrameNumber << X64_PAGE_SHIFT, TableAddress);
      DisplayPte (&Pte, 5);
      dprintf ("\n");
      if (Pte.Valid == 0) {
        dprintf ("PLE Invalid\n");
        return;
      }

      TableAddress = Pte.PageFrameNumber << X64_PAGE_SHIFT;
    }

    PteAddress = GetPxeAddressX64 (Address, Levels, SelfMapIndex);
    ReadPte (PteAddress, &Pte, TRUE);
    // if we have 5 level paging, then physical address here is whatever the PLE PTE points to. If it is 4 level
    // paging, then it is the root of the page table
    DisplayHardwarePte ("Pxe", PteAddress, TRUE, Pte.PageFrameNumber << X64_PAGE_SHIFT, TableAddress);
    DisplayPte (&Pte, 4);
    dprintf ("\n");
    if (Pte.Valid == 0) {
      dprintf ("PXE Invalid\n");
      return;
    }

    TableAddress = Pte.PageFrameNumber << X64_PAGE_SHIFT;

    PteAddress = GetPpeAddressX64 (Address, Levels, SelfMapIndex);
    ReadPte (PteAddress, &Pte, TRUE);
    DisplayHardwarePte ("Ppe", PteAddress, TRUE, Pte.PageFrameNumber << X64_PAGE_SHIFT, TableAddress);
    DisplayPte (&Pte, 3);
    dprintf ("\n");

    TableAddress = Pte.PageFrameNumber << X64_PAGE_SHIFT;

    if (Pte.Valid == 0) {
      dprintf ("PPE Invalid\n");
      return;
    }

    if ((Pte.Valid != 0) &&
        (IsLargePage (&Pte) != FALSE))
    {
      PageFrameIndex = Pte.PageFrameNumber + PdeOffset * 512 + PteOffset;
      dprintf ("HUGE PAGE ");
      dprintf ("\n");
      goto PrintAddress;
    }

    PteAddress = GetPdeAddressX64 (Address, Levels, SelfMapIndex);
    ReadPte (PteAddress, &Pte, TRUE);
    DisplayHardwarePte ("Pde", PteAddress, TRUE, Pte.PageFrameNumber << X64_PAGE_SHIFT, TableAddress);
    DisplayPte (&Pte, 2);
    dprintf ("\n");

    TableAddress = Pte.PageFrameNumber << X64_PAGE_SHIFT;

    if (Pte.Valid == 0) {
      dprintf ("PDE Invalid\n");
      return;
    }

    if ((Pte.Valid != 0) &&
        (IsLargePage (&Pte) != FALSE))
    {
      PageFrameIndex = Pte.PageFrameNumber + PteOffset;
      dprintf ("LARGE PAGE ");
      dprintf ("\n");
      goto PrintAddress;
    }

    PteAddress = GetPteAddressX64 (Address, Levels, SelfMapIndex);
    ReadPte (PteAddress, &Pte, TRUE);
    DisplayHardwarePte ("Pte", PteAddress, TRUE, Pte.PageFrameNumber << X64_PAGE_SHIFT, TableAddress);
    DisplayPte (&Pte, 1);
    dprintf ("\n");

    if (Pte.Valid == 0) {
      dprintf ("PTE Invalid\n");
      return;
    }
  } else {
    DisplayRoot (PhysicalAddress);

    //
    // Get PLE
    //

    if (Levels == 5) {
      PhysicalAddress = PhysicalAddress + PleOffset * sizeof (Pte);
      ReadPte (PhysicalAddress, &Pte);
      DisplayHardwarePte ("Ple", PhysicalAddress);
      DisplayPte (&Pte, 5);
      dprintf ("\n");
      if (Pte.Valid == 0) {
        dprintf ("PLE Invalid\n");
        return;
      }

      PhysicalAddress = Pte.PageFrameNumber << X64_PAGE_SHIFT;
    }

    //
    // Get PXE
    //

    PhysicalAddress = PhysicalAddress + PxeOffset * sizeof (Pte);
    ReadPte (PhysicalAddress, &Pte);

    DisplayHardwarePte ("Pxe", PhysicalAddress);
    DisplayPte (&Pte, 4);
    dprintf ("\n");
    if (Pte.Valid == 0) {
      dprintf ("PXE Invalid\n");
      return;
    }

    //
    // Get PPE
    //

    PhysicalAddress  = Pte.PageFrameNumber << X64_PAGE_SHIFT;
    PhysicalAddress += PpeOffset * sizeof (Pte);

    ReadPte (PhysicalAddress, &Pte);

    DisplayHardwarePte ("Ppe", PhysicalAddress);
    DisplayPte (&Pte, 3);
    dprintf ("\n");
    if (Pte.Valid == 0) {
      dprintf ("PPE Invalid\n");
      return;
    }

    if (IsLargePage (&Pte) != FALSE) {
      PageFrameIndex = Pte.PageFrameNumber + PdeOffset * 512 + PteOffset;
      dprintf ("HUGE PAGE ");
      dprintf ("\n");
      goto PrintAddress;
    }

    //
    // Get PDE
    //

    PhysicalAddress  = Pte.PageFrameNumber << X64_PAGE_SHIFT;
    PhysicalAddress += PdeOffset * sizeof (Pte);

    ReadPte (PhysicalAddress, &Pte);

    DisplayHardwarePte ("Pde", PhysicalAddress);
    DisplayPte (&Pte, 2);
    dprintf ("\n");
    if (Pte.Valid == 0) {
      dprintf ("PDE Invalid\n");
      return;
    }

    if (IsLargePage (&Pte) != FALSE) {
      PageFrameIndex = Pte.PageFrameNumber + PteOffset;
      dprintf ("LARGE PAGE ");
      dprintf ("\n");
      goto PrintAddress;
    }

    //
    // Get PTE
    //

    PhysicalAddress  = Pte.PageFrameNumber << X64_PAGE_SHIFT;
    PhysicalAddress += PteOffset * sizeof (Pte);

    ReadPte (PhysicalAddress, &Pte);

    DisplayHardwarePte ("Pte", PhysicalAddress);
    DisplayPte (&Pte, 1);
    dprintf ("\n");
    if (Pte.Valid == 0) {
      dprintf ("PTE Invalid\n");
      return;
    }
  }

  PageFrameIndex = Pte.PageFrameNumber;

PrintAddress:
  PhysicalAddress  = PageFrameIndex << X64_PAGE_SHIFT;
  PhysicalAddress += PageOffset;

  // Get the cache type from MTRRs
  CacheType = MonitorCommandWithOutput (Client, Format ("arch mtrr %llX", Address).c_str (), 0);

  // if CacheType has spaces in it, it means the monitor command didn't exist
  if (strchr (CacheType, ' ') != NULL) {
    CacheType = "Unknown";
  }

  DisplayPhysicalAddress (PhysicalAddress, Address, CacheType);
  return;
}

// This assumes TTBR0_EL2 only, e.g. EL2 translation scheme
#define ARM64_PTE_BASE(SelfMapIndex)  ((SelfMapIndex << 39))
#define ARM64_PDE_BASE(SelfMapIndex)  ((SelfMapIndex << 39) | (SelfMapIndex << 30))
#define ARM64_PPE_BASE(SelfMapIndex)  ((SelfMapIndex << 39) | (SelfMapIndex << 30) | (SelfMapIndex << 21))
#define ARM64_PXE_BASE(SelfMapIndex)  ((SelfMapIndex << 39) | (SelfMapIndex << 30) | (SelfMapIndex << 21) | (SelfMapIndex << 12))

ULONG64
GetPteAddressARM64 (
  _In_ ULONG64  Va,
  _In_ ULONG64  SelfMapIndex,
  _In_ ULONG    PagingLevels = 4
  )
{
  UNREFERENCED_PARAMETER (PagingLevels);

  return (((((ULONG64)(Va) & VA_MASK_ARM64) >> PTI_SHIFT (0)) << PTE_SHIFT_ARM64) +  ARM64_PTE_BASE (SelfMapIndex));
}

ULONG64
GetPdeAddressARM64 (
  _In_ ULONG64  Va,
  _In_ ULONG64  SelfMapIndex,
  _In_ ULONG    PagingLevels = 4
  )
{
  UNREFERENCED_PARAMETER (PagingLevels);

  return (((((ULONG64)(Va) & VA_MASK_ARM64) >> PTI_SHIFT (1)) << PTE_SHIFT_ARM64) + ARM64_PDE_BASE (SelfMapIndex));
}

ULONG64
GetPpeAddressARM64 (
  _In_ ULONG64  Va,
  _In_ ULONG64  SelfMapIndex,
  _In_ ULONG    PagingLevels = 4
  )
{
  UNREFERENCED_PARAMETER (PagingLevels);

  return (((((ULONG64)(Va) & VA_MASK_ARM64) >> PTI_SHIFT (2)) << PTE_SHIFT_ARM64) + ARM64_PPE_BASE (SelfMapIndex));
}

ULONG64
GetPxeAddressARM64 (
  _In_ ULONG64  Va,
  _In_ ULONG64  SelfMapIndex,
  _In_ ULONG    PagingLevels = 4
  )
{
  UNREFERENCED_PARAMETER (PagingLevels);

  return (((((ULONG64)(Va) & VA_MASK_ARM64) >> PTI_SHIFT (3)) << PTE_SHIFT_ARM64) +  ARM64_PXE_BASE (SelfMapIndex));
}

std::string
GetCacheTypeFromMair (
  _In_ ULONG64  MairReg,
  _In_ ULONG    CacheIndex
  )
{
  PCSTR        InnerDescription;
  PCSTR        OuterDescription;
  PCSTR        Description;
  UINT8        Attr7_4;
  UINT8        Attr3_0;
  UINT8        Mair;
  std::string  MemoryType;

  InnerDescription = UNPREDICTABLE_MEMORY;
  OuterDescription = UNPREDICTABLE_MEMORY;
  Description      = UNPREDICTABLE_MEMORY;

  Mair = (UINT8)((MairReg >> (CacheIndex * 8)) & 0xFF);

  Attr7_4 = (Mair & 0xF0) >> 4;
  Attr3_0 = (Mair & 0x0F);

  //
  // If Attr[7:4] is 0, decode device memory types, othervice decode normal memory types.
  //

  if (Attr7_4 == 0) {
    for (auto Index = 0UL; Index < RTL_NUMBER_OF (MairAttr3_0_DeviceMemory); Index += 1) {
      if (Attr3_0 == MairAttr3_0_DeviceMemory[Index].Attribute) {
        Description = MairAttr3_0_DeviceMemory[Index].Description;
      }
    }

    MemoryType = Format ("%s", Description);
  } else {
    //
    // Check for UNPREDICTABLE memory type.
    //

    if (Attr3_0 == 0) {
      MemoryType = Format ("%s", Description);
      goto Exit;
    }

    //
    // Decode Outer Attributes
    //

    for (auto Index = 0UL; Index < RTL_NUMBER_OF (MairAttr7_4); Index += 1) {
      if (Attr7_4 == MairAttr7_4[Index].Attribute) {
        OuterDescription = MairAttr7_4[Index].Description;
      }
    }

    //
    // Decode Inner Attributes
    //

    for (auto Index = 0UL; Index < RTL_NUMBER_OF (MairAttr3_0); Index += 1) {
      if (Attr3_0 == MairAttr3_0[Index].Attribute) {
        InnerDescription = MairAttr3_0[Index].Description;
      }
    }

    MemoryType = Format ("O:%s:I:%s", OuterDescription, InnerDescription);
  }

Exit:
  return MemoryType;
}

VOID
DumpPteArm64 (
  __in PDEBUG_CLIENT4  Client,
  __in ULONG64         Address,
  __in ULONG64         UserRoot,
  __in ULONG64         Flags
  )
{
  ULONG               PxeOffset;
  ULONG               PpeOffset;
  ULONG               PdeOffset;
  ULONG               PteOffset;
  ULONG               PageOffset;
  HARDWARE_PTE_ARM64  Pte;
  ULONG64             PhysicalAddress;
  ULONG64             PageFrameIndex;
  ULONG64             PteAddress;
  ULONG               PagingLevels;
  std::string         AddressStr;
  ULONG64             SelfMapIndex = 512;
  LONG                TestIndex    = 511;
  ULONG64             TableAddress;
  PCSTR               Regs;
  std::string         CacheTypeStr = "Unknown";
  PCSTR               CacheType    = "Unknown";
  ULONG               CacheIndex;
  ULONG64             Mair;

  AddressStr = FormatAddress (Address);

  //
  // Get page table root.
  //

  PhysicalAddress = GetPageTableRoot (Client, UserRoot, &PagingLevels, &Address);
  PxeOffset       = GetPxeOffsetARM64 (Address);
  PpeOffset       = GetPpeOffsetARM64 (Address);
  PdeOffset       = GetPdeOffsetARM64 (Address);
  PteOffset       = GetPteOffsetARM64 (Address);
  PageOffset      = ((ULONG)(Address << 20)) >> 20;

  dprintf (
    "VA: %s %03x %03x %03x %03x %03x\n",
    AddressStr.c_str (),
    PxeOffset,
    PpeOffset,
    PdeOffset,
    PteOffset,
    PageOffset
    );

  if (PhysicalAddress == 0) {
    dprintf ("PageTableRoot is NULL\n");
    return;
  }

  // the first PA of the page table is the root
  TableAddress = PhysicalAddress;

  if (Flags & FLAG_IGNORE_SELFMAP) {
    dprintf ("Ignoring self map\n");
  } else {
    //
    // Search backwards for self-mapped PTE.
    //
    for ( ; TestIndex >= 0; TestIndex--) {
      ReadPte (PhysicalAddress + (TestIndex * 8), &Pte);
      if ((Pte.PageFrameNumber << ARM64_PAGE_SHIFT) == PhysicalAddress) {
        SelfMapIndex = TestIndex;
        dprintf ("Self-mapped PTE found at index 0x%x, using self map\n", SelfMapIndex);
        break;
      }
    }
  }

  if (SelfMapIndex != 512) {
    PteAddress = GetPxeAddressARM64 (Address, SelfMapIndex);
    ReadPte (PteAddress, &Pte);
    DisplayHardwarePte ("Pxe", PteAddress, TRUE, Pte.PageFrameNumber << ARM64_PAGE_SHIFT, TableAddress);
    DisplayPte (&Pte, 4);
    dprintf ("\n");
    TableAddress = Pte.PageFrameNumber << ARM64_PAGE_SHIFT;
    if (Pte.Valid == 0) {
      dprintf ("PXE Invalid\n");
      return;
    }

    PteAddress = GetPpeAddressARM64 (Address, SelfMapIndex);
    ReadPte (PteAddress, &Pte);
    DisplayHardwarePte ("Ppe", PteAddress, TRUE, Pte.PageFrameNumber << ARM64_PAGE_SHIFT, TableAddress);
    DisplayPte (&Pte, 3);
    dprintf ("\n");
    TableAddress = Pte.PageFrameNumber << ARM64_PAGE_SHIFT;
    if (Pte.Valid == 0) {
      dprintf ("PPE Invalid\n");
      return;
    }

    if ((Pte.Valid != 0) &&
        (IsLargePage (&Pte) != FALSE))
    {
      PageFrameIndex = Pte.PageFrameNumber + PdeOffset * 512 + PteOffset;
      CacheIndex     = Pte.CacheType;
      dprintf ("HUGE PAGE ");
      dprintf ("\n");
      goto PrintAddress;
    }

    PteAddress = GetPdeAddressARM64 (Address, SelfMapIndex);
    ReadPte (PteAddress, &Pte);
    DisplayHardwarePte ("Pde", PteAddress, TRUE, Pte.PageFrameNumber << ARM64_PAGE_SHIFT, TableAddress);
    DisplayPte (&Pte, 2);
    dprintf ("\n");
    TableAddress = Pte.PageFrameNumber << ARM64_PAGE_SHIFT;
    if (Pte.Valid == 0) {
      dprintf ("PDE Invalid\n");
      return;
    }

    if ((Pte.Valid != 0) &&
        (IsLargePage (&Pte) != FALSE))
    {
      PageFrameIndex = Pte.PageFrameNumber + PteOffset;
      CacheIndex     = Pte.CacheType;
      dprintf ("LARGE PAGE ");
      dprintf ("\n");
      goto PrintAddress;
    }

    PteAddress = GetPteAddressARM64 (Address, SelfMapIndex);
    ReadPte (PteAddress, &Pte);
    DisplayHardwarePte ("Pte", PteAddress, TRUE, Pte.PageFrameNumber << ARM64_PAGE_SHIFT, TableAddress);
    DisplayPte (&Pte, 1);
    CacheIndex = Pte.CacheType;
    dprintf ("\n");

    if (Pte.Valid == 0) {
      dprintf ("PTE Invalid\n");
      return;
    }
  } else {
    DisplayRoot (PhysicalAddress);

    //
    // Get PXE
    //

    if (PagingLevels >= 4) {
      PhysicalAddress = PhysicalAddress + PxeOffset * sizeof (Pte);
      ReadPte (PhysicalAddress, &Pte);
      DisplayHardwarePte ("Pxe", PhysicalAddress);
      DisplayPte (&Pte);
      dprintf ("\n");
      if (Pte.Valid == 0) {
        dprintf ("PXE Invalid\n");
        return;
      }

      PhysicalAddress = Pte.PageFrameNumber << ARM64_PAGE_SHIFT;
    }

    //
    // Get PPE
    //

    PhysicalAddress += PpeOffset * sizeof (Pte);
    ReadPte (PhysicalAddress, &Pte);
    DisplayHardwarePte ("Ppe", PhysicalAddress);
    DisplayPte (&Pte);
    dprintf ("\n");
    if (Pte.Valid == 0) {
      dprintf ("PPE Invalid\n");
      return;
    }

    if (IsLargePage (&Pte) != FALSE) {
      PageFrameIndex = Pte.PageFrameNumber + PdeOffset * 512 + PteOffset;
      CacheIndex     = Pte.CacheType;
      dprintf ("HUGE PAGE ");
      dprintf ("\n");
      goto PrintAddress;
    }

    //
    // Get PDE
    //

    PhysicalAddress  = Pte.PageFrameNumber << ARM64_PAGE_SHIFT;
    PhysicalAddress += PdeOffset * sizeof (Pte);

    ReadPte (PhysicalAddress, &Pte);
    DisplayHardwarePte ("Pde", PhysicalAddress);
    DisplayPte (&Pte);
    dprintf ("\n");
    if (Pte.Valid == 0) {
      dprintf ("PDE Invalid\n");
      return;
    }

    if (IsLargePage (&Pte) != FALSE) {
      PageFrameIndex = Pte.PageFrameNumber + PteOffset;
      CacheIndex     = Pte.CacheType;
      dprintf ("LARGE PAGE ");
      dprintf ("\n");
      goto PrintAddress;
    }

    //
    // Get PTE
    //

    PhysicalAddress  = Pte.PageFrameNumber << ARM64_PAGE_SHIFT;
    PhysicalAddress += PteOffset * sizeof (Pte);

    ReadPte (PhysicalAddress, &Pte);
    DisplayHardwarePte ("Pte", PhysicalAddress);
    DisplayPte (&Pte);
    CacheIndex = Pte.CacheType;
    dprintf ("\n");
    if (Pte.Valid == 0) {
      dprintf ("PTE Invalid\n");
      return;
    }
  }

  PageFrameIndex = Pte.PageFrameNumber;

PrintAddress:
  PhysicalAddress  = PageFrameIndex << ARM64_PAGE_SHIFT;
  PhysicalAddress += PageOffset;

  // Get the cache type from MAIR
  Regs = MonitorCommandWithOutput (Client, Format ("arch regs").c_str (), 0);

  if (ParseRegsForReg (Regs, "mair_el2", &Mair)) {
    CacheTypeStr = GetCacheTypeFromMair (Mair, CacheIndex);
    CacheType    = CacheTypeStr.c_str ();
  }

  DisplayPhysicalAddress (PhysicalAddress, Address, CacheType);
  return;
}

//
// -------------------------------------------------------------- Debugger APIs
//

const PSTR  PteHelp =
  "!pt [-i] VA [PageTableRoot]\n\n\
    PageTableRoot is optional on X64 but required on ARM64.\n\
    Run !monitor arch regs to get TTBR0_EL2 value.\n\
    -i: Ignore the self map, this can be used to read an uninstalled page table.\n";

HRESULT CALLBACK
pt (
  PDEBUG_CLIENT4  Client,
  PCSTR           args
  )
{
  ULONG64  Address  = 0;
  ULONG64  UserRoot = 0;
  ULONG64  Flags    = 0;

  INIT_API ();

  for ( ; ;) {
    while (*args == ' ' || *args == '\t') {
      args++;
    }

    if ((*args == '-') || (*args == '/')) {
      switch (tolower (*++args)) {
        case 'h':
        case '?':
          dprintf (PteHelp);
          goto Exit;
        case 'i':
          Flags |= FLAG_IGNORE_SELFMAP;
          args++; // Advance past the option character
          break;
        default:
          dprintf ("Unknown option '%c'\n", *args);
          dprintf (PteHelp);
          goto Exit;
      }
    } else {
      break;
    }
  }

  if (GetExpressionEx (args, &Address, &args)) {
    GetExpressionEx (args, &UserRoot, &args);
  }

  switch (g_TargetMachine) {
    case IMAGE_FILE_MACHINE_AMD64:
      Address = (ULONG64)(LONG64)Address;
      DumpPteX64 (Client, Address, UserRoot, Flags);
      break;

    case IMAGE_FILE_MACHINE_ARM64:
      Address = (ULONG64)(LONG64)Address;
      DumpPteArm64 (Client, Address, UserRoot, Flags);
      break;

    default:
      dprintf ("Not supported\n");
  }

Exit:
  EXIT_API ();
  return S_OK;
}

std::string
Format (
  const char  *fmt,
  ...
  )
{
  va_list  args;
  char     buffer[1024];

  va_start (args, fmt);
  _vsnprintf_s (buffer, RTL_NUMBER_OF (buffer), fmt, args);
  va_end (args);
  std::string  str = buffer;

  return str;
}

std::string
FormatAddress (
  __in ULONGLONG  Address
  )
{
  LARGE_INTEGER  a;

  a.QuadPart = Address;
  return Format ("%08x`%08x", a.HighPart, a.LowPart);
}

ULONG64
GetRegisterValue (
  __in PCSTR  Name
  )
{
  HRESULT      Hr;
  ULONG        Index;
  DEBUG_VALUE  Value;

  Hr = g_ExtRegisters->GetIndexByName (Name, &Index);
  if (FAILED (Hr)) {
    VerbOut ("Failed to lookup register index for %s\n", Name);
    return 0;
  }

  Hr = g_ExtRegisters->GetValue (Index, &Value);
  if (FAILED (Hr)) {
    VerbOut ("Failed to get register value for %s\n", Name);
    return 0;
  }

  if (g_TargetMachine == IMAGE_FILE_MACHINE_AMD64) {
    return Value.I64;
  } else if (g_TargetMachine == IMAGE_FILE_MACHINE_ARM64) {
    return Value.I64;
  }

  return 0;
}
