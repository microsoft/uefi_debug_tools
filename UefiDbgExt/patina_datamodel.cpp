/*++

    Copyright (c) Microsoft Corporation.

    SPDX-License-Identifier: BSD-2-Clause-Patent

Module Name:

    patina_datamodel.cpp

Abstract:

    Native Debugger Data Model visualizers for Patina, implemented with the Data Model C++17 Client Library
    (DbgModelClientEx.h). These replace the JavaScript visualizers so the extension can be used without loading
    PatinaExt.js:

      - `patina_internal_core::collections::rbt::Rbt<*>` becomes iterable, yielding its blocks in ascending order
        (an in-order red-black tree walk performed here in C++).
      - The `MemoryBlock` / `IoBlock` enums gain decoded properties (Tag, MemoryType/IoType, BaseAddress, End,
        Length, Attributes, Capabilities) and a one-line display string.

--*/

#include <windows.h>
#include <oaidl.h>
#include <wrl.h>
#include <wrl/client.h>
#include <wrl/implements.h>
#include <wrl/module.h>

using namespace Microsoft::WRL;

#include <dbgeng.h>
#include <dbgmodel.h>
#include "DbgModelClientEx.h"

#include <vector>
#include <string>

#include "patina_datamodel.h"

using namespace Debugger::DataModel;
using namespace Debugger::DataModel::ClientEx;
using namespace Debugger::DataModel::ProviderEx;

//
// The Data Model C++ client library requires the host to provide the data model manager and host interfaces via
// these two functions.
//
static IDataModelManager  *g_pManager = nullptr;
static IDebugHost         *g_pHost    = nullptr;

namespace Debugger::DataModel::ClientEx
{
IDataModelManager *
GetManager (
  void
  )
{
  return g_pManager;
}

IDebugHost *
GetHost (
  void
  )
{
  return g_pHost;
}
}

namespace
{
//
// Formats a 64-bit value as a zero-padded 16-digit hex string.
//
std::wstring
Hex64 (
  ULONG64  Value
  )
{
  wchar_t  Buffer[32];

  swprintf_s (Buffer, ARRAYSIZE (Buffer), L"0x%016I64x", Value);
  return Buffer;
}

//
// Decodes a memory attribute/capability bitfield into a human-readable string, in the same order and with the same
// names as the JavaScript visualizer.
//
std::wstring
DecodeAttributes (
  ULONG64  Attr
  )
{
  static const struct {
    ULONG64          Mask;
    const wchar_t    *Name;
  } Flags[] = {
    { 0x8000000000000000ull, L"RT"  },
    { 0x80000,               L"CC"  },
    { 0x40000,               L"SP"  },
    { 0x20000,               L"RO"  },
    { 0x10000,               L"MR"  },
    { 0x8000,                L"NV"  },
    { 0x4000,                L"XP"  },
    { 0x2000,                L"RP"  },
    { 0x1000,                L"WP"  },
    { 0x10,                  L"UCE" },
    { 0x8,                   L"WB"  },
    { 0x4,                   L"WT"  },
    { 0x2,                   L"WC"  },
    { 0x1,                   L"UC"  },
  };

  std::wstring  Result;

  for (auto &Flag : Flags) {
    if ((Attr & Flag.Mask) != 0) {
      if (!Result.empty ()) {
        Result += L"|";
      }

      Result += Flag.Name;
    }
  }

  return Result.empty () ? std::wstring (L"None") : Result;
}

std::wstring
MemoryTypeName (
  ULONG64  Type
  )
{
  static const wchar_t  *Names[] = {
    L"NonExistent", L"Reserved", L"SystemMemory", L"MemoryMappedIo", L"Persistent", L"MoreReliable", L"Unaccepted"
  };

  if (Type < ARRAYSIZE (Names)) {
    return Names[Type];
  }

  return L"Unknown(" + std::to_wstring (Type) + L")";
}

std::wstring
IoTypeName (
  ULONG64  Type
  )
{
  static const wchar_t  *Names[] = { L"NonExistent", L"Reserved", L"Io", L"Maximum" };

  if (Type < ARRAYSIZE (Names)) {
    return Names[Type];
  }

  return L"Unknown(" + std::to_wstring (Type) + L")";
}

//
// Peels `MaybeUninit` / `ManuallyDrop` wrappers (which expose a `value` member) off an object until the underlying
// enum (which exposes its active variant payload as `__0`) is reached. The tree stores blocks as
// `MaybeUninit<ManuallyDrop<Block>>`, so the raw field navigation lands on a wrapper rather than the enum itself.
//
Object
UnwrapToEnum (
  const Object  &Wrapped
  )
{
  Object  Cur = Wrapped;

  for (int i = 0; i < 4; i++) {
    if (Cur.TryGetFieldValue (L"__0").has_value ()) {
      break;
    }

    auto  Inner = Cur.TryGetFieldValue (L"value");
    if (!Inner.has_value ()) {
      break;
    }

    Cur = *Inner;
  }

  return Cur;
}

//
// Field byte offsets within the descriptor payload (both descriptors are #[repr(C)]), and the descriptor's byte
// offset within the block enum (the 1-byte discriminant sits at offset 0, the 8-aligned payload follows at 8).
//
#define GCD_DESC_OFFSET_IN_ENUM  8

#define MSD_BASE_ADDRESS  0
#define MSD_LENGTH        8
#define MSD_CAPABILITIES  16
#define MSD_ATTRIBUTES    24
#define MSD_MEMORY_TYPE   32
#define MSD_IMAGE_HANDLE  40

#define IOSD_IO_TYPE  16

//
// Reads an 8-byte value at the given byte offset from the start of the block enum, directly from target memory.
// This works whether `Block` is the bare enum or one of the transparent wrappers around it (MaybeUninit /
// ManuallyDrop / MaybeDangling), since they all share the enum's address. Returns 0 on failure.
//
ULONG64
ReadEnumU64 (
  const Object  &Block,
  ULONG64       EnumOffset
  )
{
  Object  Enum = UnwrapToEnum (Block);

  try {
    auto  Loc = Enum.GetLocation ();
    Loc.Offset += EnumOffset;

    IModelObject  *Raw = Enum.GetObject ();

    ComPtr<IDebugHostContext>  Context;
    if (FAILED (Raw->GetContext (&Context))) {
      return 0;
    }

    ComPtr<IDebugHostMemory>  Memory;
    if (FAILED (GetHost ()->QueryInterface (IID_PPV_ARGS (&Memory)))) {
      return 0;
    }

    ULONG64  Value     = 0;
    ULONG64  BytesRead = 0;
    if (FAILED (Memory->ReadBytes (Context.Get (), Loc, &Value, sizeof (Value), &BytesRead)) ||
        (BytesRead != sizeof (Value)))
    {
      return 0;
    }

    return Value;
  }
  catch (...) {
    return 0;
  }
}

//
// Reads an 8-byte descriptor field (the #[repr(C)] payload begins GCD_DESC_OFFSET_IN_ENUM bytes into the enum).
//
ULONG64
DescU64 (
  const Object  &Block,
  ULONG64       FieldOffset
  )
{
  return ReadEnumU64 (Block, GCD_DESC_OFFSET_IN_ENUM + FieldOffset);
}

//
// Returns true if the block is Allocated, reading the enum discriminant byte (0 = Unallocated, 1 = Allocated) at
// offset 0 directly from memory so it works for the bare enum and its transparent wrappers alike.
//
bool
BlockIsAllocated (
  const Object  &Block
  )
{
  return (ReadEnumU64 (Block, 0) & 0xFF) != 0;
}

//
// Visualizer for `MemoryBlock` (enum2$<patina_dxe_core::gcd::memory_block::MemoryBlock>).
//
class MemoryBlockModel : public ExtensionModel
{
public:
  MemoryBlockModel (
                    ) :
    ExtensionModel (
                    TypeSignatureRegistration (L"enum2$<patina_dxe_core::gcd::memory_block::MemoryBlock>"),
                    TypeSignatureRegistration (L"core::mem::maybe_uninit::MaybeUninit<enum2$<patina_dxe_core::gcd::memory_block::MemoryBlock> >"),
                    TypeSignatureRegistration (L"core::mem::manually_drop::ManuallyDrop<enum2$<patina_dxe_core::gcd::memory_block::MemoryBlock> >"),
                    TypeSignatureRegistration (L"core::mem::maybe_dangling::MaybeDangling<enum2$<patina_dxe_core::gcd::memory_block::MemoryBlock> >")
                    )
  {
    AddReadOnlyProperty (L"Tag", this, &MemoryBlockModel::Get_Tag);
    AddReadOnlyProperty (L"MemoryType", this, &MemoryBlockModel::Get_MemoryType);
    AddReadOnlyProperty (L"BaseAddress", this, &MemoryBlockModel::Get_BaseAddress);
    AddReadOnlyProperty (L"End", this, &MemoryBlockModel::Get_End);
    AddReadOnlyProperty (L"Length", this, &MemoryBlockModel::Get_Length);
    AddReadOnlyProperty (L"Attributes", this, &MemoryBlockModel::Get_Attributes);
    AddReadOnlyProperty (L"Capabilities", this, &MemoryBlockModel::Get_Capabilities);
    AddStringDisplayableFunction (this, &MemoryBlockModel::GetDisplayString);
  }

  std::wstring
  Get_Tag (
    const Object  &Inst
    )
  {
    return BlockIsAllocated (Inst) ? L"Allocated" : L"Unallocated";
  }

  std::wstring
  Get_MemoryType (
    const Object  &Inst
    )
  {
    return MemoryTypeName (DescU64 (Inst, MSD_MEMORY_TYPE) & 0xFF);
  }

  ULONG64
  Get_BaseAddress (
    const Object  &Inst
    )
  {
    return DescU64 (Inst, MSD_BASE_ADDRESS);
  }

  ULONG64
  Get_Length (
    const Object  &Inst
    )
  {
    return DescU64 (Inst, MSD_LENGTH);
  }

  ULONG64
  Get_End (
    const Object  &Inst
    )
  {
    return DescU64 (Inst, MSD_BASE_ADDRESS) + DescU64 (Inst, MSD_LENGTH);
  }

  std::wstring
  Get_Attributes (
    const Object  &Inst
    )
  {
    return DecodeAttributes (DescU64 (Inst, MSD_ATTRIBUTES));
  }

  std::wstring
  Get_Capabilities (
    const Object  &Inst
    )
  {
    return DecodeAttributes (DescU64 (Inst, MSD_CAPABILITIES));
  }

  std::wstring
  GetDisplayString (
    const Object  &Inst,
    const Metadata &                                                  /*metadata*/
    )
  {
    ULONG64  Base   = DescU64 (Inst, MSD_BASE_ADDRESS);
    ULONG64  Length = DescU64 (Inst, MSD_LENGTH);

    return Get_Tag (Inst) + L" " + Get_MemoryType (Inst) + L" [" + Hex64 (Base) + L", " + Hex64 (Base + Length) + L")";
  }
};

//
// Visualizer for `IoBlock` (enum2$<patina_dxe_core::gcd::io_block::IoBlock>).
//
class IoBlockModel : public ExtensionModel
{
public:
  IoBlockModel (
                ) :
    ExtensionModel (
                    TypeSignatureRegistration (L"enum2$<patina_dxe_core::gcd::io_block::IoBlock>"),
                    TypeSignatureRegistration (L"core::mem::maybe_uninit::MaybeUninit<enum2$<patina_dxe_core::gcd::io_block::IoBlock> >"),
                    TypeSignatureRegistration (L"core::mem::manually_drop::ManuallyDrop<enum2$<patina_dxe_core::gcd::io_block::IoBlock> >"),
                    TypeSignatureRegistration (L"core::mem::maybe_dangling::MaybeDangling<enum2$<patina_dxe_core::gcd::io_block::IoBlock> >")
                    )
  {
    AddReadOnlyProperty (L"Tag", this, &IoBlockModel::Get_Tag);
    AddReadOnlyProperty (L"IoType", this, &IoBlockModel::Get_IoType);
    AddReadOnlyProperty (L"BaseAddress", this, &IoBlockModel::Get_BaseAddress);
    AddReadOnlyProperty (L"End", this, &IoBlockModel::Get_End);
    AddReadOnlyProperty (L"Length", this, &IoBlockModel::Get_Length);
    AddStringDisplayableFunction (this, &IoBlockModel::GetDisplayString);
  }

  std::wstring
  Get_Tag (
    const Object  &Inst
    )
  {
    return BlockIsAllocated (Inst) ? L"Allocated" : L"Unallocated";
  }

  std::wstring
  Get_IoType (
    const Object  &Inst
    )
  {
    return IoTypeName (DescU64 (Inst, IOSD_IO_TYPE) & 0xFF);
  }

  ULONG64
  Get_BaseAddress (
    const Object  &Inst
    )
  {
    return DescU64 (Inst, MSD_BASE_ADDRESS);
  }

  ULONG64
  Get_Length (
    const Object  &Inst
    )
  {
    return DescU64 (Inst, MSD_LENGTH);
  }

  ULONG64
  Get_End (
    const Object  &Inst
    )
  {
    return DescU64 (Inst, MSD_BASE_ADDRESS) + DescU64 (Inst, MSD_LENGTH);
  }

  std::wstring
  GetDisplayString (
    const Object  &Inst,
    const Metadata &                                                  /*metadata*/
    )
  {
    ULONG64  Base   = DescU64 (Inst, MSD_BASE_ADDRESS);
    ULONG64  Length = DescU64 (Inst, MSD_LENGTH);

    return Get_Tag (Inst) + L" " + Get_IoType (Inst) + L" [" + Hex64 (Base) + L", " + Hex64 (Base + Length) + L")";
  }
};

//
// Visualizer for the red-black tree `patina_internal_core::collections::rbt::Rbt<*>`. Makes the tree iterable,
// yielding each block (the node's `data.value`) in ascending base-address order via an in-order traversal.
//
class RbtModel : public ExtensionModel
{
public:
  RbtModel (
            ) :
    ExtensionModel (TypeSignatureRegistration (L"patina_internal_core::collections::rbt::Rbt<*>"))
  {
    AddReadOnlyProperty (L"Length", this, &RbtModel::Get_Length);
    AddGeneratorFunction (this, &RbtModel::GetBlocks);
  }

  ULONG64
  Get_Length (
    const Object  &Rbt
    )
  {
    return (ULONG64)Rbt.FieldValue (L"storage").FieldValue (L"length");
  }

  //
  // Produces the blocks of the tree, in ascending order, using an iterative in-order traversal that follows the
  // `Cell<*mut Node>` child pointers (mirroring the previous JavaScript visualizer).
  //
  std::vector<Object>
  GetBlocks (
    const Object  &Rbt
    )
  {
    std::vector<Object>  Blocks;

    try {
      Object               Cur = ChildPointer (Rbt.FieldValue (L"root"));
      std::vector<Object>  Stack;

      while (((ULONG64)Cur != 0) || !Stack.empty ()) {
        while ((ULONG64)Cur != 0) {
          Object  Node = Cur.Dereference ();
          Stack.push_back (Node);
          Cur = ChildPointer (Node.FieldValue (L"left"));
        }

        Object  Node = Stack.back ();
        Stack.pop_back ();

        // The node's data is a MaybeUninit<ManuallyDrop<Block>>; unwrap to the bare block enum.
        Blocks.push_back (UnwrapToEnum (Node.FieldValue (L"data").FieldValue (L"value")));

        Cur = ChildPointer (Node.FieldValue (L"right"));

        if (Blocks.size () > 1000000) {
          break;   // Corruption guard.
        }
      }
    }
    catch (...) {
      // Return whatever was gathered before the error.
    }

    return Blocks;
  }

private:
  //
  // Extracts the raw `*mut Node` from a `Cell<*mut Node>` field (Cell -> UnsafeCell -> pointer).
  //
  static Object
  ChildPointer (
    const Object  &Cell
    )
  {
    return Cell.FieldValue (L"value").FieldValue (L"value");
  }
};

//
// Holds the singleton visualizer instances. Constructing them registers the models; destroying them unregisters.
//
class PatinaProvider
{
public:
  PatinaProvider (
                  )
  {
    m_MemoryBlock = std::make_unique<MemoryBlockModel> ();
    m_IoBlock     = std::make_unique<IoBlockModel> ();
    m_Rbt         = std::make_unique<RbtModel> ();
  }

private:
  std::unique_ptr<MemoryBlockModel> m_MemoryBlock;
  std::unique_ptr<IoBlockModel> m_IoBlock;
  std::unique_ptr<RbtModel> m_Rbt;
};

PatinaProvider  *g_pProvider = nullptr;
} // anonymous namespace

//
// *******************************************************  External Functions
//

HRESULT
PatinaDataModelInitialize (
  void
  )
{
  HRESULT  Hr = S_OK;

  if (g_pProvider != nullptr) {
    return S_OK;   // Already initialized.
  }

  try {
    ComPtr<IDebugClient>          spClient;
    ComPtr<IHostDataModelAccess>  spAccess;

    Hr = DebugCreate (__uuidof (IDebugClient), (void **)&spClient);
    if (SUCCEEDED (Hr)) {
      Hr = spClient.As (&spAccess);
    }

    if (SUCCEEDED (Hr)) {
      Hr = spAccess->GetDataModel (&g_pManager, &g_pHost);
    }

    if (SUCCEEDED (Hr)) {
      g_pProvider = new PatinaProvider ();
    }
  }
  catch (...) {
    Hr = E_FAIL;
  }

  if (FAILED (Hr)) {
    PatinaDataModelUninitialize ();
  }

  return Hr;
}

void
PatinaDataModelUninitialize (
  void
  )
{
  if (g_pProvider != nullptr) {
    delete g_pProvider;
    g_pProvider = nullptr;
  }

  if (g_pManager != nullptr) {
    g_pManager->Release ();
    g_pManager = nullptr;
  }

  if (g_pHost != nullptr) {
    g_pHost->Release ();
    g_pHost = nullptr;
  }
}

//
// Data-model-aware unload support. The debugger will not unload the extension while live references into its data
// model objects remain (tracked by the WRL module object count).
//
extern "C"
HRESULT
CALLBACK
DebugExtensionCanUnload (
  void
  )
{
  auto  ObjectCount = Microsoft::WRL::Module<InProc>::GetModule ().GetObjectCount ();

  return (ObjectCount == 0) ? S_OK : S_FALSE;
}

extern "C"
void
CALLBACK
DebugExtensionUnload (
  void
  )
{
}
