/*++

    Copyright (c) Microsoft Corporation.

    SPDX-License-Identifier: BSD-2-Clause-Patent

Module Name:

    memory.cpp

Abstract:

    This file contains command forwarders to the Patina javascript extension.

--*/

#include "uefiext.h"
#include <string>
#include <sstream>
#include <vector>
#include <functional>

//
// *******************************************************  External Functions
//

//
// *******************************************************  Native GCD Implementation
//
// The `!gcd` command walks the Patina GCD memory-space red-black tree in C++, reading each node from the target and
// decoding the block descriptors. It shows the map a 0x50-block chunk at a time (with clickable DML paging) and can
// also locate the block containing a given address.
//

#define GCD_PAGE_SIZE  0x50

//
// Short type-name table, matching the JavaScript formatting.
//
static PCSTR  gGcdMemTypeNames[] = {
  "NonExistent", "Reserved", "SystemMemory", "MemoryMappedIo", "Persistent", "MoreReliable", "Unaccepted"
};

//
// Attribute/capability flags, in the display order produced by the JavaScript implementation.
//
typedef struct {
  ULONG64    Mask;
  PCSTR      Name;
} GCD_ATTR_FLAG;

static GCD_ATTR_FLAG  gGcdAttrFlags[] = {
  { 0x8000000000000000ull, "RT"  },
  { 0x80000,               "CC"  },
  { 0x40000,               "SP"  },
  { 0x20000,               "RO"  },
  { 0x10000,               "MR"  },
  { 0x8000,                "NV"  },
  { 0x4000,                "XP"  },
  { 0x2000,                "RP"  },
  { 0x1000,                "WP"  },
  { 0x10,                  "UCE" },
  { 0x8,                   "WB"  },
  { 0x4,                   "WT"  },
  { 0x2,                   "WC"  },
  { 0x1,                   "UC"  },
};

//
// Description of a located red-black tree, with the field offsets needed to parse nodes out of the bulk buffer.
//
typedef struct {
  ULONG64    Base;        // Address of node[0] (start of the storage array).
  ULONG64    Capacity;    // Number of node slots in the storage array.
  ULONG64    Stride;      // Size of a single Node<D> in bytes.
  ULONG64    LeftOff;     // Offset of the left-child pointer within a node.
  ULONG64    RightOff;    // Offset of the right-child pointer within a node.
  ULONG64    DescOff;     // Offset of the (repr(C)) descriptor within a node.
  ULONG64    TagOff;      // Offset of the enum discriminant byte within a node.
  ULONG64    RootPtr;     // Raw pointer to the root node.
} GCD_TREE_INFO;

//
// Converts an attribute/capability bitfield into a human-readable string, matching the JavaScript formatting.
//
static std::string
GcdAttrToStr (
  ULONG64  Attr
  )
{
  std::string  Result;

  for (auto &Flag : gGcdAttrFlags) {
    if ((Attr & Flag.Mask) != 0) {
      if (!Result.empty ()) {
        Result += "|";
      }

      Result += Flag.Name;
    }
  }

  return Result.empty () ? std::string ("None") : Result;
}

//
// Evaluates a `dx` expression that yields an unsigned 64-bit integer and returns its value. The `,d` format forces
// decimal output so the result is unambiguous to parse. Returns false on any evaluation or parse failure.
//
static bool
EvalDxU64 (
  PDEBUG_CLIENT4     Client,
  const std::string  &Expr,
  ULONG64            *Out
  )
{
  std::string  Command = "dx -r0 " + Expr + ",d";
  std::string  Output  = ExecuteCommandWithOutput (Client, Command.c_str ());

  size_t  SepPos = Output.rfind (" : ");

  if (SepPos == std::string::npos) {
    return false;
  }

  std::string  Value = Output.substr (SepPos + 3);

  // Strip leading whitespace.
  size_t  Start = Value.find_first_not_of (" \t\r\n");

  if (Start == std::string::npos) {
    return false;
  }

  Value = Value.substr (Start);

  // Keep only the first token.
  size_t  End = Value.find_first_of (" \t\r\n");

  if (End != std::string::npos) {
    Value = Value.substr (0, End);
  }

  // Remove any WinDbg digit-group backticks.
  std::string  Clean;

  for (char c : Value) {
    if (c != '`') {
      Clean += c;
    }
  }

  if (Clean.empty ()) {
    return false;
  }

  char     *EndPtr = nullptr;
  ULONG64  Parsed  = _strtoui64 (Clean.c_str (), &EndPtr, 0);

  if (EndPtr == Clean.c_str ()) {
    return false;
  }

  *Out = Parsed;
  return true;
}

//
// Resolves the module-qualified name (e.g. "module!patina_dxe_core::GCD") of the Patina GCD static.
//
static bool
GetGcdModuleSymbol (
  std::string  &ModSym
  )
{
  ULONG64  GcdAddr = GetExpression ("patina_dxe_core::GCD");

  if (GcdAddr == 0) {
    return false;
  }

  ULONG64  Base = 0;

  if (g_ExtSymbols->GetModuleByOffset (GcdAddr, 0, NULL, &Base) != S_OK) {
    return false;
  }

  char   NameBuf[128] = { 0 };
  ULONG  NameSize     = 0;

  if (g_ExtSymbols->GetModuleNameString (DEBUG_MODNAME_MODULE, DEBUG_ANY_ID, Base, NameBuf, sizeof (NameBuf), &NameSize) != S_OK) {
    return false;
  }

  ModSym = std::string (NameBuf) + "!patina_dxe_core::GCD";
  return true;
}

//
// Reads the layout of a GCD red-black tree via a handful of one-time `dx` evaluations (the field offsets and array
// bounds), so that the node array can subsequently be read and walked entirely from a local buffer.
//
// `TreePath` is the field path from the GCD static to the Rbt, e.g. "memory.data.memory_blocks".
//
static bool
GcdSetup (
  PDEBUG_CLIENT4     Client,
  const std::string  &ModSym,
  const std::string  &TreePath,
  GCD_TREE_INFO      *Info
  )
{
  std::string  Prefix = ModSym + "." + TreePath;
  ULONG        BytesRead;

  memset (Info, 0, sizeof (*Info));

  // The Rust slice `storage.data` is a fat pointer (data pointer + length) stored inline; read both at once.
  ULONG64  FatPtrAddr;

  if (!EvalDxU64 (Client, "(unsigned __int64)&(" + Prefix + ".storage.data)", &FatPtrAddr)) {
    return false;
  }

  ULONG64  Fat[2] = { 0, 0 };

  ReadMemory (FatPtrAddr, Fat, sizeof (Fat), &BytesRead);
  if (BytesRead != sizeof (Fat)) {
    return false;
  }

  Info->Base     = Fat[0];
  Info->Capacity = Fat[1];

  // Read the root pointer out of its Cell.
  ULONG64  RootCellAddr;

  if (!EvalDxU64 (Client, "(unsigned __int64)&(" + Prefix + ".root)", &RootCellAddr)) {
    return false;
  }

  ReadMemory (RootCellAddr, &Info->RootPtr, sizeof (ULONG64), &BytesRead);
  if (BytesRead != sizeof (ULONG64)) {
    return false;
  }

  if ((Info->Capacity == 0) || (Info->RootPtr == 0)) {
    // Empty tree; nothing more to resolve.
    return true;
  }

  // Resolve node field offsets from node[0]. `left`/`right` are Cell<*mut Node> (transparent, so the Cell address is
  // the pointer address); `data` is a MaybeUninit<enum> whose discriminant byte precedes an 8-byte-aligned payload.
  ULONG64  LeftAddr, RightAddr, DataAddr;

  if (!EvalDxU64 (Client, "(unsigned __int64)&(" + Prefix + ".storage.data[0].left)", &LeftAddr)) {
    return false;
  }

  if (!EvalDxU64 (Client, "(unsigned __int64)&(" + Prefix + ".storage.data[0].right)", &RightAddr)) {
    return false;
  }

  if (!EvalDxU64 (Client, "(unsigned __int64)&(" + Prefix + ".storage.data[0].data)", &DataAddr)) {
    return false;
  }

  Info->LeftOff  = LeftAddr - Info->Base;
  Info->RightOff = RightAddr - Info->Base;

  ULONG64  DataOff = DataAddr - Info->Base;

  Info->TagOff  = DataOff;        // The 2-variant enum stores its discriminant first.
  Info->DescOff = DataOff + 8;    // The repr(C) descriptor payload follows the padded tag.

  // Node stride: prefer the address delta between two adjacent slots; fall back to sizeof for a single-node array.
  if (Info->Capacity >= 2) {
    ULONG64  Node1Addr;
    if (!EvalDxU64 (Client, "(unsigned __int64)&(" + Prefix + ".storage.data[1])", &Node1Addr)) {
      return false;
    }

    Info->Stride = Node1Addr - Info->Base;
  } else {
    if (!EvalDxU64 (Client, "(unsigned __int64)sizeof(" + Prefix + ".storage.data[0])", &Info->Stride)) {
      return false;
    }
  }

  return (Info->Stride != 0);
}

//
// A single parsed memory-tree node (child pointers plus the descriptor fields needed for display).
//
typedef struct {
  ULONG64    Left;
  ULONG64    Right;
  ULONG64    Base;
  ULONG64    Length;
  ULONG64    Caps;
  ULONG64    Attrs;
  BYTE       MemType;
  BYTE       Tag;
} GCD_MEM_NODE;

//
// Reads and parses a single memory node from the target into `Out`. `Scratch` must be at least `Stride` bytes.
//
static bool
GcdReadMemNode (
  ULONG64              Addr,
  const GCD_TREE_INFO  *Info,
  BYTE                 *Scratch,
  GCD_MEM_NODE         *Out
  )
{
  ULONG  BytesRead = 0;

  ReadMemory (Addr, Scratch, (ULONG)Info->Stride, &BytesRead);
  if (BytesRead != (ULONG)Info->Stride) {
    return false;
  }

  memcpy (&Out->Left, Scratch + Info->LeftOff, sizeof (Out->Left));
  memcpy (&Out->Right, Scratch + Info->RightOff, sizeof (Out->Right));
  memcpy (&Out->Base, Scratch + Info->DescOff + 0, sizeof (Out->Base));
  memcpy (&Out->Length, Scratch + Info->DescOff + 8, sizeof (Out->Length));
  memcpy (&Out->Caps, Scratch + Info->DescOff + 16, sizeof (Out->Caps));
  memcpy (&Out->Attrs, Scratch + Info->DescOff + 24, sizeof (Out->Attrs));
  Out->MemType = *(Scratch + Info->DescOff + 32);
  Out->Tag     = *(Scratch + Info->TagOff);
  return true;
}

//
// Formats a memory node into a display row (matching the JavaScript columns).
//
static void
GcdFormatMemRow (
  const GCD_MEM_NODE  *N,
  char                *Buf,
  size_t              BufSize
  )
{
  char   MemTypeBuf[32];
  PCSTR  MemTypeStr;

  if (N->MemType < (sizeof (gGcdMemTypeNames) / sizeof (gGcdMemTypeNames[0]))) {
    MemTypeStr = gGcdMemTypeNames[N->MemType];
  } else {
    sprintf_s (MemTypeBuf, sizeof (MemTypeBuf), "Unknown(%u)", N->MemType);
    MemTypeStr = MemTypeBuf;
  }

  std::string  AttrStr = GcdAttrToStr (N->Attrs);
  std::string  CapStr  = GcdAttrToStr (N->Caps);

  sprintf_s (
    Buf,
    BufSize,
    "%-12s%-16s0x%016I64x  0x%016I64x  0x%016I64x  %-20s%-24s",
    N->Tag ? "Allocated" : "Unallocated",
    MemTypeStr,
    N->Base,
    N->Base + N->Length,
    N->Length,
    AttrStr.c_str (),
    CapStr.c_str ()
    );
}

//
// DML theme color names for the zebra-striped memory map rows. One stripe is left unhighlighted (default background
// with the normal foreground, i.e. white text in dark mode); the alternating stripe uses the emphasized pair, which
// is a light background with a coordinated contrasting foreground. Both are theme-defined pairs, so the foreground
// always contrasts with its background in light and dark themes. The block that contains a located address is drawn
// separately in red via PrintDml (Err).
//
#define GCD_ROW_FG_EVEN  "normfg"    // unhighlighted row (default text)
#define GCD_ROW_BG_EVEN  "normbg"
#define GCD_ROW_FG_ODD   "emphfg"    // light-background row (contrasting text)
#define GCD_ROW_BG_ODD   "empbg"

//
// Prints a single pre-formatted row with the given DML foreground/background theme colors. `Line` is emitted as a
// `%s` argument and contains no format or DML metacharacters, so it is safe to pass through unescaped.
//
static void
GcdPrintRow (
  const char  *Line,
  PCSTR       Fg,
  PCSTR       Bg
  )
{
  g_ExtControl->ControlledOutput (
                  DEBUG_OUTCTL_AMBIENT_DML,
                  DEBUG_OUTPUT_NORMAL,
                  "<col fg=\"%s\" bg=\"%s\">%s</col>\n",
                  Fg,
                  Bg,
                  Line
                  );
}

//
// In-order traversal of the memory tree, reading each node from the target exactly once and invoking `Visit` for
// each (in ascending base-address order). `Visit` returns false to stop early. Returns false on a read error.
//
static bool
GcdTraverseMem (
  const GCD_TREE_INFO                               *Info,
  BYTE                                              *Scratch,
  const std::function<bool (const GCD_MEM_NODE &)>  &Visit
  )
{
  std::vector<GCD_MEM_NODE>  Stack;
  ULONG64                    Cur      = Info->RootPtr;
  ULONG64                    ArrayEnd = Info->Base + (Info->Capacity * Info->Stride);
  ULONG64                    Guard    = 0;
  ULONG64                    GuardMax = Info->Capacity + 8;

  while ((Cur != 0) || !Stack.empty ()) {
    while (Cur != 0) {
      if ((Cur < Info->Base) || (Cur >= ArrayEnd) || (((Cur - Info->Base) % Info->Stride) != 0)) {
        Cur = 0;   // Out-of-range pointer; treat as null.
        break;
      }

      GCD_MEM_NODE  N;
      if (!GcdReadMemNode (Cur, Info, Scratch, &N)) {
        return false;
      }

      Stack.push_back (N);
      Cur = N.Left;

      if (++Guard > GuardMax) {
        return false;
      }
    }

    if (Stack.empty ()) {
      break;
    }

    GCD_MEM_NODE  N = Stack.back ();
    Stack.pop_back ();

    if (!Visit (N)) {
      return true;   // Stopped early; not an error.
    }

    Cur = N.Right;

    if (++Guard > GuardMax) {
      return false;
    }
  }

  return true;
}

//
// Native C++ implementation of `!gcd memory`.
//
// The argument selects the mode:
//   - empty or `C<n>` (e.g. `C0`, `C2`) -> show one 0x50-block chunk `n` (default 0), with clickable DML paging.
//   - anything else                     -> treat as an address and show the containing block with 5 lines of
//                                          context on each side.
//
// In both modes the tree is walked in-order, reading each visited node from the target with a single ReadMemory
// (no whole-array read), so the per-node read cost can be compared against the chunked JavaScript path.
//
static void
GcdcMemory (
  PDEBUG_CLIENT4     Client,
  const std::string  &ModSym,
  const std::string  &Arg
  )
{
  GCD_TREE_INFO  Info;

  if (!GcdSetup (Client, ModSym, "memory.data.memory_blocks", &Info)) {
    dprintf ("Failed to resolve GCD memory tree layout (symbols missing?).\n");
    return;
  }

  if ((Info.Capacity == 0) || (Info.RootPtr == 0)) {
    dprintf ("No GCD memory blocks found.\n");
    return;
  }

  BYTE  *Node = (BYTE *)malloc ((size_t)Info.Stride);

  if (Node == NULL) {
    dprintf ("Out of memory.\n");
    return;
  }

  //
  // Parse the argument. A `C`-prefixed value selects a chunk; anything else is an address to locate.
  //
  bool     AddrMode = false;
  ULONG    Chunk    = 0;
  ULONG64  Target   = 0;

  if (!Arg.empty ()) {
    if ((Arg[0] == 'C') || (Arg[0] == 'c')) {
      Chunk = (ULONG)strtoul (Arg.c_str () + 1, NULL, 0);
    } else {
      AddrMode = true;
      Target   = GetExpression (Arg.c_str ());
    }
  }

  dprintf (
    "%-12s%-16s%-20s%-20s%-20s%-20s%s\n",
    "Tag",
    "MemoryType",
    "BaseAddress",
    "End",
    "Length",
    "Attributes",
    "Capabilities"
    );

  if (AddrMode) {
    //
    // Address window: locate the block containing Target and show 5 entries of context on each side.
    //
    std::vector<std::string>  Lines;
    LONG64                    Found = -1;
    ULONG64                   Pos   = 0;

    bool  Ok = GcdTraverseMem (
                 &Info,
                 Node,
                 [&] (const GCD_MEM_NODE &N) -> bool {
      char  LineBuf[256];
      GcdFormatMemRow (&N, LineBuf, sizeof (LineBuf));
      Lines.push_back (LineBuf);

      if ((Found < 0) && (Target >= N.Base) && (Target < N.Base + N.Length)) {
        Found = (LONG64)Pos;
      }

      Pos++;

      // Once found, gather five more rows of trailing context, then stop.
      return !((Found >= 0) && ((LONG64)Pos >= Found + 6));
    }
                 );

    free (Node);

    if (!Ok) {
      dprintf ("\nError reading GCD nodes; output may be incomplete.\n");
    }

    if (Found < 0) {
      dprintf ("No GCD memory block contains address 0x%I64x.\n", Target);
      return;
    }

    LONG64  First = (Found > 5) ? (Found - 5) : 0;
    LONG64  Last  = Found + 6;
    if (Last > (LONG64)Lines.size ()) {
      Last = (LONG64)Lines.size ();
    }

    for (LONG64 i = First; i < Last; i++) {
      if (i == Found) {
        //
        // Highlight the matched row in red. DML `<col>` only recognizes the syntax color tokens (normfg, empbg,
        // changed, srckw, ...) - the mask-based err/warn colors and the error output stream do not render distinctly
        // in every theme. `changed` is the debugger's register-diff red and is a valid `<col>` token, drawn here on
        // the light emphasized background so it stands out from both zebra stripes.
        //
        GcdPrintRow (Lines[(size_t)i].c_str (), "changed", "empbg");
        continue;
      }

      GcdPrintRow (
        Lines[(size_t)i].c_str (),
        (i & 1) ? GCD_ROW_FG_ODD : GCD_ROW_FG_EVEN,
        (i & 1) ? GCD_ROW_BG_ODD : GCD_ROW_BG_EVEN
        );
    }

    dprintf (
      "\nAddress 0x%I64x is in block %d (highlighted), chunk %d; showing blocks %d..%d.\n",
      Target,
      (int)Found,
      (int)(Found / GCD_PAGE_SIZE),
      (int)First,
      (int)(Last - 1)
      );

    return;
  }

  //
  // Chunk mode: read and show one 0x50-block chunk, with clickable DML paging.
  //
  ULONG64  StartPos = (ULONG64)Chunk * GCD_PAGE_SIZE;
  ULONG64  EndPos   = StartPos + GCD_PAGE_SIZE;
  ULONG64  Pos      = 0;
  ULONG    Shown    = 0;
  bool     More     = false;

  bool  Ok = GcdTraverseMem (
               &Info,
               Node,
               [&] (const GCD_MEM_NODE &N) -> bool {
    if (Pos >= EndPos) {
      More = true;      // A node exists beyond this chunk.
      return false;
    }

    if (Pos >= StartPos) {
      char  LineBuf[256];
      GcdFormatMemRow (&N, LineBuf, sizeof (LineBuf));
      GcdPrintRow (
        LineBuf,
        (Pos & 1) ? GCD_ROW_FG_ODD : GCD_ROW_FG_EVEN,
        (Pos & 1) ? GCD_ROW_BG_ODD : GCD_ROW_BG_EVEN
        );
      Shown++;
    }

    Pos++;
    return true;
  }
               );

  free (Node);

  if (!Ok) {
    dprintf ("\nError reading GCD nodes; output may be incomplete.\n");
  }

  if (Shown == 0) {
    dprintf (
      "\nChunk %u is past the end of the map (%u block(s) total).\n",
      Chunk,
      (ULONG)Pos
      );

    if (Chunk > 0) {
      g_ExtControl->ControlledOutput (
                      DEBUG_OUTCTL_AMBIENT_DML,
                      DEBUG_OUTPUT_NORMAL,
                      "  <exec cmd=\"!gcd C%u\">[ prev ]</exec>\n",
                      Chunk - 1
                      );
    }

    return;
  }

  dprintf (
    "\nChunk %u: blocks %u..%u.\n",
    Chunk,
    (ULONG)StartPos,
    (ULONG)(StartPos + Shown - 1)
    );

  //
  // Emit clickable DML navigation links. `<exec>` runs the given command when clicked, giving grid-like paging
  // without a data-model object.
  //
  if ((Chunk > 0) || More) {
    g_ExtControl->ControlledOutput (DEBUG_OUTCTL_AMBIENT_DML, DEBUG_OUTPUT_NORMAL, "  ");

    if (Chunk > 0) {
      g_ExtControl->ControlledOutput (
                      DEBUG_OUTCTL_AMBIENT_DML,
                      DEBUG_OUTPUT_NORMAL,
                      "<exec cmd=\"!gcd C%u\">[ prev ]</exec>  ",
                      Chunk - 1
                      );
    }

    if (More) {
      g_ExtControl->ControlledOutput (
                      DEBUG_OUTCTL_AMBIENT_DML,
                      DEBUG_OUTPUT_NORMAL,
                      "<exec cmd=\"!gcd C%u\">[ next ]</exec>",
                      Chunk + 1
                      );
    } else {
      g_ExtControl->ControlledOutput (DEBUG_OUTCTL_AMBIENT_DML, DEBUG_OUTPUT_NORMAL, "(end of map)");
    }

    dprintf ("\n");
  } else {
    dprintf ("  (entire map shown)\n");
  }
}

//
// Handles the `!gcd` command in the Patina environment. The caller must already have performed INIT_API (); this
// routine does not manage the extension interfaces.
//
// With no argument it dumps the first chunk of the GCD memory map. It also accepts an optional 0x50-block chunk
// selector (`C<n>`, e.g. C0, C2) or an address to locate.
//
VOID
PatinaGcdCommand (
  PDEBUG_CLIENT4  Client,
  PCSTR           args
  )
{
  std::string  Arg;

  if ((args != NULL) && (*args != '\0')) {
    std::istringstream  iss (args);
    iss >> Arg;
  }

  if ((Arg == "help") || (Arg == "-h") || (Arg == "/?") || (Arg == "?")) {
    dprintf (
      "Help for gcd command (Patina GCD memory map):\n"
      "\nUsage:\n"
      "  !gcd          - Show the first 0x50-block chunk of the GCD memory map.\n"
      "  !gcd C<n>     - Show 0x50-block chunk <n> (e.g. C0, C2).\n"
      "  !gcd <addr>   - Show the block containing <addr> with 5 lines of context on each side.\n"
      );
    return;
  }

  std::string  ModSym;

  if (!GetGcdModuleSymbol (ModSym)) {
    dprintf ("Failed to locate the Patina GCD symbol (is the Patina DXE Core module loaded?).\n");
    return;
  }

  GcdcMemory (Client, ModSym, Arg);
}
