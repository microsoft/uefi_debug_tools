/*++

Copyright (c) Microsoft Corporation.

SPDX-License-Identifier: BSD-2-Clause-Patent

Module Name:

    swdebug.cpp

Abstract:

    This file contains implementations specific to the UEFI software debugger.

--*/

#include "uefiext.h"

HRESULT CALLBACK
monitor (
  PDEBUG_CLIENT4  Client,
  PCSTR           args
  )
{
  PSTR         Response;
  ULONG        Len;
  const CHAR   *TruncateTag   = "#T#";
  const ULONG  TruncateTagLen = sizeof ("#T#") - 1; // Exclude the null terminator.
  ULONG        Offset;

  INIT_API ();

  Offset = 0;

  // Loop on the command until the entire response is received.
  while (TRUE) {
    Response = MonitorCommandWithOutput (Client, args, Offset);

    // Strip of the trailing newline character if it exists since this in injected
    // by windbg and is not part of the response.
    Len = (ULONG)strlen (Response);
    if ((Len > 0) && (Response[Len - 1] == '\n')) {
      Len--;
    }

    if (Len > TruncateTagLen) {
      if (strncmp (Response + Len - TruncateTagLen, TruncateTag, TruncateTagLen) == 0) {
        // The response was truncated, so we need to read more.
        Response[Len - TruncateTagLen] = 0; // Remove the truncate tag.
        dprintf ("%s", Response);
        Offset += Len - TruncateTagLen;
        continue;
      }
    }

    break;
  }

  dprintf ("%s\n", Response);

  EXIT_API ();
  return S_OK;
}

HRESULT CALLBACK
info (
  PDEBUG_CLIENT4  Client,
  PCSTR           args
  )
{
  INIT_API ();

  monitor (Client, "?");

  EXIT_API ();
  return S_OK;
}

HRESULT CALLBACK
modulebreak (
  PDEBUG_CLIENT4  Client,
  PCSTR           args
  )
{
  CHAR  Command[512];

  INIT_API ();

  if (PATINA == gUefiEnv) {
    sprintf_s (Command, sizeof (Command), "mod break %s", args);
  } else {
    sprintf_s (Command, sizeof (Command), "b%s", args);
  }

  monitor (Client, Command);

  EXIT_API ();
  return S_OK;
}

HRESULT CALLBACK
readmsr (
  PDEBUG_CLIENT4  Client,
  PCSTR           args
  )
{
  CHAR  Command[512];

  INIT_API ();

  if (strlen (args) == 0) {
    dprintf ("Must provide MSR index in HEX! E.g. 0x1234\n");
  }

  sprintf_s (Command, sizeof (Command), "m%s", args);
  monitor (Client, Command);

  EXIT_API ();
  return S_OK;
}

HRESULT CALLBACK
reboot (
  PDEBUG_CLIENT4  Client,
  PCSTR           args
  )
{
  INIT_API ();

  // Set reboot on continue
  g_ExtControl->Execute (
                  DEBUG_OUTCTL_ALL_CLIENTS,
                  ".exdicmd target:0:R",
                  DEBUG_EXECUTE_DEFAULT
                  );

  // Clear the symbols since the modules will be unloaded across reset.
  g_ExtControl->Execute (
                  DEBUG_OUTCTL_ALL_CLIENTS,
                  ".reload /u",
                  DEBUG_EXECUTE_DEFAULT
                  );

  // Continue, this will reboot the system.
  dprintf ("\nRebooting...\n");
  g_ExtControl->Execute (
                  DEBUG_OUTCTL_ALL_CLIENTS,
                  "g",
                  DEBUG_EXECUTE_DEFAULT
                  );

  EXIT_API ();
  return S_OK;
}

ULONG64
ReadTaggedValue (
  PCSTR  Response,
  PCSTR  Tag
  )
{
  PCSTR  TagPos = strstr (Response, Tag);

  if (TagPos != NULL) {
    PCSTR  ValuePos = TagPos + strlen (Tag);
    return strtoull (ValuePos, NULL, 16);
  }

  return 0;
}

HRESULT CALLBACK
loadcore (
  PDEBUG_CLIENT4  Client,
  PCSTR           args
  )
{
  HANDLE   hFile = INVALID_HANDLE_VALUE;
  CHAR     Command[512];
  PSTR     Response;
  BYTE     *ImageBuffer     = NULL;
  BYTE     *CompressedImage = NULL;
  BOOLEAN  NoGo             = FALSE;

  INIT_API ();

  if (PATINA != gUefiEnv) {
    dprintf ("!uefiext.loadcore is only supported in Patina environments.\n");
    goto Exit;
  }

  // Get the provided image path
  if (strlen (args) == 0) {
    dprintf ("Usage: !uefiext.loadcore </nogo> [ImagePath]\n");
    goto Exit;
  }

  // Check for the /nogo argument
  if (strstr (args, "/nogo ") == args) {
    dprintf ("Will not resume after loading\n");
    NoGo = TRUE;
    // Move past the /nogo argument
    args += 6;
  }

  // open the file from from the local disk
  hFile = CreateFileA (
            args,
            GENERIC_READ,
            FILE_SHARE_READ,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL
            );

  if (hFile == INVALID_HANDLE_VALUE) {
    dprintf ("Failed to open file: %s (Error: %d)\n", args, GetLastError ());
    goto Exit;
  }

  DWORD  FileSize = GetFileSize (hFile, NULL);

  dprintf ("Loading image of size %u bytes from %s\n", FileSize, args);
  ImageBuffer = (BYTE *)malloc (FileSize);
  if (ImageBuffer == NULL) {
    dprintf ("Failed to allocate memory for image buffer.\n");
    goto Exit;
  }

  DWORD  BytesRead = 0;

  if (!ReadFile (hFile, ImageBuffer, FileSize, &BytesRead, NULL) || (BytesRead != FileSize)) {
    dprintf ("Failed to read file: %s (Error: %d)\n", args, GetLastError ());
    goto Exit;
  }

  // Close early to avoid leaked handles.
  CloseHandle (hFile);
  hFile = INVALID_HANDLE_VALUE;

  // Compress the buffer.
  CompressedImage = (BYTE *)malloc (FileSize);
  if (CompressedImage == NULL) {
    dprintf ("Failed to allocate memory for compressed image buffer.\n");
    goto Exit;
  }

  UINT32      CompressedSize = FileSize;
  EFI_STATUS  EfiStatus      = EfiCompress (ImageBuffer, FileSize, CompressedImage, &CompressedSize);

  if (EfiStatus != EFI_SUCCESS) {
    dprintf ("Failed to compress image. %x\n", EfiStatus);
    goto Exit;
  }

  FileSize = CompressedSize;
  dprintf ("Compressed image size: %u bytes\n", FileSize);

  // Allocate a transfer buffer in the target.
  sprintf_s (Command, sizeof (Command), "reload alloc_buffer %u", FileSize);
  Response = MonitorCommandWithOutput (Client, Command, 0);
  ULONG64  TransferBuffer = strtoull (Response, NULL, 16);

  if (TransferBuffer == 0) {
    dprintf ("Failed to allocate target buffer in Patina debugger.\n");
    dprintf ("    Monitor: %s\n", Response);
    goto Exit;
  }

  // Capture a timestamp before starting the transfer.
  LARGE_INTEGER  frequency, startTime, CheckpointTime;

  QueryPerformanceFrequency (&frequency);
  QueryPerformanceCounter (&startTime);

  // Start loading the image into the transfer buffer
  DWORD  TotalBytesWritten = 0;
  DWORD  NextCheckpoint    = 1;

  while (TotalBytesWritten < FileSize) {
    DWORD    BlockSize    = min (0x800, FileSize - TotalBytesWritten);
    ULONG64  WriteAddress = TransferBuffer + TotalBytesWritten;
    ULONG    BytesWritten = 0;

    if (!WriteMemory (WriteAddress, CompressedImage + TotalBytesWritten, BlockSize, &BytesWritten) || (BytesWritten != BlockSize)) {
      dprintf ("Failed to write to target memory at %llx. Error: %d\n", WriteAddress, GetLastError ());
      goto Exit;
    }

    TotalBytesWritten += BytesWritten;
    QueryPerformanceCounter (&CheckpointTime);
    DWORD  ElapsedTime = (DWORD)((CheckpointTime.QuadPart - startTime.QuadPart) / frequency.QuadPart);
    if ((ElapsedTime >= NextCheckpoint) || (TotalBytesWritten == FileSize)) {
      dprintf (
        "\rTransferred %u / %u bytes (%u%%) in %u seconds (%u kbps)...",
        TotalBytesWritten,
        FileSize,
        (TotalBytesWritten * 100) / FileSize,
        ElapsedTime,
        (TotalBytesWritten * 8) / (ElapsedTime * 1024)
        );

      NextCheckpoint = ElapsedTime + 1;
    }
  }

  dprintf ("\n");
  // Instruct the debugger to reload the image from the transfer buffer.
  sprintf_s (Command, sizeof (Command), "reload load %llu %u compressed", TransferBuffer, FileSize);
  Response = MonitorCommandWithOutput (Client, Command, 0);

  // Check if the response contains "success:"
  if (strstr (Response, "success:") == NULL) {
    dprintf ("Load command failed. Response: %s\n", Response);
    goto Exit;
  } else {
    dprintf ("Image loaded successfully.\n");
  }

  // Extract the address of the new core from the response.
  ULONG64  RegValue[3];
  ULONG64  NewCoreAddress = ReadTaggedValue (Response, "success:");

  RegValue[0] = ReadTaggedValue (Response, "ip:");
  RegValue[1] = ReadTaggedValue (Response, "sp:");
  RegValue[2] = ReadTaggedValue (Response, "arg0:");
  if ((NewCoreAddress == 0) || (RegValue[0] == 0) || (RegValue[1] == 0) || (RegValue[2] == 0)) {
    dprintf ("Failed to extract details from response: %s\n", Response);
    goto Exit;
  }

  // Unload all symbols
  g_ExtControl->Execute (
                  DEBUG_OUTCTL_ALL_CLIENTS,
                  ".reload /u",
                  DEBUG_EXECUTE_DEFAULT
                  );

  // Load the new core symbols
  FindModuleBackwards (NewCoreAddress);

  dprintf ("New instruction pointer: %llx\n", RegValue[0]);
  dprintf ("New stack pointer: %llx\n", RegValue[1]);
  dprintf ("New argument 0: %llx\n", RegValue[2]);

  // Fixing up registers. This is done here since registers changing during a break is unstable.
  PCSTR  RegName[3];

  if (g_TargetMachine == IMAGE_FILE_MACHINE_AMD64) {
    RegName[0] = "rip";
    RegName[1] = "rsp";
    RegName[2] = "rcx";
  } else if (g_TargetMachine == IMAGE_FILE_MACHINE_ARM64) {
    RegName[0] = "pc";
    RegName[1] = "sp";
    RegName[2] = "x0";
  } else {
    dprintf ("Unsupported target machine: %u\n", g_TargetMachine);
    goto Exit;
  }

  for (int i = 0; i < 3; i++) {
    sprintf_s (Command, sizeof (Command), "r %s=%llx", RegName[i], RegValue[i]);
    g_ExtControl->Execute (
                    DEBUG_OUTCTL_ALL_CLIENTS,
                    Command,
                    DEBUG_EXECUTE_DEFAULT
                    );
  }

  // resume execution
  dprintf ("Executing new core...\n");
  if (!NoGo) {
    g_ExtControl->Execute (
                    DEBUG_OUTCTL_ALL_CLIENTS,
                    "g",
                    DEBUG_EXECUTE_DEFAULT
                    );
  }

Exit:
  if (hFile != INVALID_HANDLE_VALUE) {
    CloseHandle (hFile);
  }

  if (ImageBuffer != NULL) {
    free (ImageBuffer);
  }

  if (CompressedImage != NULL) {
    free (CompressedImage);
  }

  EXIT_API ();
  return S_OK;
}
