
#include "EfiSymComposition.h"
#include <shlwapi.h>

#pragma comment(lib, "shlwapi.lib")

// Simple file wrapper that implements ISvcDebugSourceFile
class DebugSourceFile : public Microsoft::WRL::RuntimeClass<
    Microsoft::WRL::RuntimeClassFlags<Microsoft::WRL::RuntimeClassType::ClassicCom>,
    ISvcDebugSourceFile>
{
public:
    HRESULT RuntimeClassInitialize(_In_ PCSTR filePath)
    {
        m_hFile = CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ, nullptr,
                             OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (m_hFile == INVALID_HANDLE_VALUE)
        {
            return HRESULT_FROM_WIN32(GetLastError());
        }
        return S_OK;
    }

    ~DebugSourceFile()
    {
        if (m_hFile != INVALID_HANDLE_VALUE)
        {
            CloseHandle(m_hFile);
        }
    }

    IFACEMETHOD(Read)(_In_ ULONG64 byteOffset,
                     _Out_writes_to_(readSize, *bytesRead) PVOID buffer,
                     _In_ ULONG64 readSize,
                     _Out_ PULONG64 bytesRead) override
    {
        *bytesRead = 0;

        LARGE_INTEGER offset;
        offset.QuadPart = byteOffset;
        if (!SetFilePointerEx(m_hFile, offset, nullptr, FILE_BEGIN))
        {
            return HRESULT_FROM_WIN32(GetLastError());
        }

        DWORD dwBytesRead = 0;
        DWORD dwReadSize = (readSize > MAXDWORD) ? MAXDWORD : (DWORD)readSize;

        if (!ReadFile(m_hFile, buffer, dwReadSize, &dwBytesRead, nullptr))
        {
            return HRESULT_FROM_WIN32(GetLastError());
        }

        *bytesRead = dwBytesRead;
        return (dwBytesRead == dwReadSize) ? S_OK : S_FALSE;
    }

    IFACEMETHOD(Write)(_In_ ULONG64 byteOffset,
                      _In_reads_(writeSize) PVOID buffer,
                      _In_ ULONG64 writeSize,
                      _Out_ PULONG64 bytesWritten) override
    {
        // Not implemented for read-only access
        *bytesWritten = 0;
        return E_NOTIMPL;
    }

private:
    HANDLE m_hFile = INVALID_HANDLE_VALUE;
};

BOOLEAN LoadEfiSymbols(ULONG64 BaseAddress, PCSTR FilePath, _COM_Outptr_ ISvcSymbolSet **ppSymbolSet, _In_ ISvcModule *pImage)
{
    if (FilePath == nullptr || FilePath[0] == '\0' || BaseAddress == 0 || pImage == nullptr)
    {
        return FALSE;
    }

    // Get the debug client for logging
    ComPtr<IDebugClient> spDebugClient;
    HRESULT hr = DebugCreate(__uuidof(IDebugClient), &spDebugClient);
    if (FAILED(hr))
    {
        return FALSE;
    }

    ComPtr<IDebugControl> spControl;
    hr = spDebugClient.As(&spControl);
    if (FAILED(hr))
    {
        return FALSE;
    }

    spControl->Output(DEBUG_OUTPUT_SYMBOLS, "EfiSymComposition: Loading EFI symbols for base %I64x, PDB path: %s\n", BaseAddress, FilePath);

    // Get symbols interface for symbol path
    ComPtr<IDebugSymbols3> spSymbols;
    hr = spDebugClient.As(&spSymbols);
    if (FAILED(hr))
    {
        return FALSE;
    }

    // Get the symbol path
    ULONG pathSize = 0;
    hr = spSymbols->GetSymbolPath(nullptr, 0, &pathSize);
    if (FAILED(hr))
    {
        return FALSE;
    }

    std::vector<char> symbolPath(pathSize);
    hr = spSymbols->GetSymbolPath(symbolPath.data(), pathSize, nullptr);
    if (FAILED(hr))
    {
        spControl->Output(DEBUG_OUTPUT_SYMBOLS, "EfiSymComposition: Failed to get symbol path (hr=0x%08x)\n", hr);
        return FALSE;
    }

    spControl->Output(DEBUG_OUTPUT_SYMBOLS, "EfiSymComposition: Symbol path: %s\n", symbolPath.data());

    // Extract just the filename from the PDB path
    const char* fileName = strrchr(FilePath, '\\');
    if (fileName == nullptr)
    {
        fileName = strrchr(FilePath, '/');
    }
    if (fileName != nullptr)
    {
        fileName++; // Skip the slash
    }
    else
    {
        fileName = FilePath;
    }

    // If this is a .dll file, convert to a .debug filename. The symbol path is unlikely to include the .dll.
    char fixedName[MAX_PATH];
    if (strstr(fileName, ".dll") != nullptr)
    {
        strcpy_s(fixedName, sizeof(fixedName), fileName);
        char* ext = strrchr(fixedName, '.');
        if (ext != nullptr)
        {
            strcpy_s(ext, sizeof(fixedName) - (ext - fixedName), ".debug");
        }
        fileName = fixedName;
        spControl->Output(DEBUG_OUTPUT_SYMBOLS, "EfiSymComposition: Converted .dll to .debug: %s\n", fileName);
    } else {
        strcpy_s(fixedName, sizeof(fixedName), fileName);
        fileName = fixedName;
    }

    spControl->Output(DEBUG_OUTPUT_SYMBOLS, "EfiSymComposition: Searching for symbol file: %s\n", fileName);

    // Parse the symbol path and search for the PDB file
    // Symbol path is semicolon-delimited
    char* pathContext = nullptr;
    char* pathCopy = _strdup(symbolPath.data());
    if (pathCopy == nullptr)
    {
        return FALSE;
    }

    BOOLEAN found = FALSE;
    char fullPath[MAX_PATH];
    char* token = strtok_s(pathCopy, ";", &pathContext);

    while (token != nullptr && !found)
    {
        // Skip srv* and symsrv* prefixes for symbol servers
        if (_strnicmp(token, "srv*", 4) == 0 || _strnicmp(token, "symsrv*", 7) == 0)
        {
            // Symbol server path - we'll let the debugger handle this
            token = strtok_s(nullptr, ";", &pathContext);
            continue;
        }

        // Build full path to potential PDB file
        if (PathCombineA(fullPath, token, fileName))
        {
            spControl->Output(DEBUG_OUTPUT_SYMBOLS, "EfiSymComposition: Checking path: %s\n", fullPath);

            // Check if file exists
            DWORD attribs = GetFileAttributesA(fullPath);
            if (attribs != INVALID_FILE_ATTRIBUTES && !(attribs & FILE_ATTRIBUTE_DIRECTORY))
            {
                spControl->Output(DEBUG_OUTPUT_SYMBOLS, "EfiSymComposition: Found symbol file: %s\n", fullPath);

                // TODO: Layer on top of ElfBinComposition and use OpenSymbols to have it load the ELF based .debug file.

                found = TRUE;
                break;
            }
        }

        token = strtok_s(nullptr, ";", &pathContext);
    }

    free(pathCopy);

    if (!found)
    {
        spControl->Output(DEBUG_OUTPUT_SYMBOLS, "EfiSymComposition: Symbol file not found for %s\n", FilePath);
    }

    return found;
}
