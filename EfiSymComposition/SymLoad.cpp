
#include "EfiSymComposition.h"
#include <shlwapi.h>

#pragma comment(lib, "shlwapi.lib")

// Simple file wrapper that implements ISvcDebugSourceFile
class DebugSourceFile final : public Microsoft::WRL::RuntimeClass<
    Microsoft::WRL::RuntimeClassFlags<Microsoft::WRL::RuntimeClassType::ClassicCom>,
    ISvcDebugSourceFile,
    ISvcDebugSourceFileMapping>
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
        if (m_pMappedView != nullptr)
        {
            UnmapViewOfFile(m_pMappedView);
        }
        if (m_hMapping != nullptr)
        {
            CloseHandle(m_hMapping);
        }
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

    // ISvcDebugSourceFileMapping methods
    IFACEMETHOD(MapFile)(_Out_ PVOID *mapAddress, _Out_ PULONG64 mapSize) override
    {
        *mapAddress = nullptr;
        *mapSize = 0;

        if (m_hFile == INVALID_HANDLE_VALUE)
        {
            return E_HANDLE;
        }

        // If already mapped, return the existing mapping
        if (m_pMappedView != nullptr)
        {
            *mapAddress = m_pMappedView;
            *mapSize = m_mappedSize;
            return S_OK;
        }

        // Get file size
        LARGE_INTEGER fileSize;
        if (!GetFileSizeEx(m_hFile, &fileSize))
        {
            return HRESULT_FROM_WIN32(GetLastError());
        }

        if (fileSize.QuadPart == 0)
        {
            // Empty file - return success with null mapping
            return S_OK;
        }

        // Create file mapping object
        m_hMapping = CreateFileMappingA(m_hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
        if (m_hMapping == nullptr)
        {
            return HRESULT_FROM_WIN32(GetLastError());
        }

        // Map view of the entire file
        m_pMappedView = MapViewOfFile(m_hMapping, FILE_MAP_READ, 0, 0, 0);
        if (m_pMappedView == nullptr)
        {
            HRESULT hr = HRESULT_FROM_WIN32(GetLastError());
            CloseHandle(m_hMapping);
            m_hMapping = nullptr;
            return hr;
        }

        m_mappedSize = fileSize.QuadPart;
        *mapAddress = m_pMappedView;
        *mapSize = m_mappedSize;
        return S_OK;
    }

    IFACEMETHOD(GetHandle)(_Out_ HANDLE *pHandle) override
    {
        *pHandle = m_hFile;
        return S_OK;
    }

private:
    HANDLE m_hFile = INVALID_HANDLE_VALUE;
    HANDLE m_hMapping = nullptr;
    PVOID m_pMappedView = nullptr;
    ULONG64 m_mappedSize = 0;
};

BOOLEAN LoadEfiSymbols(ULONG64 BaseAddress, PCSTR FilePath, _COM_Outptr_ ISvcSymbolSet **ppSymbolSet, _In_ ISvcSymbolProvider2 *spSymbolProvider2, _In_opt_ IDebugClient *pDebugClient)
{
    if (FilePath == nullptr || FilePath[0] == '\0' || BaseAddress == 0 || spSymbolProvider2 == nullptr)
    {
        return FALSE;
    }

    HRESULT hr = S_OK;

    // Get debug control interface for logging
    ComPtr<IDebugControl> spControl;
    if (pDebugClient != nullptr)
    {
        pDebugClient->QueryInterface(IID_PPV_ARGS(&spControl));
    }

    if (spControl) spControl->Output(DEBUG_OUTPUT_SYMBOLS, "EfiSymComposition: Loading EFI symbols for base %I64x, PDB path: %s\n", BaseAddress, FilePath);

    // Get symbol path from debugger if available
    char symbolPathBuf[4096] = {0};

    if (pDebugClient != nullptr)
    {
        ComPtr<IDebugSymbols3> spSymbols;
        if (SUCCEEDED(pDebugClient->QueryInterface(IID_PPV_ARGS(&spSymbols))))
        {
            ULONG pathSize = 0;
            spSymbols->GetSymbolPath(symbolPathBuf, sizeof(symbolPathBuf), &pathSize);
        }
    }

    // Fallback to default if we couldn't get the symbol path
    if (symbolPathBuf[0] == '\0')
    {
        if (spControl) spControl->Output(DEBUG_OUTPUT_SYMBOLS, "EfiSymComposition: Failed to get symbol path from debugger, using default\n");
        strcpy_s(symbolPathBuf, sizeof(symbolPathBuf), "D:\\wslsym;D:\\sym");
    }

    if (spControl) spControl->Output(DEBUG_OUTPUT_SYMBOLS, "EfiSymComposition: Symbol path: %s\n", symbolPathBuf);

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
        if (spControl) spControl->Output(DEBUG_OUTPUT_SYMBOLS, "EfiSymComposition: Converted .dll to .debug: %s\n", fileName);
    } else {
        strcpy_s(fixedName, sizeof(fixedName), fileName);
        fileName = fixedName;
    }

    if (spControl) spControl->Output(DEBUG_OUTPUT_SYMBOLS, "EfiSymComposition: Searching for symbol file: %s\n", fileName);

    // Parse the symbol path and search for the PDB file
    // Symbol path is semicolon-delimited
    char* pathContext = nullptr;
    char* pathCopy = _strdup(symbolPathBuf);
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
            if (spControl) spControl->Output(DEBUG_OUTPUT_SYMBOLS, "EfiSymComposition: Checking path: %s\n", fullPath);

            // Check if file exists
            DWORD attribs = GetFileAttributesA(fullPath);
            if (attribs != INVALID_FILE_ATTRIBUTES && !(attribs & FILE_ATTRIBUTE_DIRECTORY))
            {
                if (spControl) spControl->Output(DEBUG_OUTPUT_SYMBOLS, "EfiSymComposition: Found symbol file: %s\n", fullPath);

                // Create debug source file for the .debug file
                ComPtr<ISvcDebugSourceFile> spDebugFile;
                hr = Microsoft::WRL::MakeAndInitialize<DebugSourceFile>(&spDebugFile, fullPath);
                if (FAILED(hr))
                {
                    if (spControl) spControl->Output(DEBUG_OUTPUT_SYMBOLS, "EfiSymComposition: Failed to create debug source file (hr=0x%08x)\n", hr);
                    goto Exit;
                }

                // open symbols
                hr = spSymbolProvider2->OpenSymbols(
                    spDebugFile.Get(),
                    nullptr,
                    nullptr,
                    BaseAddress,
                    ppSymbolSet
                );

                if (FAILED(hr))
                {
                    if (spControl) spControl->Output(DEBUG_OUTPUT_SYMBOLS, "EfiSymComposition: Failed to open symbols (hr=0x%08x)\n", hr);
                    goto Exit;
                }

                found = TRUE;
                break;
            }
        }

        token = strtok_s(nullptr, ";", &pathContext);
    }

Exit:
    free(pathCopy);

    if (!found)
    {
        if (spControl) spControl->Output(DEBUG_OUTPUT_SYMBOLS, "EfiSymComposition: Symbol file not found for %s\n", FilePath);
    }

    return found;
}
