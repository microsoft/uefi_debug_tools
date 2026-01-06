
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

// Helper function to verify build-id matches between image and ELF debug file
static bool VerifyBuildId(_In_ PCSTR elfFilePath, _In_ PVOID pBldIdData, _In_ SIZE_T bldIdSize)
{
    HANDLE hElfFile = CreateFileA(elfFilePath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hElfFile == INVALID_HANDLE_VALUE)
    {
        return false;
    }

    bool buildIdMatches = false;

    // Parse the build-id from the image's .build-id section
    // The format is: namesz(4) descsz(4) type(4) name(aligned) desc(aligned)
    BYTE* buildIdBytes = (BYTE*)pBldIdData;
    DWORD imageBuildIdSize = 0;
    BYTE* pImageBuildId = nullptr;

    if (bldIdSize >= 12)
    {
        DWORD namesz = *(DWORD*)&buildIdBytes[0];
        DWORD descsz = *(DWORD*)&buildIdBytes[4];
        DWORD type = *(DWORD*)&buildIdBytes[8];

        // GNU build-id note has type 3 and name "GNU\0"
        if (type == 3 && namesz == 4 && bldIdSize >= 12 + namesz + descsz)
        {
            SIZE_T nameEnd = 12 + namesz;
            SIZE_T alignedNameEnd = (nameEnd + 3) & ~3;

            if (memcmp(&buildIdBytes[12], "GNU\0", 4) == 0)
            {
                pImageBuildId = &buildIdBytes[alignedNameEnd];
                imageBuildIdSize = descsz;
            }
        }
    }

    if (pImageBuildId == nullptr || imageBuildIdSize == 0)
    {
        CloseHandle(hElfFile);
        return false;
    }

    // Read ELF header to find section headers
    BYTE elfHeader[64] = {};
    DWORD dwRead = 0;
    if (ReadFile(hElfFile, elfHeader, sizeof(elfHeader), &dwRead, nullptr) && dwRead >= 52)
    {
        // Parse ELF header (support both 32-bit and 64-bit)
        bool is64bit = (elfHeader[4] == 2); // EI_CLASS: 1=32-bit, 2=64-bit
        ULONG64 shoff = 0;  // Section header offset
        WORD shentsize = 0; // Section header entry size
        WORD shnum = 0;     // Number of section headers
        WORD shstrndx = 0;  // Section name string table index

        if (is64bit && dwRead >= 64)
        {
            shoff = *(ULONG64*)&elfHeader[40];
            shentsize = *(WORD*)&elfHeader[58];
            shnum = *(WORD*)&elfHeader[60];
            shstrndx = *(WORD*)&elfHeader[62];
        }
        else
        {
            shoff = *(DWORD*)&elfHeader[32];
            shentsize = *(WORD*)&elfHeader[46];
            shnum = *(WORD*)&elfHeader[48];
            shstrndx = *(WORD*)&elfHeader[50];
        }

        // Read section name string table
        std::unique_ptr<BYTE[]> shstrtab;
        ULONG64 shstrtabSize = 0;
        if (shstrndx < shnum)
        {
            LARGE_INTEGER shstrtabHeaderOffset;
            shstrtabHeaderOffset.QuadPart = shoff + (shstrndx * shentsize);
            SetFilePointer(hElfFile, shstrtabHeaderOffset.LowPart, &shstrtabHeaderOffset.HighPart, FILE_BEGIN);

            BYTE shstrtabHeader[64] = {};
            if (ReadFile(hElfFile, shstrtabHeader, shentsize, &dwRead, nullptr) && dwRead == shentsize)
            {
                ULONG64 shstrtabOffset = 0;
                if (is64bit)
                {
                    shstrtabOffset = *(ULONG64*)&shstrtabHeader[24];
                    shstrtabSize = *(ULONG64*)&shstrtabHeader[32];
                }
                else
                {
                    shstrtabOffset = *(DWORD*)&shstrtabHeader[16];
                    shstrtabSize = *(DWORD*)&shstrtabHeader[20];
                }

                if (shstrtabSize > 0 && shstrtabSize < 1024 * 1024) // Sanity check
                {
                    shstrtab = std::make_unique<BYTE[]>((SIZE_T)shstrtabSize);
                    LARGE_INTEGER strtabOffset;
                    strtabOffset.QuadPart = shstrtabOffset;
                    SetFilePointer(hElfFile, strtabOffset.LowPart, &strtabOffset.HighPart, FILE_BEGIN);
                    ReadFile(hElfFile, shstrtab.get(), (DWORD)shstrtabSize, &dwRead, nullptr);
                }
            }
        }

        // Search for .build-id section in the ELF debug file
        for (WORD i = 0; i < shnum && !buildIdMatches; i++)
        {
            LARGE_INTEGER sectionOffset;
            sectionOffset.QuadPart = shoff + (i * shentsize);
            SetFilePointer(hElfFile, sectionOffset.LowPart, &sectionOffset.HighPart, FILE_BEGIN);

            BYTE sectionHeader[64] = {};
            if (ReadFile(hElfFile, sectionHeader, shentsize, &dwRead, nullptr) && dwRead == shentsize)
            {
                DWORD sh_name = *(DWORD*)&sectionHeader[0];
                DWORD sh_type = *(DWORD*)&sectionHeader[4];
                ULONG64 sh_offset = 0;
                ULONG64 sh_size = 0;

                if (is64bit)
                {
                    sh_offset = *(ULONG64*)&sectionHeader[24];
                    sh_size = *(ULONG64*)&sectionHeader[32];
                }
                else
                {
                    sh_offset = *(DWORD*)&sectionHeader[16];
                    sh_size = *(DWORD*)&sectionHeader[20];
                }

                // Check if this is a .build-id section by name
                if (shstrtab && sh_name < shstrtabSize)
                {
                    const char* sectionName = (const char*)&shstrtab[sh_name];
                    if (strcmp(sectionName, ".build-id") == 0 && sh_size > 0)
                    {
                        // Read .build-id section data
                        std::unique_ptr<BYTE[]> noteData = std::make_unique<BYTE[]>((SIZE_T)sh_size);
                        LARGE_INTEGER noteOffset;
                        noteOffset.QuadPart = sh_offset;
                        SetFilePointer(hElfFile, noteOffset.LowPart, &noteOffset.HighPart, FILE_BEGIN);

                        if (ReadFile(hElfFile, noteData.get(), (DWORD)sh_size, &dwRead, nullptr) && dwRead == sh_size)
                        {
                            // Parse note entries (name size, desc size, type, name, desc)
                            SIZE_T offset = 0;
                            while (offset + 12 <= sh_size)
                            {
                                DWORD namesz = *(DWORD*)&noteData[offset];
                                DWORD descsz = *(DWORD*)&noteData[offset + 4];
                                DWORD type = *(DWORD*)&noteData[offset + 8];
                                offset += 12;

                                // Align name
                                SIZE_T nameEnd = offset + namesz;
                                SIZE_T alignedNameEnd = (nameEnd + 3) & ~3;

                                // Check if this is a GNU build-id note (type 3)
                                if (type == 3 && namesz >= 4 && offset + namesz <= sh_size)
                                {
                                    if (memcmp(&noteData[offset], "GNU\0", 4) == 0)
                                    {
                                        offset = alignedNameEnd;

                                        // Compare build-id from ELF debug file with image's build-id
                                        if (offset + descsz <= sh_size && descsz == imageBuildIdSize)
                                        {
                                            if (memcmp(&noteData[offset], pImageBuildId, imageBuildIdSize) == 0)
                                            {
                                                buildIdMatches = true;
                                                break;
                                            }
                                        }
                                    }
                                }

                                offset = alignedNameEnd + ((descsz + 3) & ~3);
                            }
                        }
                        break;
                    }
                }
            }
        }
    }

    CloseHandle(hElfFile);
    return buildIdMatches;
}

BOOLEAN LoadEfiSymbols(ULONG64 BaseAddress,
                       PCSTR FilePath,
                       _COM_Outptr_ ISvcSymbolSet **ppSymbolSet,
                       _In_ ISvcSymbolProvider2 *spSymbolProvider2,
                       _In_opt_ IDebugClient *pDebugClient,
                       _In_opt_ PVOID pBldIdData,
                       _In_ SIZE_T bldIdSize)

{
    if (FilePath == nullptr || FilePath[0] == '\0' || BaseAddress == 0 || spSymbolProvider2 == nullptr || (pBldIdData == nullptr && bldIdSize != 0))
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

    if (spControl)
        spControl->Output(DEBUG_OUTPUT_SYMBOLS,
                         "EfiSymComposition: Loading EFI symbols for base %I64x, PDB path: %s, Build-ID Size: %llu\n",
                         BaseAddress,
                         FilePath,
                         bldIdSize);

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
        if (spControl)
            spControl->Output(DEBUG_OUTPUT_SYMBOLS, "EfiSymComposition: Failed to get symbol path from debugger, using default\n");
        strcpy_s(symbolPathBuf, sizeof(symbolPathBuf), "D:\\wslsym;D:\\sym");
    }

    if (spControl)
        spControl->Output(DEBUG_OUTPUT_SYMBOLS, "EfiSymComposition: Symbol path: %s\n", symbolPathBuf);

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
        if (spControl)
            spControl->Output(DEBUG_OUTPUT_SYMBOLS, "EfiSymComposition: Converted .dll to .debug: %s\n", fileName);
    } else {
        strcpy_s(fixedName, sizeof(fixedName), fileName);
        fileName = fixedName;
    }

    if (spControl)
        spControl->Output(DEBUG_OUTPUT_SYMBOLS, "EfiSymComposition: Searching for symbol file: %s\n", fileName);

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

    while (token != nullptr)
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
            if (spControl)
                spControl->Output(DEBUG_OUTPUT_SYMBOLS, "EfiSymComposition: Checking path: %s\n", fullPath);

            // Check if file exists
            DWORD attribs = GetFileAttributesA(fullPath);
            if (attribs != INVALID_FILE_ATTRIBUTES && !(attribs & FILE_ATTRIBUTE_DIRECTORY))
            {
                if (bldIdSize > 0 && pBldIdData != nullptr)
                {
                    // Verify the build-id matches
                    if (!VerifyBuildId(fullPath, pBldIdData, bldIdSize))
                    {
                        // Build-ID mismatch, skip this file
                        if (spControl)
                            spControl->Output(DEBUG_OUTPUT_SYMBOLS, "EfiSymComposition: Build-ID mismatch for %s, skipping\n", fullPath);
                        token = strtok_s(nullptr, ";", &pathContext);
                        continue;
                    }
                }

                if (spControl)
                    spControl->Output(DEBUG_OUTPUT_SYMBOLS, "EfiSymComposition: Found symbol file: %s\n", fullPath);

                // Create debug source file for the .debug file
                ComPtr<ISvcDebugSourceFile> spDebugFile;
                hr = Microsoft::WRL::MakeAndInitialize<DebugSourceFile>(&spDebugFile, fullPath);
                if (FAILED(hr))
                {
                    if (spControl)
                        spControl->Output(DEBUG_OUTPUT_SYMBOLS, "EfiSymComposition: Failed to create debug source file (hr=0x%08x)\n", hr);
                    goto Exit;
                }

                // open symbols
                hr = spSymbolProvider2->OpenSymbols(
                    spDebugFile.Get(),
                    nullptr,
                    nullptr,
                    BaseAddress,
                    0,
                    ppSymbolSet
                );

                if (FAILED(hr))
                {
                    if (spControl)
                        spControl->Output(DEBUG_OUTPUT_SYMBOLS, "EfiSymComposition: Failed to open symbols (hr=0x%08x)\n", hr);
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
        if (spControl)
            spControl->Output(DEBUG_OUTPUT_SYMBOLS, "EfiSymComposition: Symbol file not found for %s\n", FilePath);
    }

    return found;
}
