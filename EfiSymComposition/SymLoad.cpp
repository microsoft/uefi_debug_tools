
#include "EfiSymComposition.h"
#include <shlwapi.h>

#pragma comment(lib, "shlwapi.lib")

BOOLEAN LoadEfiSymbols (ULONG64 BaseAddress, PCSTR FilePath) {
    if (FilePath == nullptr || FilePath[0] == '\0' || BaseAddress == 0)
    {
        return FALSE;
    }

    // Get the debug client to access symbol functions
    ComPtr<IDebugClient> spDebugClient;
    HRESULT hr = DebugCreate(__uuidof(IDebugClient), &spDebugClient);
    if (FAILED(hr))
    {
        return FALSE;
    }

    // Get symbols interface
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
        return FALSE;
    }

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
        fileName = FilePath; // No path separator, use the whole string
    }

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
            // Check if file exists
            DWORD attribs = GetFileAttributesA(fullPath);
            if (attribs != INVALID_FILE_ATTRIBUTES && !(attribs & FILE_ATTRIBUTE_DIRECTORY))
            {
                // Found the PDB file!
                found = TRUE;

                // TODO: Actually load the symbols using this path
                // For now, we've validated the file exists in the symbol path
                break;
            }
        }

        token = strtok_s(nullptr, ";", &pathContext);
    }

    free(pathCopy);
    return found;
}
