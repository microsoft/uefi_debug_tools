//**************************************************************************
//
// EfiSymCompositionService.h
//
// Defines the symbol provider service that intercepts LocateSymbolsForImage
//
//**************************************************************************
//
// Copyright (c) Microsoft Corporation.  All rights reserved.
//
//**************************************************************************

#ifndef __EFISYMCOMPOSITIONSERVICE_H__
#define __EFISYMCOMPOSITIONSERVICE_H__

namespace Debugger
{
namespace TargetComposition
{
namespace Services
{
namespace EfiSymComposition
{

// EfiSymCompositionProvider:
//
// A symbol provider that intercepts symbol location requests via LocateSymbolsForImage.
// This provider does not actually provide symbols - it simply gets notified whenever
// the debugger attempts to resolve symbols for an image.
//
class EfiSymCompositionProvider :
    public Microsoft::WRL::RuntimeClass<
        Microsoft::WRL::RuntimeClassFlags<Microsoft::WRL::RuntimeClassType::ClassicCom>,
        IDebugServiceLayer,
        ISvcSymbolProvider
        >
{
public:

    //*************************************************
    // IDebugServiceLayer:
    //

    // RegisterServices():
    //
    // Registers the symbol provider service with the service manager.
    //
    IFACEMETHOD(RegisterServices)(_In_ IDebugServiceManager *pServiceManager)
    {
        HRESULT hr = S_OK;
        m_spServiceManager = pServiceManager;
        IfFailedReturn(pServiceManager->RegisterService(DEBUG_SERVICE_SYMBOL_PROVIDER, this));
        return hr;
    }

    // GetServiceDependencies():
    //
    // Returns the set of services which this service depends on.
    //
    IFACEMETHOD(GetServiceDependencies)(_In_ ServiceNotificationKind /*notificationKind*/,
                                        _In_ IDebugServiceManager * /*pServiceManager*/,
                                        _In_ REFGUID /*serviceGuid*/,
                                        _In_ ULONG64 sizeHardDependencies,
                                        _Out_writes_(sizeHardDependencies) GUID * /*pHardDependencies*/,
                                        _Out_ ULONG64 *pNumHardDependencies,
                                        _In_ ULONG64 sizeSoftDependencies,
                                        _Out_writes_(sizeSoftDependencies) GUID * /*pSoftDependencies*/,
                                        _Out_ ULONG64 *pNumSoftDependencies)
    {
        // No dependencies required
        *pNumHardDependencies = 0;
        *pNumSoftDependencies = 0;
        return S_OK;
    }

    // InitializeServices():
    //
    // Called when the service is being initialized.
    //
    IFACEMETHOD(InitializeServices)(_In_ ServiceNotificationKind /*notificationKind*/,
                                    _In_ IDebugServiceManager * /*pServiceManager*/,
                                    _In_ REFGUID /*serviceGuid*/)
    {
        return S_OK;
    }

    // NotifyServiceChange():
    //
    // Called when a service we depend on changes.
    //
    IFACEMETHOD(NotifyServiceChange)(_In_ ServiceNotificationKind /*notificationKind*/,
                                     _In_ IDebugServiceManager * /*pServiceManager*/,
                                     _In_ REFGUID /*serviceGuid*/,
                                     _In_opt_ IDebugServiceLayer * /*pPriorService*/,
                                     _In_opt_ IDebugServiceLayer * /*pNewService*/)
    {
        return S_OK;
    }

    // NotifyEvent():
    //
    // Called when an event occurs in the service container.
    //
    IFACEMETHOD(NotifyEvent)(_In_ IDebugServiceManager * /*pServiceManager*/,
                             _In_ REFIID /*eventGuid*/,
                             _In_opt_ IUnknown * /*pEventArgument*/)
    {
        return S_OK;
    }

    //*************************************************
    // ISvcSymbolProvider:
    //

    // LocateSymbolsForImage():
    //
    // Called by the debugger when it needs to locate symbols for a particular image.
    // This is our callback point to observe symbol resolution attempts.
    //
    // We return E_UNHANDLED_REQUEST_TYPE to indicate we don't provide symbols,
    // allowing other providers to handle the request.
    //
    IFACEMETHOD(LocateSymbolsForImage)(_In_ ISvcModule *pImage,
                                       _COM_Outptr_ ISvcSymbolSet **ppSymbolSet)
    {
        *ppSymbolSet = nullptr;

        HRESULT hr = S_OK;

        // Get the base address of the module
        ULONG64 baseAddress = 0;
        hr = pImage->GetBaseAddress(&baseAddress);
        if (FAILED(hr) || baseAddress == 0)
        {
            return E_UNHANDLED_REQUEST_TYPE;
        }

        // Query for memory access service
        Microsoft::WRL::ComPtr<ISvcMemoryAccess> spMemory;
        hr = m_spServiceManager->QueryService(DEBUG_SERVICE_VIRTUAL_MEMORY, IID_PPV_ARGS(&spMemory));
        if (FAILED(hr))
        {
            return E_UNHANDLED_REQUEST_TYPE;
        }

        // Get kernel/machine address context (bare metal UEFI debugging has no process context)
        Microsoft::WRL::ComPtr<ISvcMachineDebug> spMachineDebug;
        hr = m_spServiceManager->QueryService(DEBUG_SERVICE_MACHINE, IID_PPV_ARGS(&spMachineDebug));
        if (FAILED(hr))
        {
            return E_UNHANDLED_REQUEST_TYPE;
        }

        Microsoft::WRL::ComPtr<ISvcAddressContext> spAddrCtx;
        hr = spMachineDebug->GetDefaultAddressContext(&spAddrCtx);
        if (FAILED(hr))
        {
            return E_UNHANDLED_REQUEST_TYPE;
        }

        // Read DOS header
        IMAGE_DOS_HEADER dosHeader = {};
        ULONG64 bytesRead = 0;
        hr = spMemory->ReadMemory(spAddrCtx.Get(), baseAddress, &dosHeader, sizeof(dosHeader), &bytesRead);
        if (FAILED(hr) || bytesRead != sizeof(dosHeader))
        {
            return E_UNHANDLED_REQUEST_TYPE;
        }

        // Validate DOS signature
        if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
        {
            return E_UNHANDLED_REQUEST_TYPE;
        }

        // Read NT headers
        ULONG64 ntHeadersAddress = baseAddress + dosHeader.e_lfanew;
        IMAGE_NT_HEADERS64 ntHeaders = {};
        hr = spMemory->ReadMemory(spAddrCtx.Get(), ntHeadersAddress, &ntHeaders, sizeof(ntHeaders), &bytesRead);
        if (FAILED(hr) || bytesRead != sizeof(ntHeaders))
        {
            return E_UNHANDLED_REQUEST_TYPE;
        }

        // Validate PE signature
        if (ntHeaders.Signature != IMAGE_NT_SIGNATURE)
        {
            return E_UNHANDLED_REQUEST_TYPE;
        }

        // Check for EFI subsystem types, otherwise not an EFI image
        WORD subsystem = ntHeaders.OptionalHeader.Subsystem;
        if (subsystem != IMAGE_SUBSYSTEM_EFI_APPLICATION &&
            subsystem != IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER &&
            subsystem != IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER &&
            subsystem != IMAGE_SUBSYSTEM_EFI_ROM)
        {
            return E_UNHANDLED_REQUEST_TYPE;
        }

        // This is an EFI image! Now get the debug directory for symbol path
        DWORD debugDirRva = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;
        DWORD debugDirSize = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;

        if (debugDirRva != 0 && debugDirSize >= sizeof(IMAGE_DEBUG_DIRECTORY))
        {
            // Read debug directory
            IMAGE_DEBUG_DIRECTORY debugDir = {};
            hr = spMemory->ReadMemory(spAddrCtx.Get(), baseAddress + debugDirRva, &debugDir, sizeof(debugDir), &bytesRead);
            if (SUCCEEDED(hr) && bytesRead == sizeof(debugDir))
            {
                // Check if this is a CodeView debug entry
                if (debugDir.Type == IMAGE_DEBUG_TYPE_CODEVIEW && debugDir.AddressOfRawData != 0)
                {
                    // Read CodeView signature
                    DWORD cvSignature = 0;
                    hr = spMemory->ReadMemory(spAddrCtx.Get(), baseAddress + debugDir.AddressOfRawData, &cvSignature, sizeof(cvSignature), &bytesRead);
                    if (SUCCEEDED(hr) && bytesRead == sizeof(cvSignature))
                    {
                        char pdbPath[MAX_PATH] = {};
                        ULONG64 pdbPathOffset = 0;

                        if (cvSignature == 0x53445352) // 'RSDS'
                        {
                            // RSDS format: Signature(4) + GUID(16) + Age(4) + PDB path string
                            pdbPathOffset = baseAddress + debugDir.AddressOfRawData + sizeof(DWORD) + 16 + sizeof(DWORD);
                        }
                        else if (cvSignature == 0x3031424E) // 'NB10'
                        {
                            // NB10 format: Signature(4) + Offset(4) + Timestamp(4) + Age(4) + PDB path string
                            pdbPathOffset = baseAddress + debugDir.AddressOfRawData + sizeof(DWORD) + sizeof(DWORD) + sizeof(DWORD) + sizeof(DWORD);
                        }

                        if (pdbPathOffset != 0)
                        {
                            hr = spMemory->ReadMemory(spAddrCtx.Get(), pdbPathOffset, pdbPath, sizeof(pdbPath) - 1, &bytesRead);
                            if (SUCCEEDED(hr) && bytesRead > 0)
                            {
                                pdbPath[sizeof(pdbPath) - 1] = '\0';

                                // Check if this is a ELF file path
                                if (strstr(pdbPath, ".dll") != NULL || strstr(pdbPath, ".debug") != NULL)
                                {
                                    // This is an EFI image with ELF debug info
                                    // Try to locate the .bldid section
                                    PVOID pBldIdData = nullptr;
                                    SIZE_T bldIdSize = 0;
                                    std::unique_ptr<BYTE[]> bldIdBuffer;

                                    // Read section headers
                                    WORD numSections = ntHeaders.FileHeader.NumberOfSections;
                                    ULONG64 sectionHeadersAddress = ntHeadersAddress + FIELD_OFFSET(IMAGE_NT_HEADERS64, OptionalHeader) + ntHeaders.FileHeader.SizeOfOptionalHeader;

                                    for (WORD i = 0; i < numSections; i++)
                                    {
                                        IMAGE_SECTION_HEADER sectionHeader = {};
                                        hr = spMemory->ReadMemory(spAddrCtx.Get(), sectionHeadersAddress + (i * sizeof(IMAGE_SECTION_HEADER)), &sectionHeader, sizeof(sectionHeader), &bytesRead);
                                        if (SUCCEEDED(hr) && bytesRead == sizeof(sectionHeader))
                                        {
                                            // Check if this is the .bldid section
                                            if (strcmp((const char*)sectionHeader.Name, ".bldid") == 0 && sectionHeader.SizeOfRawData > 0)
                                            {
                                                // Allocate buffer and read the section data
                                                bldIdSize = sectionHeader.SizeOfRawData;
                                                bldIdBuffer = std::make_unique<BYTE[]>(bldIdSize);
                                                hr = spMemory->ReadMemory(spAddrCtx.Get(), baseAddress + sectionHeader.VirtualAddress, bldIdBuffer.get(), bldIdSize, &bytesRead);
                                                if (SUCCEEDED(hr) && bytesRead == bldIdSize)
                                                {
                                                    pBldIdData = bldIdBuffer.get();
                                                }
                                                break;
                                            }
                                        }
                                    }

                                    // Call LoadEfiSymbols to handle file search and delegate to ElfBinComposition
                                    if (LoadEfiSymbols(baseAddress, pdbPath, ppSymbolSet, m_spSymbolProvider.Get(), m_spDebugClient.Get(), pBldIdData, bldIdSize))
                                    {
                                        // Successfully loaded symbols
                                        return S_OK;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        return E_UNHANDLED_REQUEST_TYPE;
    }

    //*************************************************
    // Internal APIs:
    //

    // RuntimeClassInitialize():
    //
    // Initializes the symbol locator provider.
    //
    HRESULT RuntimeClassInitialize()
    {
        return S_OK;
    }

    VOID SetSymbolProvider(_In_ ISvcSymbolProvider2 *pProvider)
    {
        m_spSymbolProvider = pProvider;
    }

    VOID SetDebugClient(_In_opt_ IDebugClient *pClient)
    {
        m_spDebugClient = pClient;
    }

private:

    // Service manager for querying other services
    Microsoft::WRL::ComPtr<IDebugServiceManager> m_spServiceManager;
    Microsoft::WRL::ComPtr<ISvcSymbolProvider2> m_spSymbolProvider;
    Microsoft::WRL::ComPtr<IDebugClient> m_spDebugClient;

};

} // EfiSymComposition
} // Services
} // TargetComposition
} // Debugger

#endif // __EFISYMCOMPOSITIONSERVICE_H__
