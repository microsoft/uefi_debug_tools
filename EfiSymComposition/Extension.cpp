//**************************************************************************
//
// Extension.cpp
//
// Main export functions to be a debugger extension. This extension registers
// a symbol provider that intercepts LocateSymbolsForImage callbacks.
//
//**************************************************************************
//
// Copyright (c) Microsoft Corporation.  All rights reserved.
//
//**************************************************************************

#include "EfiSymComposition.h"

using namespace Microsoft::WRL;
using namespace Debugger::TargetComposition::Services::EfiSymComposition;

//**************************************************************************
// Classic DbgEng Style Initialization:
//
// The symbol provider is automatically discovered through the extension DLL.
//

extern "C"
HRESULT CALLBACK DebugExtensionInitialize(PULONG /*pVersion*/, PULONG /*pFlags*/)
{
    HRESULT hr = S_OK;

    //
    // Get the debug client to access the service manager
    //
    ComPtr<IDebugClient> spClient;
    hr = DebugCreate(__uuidof(IDebugClient), (void**)&spClient);
    if (FAILED(hr))
    {
        return hr;
    }

    //
    // Get the composition bridge
    //
    ComPtr<IDebugTargetCompositionBridge> spCompositionBridge;
    hr = spClient.As(&spCompositionBridge);
    if (FAILED(hr))
    {
        return hr;
    }

    //
    // Get the service manager for the current composition
    //
    ULONG systemId = 0;
    ComPtr<IDebugServiceManager> spServiceManager;
    hr = spCompositionBridge->GetServiceManager(systemId, &spServiceManager);
    if (FAILED(hr))
    {
        return hr;
    }

    //
    // Create and initialize our symbol provider service
    //
    ComPtr<EfiSymCompositionProvider> spProvider;
    hr = MakeAndInitialize<EfiSymCompositionProvider>(&spProvider);
    if (FAILED(hr))
    {
        return hr;
    }

    //
    // Register the symbol provider service.
    // This will cause LocateSymbolsForImage to be called for every module symbol resolution.
    //
    hr = spProvider->RegisterServices(spServiceManager.Get());
    if (FAILED(hr))
    {
        return hr;
    }

    //
    // Make sure that Elf composition is loaded.
    //
    ComPtr<IDebugControl> spControl;
    if (FAILED(spClient.As(&spControl)))
    {
        return hr;
    }

    hr = spControl->Execute(DEBUG_OUTCTL_IGNORE,
                            ".load ElfBinComposition",
                            DEBUG_EXECUTE_NOT_LOGGED);
    if (FAILED(hr))
    {
        return hr;
    }

    //
    // Create the elf service and stash the pointer for later use.
    //
    ComPtr<IDebugTargetComposition> spCompositionManager;
    IfFailedReturn(spCompositionBridge->GetCompositionManager(&spCompositionManager));

    ComPtr<IDebugServiceLayer> spElfProvider;
    IfFailedReturn(spCompositionManager->CreateComponent(DEBUG_COMPONENT_ELFIMAGE_SYMBOLPROVIDER,
                                                         &spElfProvider));

    // convert to the symbol provider and store globally
    ComPtr<ISvcSymbolProvider2> spElfSymbolProvider;
    IfFailedReturn(spElfProvider.As(&spElfSymbolProvider));
    spProvider->SetSymbolProvider(spElfSymbolProvider.Detach());

    // Store the debug client so we can get symbol paths
    spProvider->SetDebugClient(spClient.Get());

    return S_OK;
}

extern "C"
HRESULT CALLBACK DebugExtensionCanUnload(void)
{
    //
    // We can successfully unload if there are no objects left.
    //
    auto objCount = Microsoft::WRL::Module<InProc>::GetModule().GetObjectCount();
    return (objCount == 0) ? S_OK : S_FALSE;
}

extern "C"
void CALLBACK DebugExtensionUninitialize(void)
{
    // Nothing to clean up
}

extern "C"
void CALLBACK DebugExtensionUnload(void)
{
    // Nothing to do here
}
