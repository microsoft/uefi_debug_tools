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

// Global verbose flag for logging control
bool g_VerboseLogging = false;

//**************************************************************************
// Extension Commands:
//

extern "C"
HRESULT CALLBACK verbose(IDebugClient* pClient, PCSTR args)
{
    ComPtr<IDebugControl> spControl;
    if (FAILED(pClient->QueryInterface(IID_PPV_ARGS(&spControl))))
    {
        return E_FAIL;
    }

    // Toggle verbose mode
    g_VerboseLogging = !g_VerboseLogging;

    spControl->Output(DEBUG_OUTPUT_NORMAL, "EfiSymComposition verbose logging: %s\n",
                     g_VerboseLogging ? "ENABLED" : "DISABLED");
    return S_OK;
}

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
    IfFailedReturn(DebugCreate(__uuidof(IDebugClient), (void**)&spClient));

    ComPtr<IDebugControl> spControl;
    IfFailedReturn(spClient.As(&spControl));

    //
    // Get the composition bridge
    //
    ComPtr<IDebugTargetCompositionBridge> spCompositionBridge;
    IfFailedReturn(spClient.As(&spCompositionBridge));

    //
    // Get the service manager for the current composition
    //
    ULONG systemId = 0;
    ComPtr<IDebugServiceManager> spServiceManager;
    IfFailedReturn(spCompositionBridge->GetServiceManager(systemId, &spServiceManager));

    ComPtr<IDebugServiceManager5> spServiceManager5;
    IfFailedReturn(spServiceManager.As(&spServiceManager5));

    //
    // There can be different types of images in a EFI environment, setup an aggregator and preserve existing symbols
    // providers if needed.
    //
    ComPtr<IDebugServiceLayer> spExistingProvider = nullptr;
    hr = spServiceManager->QueryService(DEBUG_SERVICE_SYMBOL_PROVIDER, IID_PPV_ARGS(&spExistingProvider));

    //
    // Create and initialize our symbol provider service
    //
    ComPtr<EfiSymCompositionProvider> spProvider;
    IfFailedReturn(MakeAndInitialize<EfiSymCompositionProvider>(&spProvider));

    //
    // If there's an existing symbol provider, use AggregateService to combine them.
    // Otherwise, just register our provider.
    //
    if (spExistingProvider)
    {
        IfFailedReturn(spServiceManager5->AggregateService(DEBUG_SERVICE_SYMBOL_PROVIDER, spProvider.Get()));
    }
    else
    {
        IfFailedReturn(spProvider->RegisterServices(spServiceManager.Get()));
    }

    //
    // Make sure that Elf composition is loaded.
    //
    IfFailedReturn(spControl->Execute(DEBUG_OUTCTL_IGNORE,
                                      ".load ElfBinComposition",
                                      DEBUG_EXECUTE_NOT_LOGGED));

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
