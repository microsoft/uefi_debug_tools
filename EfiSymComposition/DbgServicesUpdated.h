//**************************************************************************
//
// Debugger Target Composition
// Services Layer
//
// Copyright (c) Microsoft Corporation.  All rights reserved.
//
// PLEASE READ:
//
// Many of the interfaces in this file (particularly those involving general user mode debugging:
// process/thread/stack enumeration, symbols, etc...) are presently in-design and undergoing significant
// breaking changes.  Do not take a dependency on these interfaces without communication with the debugger
// team.  IIDs will rev as these change.
//
//**************************************************************************

#pragma once
#ifndef __DBGSERVICES_H__
#define __DBGSERVICES_H__

// IMAGE_CUSTOM:
//
// For a "custom architecture" defined by GUID instead of an IMAGE_FILE_MACHINE_*, this is returned as the
// architecture constant.  The GUID *MUST* be used to uniquely identify the architecture.
//
#define IMAGE_CUSTOM 0xc031

#include <windows.h>
#include <objbase.h>

#if defined(__cplusplus) && !defined(RUST_BINDGEN)
#include <wrl/client.h>
#include <wrl/implements.h>
#endif // __cplusplus

#define NOEXTAPI
#include <wdbgexts.h>

#ifndef HR_PAGE_NOT_AVAILABLE
#define HR_PAGE_NOT_AVAILABLE HRESULT_FROM_NT(STATUS_NO_PAGEFILE)
#endif // HR_PAGE_NOT_AVAILABLE

#ifndef HR_NON_CANONICAL_VA
#define HR_NON_CANONICAL_VA HRESULT_FROM_NT(STATUS_INVALID_ADDRESS)
#endif // HR_NON_CANONICAL_VA

#ifndef E_INSUFFICIENT_BUFFER
#define E_INSUFFICIENT_BUFFER HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER)
#endif // E_INSUFFICIENT_BUFFER

#ifndef E_UNHANDLED_REQUEST_TYPE
// E_UNHANDLED_REQUEST_TYPE:
//
// Any service in an aggregate container which returns E_UNHANDLED_REQUEST_TYPE is indicating that it cannot
// handle the given request and that it should be passed to another service implementation.
//
#define E_UNHANDLED_REQUEST_TYPE 0x807f377e
#endif // E_UNHANDLED_REQUEST_TYPE

#ifndef S_UNATTRIBUTABLE_RESULT
// S_UNATTRIBUTABLE_RESULT
//
// While the given query succeeded, the result is unattributable.  This is often used to indicate things
// like offsets/instructions for which the underlying symbol provider has information but indicates that
// the offset/instruction cannot be attributed to a user source line (e.g.: it is compiler generated code
// or otherwise not associable with user code).
//
#define S_UNATTRIBUTABLE_RESULT 0x007f377f
#endif // S_UNATTRIBUTABLE_RESULT

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

// {FDD4EF98-93FD-4773-BCDF-AACFB87257A6}
DEFINE_GUID(IID_IDebugTargetCompositionComponent, 0xfdd4ef98, 0x93fd, 0x4773, 0xbc, 0xdf, 0xaa, 0xcf, 0xb8, 0x72, 0x57, 0xa6);

// {6D4E5F39-657E-4905-9670-448978F7FB27}
DEFINE_GUID(IID_IDebugTargetComposition, 0x6d4e5f39, 0x657e, 0x4905, 0x96, 0x70, 0x44, 0x89, 0x78, 0xf7, 0xfb, 0x27);

// {66403806-4988-4a0a-A552-F14B1B5E33D5}
DEFINE_GUID(IID_IDebugTargetComposition2, 0x66403806, 0x4988, 0x4a0a, 0xa5, 0x52, 0xf1, 0x4b, 0x1b, 0x5e, 0x33, 0xd5);

// {6E8041B9-CB1B-4071-B789-D8A871124B57}
DEFINE_GUID(IID_IDebugTargetComposition3, 0x6e8041b9, 0xcb1b, 0x4071, 0xb7, 0x89, 0xd8, 0xa8, 0x71, 0x12, 0x4b, 0x57);

// {AB73D421-5FBA-403d-BC0D-4EB92720135A}
DEFINE_GUID(IID_IDebugServiceManager, 0xab73d421, 0x5fba, 0x403d, 0xbc, 0xd, 0x4e, 0xb9, 0x27, 0x20, 0x13, 0x5a);

// {71BE9D83-969F-428b-A28D-3A439D61FDE9}
DEFINE_GUID(IID_IDebugServiceEnumerator, 0x71be9d83, 0x969f, 0x428b, 0xa2, 0x8d, 0x3a, 0x43, 0x9d, 0x61, 0xfd, 0xe9);

// {099FCD6F-0A4D-45cc-BD8B-C10C6ED53AC7}
DEFINE_GUID(IID_IDebugServiceManager2, 0x99fcd6f, 0xa4d, 0x45cc, 0xbd, 0x8b, 0xc1, 0xc, 0x6e, 0xd5, 0x3a, 0xc7);

// {17B978DD-15C0-4318-A3D0-15305C6DD0D4}
DEFINE_GUID(IID_IDebugServiceManager3, 0x17b978dd, 0x15c0, 0x4318, 0xa3, 0xd0, 0x15, 0x30, 0x5c, 0x6d, 0xd0, 0xd4);

// {84069FCD-E8B0-48e5-8611-7F0A8FA130D2}
DEFINE_GUID(IID_IDebugServiceManager4, 0x84069fcd, 0xe8b0, 0x48e5, 0x86, 0x11, 0x7f, 0xa, 0x8f, 0xa1, 0x30, 0xd2);

// {5637D1DE-5804-4aee-A98B-9BA1E97A8A07}
DEFINE_GUID(IID_IDebugServiceManager5, 0x5637d1de, 0x5804, 0x4aee, 0xa9, 0x8b, 0x9b, 0xa1, 0xe9, 0x7a, 0x8a, 0x7);

// {6BF32043-E2A9-462d-99B1-B2E6C15252A2}
DEFINE_GUID(IID_IDebugServiceLayer, 0x6bf32043, 0xe2a9, 0x462d, 0x99, 0xb1, 0xb2, 0xe6, 0xc1, 0x52, 0x52, 0xa2);

// {12954378-FAFD-4749-ADD8-7A98A5A4B896}
DEFINE_GUID(IID_IDebugServiceLayer2, 0x12954378, 0xfafd, 0x4749, 0xad, 0xd8, 0x7a, 0x98, 0xa5, 0xa4, 0xb8, 0x96);

// {729CF17B-E82F-4ff8-B27C-F13693971FE3}
DEFINE_GUID(IID_IDebugServiceCapabilities, 0x729cf17b, 0xe82f, 0x4ff8, 0xb2, 0x7c, 0xf1, 0x36, 0x93, 0x97, 0x1f, 0xe3);

// {6041DBC4-5BDA-4581-9BF4-0A6F74A643D4}
DEFINE_GUID(IID_IDebugServiceAggregate, 0x6041dbc4, 0x5bda, 0x4581, 0x9b, 0xf4, 0xa, 0x6f, 0x74, 0xa6, 0x43, 0xd4);

// {1C1772AC-D830-4558-803C-E049D4710E9D}
DEFINE_GUID(IID_IDebugComponentManager, 0x1c1772ac, 0xd830, 0x4558, 0x80, 0x3c, 0xe0, 0x49, 0xd4, 0x71, 0xe, 0x9d);

// {A0E9E780-FE9A-4085-AB4B-8B4CC276266A}
DEFINE_GUID(IID_ISvcDebugSourceFile, 0xa0e9e780, 0xfe9a, 0x4085, 0xab, 0x4b, 0x8b, 0x4c, 0xc2, 0x76, 0x26, 0x6a);

// {7EBB44D0-3C22-41e1-AAB9-083E774CFF5D}
DEFINE_GUID(IID_ISvcDebugSourceFileMapping, 0x7ebb44d0, 0x3c22, 0x41e1, 0xaa, 0xb9, 0x8, 0x3e, 0x77, 0x4c, 0xff, 0x5d);

// {D9F5A718-E130-46c2-AECD-D66C557027B8}
DEFINE_GUID(IID_ISvcDebugSourceFileInformation, 0xd9f5a718, 0xe130, 0x46c2, 0xae, 0xcd, 0xd6, 0x6c, 0x55, 0x70, 0x27, 0xb8);

// {52276F45-1CA1-4c47-8DC5-426AE90D7A26}
DEFINE_GUID(IID_ISvcDebugSourceView, 0x52276f45, 0x1ca1, 0x4c47, 0x8d, 0xc5, 0x42, 0x6a, 0xe9, 0xd, 0x7a, 0x26);

// {A271F928-F2B8-4a4f-9B2E-89FCB1F58680}
DEFINE_GUID(IID_ISvcDebugSourceWindowsKernelDebug, 0xa271f928, 0xf2b8, 0x4a4f, 0x9b, 0x2e, 0x89, 0xfc, 0xb1, 0xf5, 0x86, 0x80);

// {E069DD06-1004-4010-A865-39635C4782B7}
DEFINE_GUID(IID_ISvcFileFormatPrivateData, 0xe069dd06, 0x1004, 0x4010, 0xa8, 0x65, 0x39, 0x63, 0x5c, 0x47, 0x82, 0xb7);

// {BF676866-9724-44d1-87F7-62047EB0A86C}
DEFINE_GUID(IID_ISvcFileFormatDataBlock, 0xbf676866, 0x9724, 0x44d1, 0x87, 0xf7, 0x62, 0x4, 0x7e, 0xb0, 0xa8, 0x6c);

// {2DDF4CC0-BBA8-4fb0-BD53-5F4C92218280}
DEFINE_GUID(IID_ISvcAddressContext, 0x2ddf4cc0, 0xbba8, 0x4fb0, 0xbd, 0x53, 0x5f, 0x4c, 0x92, 0x21, 0x82, 0x80);

// {1A39F548-ECF8-4ffe-830D-C923F51E752D}
DEFINE_GUID(IID_ISvcAddressContextHardware, 0x1a39f548, 0xecf8, 0x4ffe, 0x83, 0xd, 0xc9, 0x23, 0xf5, 0x1e, 0x75, 0x2d);

// {A99D428E-6948-4073-863F-8E14E8A469DC}
DEFINE_GUID(IID_ISvcIoSpace, 0xa99d428e, 0x6948, 0x4073, 0x86, 0x3f, 0x8e, 0x14, 0xe8, 0xa4, 0x69, 0xdc);

// {890C0F06-D269-4ba6-B5BB-C8335D6EC8C2}
DEFINE_GUID(IID_ISvcSecurityConfiguration, 0x890c0f06, 0xd269, 0x4ba6, 0xb5, 0xbb, 0xc8, 0x33, 0x5d, 0x6e, 0xc8, 0xc2);

// {0CF0EE09-1ABD-4f54-85C4-49775DE19CB1}
DEFINE_GUID(IID_ISvcSecurityConfiguration2, 0xcf0ee09, 0x1abd, 0x4f54, 0x85, 0xc4, 0x49, 0x77, 0x5d, 0xe1, 0x9c, 0xb1);

// {B45C31AD-8149-4ea9-9DB8-F4468D710A36}
DEFINE_GUID(IID_ISvcProcess, 0xb45c31ad, 0x8149, 0x4ea9, 0x9d, 0xb8, 0xf4, 0x46, 0x8d, 0x71, 0xa, 0x36);

// {3A0957C5-A583-4ce1-ACC4-DFE9CACE0CF0}
DEFINE_GUID(IID_ISvcProcessBasicInformation, 0x3a0957c5, 0xa583, 0x4ce1, 0xac, 0xc4, 0xdf, 0xe9, 0xca, 0xce, 0xc, 0xf0);

// {2F5A6E6F-23F1-47d9-9DCF-A359B51AAAB0}
DEFINE_GUID(IID_ISvcMachineConfiguration, 0x2f5a6e6f, 0x23f1, 0x47d9, 0x9d, 0xcf, 0xa3, 0x59, 0xb5, 0x1a, 0xaa, 0xb0);

// {D63778DF-FE4F-4ab8-904E-0E334E5A7CD3}
DEFINE_GUID(IID_ISvcMachineConfiguration2, 0xd63778df, 0xfe4f, 0x4ab8, 0x90, 0x4e, 0xe, 0x33, 0x4e, 0x5a, 0x7c, 0xd3);

// {C9CD3D26-2A2D-4e14-99CD-2196F08C921A}
DEFINE_GUID(IID_ISvcMachineArchitecture, 0xc9cd3d26, 0x2a2d, 0x4e14, 0x99, 0xcd, 0x21, 0x96, 0xf0, 0x8c, 0x92, 0x1a);

// {FAFCA4B4-66DA-4ac0-86B6-AAC5C2498BC6}
DEFINE_GUID(IID_ISvcBasicDisassembly, 0xfafca4b4, 0x66da, 0x4ac0, 0x86, 0xb6, 0xaa, 0xc5, 0xc2, 0x49, 0x8b, 0xc6);

// {7D42C7D1-B9D3-4ddf-B9F9-05694F013B86}
DEFINE_GUID(IID_ISvcMemoryAccess, 0x7d42c7d1, 0xb9d3, 0x4ddf, 0xb9, 0xf9, 0x5, 0x69, 0x4f, 0x1, 0x3b, 0x86);

// {AB7C5913-E08E-4b62-91E3-519253BAAFC1}
DEFINE_GUID(IID_ISvcMemoryAccessCacheControl, 0xab7c5913, 0xe08e, 0x4b62, 0x91, 0xe3, 0x51, 0x92, 0x53, 0xba, 0xaf, 0xc1);

// {2506F23D-C4B3-4248-9C37-7F80BB7E4893}
DEFINE_GUID(IID_ISvcMemoryInformation, 0x2506f23d, 0xc4b3, 0x4248, 0x9c, 0x37, 0x7f, 0x80, 0xbb, 0x7e, 0x48, 0x93);

// {E327A72A-65D9-4545-9304-09F0104BB138}
DEFINE_GUID(IID_ISvcMemoryRegion, 0xe327a72a, 0x65d9, 0x4545, 0x93, 0x4, 0x9, 0xf0, 0x10, 0x4b, 0xb1, 0x38);

// {66FF5B9F-A8D1-4a78-ADA9-4DFEDCC12C3A}
DEFINE_GUID(IID_ISvcMemoryRegionEnumerator, 0x66ff5b9f, 0xa8d1, 0x4a78, 0xad, 0xa9, 0x4d, 0xfe, 0xdc, 0xc1, 0x2c, 0x3a);

// {56373E0F-D615-487f-95B9-37931E2A9A90}
DEFINE_GUID(IID_ISvcMemoryTranslation, 0x56373e0f, 0xd615, 0x487f, 0x95, 0xb9, 0x37, 0x93, 0x1e, 0x2a, 0x9a, 0x90);

// {3603A7EE-E996-46e0-85BA-9CEA48EEF6E1}
DEFINE_GUID(IID_ISvcPageFileReader, 0x3603a7ee, 0xe996, 0x46e0, 0x85, 0xba, 0x9c, 0xea, 0x48, 0xee, 0xf6, 0xe1);

// {FF85423A-3B47-4205-8D0C-3F28F47FF3D7}
DEFINE_GUID(IID_ISvcProcessEnumerator, 0xff85423a, 0x3b47, 0x4205, 0x8d, 0xc, 0x3f, 0x28, 0xf4, 0x7f, 0xf3, 0xd7);

// {3CFA6328-A170-4d90-BCE2-C9FDB898C1F5}
DEFINE_GUID(IID_ISvcProcessEnumeration, 0x3cfa6328, 0xa170, 0x4d90, 0xbc, 0xe2, 0xc9, 0xfd, 0xb8, 0x98, 0xc1, 0xf5);

// {C6648B7C-F2E4-4304-9A3E-ED71CF0F26C6}
DEFINE_GUID(IID_ISvcThread, 0xc6648b7c, 0xf2e4, 0x4304, 0x9a, 0x3e, 0xed, 0x71, 0xcf, 0xf, 0x26, 0xc6);

// {A4D4186A-CA0E-483b-BB2A-A83F9D3F3115}
DEFINE_GUID(IID_ISvcThreadEnumeration, 0xa4d4186a, 0xca0e, 0x483b, 0xbb, 0x2a, 0xa8, 0x3f, 0x9d, 0x3f, 0x31, 0x15);

// {10545A55-D561-4119-BDBC-D885F23045DA}
DEFINE_GUID(IID_ISvcThreadEnumerator, 0x10545a55, 0xd561, 0x4119, 0xbd, 0xbc, 0xd8, 0x85, 0xf2, 0x30, 0x45, 0xda);

// {58EE46F3-209E-4402-8452-C3797D5C3355}
DEFINE_GUID(IID_ISvcThreadLocalStorageProvider, 0x58ee46f3, 0x209e, 0x4402, 0x84, 0x52, 0xc3, 0x79, 0x7d, 0x5c, 0x33, 0x55);

// {D795507F-956D-4efb-B829-AC3EABCA961B}
DEFINE_GUID(IID_ISvcIoSpaceEnumeration, 0xd795507f, 0x956d, 0x4efb, 0xb8, 0x29, 0xac, 0x3e, 0xab, 0xca, 0x96, 0x1b);

// {360DE704-D055-483a-8E3B-BD67D2DA0133}
DEFINE_GUID(IID_ISvcModule, 0x360de704, 0xd055, 0x483a, 0x8e, 0x3b, 0xbd, 0x67, 0xd2, 0xda, 0x1, 0x33);

// {FF4713F1-74DD-4cbc-830C-7F13D7E31AA3}
DEFINE_GUID(IID_ISvcModuleWithTimestampAndChecksum, 0xff4713f1, 0x74dd, 0x4cbc, 0x83, 0xc, 0x7f, 0x13, 0xd7, 0xe3, 0x1a, 0xa3);

// {31A3942E-E145-4112-9014-88DC7593028E}
DEFINE_GUID(IID_ISvcMappingInformation, 0x31a3942e, 0xe145, 0x4112, 0x90, 0x14, 0x88, 0xdc, 0x75, 0x93, 0x2, 0x8e);

// {A4D7D798-A4C1-40ad-9235-B80F0BF8E2AD}
DEFINE_GUID(IID_ISvcAddressRangeEnumeration, 0xa4d7d798, 0xa4c1, 0x40ad, 0x92, 0x35, 0xb8, 0xf, 0xb, 0xf8, 0xe2, 0xad);

// {20D4BA1D-BE37-4dc4-9F6A-90E3C373200E}
DEFINE_GUID(IID_ISvcModuleEnumeration, 0x20d4ba1d, 0xbe37, 0x4dc4, 0x9f, 0x6a, 0x90, 0xe3, 0xc3, 0x73, 0x20, 0xe);

// {04E3E600-9A10-48df-A618-775B3E36A740}
DEFINE_GUID(IID_ISvcPrimaryModules, 0x4e3e600, 0x9a10, 0x48df, 0xa6, 0x18, 0x77, 0x5b, 0x3e, 0x36, 0xa7, 0x40);

// {ABE84A4B-1EA3-4058-B875-A1D69A7BB3FE}
DEFINE_GUID(IID_ISvcModuleEnumerator, 0xabe84a4b, 0x1ea3, 0x4058, 0xb8, 0x75, 0xa1, 0xd6, 0x9a, 0x7b, 0xb3, 0xfe);

// {5AC23A8A-6D8C-4c92-AC1B-813E6EF1B48A}
DEFINE_GUID(IID_ISvcModuleIndexProvider, 0x5ac23a8a, 0x6d8c, 0x4c92, 0xac, 0x1b, 0x81, 0x3e, 0x6e, 0xf1, 0xb4, 0x8a);

// {B497B0C9-9572-4257-A156-792D3AF03D94}
DEFINE_GUID(IID_ISourceCodeDownloadUrlLinkProvider, 0xb497b0c9, 0x9572, 0x4257, 0xa1, 0x56, 0x79, 0x2d, 0x3a, 0xf0, 0x3d, 0x94);

// {498CBE80-B1F4-4f55-91E1-477C507A1D9F}
DEFINE_GUID(IID_IClrDacAndSosProvider, 0x498cbe80, 0xb1f4, 0x4f55, 0x91, 0xe1, 0x47, 0x7c, 0x50, 0x7a, 0x1d, 0x9f);

// {BC6823E0-6E29-4474-9A9B-7728844E90A2}
DEFINE_GUID(IID_IClrDacDbiAndSosProvider, 0xbc6823e0, 0x6e29, 0x4474, 0x9a, 0x9b, 0x77, 0x28, 0x84, 0x4e, 0x90, 0xa2);

// {4C1BEC33-1B39-4708-AB0A-C8AE0E9DDB3E}
DEFINE_GUID(IID_ISvcSegmentTranslation, 0x4c1bec33, 0x1b39, 0x4708, 0xab, 0xa, 0xc8, 0xae, 0xe, 0x9d, 0xdb, 0x3e);

// {CA1AFE05-244C-4fa3-BED4-A355418587EF}
DEFINE_GUID(IID_ISvcRegisterContext, 0xca1afe05, 0x244c, 0x4fa3, 0xbe, 0xd4, 0xa3, 0x55, 0x41, 0x85, 0x87, 0xef);

// {D9E1F476-4FAE-4051-89C9-45D25925DB41}
DEFINE_GUID(IID_ISvcClassicRegisterContext, 0xd9e1f476, 0x4fae, 0x4051, 0x89, 0xc9, 0x45, 0xd2, 0x59, 0x25, 0xdb, 0x41);

// {33D1251E-BD8C-489e-B07A-CC545A27042C}
DEFINE_GUID(IID_ISvcClassicSpecialContext, 0x33d1251e, 0xbd8c, 0x489e, 0xb0, 0x7a, 0xcc, 0x54, 0x5a, 0x27, 0x4, 0x2c);

// {B91E34DE-6407-4583-BBAE-95FE20548363}
DEFINE_GUID(IID_ISvcRegisterInformation, 0xb91e34de, 0x6407, 0x4583, 0xbb, 0xae, 0x95, 0xfe, 0x20, 0x54, 0x83, 0x63);

// {AE8EC624-52F6-43a4-BBAB-57A6C1C393C3}
DEFINE_GUID(IID_ISvcRegisterEnumerator, 0xae8ec624, 0x52f6, 0x43a4, 0xbb, 0xab, 0x57, 0xa6, 0xc1, 0xc3, 0x93, 0xc3);

// {5ED13135-FA5D-4d29-BB93-C80CB72ADFD4}
DEFINE_GUID(IID_ISvcRegisterFlagInformation, 0x5ed13135, 0xfa5d, 0x4d29, 0xbb, 0x93, 0xc8, 0xc, 0xb7, 0x2a, 0xdf, 0xd4);

// {55C7E6F4-D357-4209-ACF7-55D945AF3841}
DEFINE_GUID(IID_ISvcRegisterFlagsEnuemrator, 0x55c7e6f4, 0xd357, 0x4209, 0xac, 0xf7, 0x55, 0xd9, 0x45, 0xaf, 0x38, 0x41);

// {C5A05162-A375-48fc-AB00-3045C6386836}
DEFINE_GUID(IID_ISvcRegisterTranslation, 0xc5a05162, 0xa375, 0x48fc, 0xab, 0x0, 0x30, 0x45, 0xc6, 0x38, 0x68, 0x36);

// {A61B284D-EC7D-4ee7-A3B0-99B59F171F9A}
DEFINE_GUID(IID_ISvcDwarfRegisterTranslation, 0xa61b284d, 0xec7d, 0x4ee7, 0xa3, 0xb0, 0x99, 0xb5, 0x9f, 0x17, 0x1f, 0x9a);

// {EDDC117F-50EB-48c6-B201-1B7CB9C675AB}
DEFINE_GUID(IID_ISvcRegisterContextTranslation, 0xeddc117f, 0x50eb, 0x48c6, 0xb2, 0x1, 0x1b, 0x7c, 0xb9, 0xc6, 0x75, 0xab);

// {3870640B-8D1E-469d-8552-F38D48E28766}
DEFINE_GUID(IID_ISvcTrapContextRestoration, 0x3870640b, 0x8d1e, 0x469d, 0x85, 0x52, 0xf3, 0x8d, 0x48, 0xe2, 0x87, 0x66);

// {01C932D4-9F5E-4268-8B12-EC246582A82D}
DEFINE_GUID(IID_ISvcExecutionUnit, 0x1c932d4, 0x9f5e, 0x4268, 0x8b, 0x12, 0xec, 0x24, 0x65, 0x82, 0xa8, 0x2d);

// {F272C72D-E794-498f-B169-2F74B38A2DAE}
DEFINE_GUID(IID_ISvcExecutionUnitHardware, 0xf272c72d, 0xe794, 0x498f, 0xb1, 0x69, 0x2f, 0x74, 0xb3, 0x8a, 0x2d, 0xae);

// {59C0BA4E-84E8-4a2e-8874-83DF03E3CFF5}
DEFINE_GUID(IID_ISvcMachineDebug, 0x59c0ba4e, 0x84e8, 0x4a2e, 0x88, 0x74, 0x83, 0xdf, 0x3, 0xe3, 0xcf, 0xf5);

// {92F3C9F5-5B7B-4202-8163-44D86E4C051E}
DEFINE_GUID(IID_ISvcOSKernelInfrastructure, 0x92f3c9f5, 0x5b7b, 0x4202, 0x81, 0x63, 0x44, 0xd8, 0x6e, 0x4c, 0x5, 0x1e);

// {C809D0B1-4563-4577-BFDC-AF951FCE5308}
DEFINE_GUID(IID_ISvcOSKernelTypes, 0xc809d0b1, 0x4563, 0x4577, 0xbf, 0xdc, 0xaf, 0x95, 0x1f, 0xce, 0x53, 0x8);

// {B1383D5C-3630-4492-9AD8-720CC34AD12F}
DEFINE_GUID(IID_ISvcOSKernelTransitions, 0xb1383d5c, 0x3630, 0x4492, 0x9a, 0xd8, 0x72, 0xc, 0xc3, 0x4a, 0xd1, 0x2f);

// {E14E5358-56DD-4c71-98F8-EDED11398426}
DEFINE_GUID(IID_ISvcOSKernelObject, 0xe14e5358, 0x56dd, 0x4c71, 0x98, 0xf8, 0xed, 0xed, 0x11, 0x39, 0x84, 0x26);

// {8E18CBC7-B80A-4c42-A10D-A56E17A555CE}
DEFINE_GUID(IID_ISvcOSKernelObjectAccessor, 0x8e18cbc7, 0xb80a, 0x4c42, 0xa1, 0xd, 0xa5, 0x6e, 0x17, 0xa5, 0x55, 0xce);

// {995F51EF-FE22-441e-BCE6-0F6FECFB9A0A}
DEFINE_GUID(IID_ISvcOSKernelLocator, 0x995f51ef, 0xfe22, 0x441e, 0xbc, 0xe6, 0xf, 0x6f, 0xec, 0xfb, 0x9a, 0xa);

// {F980577B-73FA-40fe-95A3-C4D44100FD68}
DEFINE_GUID(IID_ISvcWindowsKdInfrastructure, 0xf980577b, 0x73fa, 0x40fe, 0x95, 0xa3, 0xc4, 0xd4, 0x41, 0x0, 0xfd, 0x68);

// {C6B492DC-CBC1-4574-8E16-95BDFC06AEA0}
DEFINE_GUID(IID_ISvcWindowsKernelInfrastructure, 0xc6b492dc, 0xcbc1, 0x4574, 0x8e, 0x16, 0x95, 0xbd, 0xfc, 0x6, 0xae, 0xa0);

// {2559B271-BFE2-4ecc-9FFB-DA5F49D17F3D}
DEFINE_GUID(IID_ISvcWindowsExceptionTranslation, 0x2559b271, 0xbfe2, 0x4ecc, 0x9f, 0xfb, 0xda, 0x5f, 0x49, 0xd1, 0x7f, 0x3d);

// {292A1D08-3971-40c1-883A-8E8289CF685D}
DEFINE_GUID(IID_ISvcWindowsThreadInformation, 0x292a1d08, 0x3971, 0x40c1, 0x88, 0x3a, 0x8e, 0x82, 0x89, 0xcf, 0x68, 0x5d);

// {48BE7867-8C93-449d-8574-01C9375EB112}
DEFINE_GUID(IID_ISvcWindowsProcessInformation, 0x48be7867, 0x8c93, 0x449d, 0x85, 0x74, 0x1, 0xc9, 0x37, 0x5e, 0xb1, 0x12);

// {23ED1044-166C-4c62-91FC-B5656E4A74EF}
DEFINE_GUID(IID_ISvcSymbolProvider, 0x23ed1044, 0x166c, 0x4c62, 0x91, 0xfc, 0xb5, 0x65, 0x6e, 0x4a, 0x74, 0xef);

// {5E93C234-11E1-46ed-836C-44FD3E949623}
DEFINE_GUID(IID_ISvcSymbolProvider2, 0x5e93c234, 0x11e1, 0x46ed, 0x83, 0x6c, 0x44, 0xfd, 0x3e, 0x94, 0x96, 0x23);

// {31C1B07E-745A-461c-90C0-8FBC5162AC86}
DEFINE_GUID(IID_ISvcJITSymbolProvider, 0x31c1b07e, 0x745a, 0x461c, 0x90, 0xc0, 0x8f, 0xbc, 0x51, 0x62, 0xac, 0x86);

// {EAB8E16C-12F7-4878-8E0E-A59F0B25D4CB}
DEFINE_GUID(IID_ISvcSymbolRegExIndexedDescendents, 0xeab8e16c, 0x12f7, 0x4878, 0x8e, 0xe, 0xa5, 0x9f, 0xb, 0x25, 0xd4, 0xcb);

// {D2513438-18DA-4360-8242-49E0638FB2A4}
DEFINE_GUID(IID_ISvcSymbolAddressMapping, 0xd2513438, 0x18da, 0x4360, 0x82, 0x42, 0x49, 0xe0, 0x63, 0x8f, 0xb2, 0xa4);

// {76D4EDDF-282E-4381-8389-6FA9EEB067C2}
DEFINE_GUID(IID_ISvcImageProvider, 0x76d4eddf, 0x282e, 0x4381, 0x83, 0x89, 0x6f, 0xa9, 0xee, 0xb0, 0x67, 0xc2);

// {44CFC4B1-02B5-490a-A51A-AD34E49457F4}
DEFINE_GUID(IID_ISvcStackFrameUnwind, 0x44cfc4b1, 0x2b5, 0x490a, 0xa5, 0x1a, 0xad, 0x34, 0xe4, 0x94, 0x57, 0xf4);

// {2ED57D21-39C8-4d09-9751-8A80E15DECF4}
DEFINE_GUID(IID_ISvcStackFrameUnwinderTransition, 0x2ed57d21, 0x39c8, 0x4d09, 0x97, 0x51, 0x8a, 0x80, 0xe1, 0x5d, 0xec, 0xf4);

// {83D68882-2AF7-408c-9B4E-FA5677F44C3E}
DEFINE_GUID(IID_ISvcStackFrameInjection, 0x83d68882, 0x2af7, 0x408c, 0x9b, 0x4e, 0xfa, 0x56, 0x77, 0xf4, 0x4c, 0x3e);

// {B44285F2-5FAC-4ba9-8A1F-DD264EF1F1D3}
DEFINE_GUID(IID_ISvcStackUnwindContext, 0xb44285f2, 0x5fac, 0x4ba9, 0x8a, 0x1f, 0xdd, 0x26, 0x4e, 0xf1, 0xf1, 0xd3);

// {2D742534-FC20-4472-A5DD-3A66BFED5832}
DEFINE_GUID(IID_ISvcStackUnwindContext2, 0x2d742534, 0xfc20, 0x4472, 0xa5, 0xdd, 0x3a, 0x66, 0xbf, 0xed, 0x58, 0x32);

// {E5CFCBEE-E83D-451f-A26B-D687C72159DD}
DEFINE_GUID(IID_ISvcStackUnwindContext3, 0xe5cfcbee, 0xe83d, 0x451f, 0xa2, 0x6b, 0xd6, 0x87, 0xc7, 0x21, 0x59, 0xdd);

// {F3E0DAE9-6385-41be-9EA6-75BCFBF5B727}
DEFINE_GUID(IID_ISvcSearchPaths, 0xf3e0dae9, 0x6385, 0x41be, 0x9e, 0xa6, 0x75, 0xbc, 0xfb, 0xf5, 0xb7, 0x27);

// {BE5E232C-1D4B-4983-A520-383DA865DA1C}
DEFINE_GUID(IID_ISvcContextTranslation, 0xbe5e232c, 0x1d4b, 0x4983, 0xa5, 0x20, 0x38, 0x3d, 0xa8, 0x65, 0xda, 0x1c);

// {D492514F-7CFE-4876-96AC-7FAB627895AB}
DEFINE_GUID(IID_ISvcEventArgumentsModuleDiscovery, 0xd492514f, 0x7cfe, 0x4876, 0x96, 0xac, 0x7f, 0xab, 0x62, 0x78, 0x95, 0xab);

// {8983F680-8031-4bbc-9F67-BBB206058FAB}
DEFINE_GUID(IID_ISvcEventArgumentsSourceMappingsChanged, 0x8983f680, 0x8031, 0x4bbc, 0x9f, 0x67, 0xbb, 0xb2, 0x6, 0x5, 0x8f, 0xab);

// {1579B0C9-A848-447d-BB65-0CFFE3F985FB}
DEFINE_GUID(IID_ISvcActiveExceptions, 0x1579b0c9, 0xa848, 0x447d, 0xbb, 0x65, 0xc, 0xff, 0xe3, 0xf9, 0x85, 0xfb);

// {8FCC28B1-3ADA-4876-A6D4-7BF9543DE30B}
DEFINE_GUID(IID_ISvcExceptionInformation, 0x8fcc28b1, 0x3ada, 0x4876, 0xa6, 0xd4, 0x7b, 0xf9, 0x54, 0x3d, 0xe3, 0xb);

// {5A37C25E-4F8D-47be-87F5-94A933824A83}
DEFINE_GUID(IID_ISvcExceptionControl, 0x5a37c25e, 0x4f8d, 0x47be, 0x87, 0xf5, 0x94, 0xa9, 0x33, 0x82, 0x4a, 0x83);

// {DE815F6F-5824-4555-A010-286791BC79AD}
DEFINE_GUID(IID_ISvcLinuxSignalInformation, 0xde815f6f, 0x5824, 0x4555, 0xa0, 0x10, 0x28, 0x67, 0x91, 0xbc, 0x79, 0xad);

// {228DBCF1-3E54-42fc-9DDD-5EFB76B13C70}
DEFINE_GUID(IID_ISvcWindowsBugCheckInformation, 0x228dbcf1, 0x3e54, 0x42fc, 0x9d, 0xdd, 0x5e, 0xfb, 0x76, 0xb1, 0x3c, 0x70);

// {B181A69C-9D85-4747-8CF8-2ADF53CF750A}
DEFINE_GUID(IID_ISvcExceptionFormatter, 0xb181a69c, 0x9d85, 0x4747, 0x8c, 0xf8, 0x2a, 0xdf, 0x53, 0xcf, 0x75, 0xa);

// {40B23EAC-F503-46fc-9C95-09384D050A11}
DEFINE_GUID(IID_ISvcOSPlatformInformation, 0x40b23eac, 0xf503, 0x46fc, 0x9c, 0x95, 0x9, 0x38, 0x4d, 0x5, 0xa, 0x11);

// {7B6FABD4-D271-413a-8475-31F8483179FD}
DEFINE_GUID(IID_ISvcOSPlatformInformation2, 0x7b6fabd4, 0xd271, 0x413a, 0x84, 0x75, 0x31, 0xf8, 0x48, 0x31, 0x79, 0xfd);

// {39BCF55E-9150-4bba-9472-88C972DD7885}
DEFINE_GUID(IID_ISvcTelemetry, 0x39bcf55e, 0x9150, 0x4bba, 0x94, 0x72, 0x88, 0xc9, 0x72, 0xdd, 0x78, 0x85);

// {76EB9426-DAE9-4607-8822-45BE93081D6E}
DEFINE_GUID(IID_ISvcDiagnosticLogging, 0x76eb9426, 0xdae9, 0x4607, 0x88, 0x22, 0x45, 0xbe, 0x93, 0x8, 0x1d, 0x6e);

// {B2054872-8D6A-4884-8800-9C8B82F83732}
DEFINE_GUID(IID_ISvcDiagnsoticLoggingXmlPassthrough, 0xb2054872, 0x8d6a, 0x4884, 0x88, 0x0, 0x9c, 0x8b, 0x82, 0xf8, 0x37, 0x32);

// {432BEA74-794D-46fb-AC50-EBECA9AA865C}
DEFINE_GUID(IID_ISvcDiagnosticLoggableControl, 0x432bea74, 0x794d, 0x46fb, 0xac, 0x50, 0xeb, 0xec, 0xa9, 0xaa, 0x86, 0x5c);

// {A7DF185B-CBBF-4b0d-BBA6-C58D6F9240C0}
DEFINE_GUID(IID_ISvcAddressRangeEnumerator, 0xa7df185b, 0xcbbf, 0x4b0d, 0xbb, 0xa6, 0xc5, 0x8d, 0x6f, 0x92, 0x40, 0xc0);

// {131E4723-1CC2-4ec7-BB12-9F40EDF63B66}
DEFINE_GUID(IID_ISvcDescription, 0x131e4723, 0x1cc2, 0x4ec7, 0xbb, 0x12, 0x9f, 0x40, 0xed, 0xf6, 0x3b, 0x66);

// {50DEB97A-25CC-41c1-B467-96C5E3F454CA}
DEFINE_GUID(IID_ISvcPrivateProperties, 0x50deb97a, 0x25cc, 0x41c1, 0xb4, 0x67, 0x96, 0xc5, 0xe3, 0xf4, 0x54, 0xca);

// {A4AE6E38-E6DA-4bc8-9FC0-EC65821948E5}
DEFINE_GUID(IID_ISvcImageFileViewRegionEnumerator, 0xa4ae6e38, 0xe6da, 0x4bc8, 0x9f, 0xc0, 0xec, 0x65, 0x82, 0x19, 0x48, 0xe5);

// {BF990D96-9D77-4a39-A611-74DE8F0F6B45}
DEFINE_GUID(IID_ISvcImageMemoryViewRegionEnumerator, 0xbf990d96, 0x9d77, 0x4a39, 0xa6, 0x11, 0x74, 0xde, 0x8f, 0xf, 0x6b, 0x45);

// {C11A8084-0BC4-45f8-AF3C-821FBC835312}
DEFINE_GUID(IID_ISvcStackProvider, 0xc11a8084, 0xbc4, 0x45f8, 0xaf, 0x3c, 0x82, 0x1f, 0xbc, 0x83, 0x53, 0x12);

// {81E83593-5AA9-43aa-8A5D-B964411E4B53}
DEFINE_GUID(IID_ISvcStackProviderFrameSetEnumerator, 0x81e83593, 0x5aa9, 0x43aa, 0x8a, 0x5d, 0xb9, 0x64, 0x41, 0x1e, 0x4b, 0x53);

// {2F79D431-71BF-4f40-B959-96361E92AD04}
DEFINE_GUID(IID_ISvcStackProviderFrame, 0x2f79d431, 0x71bf, 0x4f40, 0xb9, 0x59, 0x96, 0x36, 0x1e, 0x92, 0xad, 0x4);

// {96CE81F7-C6B9-4665-B2E5-6EB229079091}
DEFINE_GUID(IID_ISvcStackProviderFrameAttributes, 0x96ce81f7, 0xc6b9, 0x4665, 0xb2, 0xe5, 0x6e, 0xb2, 0x29, 0x7, 0x90, 0x91);

// {EB64279F-6EEF-451f-9DA4-55DB69FC2A95}
DEFINE_GUID(IID_ISvcStackProviderPhysicalFrame, 0xeb64279f, 0x6eef, 0x451f, 0x9d, 0xa4, 0x55, 0xdb, 0x69, 0xfc, 0x2a, 0x95);

// {46329742-2733-41fa-A125-6EEF620998B1}
DEFINE_GUID(IID_ISvcStackProviderPartialPhysicalFrame, 0x46329742, 0x2733, 0x41fa, 0xa1, 0x25, 0x6e, 0xef, 0x62, 0x9, 0x98, 0xb1);

// {4D0BDD20-61CD-4f18-936A-7E9350B30966}
DEFINE_GUID(IID_ISvcStackProviderInlineFrame, 0x4d0bdd20, 0x61cd, 0x4f18, 0x93, 0x6a, 0x7e, 0x93, 0x50, 0xb3, 0x9, 0x66);

// {6FA683AF-06AA-484d-87CF-137C1EA016BD}
DEFINE_GUID(IID_ISvcSymbolSet, 0x6fa683af, 0x6aa, 0x484d, 0x87, 0xcf, 0x13, 0x7c, 0x1e, 0xa0, 0x16, 0xbd);

// {05D19D56-C15E-4c1d-9125-BB14D61B9784}
DEFINE_GUID(IID_ISvcSymbolSetCapabilities, 0x5d19d56, 0xc15e, 0x4c1d, 0x91, 0x25, 0xbb, 0x14, 0xd6, 0x1b, 0x97, 0x84);

// {733177E7-9C18-46b7-8D00-3D50A9119FC3}
DEFINE_GUID(IID_ISvcSymbolSetSimpleNameResolution, 0x733177e7, 0x9c18, 0x46b7, 0x8d, 0x0, 0x3d, 0x50, 0xa9, 0x11, 0x9f, 0xc3);

// {8803404F-DFE5-40c5-A8B8-F39AEB04CF86}
DEFINE_GUID(IID_ISvcSymbolSetSimpleSourceLineResolution, 0x8803404f, 0xdfe5, 0x40c5, 0xa8, 0xb8, 0xf3, 0x9a, 0xeb, 0x4, 0xcf, 0x86);

// {FFD73BA2-D7E9-442d-ADA6-4EF1B07D951F}
DEFINE_GUID(IID_ISvcSymbolSetSimpleSourceFileInformation, 0xffd73ba2, 0xd7e9, 0x442d, 0xad, 0xa6, 0x4e, 0xf1, 0xb0, 0x7d, 0x95, 0x1f);

// {E1EE646E-0480-4db3-8982-7DE87ED5B174}
DEFINE_GUID(IID_ISvcSymbolSetScopeResolution, 0xe1ee646e, 0x480, 0x4db3, 0x89, 0x82, 0x7d, 0xe8, 0x7e, 0xd5, 0xb1, 0x74);

// {5742B585-5542-4a5b-93E1-A05A6D9B6B89}
DEFINE_GUID(IID_ISvcSymbolSetTypeDerivations, 0x5742b585, 0x5542, 0x4a5b, 0x93, 0xe1, 0xa0, 0x5a, 0x6d, 0x9b, 0x6b, 0x89);

// {F6B2366A-C094-4072-845D-A06E5C97F77F}
DEFINE_GUID(IID_ISvcSymbolSetRuntimeTypeInformation, 0xf6b2366a, 0xc094, 0x4072, 0x84, 0x5d, 0xa0, 0x6e, 0x5c, 0x97, 0xf7, 0x7f);

// {D15DF42A-5E14-4981-8DFE-3379D0198846}
DEFINE_GUID(IID_ISvcSymbolSetSimpleInlineSourceLineResolution, 0xd15df42a, 0x5e14, 0x4981, 0x8d, 0xfe, 0x33, 0x79, 0xd0, 0x19, 0x88, 0x46);

// {4760A68C-DCAA-432e-A787-1063C9FA0D3D}
DEFINE_GUID(IID_ISvcSymbolSetInlineScopeResolution, 0x4760a68c, 0xdcaa, 0x432e, 0xa7, 0x87, 0x10, 0x63, 0xc9, 0xfa, 0xd, 0x3d);

// {CB416186-14D7-4ded-8EC2-9B45CBF06845}
DEFINE_GUID(IID_ISvcSymbolSetInlineFrameResolution, 0xcb416186, 0x14d7, 0x4ded, 0x8e, 0xc2, 0x9b, 0x45, 0xcb, 0xf0, 0x68, 0x45);

// {078BB523-7C08-4390-8FA5-921A4A0D5E07}
DEFINE_GUID(IID_ISvcSymbolSetSourceFileChecksums, 0x78bb523, 0x7c08, 0x4390, 0x8f, 0xa5, 0x92, 0x1a, 0x4a, 0xd, 0x5e, 0x7);

// {0E6662CA-B39F-4766-9F00-6B153B568A61}
DEFINE_GUID(IID_ISvcSymbolSetComplexLocationResolution, 0xe6662ca, 0xb39f, 0x4766, 0x9f, 0x0, 0x6b, 0x15, 0x3b, 0x56, 0x8a, 0x61);

// {7947495F-383B-49c7-B1C5-1F959DD99D09}
DEFINE_GUID(IID_ISvcSymbol, 0x7947495f, 0x383b, 0x49c7, 0xb1, 0xc5, 0x1f, 0x95, 0x9d, 0xd9, 0x9d, 0x9);

// {949A8DE4-BFF9-4f84-A3EF-79B2F154415A}
DEFINE_GUID(IID_ISvcSymbolInfo, 0x949a8de4, 0xbff9, 0x4f84, 0xa3, 0xef, 0x79, 0xb2, 0xf1, 0x54, 0x41, 0x5a);

// {FA7F393E-9A93-42DE-BF41-4ED9C8E46882}
DEFINE_GUID(IID_ISvcSymbolMultipleLocations, 0xfa7f393e, 0x9a93, 0x42de, 0xbf, 0x41, 0x4e, 0xd9, 0xc8, 0xe4, 0x68, 0x82);

// {B886A5F0-96CA-4086-B7EB-24458283C4C1}
DEFINE_GUID(IID_ISvcSymbolVariantInfo, 0xb886a5f0, 0x96ca, 0x4086, 0xb7, 0xeb, 0x24, 0x45, 0x82, 0x83, 0xc4, 0xc1);

// {80450742-C0A5-4160-8430-90B2212E132C}
DEFINE_GUID(IID_ISvcSymbolDiscriminatorValuesEnumerator, 0x80450742, 0xc0a5, 0x4160, 0x84, 0x30, 0x90, 0xb2, 0x21, 0x2e, 0x13, 0x2c);

// {14C37CAC-496D-4916-AF75-02345E27DA3E}
DEFINE_GUID(IID_ISvcSymbolCompilationUnit, 0x14c37cac, 0x496d, 0x4916, 0xaf, 0x75, 0x2, 0x34, 0x5e, 0x27, 0xda, 0x3e);

// {91DC29CD-F06E-46fe-8C5F-AC6787B79C6E}
DEFINE_GUID(IID_ISvcSymbolCompilationUnitSources, 0x91dc29cd, 0xf06e, 0x46fe, 0x8c, 0x5f, 0xac, 0x67, 0x87, 0xb7, 0x9c, 0x6e);

// {58AC3F3F-0886-4aa0-A074-9635CC0DDE95}
DEFINE_GUID(IID_ISvcSymbolType, 0x58ac3f3f, 0x886, 0x4aa0, 0xa0, 0x74, 0x96, 0x35, 0xcc, 0xd, 0xde, 0x95);

// {1B4FF8B8-BD87-43a2-8D53-C747C77716E0}
DEFINE_GUID(IID_ISvcSymbolChildren, 0x1b4ff8b8, 0xbd87, 0x43a2, 0x8d, 0x53, 0xc7, 0x47, 0xc7, 0x77, 0x16, 0xe0);

// {92E1C85D-C0FB-4f37-8961-F6EF486BDF09}
DEFINE_GUID(IID_ISvcSymbolChildrenByRegEx, 0x92e1c85d, 0xc0fb, 0x4f37, 0x89, 0x61, 0xf6, 0xef, 0x48, 0x6b, 0xdf, 0x9);

// {D1B55D38-9B15-4287-BCF3-6032EC3480C2}
DEFINE_GUID(IID_ISvcSymbolParents, 0xd1b55d38, 0x9b15, 0x4287, 0xbc, 0xf3, 0x60, 0x32, 0xec, 0x34, 0x80, 0xc2);

// {B76E15E2-132E-42ed-9EFA-D798ED6EA6A5}
DEFINE_GUID(IID_ISvcSymbolNameIndexedDescendents, 0xb76e15e2, 0x132e, 0x42ed, 0x9e, 0xfa, 0xd7, 0x98, 0xed, 0x6e, 0xa6, 0xa5);

// {2D8214A6-A620-4452-93A0-DF5DAEB43DA1}
DEFINE_GUID(IIC_ISvcSymbolSetEnumerator, 0x2d8214a6, 0xa620, 0x4452, 0x93, 0xa0, 0xdf, 0x5d, 0xae, 0xb4, 0x3d, 0xa1);

// {99D912AF-630F-473e-9B4D-A55829753070}
DEFINE_GUID(IID_ISvcSymbolSetScope, 0x99d912af, 0x630f, 0x473e, 0x9b, 0x4d, 0xa5, 0x58, 0x29, 0x75, 0x30, 0x70);

// {58B61CE1-875D-421f-BA4F-B8FFF3DE0964}
DEFINE_GUID(IID_ISvcSymbolSetScopeFrame, 0x58b61ce1, 0x875d, 0x421f, 0xba, 0x4f, 0xb8, 0xff, 0xf3, 0xde, 0x9, 0x64);

// {073DE56A-473E-4a8a-A059-DA7A185B2F90}
DEFINE_GUID(IID_ISvcSourceFile, 0x73de56a, 0x473e, 0x4a8a, 0xa0, 0x59, 0xda, 0x7a, 0x18, 0x5b, 0x2f, 0x90);

// {55ED5393-5417-4582-BA85-850D58D5ECF0}
DEFINE_GUID(IID_ISvcSourceFileEnumerator, 0x55ed5393, 0x5417, 0x4582, 0xba, 0x85, 0x85, 0xd, 0x58, 0xd5, 0xec, 0xf0);

// {471934B0-B6B6-4259-B16B-0784CE0274A7}
DEFINE_GUID(IID_ISvcImageParseProvider, 0x471934b0, 0xb6b6, 0x4259, 0xb1, 0x6b, 0x7, 0x84, 0xce, 0x2, 0x74, 0xa7);

// {27F4290C-41B2-453d-9980-E34B9DAF8E34}
DEFINE_GUID(IID_ISvcImageParser, 0x27f4290c, 0x41b2, 0x453d, 0x99, 0x80, 0xe3, 0x4b, 0x9d, 0xaf, 0x8e, 0x34);

// {711A2787-5747-43af-9B60-BB609BCB9996}
DEFINE_GUID(IID_ISvcImageParser2, 0x711a2787, 0x5747, 0x43af, 0x9b, 0x60, 0xbb, 0x60, 0x9b, 0xcb, 0x99, 0x96);

// {D9351812-532F-48dc-8FA7-8D0D64E1441D}
DEFINE_GUID(IID_ISvcImageVersionParser, 0xd9351812, 0x532f, 0x48dc, 0x8f, 0xa7, 0x8d, 0xd, 0x64, 0xe1, 0x44, 0x1d);

// {4EA0C43F-8378-43d9-BE1C-E698F5508E58}
DEFINE_GUID(IID_ISvcImageVersionParser2, 0x4ea0c43f, 0x8378, 0x43d9, 0xbe, 0x1c, 0xe6, 0x98, 0xf5, 0x50, 0x8e, 0x58);

// {555241CF-9322-48f9-8E71-F39307783BE6}
DEFINE_GUID(IID_ISvcImageVersionDataEnumerator, 0x555241cf, 0x9322, 0x48f9, 0x8e, 0x71, 0xf3, 0x93, 0x7, 0x78, 0x3b, 0xe6);

// {86669E84-8182-4c54-8938-04B5E5C5B958}
DEFINE_GUID(IID_ISvcImageDataLocationParser, 0x86669e84, 0x8182, 0x4c54, 0x89, 0x38, 0x4, 0xb5, 0xe5, 0xc5, 0xb9, 0x58);

// {E9BF1356-BA52-4b57-887F-2998499D5DCB}
DEFINE_GUID(IID_ISvcImageFileViewRegion, 0xe9bf1356, 0xba52, 0x4b57, 0x88, 0x7f, 0x29, 0x98, 0x49, 0x9d, 0x5d, 0xcb);

// {0DF8C531-ECA0-48f3-94BB-0964EC6EE3F0}
DEFINE_GUID(IID_ISvcImageMemoryViewRegion, 0xdf8c531, 0xeca0, 0x48f3, 0x94, 0xbb, 0x9, 0x64, 0xec, 0x6e, 0xe3, 0xf0);

// {996F652A-C052-413e-9406-87884D24FA1D}
DEFINE_GUID(IID_ISvcEventArgumentsSearchPathsChanged, 0x996f652a, 0xc052, 0x413e, 0x94, 0x6, 0x87, 0x88, 0x4d, 0x24, 0xfa, 0x1d);

// {1E020689-2351-432d-BDD2-C4DF5DB629E0}
DEFINE_GUID(IID_ISvcEventArgumentsSymbolLoad, 0x1e020689, 0x2351, 0x432d, 0xbd, 0xd2, 0xc4, 0xdf, 0x5d, 0xb6, 0x29, 0xe0);

// {2A5AFCDE-B2E7-443e-9D02-510E4F8E8040}
DEFINE_GUID(IID_ISvcEventArgumentsSymbolUnload, 0x2a5afcde, 0xb2e7, 0x443e, 0x9d, 0x2, 0x51, 0xe, 0x4f, 0x8e, 0x80, 0x40);

// {316D57FC-A856-400a-A259-93D9166955AF}
DEFINE_GUID(IID_ISvcEventArgumentExecutionStateChange, 0x316d57fc, 0xa856, 0x400a, 0xa2, 0x59, 0x93, 0xd9, 0x16, 0x69, 0x55, 0xaf);

// {1F3A5177-9D20-490c-8EF7-7BB2EF6044F3}
DEFINE_GUID(IID_ISvcEventArgumentsSymbolCacheInvalidate, 0x1f3a5177, 0x9d20, 0x490c, 0x8e, 0xf7, 0x7b, 0xb2, 0xef, 0x60, 0x44, 0xf3);

// {83D5EB18-4BFA-4832-ABC8-19D984A4BD86}
DEFINE_GUID(IID_ISvcEventArgumentsStateChangeCacheInvalidate, 0x83d5eb18, 0x4bfa, 0x4832, 0xab, 0xc8, 0x19, 0xd9, 0x84, 0xa4, 0xbd, 0x86);

// {31C02035-D414-4be0-9FE9-CFA8C88B33E9}
DEFINE_GUID(IID_ISvcNameDemangler, 0x31c02035, 0xd414, 0x4be0, 0x9f, 0xe9, 0xcf, 0xa8, 0xc8, 0x8b, 0x33, 0xe9);

// {C06B2FD1-8D55-4705-8A68-1C32B2977E94}
DEFINE_GUID(IID_ISvcTargetOperation, 0xc06b2fd1, 0x8d55, 0x4705, 0x8a, 0x68, 0x1c, 0x32, 0xb2, 0x97, 0x7e, 0x94);

// {F3F597C4-A43D-4057-A717-8E0F04E78820}
DEFINE_GUID(IID_ISvcTargetOperationStatusNotification, 0xf3f597c4, 0xa43d, 0x4057, 0xa7, 0x17, 0x8e, 0xf, 0x4, 0xe7, 0x88, 0x20);

// {DF1323B9-3586-499f-94E2-F1AAA80EBBCD}
DEFINE_GUID(IID_ISvcTargetStateChangeNotification, 0xdf1323b9, 0x3586, 0x499f, 0x94, 0xe2, 0xf1, 0xaa, 0xa8, 0xe, 0xbb, 0xcd);

// {5CA0337C-80AD-471d-9B4F-37803E4087CC}
DEFINE_GUID(IID_ISvcStepController, 0x5ca0337c, 0x80ad, 0x471d, 0x9b, 0x4f, 0x37, 0x80, 0x3e, 0x40, 0x87, 0xcc);

// {862E028B-A31A-4aaa-9661-6470F3D50B25}
DEFINE_GUID(IID_ISvcBreakpoint, 0x862e028b, 0xa31a, 0x4aaa, 0x96, 0x61, 0x64, 0x70, 0xf3, 0xd5, 0xb, 0x25);

// {53FBB33A-2F42-4465-9F02-0899ABF13460}
DEFINE_GUID(IID_ISvcBreakpointEnumerator, 0x53fbb33a, 0x2f42, 0x4465, 0x9f, 0x2, 0x8, 0x99, 0xab, 0xf1, 0x34, 0x60);

// {5D62C1F1-D49A-4749-90AA-C13443184C99}
DEFINE_GUID(IID_ISvcBreakpointController, 0x5d62c1f1, 0xd49a, 0x4749, 0x90, 0xaa, 0xc1, 0x34, 0x43, 0x18, 0x4c, 0x99);

// {F1A32D9A-922A-41b6-ADFF-AC363BB982D5}
DEFINE_GUID(IID_ISvcBreakpointControllerAdvanced, 0xf1a32d9a, 0x922a, 0x41b6, 0xad, 0xff, 0xac, 0x36, 0x3b, 0xb9, 0x82, 0xd5);

// {2F2F8A27-B2FB-491a-B86F-5A4232F1EB23}
DEFINE_GUID(IID_ISvcBreakpointControllerAdvanced2, 0x2f2f8a27, 0xb2fb, 0x491a, 0xb8, 0x6f, 0x5a, 0x42, 0x32, 0xf1, 0xeb, 0x23);

// {B751FDDF-3B41-4f4b-9EFE-EA310EEFE8D2}
DEFINE_GUID(IID_ISvcProcessConnector, 0xb751fddf, 0x3b41, 0x4f4b, 0x9e, 0xfe, 0xea, 0x31, 0xe, 0xef, 0xe8, 0xd2);

// {E184675D-EBF8-46e0-BC60-514378AF6F35}
DEFINE_GUID(IID_ISvcConnectableProcessEnumerator, 0xe184675d, 0xebf8, 0x46e0, 0xbc, 0x60, 0x51, 0x43, 0x78, 0xaf, 0x6f, 0x35);

// {0CA4DC6B-1070-4aa1-8C6C-1F626962A475}
DEFINE_GUID(IID_ISvcConnectableProcess, 0xca4dc6b, 0x1070, 0x4aa1, 0x8c, 0x6c, 0x1f, 0x62, 0x69, 0x62, 0xa4, 0x75);

// {8F815608-A145-4cf9-8488-9E0EAEA1F2B9}
DEFINE_GUID(IID_ISvcEventArgumentsProcessDiscovery, 0x8f815608, 0xa145, 0x4cf9, 0x84, 0x88, 0x9e, 0xe, 0xae, 0xa1, 0xf2, 0xb9);

// {51A92871-F1D1-4da2-9805-75A41731D636}
DEFINE_GUID(IID_ISvcEventArgumentsThreadDiscovery, 0x51a92871, 0xf1d1, 0x4da2, 0x98, 0x5, 0x75, 0xa4, 0x17, 0x31, 0xd6, 0x36);

// {3376E767-4480-4D7E-BC59-2D28BDE027AD}
DEFINE_GUID(IID_ISvcUserOperationController, 0x3376e767, 0x4480, 0x4d7e, 0xbc, 0x59, 0x2d, 0x28, 0xbd, 0xe0, 0x27, 0xad );

// {F1C16C42-3E6D-4fe5-A783-A7184B3061DF}
DEFINE_GUID(IID_ISvcSecondaryStateSynchronizationProfiles, 0xf1c16c42, 0x3e6d, 0x4fe5, 0xa7, 0x83, 0xa7, 0x18, 0x4b, 0x30, 0x61, 0xdf);

// {DDF13055-98E1-4fb7-B08B-4D95FB4693DD}
DEFINE_GUID(IID_ISvcSecondaryStateSynchronizationProfileItem, 0xddf13055, 0x98e1, 0x4fb7, 0xb0, 0x8b, 0x4d, 0x95, 0xfb, 0x46, 0x93, 0xdd);

// {C686AA07-983C-4908-A3E9-FE12636A51C4}
DEFINE_GUID(IID_ISvcSecondaryStateSynchronizationProfileItemEnumerator, 0xc686aa07, 0x983c, 0x4908, 0xa3, 0xe9, 0xfe, 0x12, 0x63, 0x6a, 0x51, 0xc4);

// {0EEEA5D0-1055-4c87-8BD8-9895FF2C9D10}
DEFINE_GUID(IID_ISvcSecondaryStateSynchronizationGenerationCounterProfileItem, 0xeeea5d0, 0x1055, 0x4c87, 0x8b, 0xd8, 0x98, 0x95, 0xff, 0x2c, 0x9d, 0x10);

struct DECLSPEC_UUID("FDD4EF98-93FD-4773-BCDF-AACFB87257A6") IDebugTargetCompositionComponent;
struct DECLSPEC_UUID("6D4E5F39-657E-4905-9670-448978F7FB27") IDebugTargetComposition;
struct DECLSPEC_UUID("66403806-4988-4a0a-A552-F14B1B5E33D5") IDebugTargetComposition2;
struct DECLSPEC_UUID("6E8041B9-CB1B-4071-B789-D8A871124B57") IDebugTargetComposition3;
struct DECLSPEC_UUID("AB73D421-5FBA-403d-BC0D-4EB92720135A") IDebugServiceManager;
struct DECLSPEC_UUID("71BE9D83-969F-428b-A28D-3A439D61FDE9") IDebugServiceEnumerator;
struct DECLSPEC_UUID("099FCD6F-0A4D-45cc-BD8B-C10C6ED53AC7") IDebugServiceManager2;
struct DECLSPEC_UUID("17B978DD-15C0-4318-A3D0-15305C6DD0D4") IDebugServiceManager3;
struct DECLSPEC_UUID("84069FCD-E8B0-48e5-8611-7F0A8FA130D2") IDebugServiceManager4;
struct DECLSPEC_UUID("5637D1DE-5804-4aee-A98B-9BA1E97A8A07") IDebugServiceManager5;
struct DECLSPEC_UUID("6BF32043-E2A9-462d-99B1-B2E6C15252A2") IDebugServiceLayer;
struct DECLSPEC_UUID("12954378-FAFD-4749-ADD8-7A98A5A4B896") IDebugServiceLayer2;
struct DECLSPEC_UUID("729CF17B-E82F-4ff8-B27C-F13693971FE3") IDebugServiceCapabilities;
struct DECLSPEC_UUID("6041DBC4-5BDA-4581-9BF4-0A6F74A643D4") IDebugServiceAggregate;
struct DECLSPEC_UUID("1C1772AC-D830-4558-803C-E049D4710E9D") IDebugComponentManager;
struct DECLSPEC_UUID("A0E9E780-FE9A-4085-AB4B-8B4CC276266A") ISvcDebugSourceFile;
struct DECLSPEC_UUID("7EBB44D0-3C22-41e1-AAB9-083E774CFF5D") ISvcDebugSourceFileMapping;
struct DECLSPEC_UUID("D9F5A718-E130-46c2-AECD-D66C557027B8") ISvcDebugSourceFileInformation;
struct DECLSPEC_UUID("52276F45-1CA1-4c47-8DC5-426AE90D7A26") ISvcDebugSourceView;
struct DECLSPEC_UUID("A271F928-F2B8-4a4f-9B2E-89FCB1F58680") ISvcDebugSourceWindowsKernelDebug;
struct DECLSPEC_UUID("E069DD06-1004-4010-A865-39635C4782B7") ISvcFileFormatPrivateData;
struct DECLSPEC_UUID("BF676866-9724-44d1-87F7-62047EB0A86C") ISvcFileFormatDataBlock;
struct DECLSPEC_UUID("2DDF4CC0-BBA8-4fb0-BD53-5F4C92218280") ISvcAddressContext;
struct DECLSPEC_UUID("1A39F548-ECF8-4ffe-830D-C923F51E752D") ISvcAddressContextHardware;
struct DECLSPEC_UUID("A99D428E-6948-4073-863F-8E14E8A469DC") ISvcIoSpace;
struct DECLSPEC_UUID("890C0F06-D269-4ba6-B5BB-C8335D6EC8C2") ISvcSecurityConfiguration;
struct DECLSPEC_UUID("0CF0EE09-1ABD-4f54-85C4-49775DE19CB1") ISvcSecurityConfiguration2;
struct DECLSPEC_UUID("B45C31AD-8149-4ea9-9DB8-F4468D710A36") ISvcProcess;
struct DECLSPEC_UUID("3A0957C5-A583-4ce1-ACC4-DFE9CACE0CF0") ISvcProcessBasicInformation;
struct DECLSPEC_UUID("2F5A6E6F-23F1-47d9-9DCF-A359B51AAAB0") ISvcMachineConfiguration;
struct DECLSPEC_UUID("D63778DF-FE4F-4ab8-904E-0E334E5A7CD3") ISvcMachineConfiguration2;
struct DECLSPEC_UUID("C9CD3D26-2A2D-4e14-99CD-2196F08C921A") ISvcMachineArchitecture;
struct DECLSPEC_UUID("FAFCA4B4-66DA-4ac0-86B6-AAC5C2498BC6") ISvcBasicDisassembly;
struct DECLSPEC_UUID("7D42C7D1-B9D3-4ddf-B9F9-05694F013B86") ISvcMemoryAccess;
struct DECLSPEC_UUID("AB7C5913-E08E-4b62-91E3-519253BAAFC1") ISvcMemoryAccessCacheControl;
struct DECLSPEC_UUID("2506F23D-C4B3-4248-9C37-7F80BB7E4893") ISvcMemoryInformation;
struct DECLSPEC_UUID("E327A72A-65D9-4545-9304-09F0104BB138") ISvcMemoryRegion;
struct DECLSPEC_UUID("66FF5B9F-A8D1-4a78-ADA9-4DFEDCC12C3A") ISvcMemoryRegionEnumerator;
struct DECLSPEC_UUID("56373E0F-D615-487f-95B9-37931E2A9A90") ISvcMemoryTranslation;
struct DECLSPEC_UUID("3603A7EE-E996-46e0-85BA-9CEA48EEF6E1") ISvcPageFileReader;
struct DECLSPEC_UUID("FF85423A-3B47-4205-8D0C-3F28F47FF3D7") ISvcProcessEnumerator;
struct DECLSPEC_UUID("3CFA6328-A170-4d90-BCE2-C9FDB898C1F5") ISvcProcessEnumeration;
struct DECLSPEC_UUID("C6648B7C-F2E4-4304-9A3E-ED71CF0F26C6") ISvcThread;
struct DECLSPEC_UUID("A4D4186A-CA0E-483b-BB2A-A83F9D3F3115") ISvcThreadEnumeration;
struct DECLSPEC_UUID("10545A55-D561-4119-BDBC-D885F23045DA") ISvcThreadEnumerator;
struct DECLSPEC_UUID("58EE46F3-209E-4402-8452-C3797D5C3355") ISvcThreadLocalStorageProvider;
struct DECLSPEC_UUID("D795507F-956D-4efb-B829-AC3EABCA961B") ISvcIoSpaceEnumeration;
struct DECLSPEC_UUID("360DE704-D055-483a-8E3B-BD67D2DA0133") ISvcModule;
struct DECLSPEC_UUID("FF4713F1-74DD-4cbc-830C-7F13D7E31AA3") ISvcModuleWithTimestampAndChecksum;
struct DECLSPEC_UUID("31A3942E-E145-4112-9014-88DC7593028E") ISvcMappingInformation;
struct DECLSPEC_UUID("A4D7D798-A4C1-40ad-9235-B80F0BF8E2AD") ISvcAddressRangeEnumeration;
struct DECLSPEC_UUID("20D4BA1D-BE37-4dc4-9F6A-90E3C373200E") ISvcModuleEnumeration;
struct DECLSPEC_UUID("04E3E600-9A10-48df-A618-775B3E36A740") ISvcPrimaryModules;
struct DECLSPEC_UUID("ABE84A4B-1EA3-4058-B875-A1D69A7BB3FE") ISvcModuleEnumerator;
struct DECLSPEC_UUID("5AC23A8A-6D8C-4c92-AC1B-813E6EF1B48A") ISvcModuleIndexProvider;
struct DECLSPEC_UUID("B497B0C9-9572-4257-A156-792D3AF03D94") ISourceCodeDownloadUrlLinkProvider;
struct DECLSPEC_UUID("498CBE80-B1F4-4f55-91E1-477C507A1D9F") IClrDacAndSosProvider;
struct DECLSPEC_UUID("BC6823E0-6E29-4474-9A9B-7728844E90A2") IClrDacDbiAndSosProvider;
struct DECLSPEC_UUID("4C1BEC33-1B39-4708-AB0A-C8AE0E9DDB3E") ISvcSegmentTranslation;
struct DECLSPEC_UUID("CA1AFE05-244C-4fa3-BED4-A355418587EF") ISvcRegisterContext;
struct DECLSPEC_UUID("D9E1F476-4FAE-4051-89C9-45D25925DB41") ISvcClassicRegisterContext;
struct DECLSPEC_UUID("33D1251E-BD8C-489e-B07A-CC545A27042C") ISvcClassicSpecialContext;
struct DECLSPEC_UUID("B91E34DE-6407-4583-BBAE-95FE20548363") ISvcRegisterInformation;
struct DECLSPEC_UUID("AE8EC624-52F6-43a4-BBAB-57A6C1C393C3") ISvcRegisterEnumerator;
struct DECLSPEC_UUID("5ED13135-FA5D-4d29-BB93-C80CB72ADFD4") ISvcRegisterFlagInformation;
struct DECLSPEC_UUID("55C7E6F4-D357-4209-ACF7-55D945AF3841") ISvcRegisterFlagsEnumerator;
struct DECLSPEC_UUID("C5A05162-A375-48fc-AB00-3045C6386836") ISvcRegisterTranslation;
struct DECLSPEC_UUID("A61B284D-EC7D-4ee7-A3B0-99B59F171F9A") ISvcDwarfRegisterTranslation;
struct DECLSPEC_UUID("EDDC117F-50EB-48c6-B201-1B7CB9C675AB") ISvcRegisterContextTranslation;
struct DECLSPEC_UUID("3870640B-8D1E-469d-8552-F38D48E28766") ISvcTrapContextRestoration;
struct DECLSPEC_UUID("01C932D4-9F5E-4268-8B12-EC246582A82D") ISvcExecutionUnit;
struct DECLSPEC_UUID("F272C72D-E794-498f-B169-2F74B38A2DAE") ISvcExecutionUnitHardware;
struct DECLSPEC_UUID("59C0BA4E-84E8-4a2e-8874-83DF03E3CFF5") ISvcMachineDebug;
struct DECLSPEC_UUID("92F3C9F5-5B7B-4202-8163-44D86E4C051E") ISvcOSKernelInfrastructure;
struct DECLSPEC_UUID("C809D0B1-4563-4577-BFDC-AF951FCE5308") ISvcOSKernelTypes;
struct DECLSPEC_UUID("B1383D5C-3630-4492-9AD8-720CC34AD12F") ISvcOSKernelTransitions;
struct DECLSPEC_UUID("E14E5358-56DD-4c71-98F8-EDED11398426") ISvcOSKernelObject;
struct DECLSPEC_UUID("8E18CBC7-B80A-4c42-A10D-A56E17A555CE") ISvcOSKernelObjectAccessor;
struct DECLSPEC_UUID("995F51EF-FE22-441e-BCE6-0F6FECFB9A0A") ISvcOSKernelLocator;
struct DECLSPEC_UUID("F980577B-73FA-40fe-95A3-C4D44100FD68") ISvcWindowsKdInfrastructure;
struct DECLSPEC_UUID("C6B492DC-CBC1-4574-8E16-95BDFC06AEA0") ISvcWindowsKernelInfrastructure;
struct DECLSPEC_UUID("2559B271-BFE2-4ecc-9FFB-DA5F49D17F3D") ISvcWindowsExceptionTranslation;
struct DECLSPEC_UUID("292A1D08-3971-40c1-883A-8E8289CF685D") ISvcWindowsThreadInformation;
struct DECLSPEC_UUID("48BE7867-8C93-449d-8574-01C9375EB112") ISvcWindowsProcessInformation;
struct DECLSPEC_UUID("23ED1044-166C-4c62-91FC-B5656E4A74EF") ISvcSymbolProvider;
struct DECLSPEC_UUID("5E93C234-11E1-46ed-836C-44FD3E949623") ISvcSymbolProvider2;
struct DECLSPEC_UUID("31C1B07E-745A-461c-90C0-8FBC5162AC86") ISvcJITSymbolProvider;
struct DECLSPEC_UUID("76D4EDDF-282E-4381-8389-6FA9EEB067C2") ISvcImageProvider;
struct DECLSPEC_UUID("44CFC4B1-02B5-490a-A51A-AD34E49457F4") ISvcStackFrameUnwind;
struct DECLSPEC_UUID("2ED57D21-39C8-4d09-9751-8A80E15DECF4") ISvcStackFrameUnwinderTransition;
struct DECLSPEC_UUID("83D68882-2AF7-408c-9B4E-FA5677F44C3E") ISvcStackFrameInjection;
struct DECLSPEC_UUID("B44285F2-5FAC-4ba9-8A1F-DD264EF1F1D3") ISvcStackUnwindContext;
struct DECLSPEC_UUID("2D742534-FC20-4472-A5DD-3A66BFED5832") ISvcStackUnwindContext2;
struct DECLSPEC_UUID("E5CFCBEE-E83D-451f-A26B-D687C72159DD") ISvcStackUnwindContext3;
struct DECLSPEC_UUID("F3E0DAE9-6385-41be-9EA6-75BCFBF5B727") ISvcSearchPaths;
struct DECLSPEC_UUID("BE5E232C-1D4B-4983-A520-383DA865DA1C") ISvcContextTranslation;
struct DECLSPEC_UUID("1579B0C9-A848-447d-BB65-0CFFE3F985FB") ISvcActiveExceptions;
struct DECLSPEC_UUID("8FCC28B1-3ADA-4876-A6D4-7BF9543DE30B") ISvcExceptionInformation;
struct DECLSPEC_UUID("5A37C25E-4F8D-47be-87F5-94A933824A83") ISvcExceptionControl;
struct DECLSPEC_UUID("DE815F6F-5824-4555-A010-286791BC79AD") ISvcLinuxSignalInformation;
struct DECLSPEC_UUID("228DBCF1-3E54-42fc-9DDD-5EFB76B13C70") ISvcWindowsBugCheckInformation;
struct DECLSPEC_UUID("B181A69C-9D85-4747-8CF8-2ADF53CF750A") ISvcExceptionFormatter;
struct DECLSPEC_UUID("40B23EAC-F503-46fc-9C95-09384D050A11") ISvcOSPlatformInformation;
struct DECLSPEC_UUID("7B6FABD4-D271-413a-8475-31F8483179FD") ISvcOSPlatformInformation2;
struct DECLSPEC_UUID("39BCF55E-9150-4bba-9472-88C972DD7885") ISvcTelemetry;
struct DECLSPEC_UUID("76EB9426-DAE9-4607-8822-45BE93081D6E") ISvcDiagnosticLogging;
struct DECLSPEC_UUID("B2054872-8D6A-4884-8800-9C8B82F83732") ISvcDiagnosticLoggingXmlPassthrough;
struct DECLSPEC_UUID("432BEA74-794D-46fb-AC50-EBECA9AA865C") ISvcDiagnosticLoggableControl;
struct DECLSPEC_UUID("A7DF185B-CBBF-4b0d-BBA6-C58D6F9240C0") ISvcAddressRangeEnumerator;
struct DECLSPEC_UUID("131E4723-1CC2-4ec7-BB12-9F40EDF63B66") ISvcDescription;
struct DECLSPEC_UUID("50DEB97A-25CC-41c1-B467-96C5E3F454CA") ISvcPrivateProperties;
struct DECLSPEC_UUID("C11A8084-0BC4-45f8-AF3C-821FBC835312") ISvcStackProvider;
struct DECLSPEC_UUID("81E83593-5AA9-43aa-8A5D-B964411E4B53") ISvcStackProviderFrameSetEnumerator;
struct DECLSPEC_UUID("2F79D431-71BF-4f40-B959-96361E92AD04") ISvcStackProviderFrame;
struct DECLSPEC_UUID("96CE81F7-C6B9-4665-B2E5-6EB229079091") ISvcStackProviderFrameAttributes;
struct DECLSPEC_UUID("EB64279F-6EEF-451f-9DA4-55DB69FC2A95") ISvcStackProviderPhysicalFrame;
struct DECLSPEC_UUID("46329742-2733-41fa-A125-6EEF620998B1") ISvcStackProviderPartialPhysicalFrame;
struct DECLSPEC_UUID("4D0BDD20-61CD-4f18-936A-7E9350B30966") ISvcStackProviderInlineFrame;
struct DECLSPEC_UUID("3376E767-4480-4D7E-BC59-2D28BDE027AD") ISvcUserOperationController;
struct DECLSPEC_UUID("F1C16C42-3E6D-4fe5-A783-A7184B3061DF") ISvcSecondaryStateSynchronizationProfiles;
struct DECLSPEC_UUID("DDF13055-98E1-4fb7-B08B-4D95FB4693DD") ISvcSecondaryStateSynchronizationProfileItem;
struct DECLSPEC_UUID("C686AA07-983C-4908-A3E9-FE12636A51C4") ISvcSecondaryStateSynchronizationProfileItemEnumerator;
struct DECLSPEC_UUID("0EEEA5D0-1055-4c87-8BD8-9895FF2C9D10") ISvcSecondaryStateSynchronizationGenerationCounterProfileItem;

//*************************************************
// Symbol Set Interfaces (and interfaces which QI off the base ISvcSymbolSet):
//
// Symbols for a module must support ISvcSymbolSet (the interface which is returned from a symbol
// provider service)).  ISvcSymbolSet is the bare minimum interface for a set of symbols
// that allows a user to discover every symbol in the set (with no search capabilities).
//
// A provider may choose to implement progressively more complex functionality through ISvcSymbolSet
// querying for a number of other interfaces:
//
// 1) Simple Name Resolution (ISvcSymbolSetSimpleNameResolution)
//
//    A provider which gives the capability to map from name -> offset and vice-versa (without regard
//    to the complexities of inlining, folding, and other optimizations) implements this interface.  It provides
//    a "simple" give me the name for an offset and give me the offset for a name style of functionality.
//
// 2) Simple Source Line Resolution (ISvcSymbolSetSimpleSourceLineResolution)
//
//    A provider which gives the capability to map from offset -> source line and vice-versa (without regard
//    to the complexities of inlining, folding, and other optimizations) implements this interface.  It provides
//    a "simple" give me the source file & line for an offset and give me the offset for a source file & line
//    style of functionality.
//
// 3) Source File Information (ISvcSymbolSetSimpleSourceFileInformation)
//
//     A provider which can enumerate source files and their association to compilation units / compilands
//     (separately from source line resolution) can implement ISvcSymbolSetSimpleSourceFileInformation.
//
// 4) Scopes and Optimization Data (ISvcSymbolSetScopeResolution)
//
//    A provider which gives the capability to look at the arguments and locals of a function and nested
//    lexical scopes implements this interface.  It provides the ability to get and enumerate scopes and
//    return the location of locals and arguments including potential optimization data where the lifetime
//    and location of locals vary during a function.
//
//    Including Inline Data (ISvcSymbolSetInlineScopeResolution)
//
//    A provider which gives the capability to look at the arguments and locals of scopes within inlined
//    function instances implements this interface.
//
// 5) Analysis and Layout of Type Derivations (ISvcSymbolSetTypeDerivations)
//
//    A provider which gives the capability to construct types based on information which does not come directly
//    from the symbols (e.g.: arrays of things which do come from symbols)
//
// 6) Runtime Type Information (IsvcSymbolSetRuntimeTypeInformation)
//
//    A provider which has the capability of giving RTTI (or other runtime type information) for objects based
//    on static type information can implement this interface.
//
// 7) Inline Frame Resolution (ISvcSymbolSetInlineFrameResolution)
//
//    A provider which has the capability of describing how functions inlined at a particular offset
//    can implement this interface.
//
// 8) Inline Source Line Resolution (ISvcSymbolSetSimpleInlineSourceLineResolution)
//
//    A provider which can return the source locations at which inline frames were inlined can implement
//    this interface to get better source line locations in stack walks.
//
// 9) Complex Location Resolution (ISvcSymbolSetComplexLocationResolution)
//
//    A provider which returns symbols that have complex locations can implement this interface in order
//    to simplify those locations (often into virtual addresses) given additional information such as the
//    full register context of the frame in which the location information is relevant.
//

struct DECLSPEC_UUID("6FA683AF-06AA-484d-87CF-137C1EA016BD") ISvcSymbolSet;
struct DECLSPEC_UUID("05D19D56-C15E-4c1d-9125-BB14D61B9784") ISvcSymbolSetCapabilities;
struct DECLSPEC_UUID("733177E7-9C18-46b7-8D00-3D50A9119FC3") ISvcSymbolSetSimpleNameResolution;
struct DECLSPEC_UUID("8803404F-DFE5-40c5-A8B8-F39AEB04CF86") ISvcSymbolSetSimpleSourceLineResolution;
struct DECLSPEC_UUID("FFD73BA2-D7E9-442d-ADA6-4EF1B07D951F") ISvcSymbolSetSimpleSourceFileInformation;
struct DECLSPEC_UUID("E1EE646E-0480-4db3-8982-7DE87ED5B174") ISvcSymbolSetScopeResolution;
struct DECLSPEC_UUID("5742B585-5542-4a5b-93E1-A05A6D9B6B89") ISvcSymbolSetTypeDerivations;
struct DECLSPEC_UUID("F6B2366A-C094-4072-845D-A06E5C97F77F") ISvcSymbolSetRuntimeTypeInformation;
struct DECLSPEC_UUID("0E6662CA-B39F-4766-9F00-6B153B568A61") ISvcSymbolSetComplexLocationResolution;

struct DECLSPEC_UUID("D15DF42A-5E14-4981-8DFE-3379D0198846") ISvcSymbolSetSimpleInlineSourceLineResolution;
struct DECLSPEC_UUID("4760A68C-DCAA-432e-A787-1063C9FA0D3D") ISvcSymbolSetInlineScopeResolution;
struct DECLSPEC_UUID("CB416186-14D7-4ded-8EC2-9B45CBF06845") ISvcSymbolSetInlineFrameResolution;

struct DECLSPEC_UUID("078BB523-7C08-4390-8FA5-921A4A0D5E07") ISvcSymbolSetSourceFileChecksums;

//*************************************************
// Symbol Interfaces (and interfaces which QI off the base ISvcSymbol):
//
// All symbol sets return symbols that support the basic ISvcSymbol interface.  Depending on the particular
// provider and its capabilities, individual symbols -- like symbol sets -- implement progressively more complex
// interfaces that provide differing increasing capabilities for understanding the nature of symbolic information.
//

struct DECLSPEC_UUID("7947495F-383B-49c7-B1C5-1F959DD99D09") ISvcSymbol;
struct DECLSPEC_UUID("949A8DE4-BFF9-4f84-A3EF-79B2F154415A") ISvcSymbolInfo;
struct DECLSPEC_UUID("FA7F393E-9A93-42DE-BF41-4ED9C8E46882") ISvcSymbolMultipleLocations;
struct DECLSPEC_UUID("14C37CAC-496D-4916-AF75-02345E27DA3E") ISvcSymbolCompilationUnit;
struct DECLSPEC_UUID("91DC29CD-F06E-46fe-8C5F-AC6787B79C6E") ISvcSymbolCompilationUnitSources;
struct DECLSPEC_UUID("58AC3F3F-0886-4aa0-A074-9635CC0DDE95") ISvcSymbolType;
struct DECLSPEC_UUID("1B4FF8B8-BD87-43a2-8D53-C747C77716E0") ISvcSymbolChildren;
struct DECLSPEC_UUID("92E1C85D-C0FB-4f37-8961-F6EF486BDF09") ISvcSymbolChildrenByRegEx;
struct DECLSPEC_UUID("D1B55D38-9B15-4287-BCF3-6032EC3480C2") ISvcSymbolParents;
struct DECLSPEC_UUID("B76E15E2-132E-42ed-9EFA-D798ED6EA6A5") ISvcSymbolNameIndexedDescendents;
struct DECLSPEC_UUID("EAB8E16C-12F7-4878-8E0E-A59F0B25D4CB") ISvcSymbolRegExIndexedDescendents;
struct DECLSPEC_UUID("D2513438-18DA-4360-8242-49E0638FB2A4") ISvcSymbolAddressMapping;

struct DECLSPEC_UUID("B886A5F0-96CA-4086-B7EB-24458283C4C1") ISvcSymbolVariantInfo;
struct DECLSPEC_UUID("80450742-C0A5-4160-8430-90B2212E132C") ISvcSymbolDiscriminatorValuesEnumerator;

struct DECLSPEC_UUID("2D8214A6-A620-4452-93A0-DF5DAEB43DA1") ISvcSymbolSetEnumerator;
struct DECLSPEC_UUID("99D912AF-630F-473e-9B4D-A55829753070") ISvcSymbolSetScope;
struct DECLSPEC_UUID("58B61CE1-875D-421f-BA4F-B8FFF3DE0964") ISvcSymbolSetScopeFrame;

struct DECLSPEC_UUID("073DE56A-473E-4a8a-A059-DA7A185B2F90") ISvcSourceFile;
struct DECLSPEC_UUID("55ED5393-5417-4582-BA85-850D58D5ECF0") ISvcSourceFileEnumerator;

//*************************************************
// Image Parse Interfaces
//

struct DECLSPEC_UUID("471934B0-B6B6-4259-B16B-0784CE0274A7") ISvcImageParseProvider;

struct DECLSPEC_UUID("27F4290C-41B2-453d-9980-E34B9DAF8E34") ISvcImageParser;
struct DECLSPEC_UUID("711A2787-5747-43af-9B60-BB609BCB9996") ISvcImageParser2;
struct DECLSPEC_UUID("D9351812-532F-48dc-8FA7-8D0D64E1441D") ISvcImageVersionParser;
struct DECLSPEC_UUID("4EA0C43F-8378-43d9-BE1C-E698F5508E58") ISvcImageVersionParser2;
struct DECLSPEC_UUID("86669E84-8182-4c54-8938-04B5E5C5B958") ISvcImageDataLocationParser;
struct DECLSPEC_UUID("E9BF1356-BA52-4b57-887F-2998499D5DCB") ISvcImageFileViewRegion;
struct DECLSPEC_UUID("0DF8C531-ECA0-48f3-94BB-0964EC6EE3F0") ISvcImageMemoryViewRegion;
struct DECLSPEC_UUID("A4AE6E38-E6DA-4bc8-9FC0-EC65821948E5") ISvcImageFileViewRegionEnumerator;
struct DECLSPEC_UUID("BF990D96-9D77-4a39-A611-74DE8F0F6B45") ISvcImageMemoryViewRegionEnumerator;
struct DECLSPEC_UUID("555241CF-9322-48f9-8E71-F39307783BE6") ISvcImageVersionDataEnumerator;

//*************************************************
// Event and Event Arguments Interfaces:
//

struct DECLSPEC_UUID("996F652A-C052-413e-9406-87884D24FA1D") ISvcEventArgumentsSearchPathsChanged;
struct DECLSPEC_UUID("1E020689-2351-432d-BDD2-C4DF5DB629E0") ISvcEventArgumentsSymbolLoad;
struct DECLSPEC_UUID("2A5AFCDE-B2E7-443e-9D02-510E4F8E8040") ISvcEventArgumentsSymbolUnload;
struct DECLSPEC_UUID("316D57FC-A856-400a-A259-93D9166955AF") ISvcEventArgumentExecutionStateChange;
struct DECLSPEC_UUID("D492514F-7CFE-4876-96AC-7FAB627895AB") ISvcEventArgumentsModuleDiscovery;
struct DECLSPEC_UUID("8F815608-A145-4cf9-8488-9E0EAEA1F2B9") ISvcEventArgumentsProcessDiscovery;
struct DECLSPEC_UUID("51A92871-F1D1-4da2-9805-75A41731D636") ISvcEventArgumentsThreadDiscovery;
struct DECLSPEC_UUID("1F3A5177-9D20-490c-8EF7-7BB2EF6044F3") ISvcEventArgumentsSymbolCacheInvalidate;
struct DECLSPEC_UUID("83D5EB18-4BFA-4832-ABC8-19D984A4BD86") ISvcEventArgumentsStateChangeCacheInvalidate;
struct DECLSPEC_UUID("8983F680-8031-4bbc-9F67-BBB206058FAB") ISvcEventArgumentsSourceMappingsChanged;

//*************************************************
// Other Symbolic / Linguistic Interfaces:
//

struct DECLSPEC_UUID("31C02035-D414-4be0-9FE9-CFA8C88B33E9") ISvcNameDemangler;

//*************************************************
// Live Target / Step Control Interfaces:
//

struct DECLSPEC_UUID("C06B2FD1-8D55-4705-8A68-1C32B2977E94") ISvcTargetOperation;
struct DECLSPEC_UUID("F3F597C4-A43D-4057-A717-8E0F04E78820") ISvcTargetOperationStatusNotification;
struct DECLSPEC_UUID("DF1323B9-3586-499f-94E2-F1AAA80EBBCD") ISvcTargetStateChangeNotification;
struct DECLSPEC_UUID("5CA0337C-80AD-471d-9B4F-37803E4087CC") ISvcStepController;

struct DECLSPEC_UUID("862E028B-A31A-4aaa-9661-6470F3D50B25") ISvcBreakpoint;
struct DECLSPEC_UUID("53FBB33A-2F42-4465-9F02-0899ABF13460") ISvcBreakpointEnumerator;
struct DECLSPEC_UUID("5D62C1F1-D49A-4749-90AA-C13443184C99") ISvcBreakpointController;
struct DECLSPEC_UUID("F1A32D9A-922A-41b6-ADFF-AC363BB982D5") ISvcBreakpointControllerAdvanced;
struct DECLSPEC_UUID("2F2F8A27-B2FB-491a-B86F-5A4232F1EB23") ISvcBreakpointControllerAdvanced2;

//*************************************************
// Live Process Server Interfaces:
//

struct DECLSPEC_UUID("B751FDDF-3B41-4f4b-9EFE-EA310EEFE8D2") ISvcProcessConnector;
struct DECLSPEC_UUID("E184675D-EBF8-46e0-BC60-514378AF6F35") ISvcConnectableProcessEnumerator;
struct DECLSPEC_UUID("0CA4DC6B-1070-4aa1-8C6C-1F626962A475") ISvcConnectableProcess;

//*************************************************
// List of "well known" module index kinds (returned by ISvcModuleIndexProvider::GetModuleIndexKey):
//

DEFINE_GUID(DEBUG_MODULEINDEXKEY_GUID, 0xdf45233d, 0x4b67, 0x40f7, 0x87, 0x08, 0x4e, 0xd9, 0x1d, 0x7a, 0xe8, 0x75);
DEFINE_GUID(DEBUG_MODULEINDEXKEY_GNU_BUILDID, 0x192e4e9b, 0xc62f, 0x47f6, 0xb7, 0x7e, 0x96, 0xd9, 0x39, 0x99, 0x45, 0xd4);
DEFINE_GUID(DEBUG_MODULEINDEXKEY_TIMESTAMP_IMAGESIZE, 0x3339721, 0x75e7, 0x4a09, 0x8b, 0x28, 0xfc, 0xc7, 0x3a, 0x8d, 0x1a, 0xbf);
DEFINE_GUID(DEBUG_MODULEINDEXKEY_GO_BUILDID, 0x367f587b, 0x45d9, 0x4007, 0x9b, 0xbd, 0x38, 0xcf, 0xfd, 0x1c, 0x94, 0x85);

//**************************************************************************
// To Be Deleted.  Q/A Temporary Section:

//
// Q: What is a target...?
// A: A target is what the *USER* perceives as an independently debuggable thing.
//
// A debugger extension can get an existing target or create a new target.  New targets are
// created in essentially a "blank" state (a services layer with no services).  The new target
// can redirect its queries to the services of an existing target.
//

//
// Q: How does a debugger extension come in and provide a "view" of a "Hyper-V" guest.
// A:
//    ON STOP (event ...?)
//        1] It finds the relevant target (e.g.: the debugger target of the Hyper-V root partition).
//        2] It queries the relevant target for the service manager
//        3] It creates a new target
//        4] It registers any components which forward to services in the root partition
//        5] It inserts a physical memory/virtual memory component which performs SLAT and the underlying
//           memory layer points at the original target's service
//        ...
//
//    ON RESUME (event ...?)
//        6] It removes the target
//

//**************************************************************************
// Target Composition Layer:
//
// A "target composition component" is an object (or an aggregation of smaller objects)
// which provide one or more standardized services.
//

#undef INTERFACE
#define INTERFACE IDebugTargetCompositionComponent
DECLARE_INTERFACE_(IDebugTargetCompositionComponent, IUnknown)
{
    // CreateInstance():
    //
    // Create a new instance of this component which is not yet bound to any service manager.
    //
    STDMETHOD(CreateInstance)(
        THIS_
        _COM_Outptr_ IDebugServiceLayer** componentService
        ) PURE;
};

#undef INTERFACE
#define INTERFACE IDebugTargetComposition
DECLARE_INTERFACE_(IDebugTargetComposition, IUnknown)
{
    // CreateServiceManager():
    //
    // Creates a service manager.
    //
    STDMETHOD(CreateServiceManager)(
        THIS_
        _COM_Outptr_ IDebugServiceManager** serviceManager
        ) PURE;

    // RegisterComponent():
    //
    // Registers a given component by GUID such that an instance of the component can be created
    // via Create[AndQuery]Component.
    //
    STDMETHOD(RegisterComponent)(
        THIS_
        _In_ REFGUID componentGuid,
        _In_ IDebugTargetCompositionComponent* component
        ) PURE;

    // CreateComponent():
    //
    STDMETHOD(CreateComponent)(
        THIS_
        _In_ REFGUID componentGuid,
        _COM_Outptr_ IDebugServiceLayer** componentService
        ) PURE;

    // CreateAndQueryComponent():
    //
    STDMETHOD(CreateAndQueryComponent)(
        THIS_
        _In_ REFGUID componentGuid,
        _COM_Outptr_opt_ IDebugServiceLayer** componentService,
        _In_ REFIID serviceInterface,
        _COM_Outptr_ PVOID* interfaceUnknown
        ) PURE;

    // UnregisterComponent():
    //
    // Unregisters a given component by GUID such that instances of the component can no longer be created
    // via Create[AndQuery]Component.
    //
    STDMETHOD(UnregisterComponent)(
        THIS_
        _In_ REFGUID componentGuid,
        _In_ IDebugTargetCompositionComponent* component
        ) PURE;
};

// SvcConditionalServiceInformation:
//
// Describes a component which is a conditional implementation of a particular service (e.g.: the disassembly
// service for the AMD64 architecture).  Conditional services should only be used when the functionality of the service
// (as provided by its methods) never needs to be dynamic (e.g.: directing to one of several choices based on
// incoming arguments).
//
struct SvcConditionalServiceInformation
{
    ULONG StructSize;               // Always must be initialzed to sizeof(SvcConditionalServiceInformation)
    GUID ServiceGuid;               // The GUID of the service (DEBUG_SERVICE_*)
    GUID PrimaryCondition;          // A GUID identifying the primary condition (e.g.: an architecture GUID)
    GUID SecondaryCondition;        // A GUID identifying any secondary condition (may be GUID_NULL)
};

#undef INTERFACE
#define INTERFACE IDebugTargetComposition2
DECLARE_INTERFACE_(IDebugTargetComposition2, IDebugTargetComposition)
{
    // RegisterComponentAsConditionalService():
    //
    // Registers a given component by GUID such that an instance of the component can be created
    // via Create[AndQuery]Component.
    //
    // In addition, registers the component as a conditional implementation of a given service as given by
    // the conditional service information.
    //
    // The given component can either be created by its explicit component GUID or it can be created by a
    // the service GUID and a description of the conditions.
    //
    STDMETHOD(RegisterComponentAsConditionalService)(
        THIS_
        _In_ REFGUID componentGuid,
        _In_ IDebugTargetCompositionComponent *component,
        _In_ SvcConditionalServiceInformation *conditionalServiceInfo
        ) PURE;

    // CreateConditionalService():
    //
    // Finds the component registered as the implementation of a particular service for a particular set of conditions
    // and creates it.
    //
    STDMETHOD(CreateConditionalService)(
        THIS_
        _In_ SvcConditionalServiceInformation *conditionalServiceInfo,
        _COM_Outptr_ IDebugServiceLayer **componentService
        ) PURE;

    // CreateAndQueryConditionalService():
    //
    STDMETHOD(CreateAndQueryConditionalService)(
        THIS_
        _In_ SvcConditionalServiceInformation *conditionalServiceInfo,
        _COM_Outptr_opt_ IDebugServiceLayer **componentService,
        _In_ REFIID serviceInterface,
        _COM_Outptr_ PVOID *interfaceUnknown
        ) PURE;
};

#undef INTERFACE
#define INTERFACE IDebugTargetComposition3
DECLARE_INTERFACE_(IDebugTargetComposition3, IDebugTargetComposition2)
{
    // RegisterComponentAsStandardAggregator():
    //
    // Registers a given component by GUID such that it acts as the standard means of aggregation for
    // another service as identified by GUID.
    //
    // The given component must implement IDebugServiceAggregate.
    //
    STDMETHOD(RegisterComponentAsStandardAggregator)(
        THIS_
        _In_ REFGUID componentGuid,
        _In_ IDebugTargetCompositionComponent *component,
        _In_ REFGUID aggregatedServiceGuid
        ) PURE;

    // CreateServiceAggregatorComponent():
    //
    // Finds the component registered as the standard implementation of an aggregator for a particular service
    // and creates it.
    //
    // The returned component will implement IDebugServiceAggregate.
    //
    STDMETHOD(CreateServiceAggregatorComponent)(
        THIS_
        _In_ REFGUID serviceGuid,
        _COM_Outptr_ IDebugServiceLayer **componentService
        ) PURE;
};

// CreateTargetCompositionManager():
//
HRESULT CreateTargetCompositionManager(_COM_Outptr_ IDebugTargetComposition** compositionManager);

//**************************************************************************
// Services Layer:
//
//     Target:
//         - A target is conceptually a unit of debuggability that a user would consider such.
//           A kernel debugger connection to a machine would be considered a target.  A window
//           into a guest VM while debugging a Hyper-V root partition would be another example
//           of a target.  A connection to a user mode debug server (multiple processes) would
//           be considered a target.
//
//           Each target contains one **Debug Service Manager**
//
//     Debug Service Manager:
//         - A management component which aggregates a set of components that provide debug services.
//           These services act in combination to provide in order to provide the capabilities of debugging
//           the target.  The following services are examples of services which may be provided
//           by the components aggregated by the service manager:
//
//           Virtual Memory Service
//           Physical Memory Service
//           Process Enumeration Service
//
//

#undef INTERFACE
#define INTERFACE IDebugServiceManager
DECLARE_INTERFACE_(IDebugServiceManager, IUnknown)
{
    // InitializeServices():
    //
    // Called once by the owner of the service manager to initialize all bound services in topological order.
    // After the initialization, services which come into or change the service stack must be prepared
    // to deal with immediate initialization and handling NotifyServiceChange calls.
    //
    STDMETHOD(InitializeServices)(
        THIS
        ) PURE;

    // QueryService():
    //
    // Find a component which implements the service given by serviceGuid and query it for the interface
    // specified by serviceInterface.  Such service is returned in interfaceUnknown.
    //
    STDMETHOD(QueryService)(
        THIS_
        _In_ REFGUID serviceGuid,
        _In_ REFIID serviceInterface,
        _COM_Outptr_ PVOID* interfaceUnknown
        ) PURE;

    // LocateService():
    //
    // Finds a component which implements the service given by serviceGuid and returns a generic IUnknown
    // interface to the service.  The service must be explicitly queried for whatever interface is required.
    //
    STDMETHOD(LocateService)(
        THIS_
        _In_ REFGUID serviceGuid,
        _COM_Outptr_ IDebugServiceLayer** service
        ) PURE;

    // RegisterService():
    //
    // Registers a service with the service manager.  If a service is already registered by the specified
    // serviceGuid, this call will replace the underlying service.
    //
    // Unregistration of a service can be performed by registering a nullptr service layer.
    //
    STDMETHOD(RegisterService)(
        THIS_
        _In_ REFGUID serviceGuid,
        _In_opt_ IDebugServiceLayer* service
        ) PURE;

    // RegisterEventNotification():
    //
    // Registers a service for event notifications on a particular event (or set of events).
    //
    STDMETHOD(RegisterEventNotification)(
        THIS_
        _In_ REFGUID eventGuid,
        _In_ IDebugServiceLayer* service
        ) PURE;

    // UnregisterEventNotification():
    //
    // Unregisters a service from event notifications on a particular event (or set of events).
    //
    STDMETHOD(UnregisterEventNotification)(
        THIS_
        _In_ REFGUID eventGuid,
        _In_ IDebugServiceLayer* service
        ) PURE;

    // FireEventNotification():
    //
    // Fires an event to all registered event sinks.
    //
    STDMETHOD(FireEventNotification)(
        THIS_
        _In_ REFGUID eventGuid,
        _In_ IUnknown* eventArgument,
        _Out_opt_ HRESULT* pSinkResult
        ) PURE;
};

//
// IDebugServiceEnumerator:
//
// Enumerates all of the services in a container.
//
#undef INTERFACE
#define INTERFACE IDebugServiceEnumerator
DECLARE_INTERFACE_(IDebugServiceEnumerator, IUnknown)
{
    //*************************************************
    // IDebugServiceEnumerator:
    //

    // Reset():
    //
    // Resets the enumerator.
    //
    STDMETHOD(Reset)(
        THIS
        ) PURE;

    // GetNext():
    //
    // Gets the next service in the container and the service GUID under which it was registered.
    //
    STDMETHOD(GetNext)(
        THIS_
        _Out_ GUID *serviceGuid,
        _COM_Outptr_ IDebugServiceLayer** service
        ) PURE;
};

//
// IDebugServiceManager2:
//
//
#undef INTERFACE
#define INTERFACE IDebugServiceManager2
DECLARE_INTERFACE_(IDebugServiceManager2, IDebugServiceManager)
{

    //*************************************************
    // IDebugServiceManager2:
    //

    // EnumerateServices():
    //
    // Enumerates all of the services in the service manager.
    //
    STDMETHOD(EnumerateServices)(
        THIS_
        _COM_Outptr_ IDebugServiceEnumerator** enumerator
        ) PURE;
};

//
// IDebugServiceManager3:
//
#undef INTERFACE
#define INTERFACE IDebugServiceManager3
DECLARE_INTERFACE_(IDebugServiceManager3, IDebugServiceManager2)
{
    //*************************************************
    // IDebugServiceManager3:
    //

    // UninitializeServices():
    //
    // Clients should call this before releasing their final reference to the service manager.  This
    // will remove and uninitialize any services still in the service container.
    //
    STDMETHOD(UninitializeServices)(
        THIS
        ) PURE;
};

//
// IDebugServiceManager4:
//
#undef INTERFACE
#define INTERFACE IDebugServiceManager4
DECLARE_INTERFACE_(IDebugServiceManager4, IDebugServiceManager3)
{
    //*************************************************
    // IDebugServiceManager4:
    //

    // RegisterConditionalService():
    //
    // Registers a conditional service with the service manager.  If a service is already registered by the specified
    // serviceGuid and conditions, this call will replace the underlying service.
    //
    // Unregistration of a service can be performed by registering a nullptr service layer.
    //
    // NOTE: If a component wishes to be both a conditional service and a canonical service, it must call
    //       both RegisterConditionalService and RegisterService and deal with the fact that it may be initialized
    //       twice.  An example of this might be a disassembler service which registers as the AMD64 disassembler
    //       but also the canonical disassembler for an AMD64 debug target.
    //
    //       It may be the case that such a service would need to listen for change notifications and add/remove
    //       itself as the canonical service if conditions can change.
    //
    STDMETHOD(RegisterConditionalService)(
        THIS_
        _In_ SvcConditionalServiceInformation *conditionalServiceInfo,
        _In_ IDebugServiceLayer *service
        ) PURE;

    // QueryConditionalService():
    //
    // Find a component which implements the service given in in the conditionalServiceInfo structure according
    // to the conditions specified there and query it for the interface specified by serviceInterface.  Such service
    // is returned in interfaceUnknown.
    //
    // If the 'dynamicAdd' parameter is true and the composition manager knows of a component that provides
    // the service under the given condition, the component will be created and added to the service container.
    //
    STDMETHOD(QueryConditionalService)(
        THIS_
        _In_ SvcConditionalServiceInformation *conditionalServiceInfo,
        _In_ bool dynamicAdd,
        _In_ REFIID serviceInterface,
        _COM_Outptr_ PVOID *serviceUnknown
        ) PURE;

    // LocateConditionalService():
    //
    // Finds a component which implements the service given in the conditionalServiceInfo structure according
    // to the conditions specified there and return a generic interface to the service.  The service must be explicitly
    // queried for whatever interface is required.
    //
    // If the 'dynamicAdd' parameter is true and the composition manager knows of a component that provides
    // the service under the given condition, the component will be created and added to the service container.
    //
    STDMETHOD(LocateConditionalService)(
        THIS_
        _In_ SvcConditionalServiceInformation *conditionalServiceInfo,
        _In_ bool dynamicAdd,
        _COM_Outptr_ IDebugServiceLayer **service
        ) PURE;
};

//
// IDebugServiceManager5:
//
#undef INTERFACE
#define INTERFACE IDebugServiceManager5
DECLARE_INTERFACE_(IDebugServiceManager5, IDebugServiceManager4)
{
    //*************************************************
    // IDebugServiceManager5:
    //

    // AggregateService():
    //
    // Adds a new service to an aggregate collection in the service manager.
    //
    // Instead of calling pService->RegisterServices(pServiceManager) to register the service, calling
    // pServiceManager->AggregateService(DEBUG_SERVICE_XXX, pService) acts as a "helper method" with the
    // following functionality:
    //
    //     - If there is no DEBUG_SERVICE_XXX in the service container, it behaves identically to
    //       calling pService->RegisterServices(pServiceManager).
    //
    //     - If there is a DEBUG_SERVICE_XXX in the service container and that service is already an aggregator,
    //       it queries the existing service for IDebugServiceAggregate and calls AggregateService.  In effect,
    //       it adds 'newAggregateService' as one of the children that the aggregator aggregates.
    //
    //     - If there is a DEBUG_SERVICE_XXX in the service container and that service is *NOT* an aggregator,
    //       it creates the default aggregator for the service
    //       (via IDebugTargetComposition3::CreateServiceAggregatorComponent), replaces what was in the container
    //       with the newly created aggregator, and adds both the pre-existing service and 'newAggregateService'
    //       as children that the aggregator aggregates.
    //
    // Note that this method can fail if there is no defualt aggregator registered for a particular service.
    //
    STDMETHOD(AggregateService)(
        THIS_
        _In_ REFGUID serviceGuid,
        _In_ IDebugServiceLayer *newAggregateService
        ) PURE;
};

// ServiceNotificationKind:
//
// Indicates the kind of notification which is occurring.
//
enum ServiceNotificationKind
{
    // Indicates that this notification is a direct notification from the service manager to the top
    // of the service stack for a given service.
    ServiceManagerNotification,

    // Indicates that this notification is being passed down the service stack from a higher level component
    // in the stack for a given service.
    LayeredNotification
};

// IDebugServiceLayer:
//
// Every service which is managed by the services manager must support IDebugServiceLayer.  Initialization of a
// service occurs in stages:
//
//     1) The service is bound to a service manager (irrevocably).  Someone will call RegisterServices() on the service
//        in order to perform this action.  The implementation of RegisterServices should call back the service manager and
//        register each service within the component via a call to RegisterService.
//
//        At this stage, the service should *NOT* make calls on dependent services.
//
//     2) When the service manager is ready, it will make a call into each and every service asking for its dependent
//        services (a call to GetServiceDependencies).  The component should return all services that it depends on:
//
//            - A "hard dependency" is a service which this component relies on and cannot do without.  The service manager
//              will not "start" the target until all dependent services are initialized.  The set of "hard dependencies"
//              should form a DAG.  Initialization of each service in the DAG will occur in topological order.
//
//            - A "soft dependency" is a service which is either not mandatory or creates a cycle in service dependencies.
//              The component in question should be prepared to deal with call failures from such a service.
//
//        NOTE: For conditional services, a dependency can be resolved via either a regular service *OR* a
//              another conditional service with the same condition set.  A regular service is preferred.
//
//     3) The service manager will perform a topological sort of the DAG of service dependencies and call InitializeServices
//        for the service in question.   At this point, calls to dependent services can be made.
//
// Note that any service which aggregates, stacks on top of, or encapsulates another service is required to handle passing
// down initialization calls in an appropriate manner.
//
#undef INTERFACE
#define INTERFACE IDebugServiceLayer
DECLARE_INTERFACE_(IDebugServiceLayer, IUnknown)
{
    // RegisterServices():
    //
    // Registers the services in a service layer / component with a service manager.  This only registers any
    // canonical services.  Registration of conditional services is via a call to
    // IDebugServiceLayer2::RegisterConditionalServices.
    //
    STDMETHOD(RegisterServices)(
        THIS_
        _In_ IDebugServiceManager* serviceManager
        ) PURE;

    // GetServiceDependencies():
    //
    // Returns the set of services which this service layer / component depends on.  Having sizeHardDependencies or
    // sizeSoftDependencies set to 0 will pass back the number of dependencies and do nothing else.
    //
    STDMETHOD(GetServiceDependencies)(
        THIS_
        _In_ ServiceNotificationKind notificationKind,
        _In_ IDebugServiceManager* serviceManager,
        _In_ REFGUID serviceGuid,
        _In_ ULONG64 sizeHardDependencies,
        _Out_writes_(sizeHardDependencies) GUID *pHardDependencies,
        _Out_ ULONG64 *pNumHardDependencies,
        _In_ ULONG64 sizeSoftDependencies,
        _Out_writes_(sizeSoftDependencies) GUID *pSoftDependencies,
        _Out_ ULONG64 *pNumSoftDependencies
        ) PURE;

    // InitializeServices():
    //
    // Performs initialization of the services in a service layer / component.  Services which aggregate, encapsulate, or
    // stack on top of other services must pass down the initialization notification in an appropriate manner (with
    // notificationKind set to LayeredNotification.
    //
    STDMETHOD(InitializeServices)(
        THIS_
        _In_ ServiceNotificationKind notificationKind,
        _In_ IDebugServiceManager* serviceManager,
        _In_ REFGUID serviceGuid
        ) PURE;

    // NotifyServiceChange():
    //
    // Services in the services stack are notified of changes (the addition or removal
    // of layers) via a call to this method.
    //
    STDMETHOD(NotifyServiceChange)(
        THIS_
        _In_ ServiceNotificationKind notificationKind,
        _In_ IDebugServiceManager* serviceManager,
        _In_ REFGUID serviceGuid,
        _In_opt_ IDebugServiceLayer* priorService,
        _In_opt_ IDebugServiceLayer* newService
        ) PURE;

    // NotifyEvent():
    //
    // Services in the service stack are notified of events they explicitly register to
    // via this API.
    //
    STDMETHOD(NotifyEvent)(
        THIS_
        _In_ IDebugServiceManager* serviceManager,
        _In_ REFGUID eventGuid,
        _In_opt_ IUnknown* eventArgument
        ) PURE;
};

// IDebugServiceLayer2:
//
#undef INTERFACE
#define INTERFACE IDebugServiceLayer2
DECLARE_INTERFACE_(IDebugServiceLayer2, IDebugServiceLayer)
{
    // RegisterConditionalServices():
    //
    // Registers the conditional services in a service layer / component with a service manager.  This o
    // only registers any conditional services.  Registration of canonical services is via an explicit decision
    // to do so and a call to IDebugServiceLayer::RegisterServices.
    //
    // Some conditional services may never be able to registered as canonical providers (RegisterServices will
    // simply return S_FALSE) and some may be able to depending on conditions (e.g.: a custom architecture
    // disassembler may be registered as both a conditional service and the canonical disassembler if the target
    // machine architecture is the custom one).
    //
    STDMETHOD(RegisterConditionalServices)(
        THIS_
        _In_ IDebugServiceManager *serviceManager
        ) PURE;

};

// IDebugServiceAggregate:
//
// A service which offers the ability to aggregate other services implements this interface.  Typically, this is
// used in one of two scenarios:
//
// 1) Enumerators which provide the capability to enumerate from multiple sources -- each an independent service.
//    An aggregate service will "merge" all of the enumerators and direct calls to Find* to the appropriate
//    service.
//
// 2) ...
//
#undef INTERFACE
#define INTERFACE IDebugServiceAggregate
DECLARE_INTERFACE_(IDebugServiceAggregate, IUnknown)
{
    // AggregateService():
    //
    // Adds a new service to the aggregate.
    //
    STDMETHOD(AggregateService)(
        THIS_
        _In_ REFGUID serviceGuid,
        _In_ IDebugServiceLayer* childService
        ) PURE;

    // DeaggregateService():
    //
    // Removes a service from the aggregate.
    STDMETHOD(DeaggregateService)(
        THIS_
        _In_ REFGUID serviceGuid,
        _In_ IDebugServiceLayer* childService
        ) PURE;
};

// IDebugServiceCapabilities:
//
// An optional interface for any service to implement to query certain capabilities that are potentially more
// granular than a QI of a single interface by IID can determine.  Each defined capability has a "default answer"
// that is assumed if this interface is not supported.
//
// An example of a service capability query is whether the target supports backward execution.  The default answer
// is "no".  Without knowing this, calling various methods on the step controller would simply return
// an E_INVALIDARG / E_NOTIMPL without indication as to why.
//
#undef INTERFACE
#define INTERFACE
DECLARE_INTERFACE_(IDebugServiceCapabilities, IUnknown)
{
    // QueryCapability():
    //
    // For the service identified by 'serviceGuid', ask whether the capability identified by the combination
    // of 'capabilitySet' and 'capabilityId' is or is not supported.  The type of data returned from the query
    // is defined by each 'capabilitySet' / 'capabilityId' combination.
    //
    // Each capability must define a default state when it is specified.  If a given service does not support
    // capability detection via IDebugServiceCapabilities, a client may assume the default state.  Should that
    // not be the case, some methods may fail with E_INVALIDARG.
    //
    // If 'serviceGuid' is not a supported service GUID, E_INVALIDARG should be returned.
    // If 'capabilitySet' and 'capabilityId' are not recognized capabilities, E_NOT_SET should be returned.
    //
    STDMETHOD(GetCapability)(
        THIS_
        _In_ REFGUID serviceGuid,
        _In_ REFGUID capabilitySet,
        _In_ ULONG capabilityId,
        _In_ ULONG bufferSize,
        _Out_writes_(bufferSize) PVOID buffer
        ) PURE;
};


//**************************************************************************
// Capability Definitions:
//

// DEBUG_SERVICECAPS_MOTION
//
// Supported on a step controller service, this defines certain capabilities of how the step controller can
// move the target.
//
// enum ServiceCapsMotionKind defines the various items in this set.
//
// {D7984BEF-AD2F-4188-A047-C21653428038}
//
DEFINE_GUID(DEBUG_SERVICECAPS_MOTION, 0xd7984bef, 0xad2f, 0x4188, 0xa0, 0x47, 0xc2, 0x16, 0x53, 0x42, 0x80, 0x38);

enum ServiceCapsMotionKind
{
    // ServiceCapsMotionSingleStep:
    //
    // Indicates that the step controller supports single stepping.  The data is a boolean value expressed as
    // a single byte of data.  The default for this capability is 'true'.  Any step controller which does not
    // support single stepping is "go" / "break" only.
    //
    ServiceCapsMotionSingleStep = 0,

    // ServiceCapsMotionMultiStep:
    //
    // Indicates that the step controller supports stepping multiple steps with a single call to the Step method.
    // This should only be supported if the fundamental hardware (or virtual hardware) actually supports this notion
    // in a more efficient manner than multiple single steps.  The data is a boolean value expressed as a single
    // byte of data.  The default for this capability is 'false'.
    //
    ServiceCapsMotionMultiStep,

    // ServiceCapsMotionReverse:
    //
    // Indicates that the step controller supports reverse motion (step and go as indicated by other capabilities).
    // The data is a boolean value expressed as a single byte of data.  The default for this capability is 'false'.
    //
    ServiceCapsMotionReverse,
};

// DEBUG_SERVICECAPS_THREADING
//
// Supported on any service, this defines whether and in what form multiple threads may access the service.
// Note that a service which supports this capability has responsibility to determine transitivity on its
// dependencies.  A service cannot, for instance, declare itself free threaded and then make unguarded calls
// to a dependent service which is *NOT* free threaded.
//
// enum ServiceCapsThreadingKind defines the various items in this set.
//
// {D209C291-7B45-473d-8249-D0DDBFDBF870}
//
DEFINE_GUID(DEBUG_SERVICECAPS_THREADING, 0xd209c291, 0x7b45, 0x473d, 0x82, 0x49, 0xd0, 0xdd, 0xbf, 0xdb, 0xf8, 0x70);

enum ServiceCapsThreadingKind
{
    // ServiceCapsThreadingModel:
    //
    // Indicates what the threading model of the service is.  This data is an enum value of the type
    // ServiceCapsThreadingModelKind expressed as four bytes of data.  The default for this capability
    // is 'ServiceCapsThreadingModelNone'.
    //
    ServiceCapsThreadingModel = 0
};

enum ServiceCapsThreadingModelKind
{
    // ServiceCapsThreadingModelNone:
    //
    // Indicates that, unless otherwise specified as part of a service contract, the given service has no
    // particular threading model.  This means that it may only be accessed by a single thread at a time.
    // This is the default value for any service which does not explicitly state otherwise via support
    // of this capability and return of another value.
    //
    ServiceCapsThreadingModelNone = 0,

    // ServiceCapsThreadingModelFree:
    //
    // Indicates that access to the service is free threaded.  This means that calls on the service interfaces
    // may happen on arbitrary and multiple threads.  Any required synchronization is provided by the service.
    // This also means that calls on objects returned from the service interfaces may happen on arbitrary and
    // multiple threads.  Those objects provide any required synchronization.
    //
    // Note that this *DOES NOT* imply a threading model on IDebugServiceLayer*
    //
    ServiceCapsThreadingModelFree
};

//**************************************************************************
// Arch Definitions:
//
// NOTE: The GUID for any architecture definition **MUST** be identical to the GUID for the architecture's
//       component aggregate.  Any plug-in supporting a custom architecture must register such a component
//       aggregate before returning a platform architecture that is a custom GUID.
//

// DEBUG_ARCHDEF_AMD64:
//
// The unique identifier which describes the AMD64 (x86-64) architecture.  This corresponds directly to
// IMAGE_FILE_MACHINE_AMD64.  This is also DEBUG_COMPONENTAGGREGATE_MACHINEARCH_AMD64.
//
// {4BC151FE-5096-47e3-8B1E-2093F20BB979}
//
DEFINE_GUID(DEBUG_ARCHDEF_AMD64, 0x4bc151fe, 0x5096, 0x47e3, 0x8b, 0x1e, 0x20, 0x93, 0xf2, 0xb, 0xb9, 0x79);

// DEBUG_ARCHDEF_X86:
//
// The unique identifier which describes the X86/I386 (x86-32) architecture.  This corresponds directly to
// IMAGE_FILE_MACHINE_I386.  This is also DEBUG_COMPONENTAGGREGATE_MACHINEARCH_X86.
//
// {EDFD8AD0-1369-431d-B574-33E72CF1B12E}
//
DEFINE_GUID(DEBUG_ARCHDEF_X86, 0xedfd8ad0, 0x1369, 0x431d, 0xb5, 0x74, 0x33, 0xe7, 0x2c, 0xf1, 0xb1, 0x2e);

// DEBUG_ARCHDEF_ARM64:
//
// The unique identifier which describes the ARM64 architecture.  This corresponds directly to
// IMAGE_FILE_MACHINE_ARM64.  This is also DEBUG_COMPONENTAGGREGATE_MACHINEARCH_ARM64.
//
// {71DCF2FF-BBD0-4300-A37A-3B04F4F9713B}
//
DEFINE_GUID(DEBUG_ARCHDEF_ARM64, 0x71dcf2ff, 0xbbd0, 0x4300, 0xa3, 0x7a, 0x3b, 0x4, 0xf4, 0xf9, 0x71, 0x3b);

// DEBUG_ARCHDEF_ARM32:
//
// The unique identifier which describes the ARM32 architecture.  This correponds to
// IMAGE_FILE_MACHINE_ARM / IMAGE_FILE_MACHINE_ARMNT.  This is also DEBUG_COMPONENTAGGREGATE_MACHINEARCH_ARM32.
//
// {1C48E7A8-CD38-477e-8661-5718A315810D}
//
DEFINE_GUID(DEBUG_ARCHDEF_ARM32, 0x1c48e7a8, 0xcd38, 0x477e, 0x86, 0x61, 0x57, 0x18, 0xa3, 0x15, 0x81, 0xd);

//**************************************************************************
// Platform Definitions:
//

// DEBUG_PLATDEF_WINDOWS:
//
// Corresponds to SvcOSPlatWindows.  This represents the Windows platform.
//
// {72911516-8FD9-4cf9-82E9-F316FDCA7474}
//
DEFINE_GUID(DEBUG_PLATDEF_WINDOWS, 0x72911516, 0x8fd9, 0x4cf9, 0x82, 0xe9, 0xf3, 0x16, 0xfd, 0xca, 0x74, 0x74);

// DEBUG_PLATDEF_LINUX:
//
// Corresponds to SvcOSPlatLinux.  This represents the Linux platform.
//
// {0EF7E0F9-DB8E-4d84-BBEA-16274A4B14DE}
//
DEFINE_GUID(DEBUG_PLATDEF_LINUX, 0xef7e0f9, 0xdb8e, 0x4d84, 0xbb, 0xea, 0x16, 0x27, 0x4a, 0x4b, 0x14, 0xde);

// DEBUG_PLATDEF_UNIX:
//
// Corresponds to SvcOSPlatUNIX.  This represents an unidentified UNIX variant (which may be Linux, etc...)
//
// {DC2EEEFF-D1F4-41f1-A829-687DFD6DC44A}
//
DEFINE_GUID(DEBUG_PLATDEF_UNIX, 0xdc2eeeff, 0xd1f4, 0x41f1, 0xa8, 0x29, 0x68, 0x7d, 0xfd, 0x6d, 0xc4, 0x4a);

// DEBUG_PLATDEF_MACOS:
//
// Corresponds to SvcOSPlatMacOS.  This represents the MacOS platform.
//
// {4CCE3765-278A-4aab-A825-28C8E54699CA}
//
DEFINE_GUID(DEBUG_PLATDEF_MACOS, 0x4cce3765, 0x278a, 0x4aab, 0xa8, 0x25, 0x28, 0xc8, 0xe5, 0x46, 0x99, 0xca);

// DEBUG_PLATDEF_IOS:
//
// Corresponds to SvcOSPlatiOS.  This represents the iOS platform.
//
// {812B2757-9303-4008-A333-67534130F421}
//
DEFINE_GUID(DEBUG_PLATDEF_IOS, 0x812b2757, 0x9303, 0x4008, 0xa3, 0x33, 0x67, 0x53, 0x41, 0x30, 0xf4, 0x21);

// DEBUG_PLATDEF_CHROMEOS:
//
// Corresponds to SvcOSPlatChromeOS.  This represents the Chrome OS or Chronium OS platforms.
//
// {56F7C7EA-AB44-4df0-BEE8-8554C0A58893}
//
DEFINE_GUID(DEBUG_PLATDEF_CHROMEOS, 0x56f7c7ea, 0xab44, 0x4df0, 0xbe, 0xe8, 0x85, 0x54, 0xc0, 0xa5, 0x88, 0x93);

// DEBUG_PLATDEF_ANDROID:
//
// Corresponds to SvcOSPlatAndroid.  This represents the Android platform.
//
// {70C591E9-9156-41d0-8637-8BEBA93D539C}
//
DEFINE_GUID(DEBUG_PLATDEF_ANDROID, 0x70c591e9, 0x9156, 0x41d0, 0x86, 0x37, 0x8b, 0xeb, 0xa9, 0x3d, 0x53, 0x9c);


//**************************************************************************
// Core Components:
//

//
// An extension to the debugger which wants to provide partial implementation of the logic
// necessary to make a full debug target can construct the following components and utilize
// them to provide requisite services in the services layer.
//

// DEBUG_COMPONENT_MEMORY_CACHE:
//
// A cache layer which sits above a service which implements ISvcMemoryAccess and provides
// caching functionality for the underlying memory.
//
// This component can be used as a cache on any ISvcMemoryAccess based service.  It will
// mirror the "services" provided by its target layer.
//
// {DAD78CB5-98DE-4445-9571-9362077EE170}
//
DEFINE_GUID(DEBUG_COMPONENT_MEMORY_CACHE, 0xdad78cb5, 0x98de, 0x4445, 0x95, 0x71, 0x93, 0x62, 0x7, 0x7e, 0xe1, 0x70);

// Q: Need this...  Or higher granulatity...?
//
// DEBUG_COMPONENT_VIRTUAL_TO_PHYSICAL_TRANSLATOR:
//
// A layer which translates virtual to physical addresses for a given machine.
//
// {B6EF76C8-2D21-45cb-AD11-20507000E78C}
//
DEFINE_GUID(DEBUG_COMPONENT_VIRTUAL_TO_PHYSICAL_TRANSLATOR, 0xb6ef76c8, 0x2d21, 0x45cb, 0xad, 0x11, 0x20, 0x50, 0x70, 0x0, 0xe7, 0x8c);

//**************************************************************************
// Aggregate Components:
//
// These are aggregations of individual components which provide multiple services designed to operate
// at a specific layer of the target composition stack.  Instead of building a "target" out of many individual
// service components, an aggregate component can be constructed to provide this set of services.
//

// DEBUG_COMPONENTAGGREGATE_MACHINEARCH_AMD64:
//
// Description:
//
//     A component which provides the architecture specific definitions of the AMD64 architecture.
//
// Components Aggregated:
//
//     DEBUG_COMPONENTSVC_MACHINEARCH_AMD64_PAGETABLEREADER
//     DEBUG_COMPONENTSVC_MACHINEARCH_AMD64_ARCHINFO
//
// Component GUID:
//
//     {4BC151FE-5096-47e3-8B1E-2093F20BB979}
//
DEFINE_GUID(DEBUG_COMPONENTAGGREGATE_MACHINEARCH_AMD64, 0x4bc151fe, 0x5096, 0x47e3, 0x8b, 0x1e, 0x20, 0x93, 0xf2, 0xb, 0xb9, 0x79);

// DEBUG_COMPONENTAGGREGATE_MACHINEARCH_X86:
//
// Description:
//
//     A component which provides the architecture specific definitions of the X86 architecture.
//
// Components Aggregated:
//
//     DEBUG_COMPONENTSVC_MACHINEARCH_X86_PAGETABLEREADER
//     DEBUG_COMPONENTSVC_MACHINEARCH_X86_ARCHINFO
//
// Component GUID:
//
//     {EDFD8AD0-1369-431d-B574-33E72CF1B12E}
//
DEFINE_GUID(DEBUG_COMPONENTAGGREGATE_MACHINEARCH_X86, 0xedfd8ad0, 0x1369, 0x431d, 0xb5, 0x74, 0x33, 0xe7, 0x2c, 0xf1, 0xb1, 0x2e);

// DEBUG_COMPONENTAGGREGATE_MACHINEARCH_ARM64:
//
// Description:
//
//     A component which provides the architecture specific definitions of the ARM64 architecture.
//
// Components Aggregated:
//
//     DEBUG_COMPONENTSVC_MACHINEARCH_ARM64_PAGETABLEREADER
//     DEBUG_COMPONENTSVC_MACHINEARCH_ARM64_ARCHINFO
//
// Component GUID:
//
//     {71DCF2FF-BBD0-4300-A37A-3B04F4F9713B}
//
DEFINE_GUID(DEBUG_COMPONENTAGGREGATE_MACHINEARCH_ARM64, 0x71dcf2ff, 0xbbd0, 0x4300, 0xa3, 0x7a, 0x3b, 0x4, 0xf4, 0xf9, 0x71, 0x3b);

// DEBUG_COMPONENTAGGREGATE_MACHINEARCH_ARM32:
//
// Description:
//
//     A component which provides the architecture specific definitions of the ARM architecture.
//
// Components Aggregated:
//
//     DEBUG_COMPONENTSVC_MACHINEARCH_ARM32_PAGETABLEREADER
//     DEBUG_COMPONENTSVC_MACHINEARCH_ARM32_ARCHINFO
//
// Component GUID:
//
//     {1C48E7A8-CD38-477e-8661-5718A315810D}
//
DEFINE_GUID(DEBUG_COMPONENTAGGREGATE_MACHINEARCH_ARM32, 0x1c48e7a8, 0xcd38, 0x477e, 0x86, 0x61, 0x57, 0x18, 0xa3, 0x15, 0x81, 0xd);

// DEBUG_COMPONENTAGGREGATE_BASE_KERNELFULLDUMP32:
//
// A base layer which understands the semantics of a 32-bit kernel full dump on top of a file service.
//
// Components Aggregated:
//
// Services Provided:
//
// {88D793FA-5DF5-43cc-A837-53C2144BF071}
//
DEFINE_GUID(DEBUG_COMPONENTAGGREGATE_BASE_KERNELFULLDUMP32, 0x88d793fa, 0x5df5, 0x43cc, 0xa8, 0x37, 0x53, 0xc2, 0x14, 0x4b, 0xf0, 0x71);

// DEBUG_COMPONENTAGGREGATE_BASE_KERNELFULLDUMP64:
//
// A base layer which understands the semantics of a 64-bit kernel full dump on top of a file service.
//
// Components Aggregated:
//
// Services Provided:
//
// {E804FF5D-DC9A-45ff-845F-DEF1C40F788A}
//
DEFINE_GUID(DEBUG_COMPONENTAGGREGATE_BASE_KERNELFULLDUMP64, 0xe804ff5d, 0xdc9a, 0x45ff, 0x84, 0x5f, 0xde, 0xf1, 0xc4, 0xf, 0x78, 0x8a);

// DEBUG_COMPONENTAGGREGATE_OS_KERNEL_WINDOWS:
//
// A layer which understands the semantics of the Windows kernel and provides requisite services on top of it.
//
// Components Aggregated:
//
// Services Provided:
//
// {30444EE1-97F6-4698-BFF3-6707BEFC0849}
//
DEFINE_GUID(DEBUG_COMPONENTAGGREGATE_OS_KERNEL_WINDOWS, 0x30444ee1, 0x97f6, 0x4698, 0xbf, 0xf3, 0x67, 0x7, 0xbe, 0xfc, 0x8, 0x49);

// DEBUG_COMPONENTAGGREGATE_OS_KERNEL_LOCATOR:
//
// A layer which understands how to find a recognized OS kernel from a set of base machine services.
//
// Components Aggregated:
//
// Services Provided:
//
// Component GUID:
//
// {049643ED-1E60-476f-A927-DCF4EC210575}
//
DEFINE_GUID(DEBUG_COMPONENTAGGREGATE_OS_KERNEL_LOCATOR, 0x49643ed, 0x1e60, 0x476f, 0xa9, 0x27, 0xdc, 0xf4, 0xec, 0x21, 0x5, 0x75);

//*************************************************
// Architecture (Individual) Components:
//

// DEBUG_COMPONENTSVC_MACHINEARCH_AMD64_PAGETABLEREADER:
//
// Description:
//
//     A component which provides an address translation service (virtual to physical) via direct reading of AMD64
//     page tables
//
// Services Provided:
//
//     DEBUG_SERVICE_VIRTUAL_TO_PHYSICAL_TRANSLATION
//
// Services Depended On:
//
//     (Required) DEBUG_SERVICE_PHYSICAL_MEMORY
//     (Required) DEBUG_SERVICE_ARCHINFO
//     (Optional) DEBUG_SERVICE_PAGEFILE_READER
//
// Component GUID:
//
//     {3EA63BF1-E7CD-4bc2-B25E-D16EC4BDDA4B}
//
DEFINE_GUID(DEBUG_COMPONENTSVC_MACHINEARCH_AMD64_PAGETABLEREADER, 0x3ea63bf1, 0xe7cd, 0x4bc2, 0xb2, 0x5e, 0xd1, 0x6e, 0xc4, 0xbd, 0xda, 0x4b);

// DEBUG_COMPONENTSVC_MACHINEARCH_AMD64_ARCHINFO:
//
// Description:
//
//     A component which provides architecture information services for AMD64
//
// Services Provided:
//
//     DEBUG_SERVICE_ARCHINFO
//
// Services Depended On:
//
//     None
//
// Component GUID:
//
//     {9C37ED47-AF09-4977-9440-56F341419B03}
//
DEFINE_GUID(DEBUG_COMPONENTSVC_MACHINEARCH_AMD64_ARCHINFO, 0x9c37ed47, 0xaf09, 0x4977, 0x94, 0x40, 0x56, 0xf3, 0x41, 0x41, 0x9b, 0x3);

// DEBUG_COMPONENTSVC_MACHINEARCH_X86_PAGETABLEREADER:
//
// Description:
//
//     A component which provides an address translation service (virtual to physical) via direct reading of X86
//     page tables
//
// Services Provided:
//
//     DEBUG_SERVICE_VIRTUAL_TO_PHYSICAL_TRANSLATION
//
// Services Depended On:
//
//     (Required) DEBUG_SERVICE_PHYSICAL_MEMORY
//     (Required) DEBUG_SERVICE_ARCHINFO
//     (Optional) DEBUG_SERVICE_PAGEFILE_READER
//
// Component GUID:
//
//     {1F5CF754-B0BA-4341-8D85-0F1F66284CF5}
//
DEFINE_GUID(DEBUG_COMPONENTSVC_MACHINEARCH_X86_PAGETABLEREADER, 0x1f5cf754, 0xb0ba, 0x4341, 0x8d, 0x85, 0xf, 0x1f, 0x66, 0x28, 0x4c, 0xf5);

// DEBUG_COMPONENTSVC_MACHINEARCH_X86_ARCHINFO:
//
// Description:
//
//     A component which provides architecture information services for X86
//
// Services Provided:
//
//     DEBUG_SERVICE_ARCHINFO
//
// Services Depended On:
//
//     None
//
// Component GUID:
//
//     {FD409ED7-B3AA-4a3c-B400-BA1D4947FB47}
//
DEFINE_GUID(DEBUG_COMPONENTSVC_MACHINEARCH_X86_ARCHINFO, 0xfd409ed7, 0xb3aa, 0x4a3c, 0xb4, 0x0, 0xba, 0x1d, 0x49, 0x47, 0xfb, 0x47);

// DEBUG_COMPONENTSVC_MACHINEARCH_ARM64_PAGETABLEREADER:
//
// Description:
//
//     A component which provides an address translation service (virtual to physical) via direct reading of ARM64
//     page tables
//
// Services Provided:
//
//     DEBUG_SERVICE_VIRTUAL_TO_PHYSICAL_TRANSLATION
//
// Services Depended On:
//
//     (Required) DEBUG_SERVICE_PHYSICAL_MEMORY
//     (Required) DEBUG_SERVICE_ARCHINFO
//     (Optional) DEBUG_SERVICE_PAGEFILE_READER
//
// Component GUID:
//
//     {1F347758-D804-4628-98F5-17B533542BBF}
//
DEFINE_GUID(DEBUG_COMPONENTSVC_MACHINEARCH_ARM64_PAGETABLEREADER, 0x1f347758, 0xd804, 0x4628, 0x98, 0xf5, 0x17, 0xb5, 0x33, 0x54, 0x2b, 0xbf);

// DEBUG_COMPONENTSVC_MACHINEARCH_ARM64_ARCHINFO:
//
// Description:
//
//     A component which provides architecture information services for ARM64
//
// Services Provided:
//
//     DEBUG_SERVICE_ARCHINFO
//
// Services Depended On:
//
//     None
//
// Component GUID:
//
//     {F492EC3E-38F3-4875-B366-5E1424F7AD52}
//
DEFINE_GUID(DEBUG_COMPONENTSVC_MACHINEARCH_ARM64_ARCHINFO, 0xf492ec3e, 0x38f3, 0x4875, 0xb3, 0x66, 0x5e, 0x14, 0x24, 0xf7, 0xad, 0x52);

// DEBUG_COMPONENTSVC_MACHINEARCH_ARM32_PAGETABLEREADER:
//
// Description:
//
//     A component which provides an address translation service (virtual to physical) via direct reading of ARM32
//     page tables
//
// Services Provided:
//
//     DEBUG_SERVICE_VIRTUAL_TO_PHYSICAL_TRANSLATION
//
// Services Depended On:
//
//     (Required) DEBUG_SERVICE_PHYSICAL_MEMORY
//     (Required) DEBUG_SERVICE_ARCHINFO
//     (Optional) DEBUG_SERVICE_PAGEFILE_READER
//
// Component GUID:
//
//     {1742F2C1-2EEC-469b-9D70-ECAB6462AE16}
//
DEFINE_GUID(DEBUG_COMPONENTSVC_MACHINEARCH_ARM32_PAGETABLEREADER, 0x1742f2c1, 0x2eec, 0x469b, 0x9d, 0x70, 0xec, 0xab, 0x64, 0x62, 0xae, 0x16);

// DEBUG_COMPONENTSVC_MACHINEARCH_ARM32_ARCHINFO:
//
// Description:
//
//     A component which provides architecture information services for ARM32
//
// Services Provided:
//
//     DEBUG_SERVICE_ARCHINFO
//
// Services Depended On:
//
//     None
//
// Component GUID:
//
//     {49F1D274-750E-4b63-B722-A86E54F27D86}
//
DEFINE_GUID(DEBUG_COMPONENTSVC_MACHINEARCH_ARM32_ARCHINFO, 0x49f1d274, 0x750e, 0x4b63, 0xb7, 0x22, 0xa8, 0x6e, 0x54, 0xf2, 0x7d, 0x86);

//**************************************************************************
// Individual Service Components:
//

//
// These are individual services typically found aggregated in a larger component that provide individual pieces
// of functionality in the target composition stack.
//

// DEBUG_COMPONENTSVC_FILESOURCE:
//
// Description:
//
//     A component which provides a file debug source service on top of a file.
//
// Initializer Interface:
//
//     IComponentFileSourceInitializer
//
// Services Provided:
//
//     DEBUG_PRIVATE_SERVICE_DEBUGSOURCE (ISvcDebugSourceFile)
//
// Services Depended On:
//
//     None
//
// Component GUID:
//
//     {5CE00BC6-2170-4f0d-B39E-0930C388D8B3}
//
DEFINE_GUID(DEBUG_COMPONENTSVC_FILESOURCE, 0x5ce00bc6, 0x2170, 0x4f0d, 0xb3, 0x9e, 0x9, 0x30, 0xc3, 0x88, 0xd8, 0xb3);

// {C0D44DDA-6D7D-4b07-923C-68242BEB9E20}
DEFINE_GUID(IID_IComponentFileSourceInitializer, 0xc0d44dda, 0x6d7d, 0x4b07, 0x92, 0x3c, 0x68, 0x24, 0x2b, 0xeb, 0x9e, 0x20);
struct DECLSPEC_UUID("C0D44DDA-6D7D-4b07-923C-68242BEB9E20") IComponentFileSourceInitializer;

#undef INTERFACE
#define INTERFACE IComponentFileSourceInitializer
DECLARE_INTERFACE_(IComponentFileSourceInitializer, IUnknown)
{
    // Initialize():
    //
    // Initializes the DEBUG_COMPONENTSVC_FILESOURCE component by opening a file at the given path.
    // This method will fail if no such file exists or it cannot be opened.
    //
    STDMETHOD(Initialize)(
        THIS_
        _In_ PCWSTR filePath
        ) PURE;
};

// {35C2DA2D-1359-44e6-996F-7A44C84B2956}
DEFINE_GUID(IID_IComponentFileSourceInitializer2, 0x35c2da2d, 0x1359, 0x44e6, 0x99, 0x6f, 0x7a, 0x44, 0xc8, 0x4b, 0x29, 0x56);
struct DECLSPEC_UUID("35C2DA2D-1359-44e6-996F-7A44C84B2956") IComponentFileSourceInitializer2;

#undef INTERFACE
#define INTERFACE IComponentFileSourceInitializer2
DECLARE_INTERFACE_(IComponentFileSourceInitializer2, IComponentFileSourceInitializer)
{
    // InitializeFromHandle():
    //
    // Initializes the DEBUG_COMPONENTSVC_FILESOURCE component from an already opened file handle.  While a file
    // name must be provided, it has no bearing on the utilized file.  If this method succeeds, ownership of the
    // file handle is *TRANSFERRED* to the file source.
    //
    STDMETHOD(InitializeFromHandle)(
        THIS_
        _In_ PCWSTR fileName,
        _In_ HANDLE fileHandle
        ) PURE;
};

// DEBUG_COMPONENTSVC_VIEWSOURCE:
//
// Description:
//
//     A component which provides a view source debug service to another service manager.
//
// Initializer Interface:
//
//     IComponentViewSourceInitializer
//
// Services Provided:
//
//     DEBUG_PRIVATE_SERVICE_DEBUGSOURCE (ISvcDebugSourceView)
//
// Services Depended On:
//
//     None
//
// Component GUID:
//
//     {CA1FA8A8-53A4-4cca-B4A8-266815E3E818}
//
DEFINE_GUID(DEBUG_COMPONENTSVC_VIEWSOURCE, 0xca1fa8a8, 0x53a4, 0x4cca, 0xb4, 0xa8, 0x26, 0x68, 0x15, 0xe3, 0xe8, 0x18);

// {8CE08C3C-A860-4604-B73E-06813B5380F8}
DEFINE_GUID(IID_IComponentViewSourceInitializer, 0x8ce08c3c, 0xa860, 0x4604, 0xb7, 0x3e, 0x6, 0x81, 0x3b, 0x53, 0x80, 0xf8);
struct DECLSPEC_UUID("8CE08C3C-A860-4604-B73E-06813B5380F8") IComponentViewSourceInitializer;

#undef INTERFACE
#define INTERFACE IComponentViewSourceInitializer
DECLARE_INTERFACE_(IComponentViewSourceInitializer, IUnknown)
{
    // Initialize():
    //
    // Initializes the DEBUG_COMPONENTSVC_VIEWSOURCE component.
    //
    STDMETHOD(Initialize)(
        THIS_
        IDebugServiceManager *pServiceManager
        ) PURE;
};

// DEBUG_COMPONENTSVC_PSEUDOSTREAMFULLMAPPER:
//
// Description:
//
//     A component which stacks on top of a file source (DEBUG_PRIVATE_SERVICE_DEBUGSOURCE / ISvcDebugSourceFile)
//     which does *NOT* support ISvcDebugSourceFileMapping and provides an implementation of "memory mapping" the
//     stream.  This memory mapping is done via a **FULL AND IMMEDIATE** read of the entire stream into memory.
//
// Initializer Interface:
//
//     IComponentPseudoStreamMapperInitializer
//
// Services Provided:
//
//     DEBUG_PRIVATE_SERVICE_DEBUGSOURCE (ISvcDebugSourceFile)
//
// Services Depended On:
//
//     None
//
// Component GUID:
//
//     {E96275D9-5FA1-4dc9-A292-53E54DCFF28B}
//
DEFINE_GUID(DEBUG_COMPONENTSVC_PSEUDOSTREAMFULLMAPPER, 0xe96275d9, 0x5fa1, 0x4dc9, 0xa2, 0x92, 0x53, 0xe5, 0x4d, 0xcf, 0xf2, 0x8b);

// DEBUG_COMPONENTSVC_PSEUDOSTREAMDEMANDMAPPER:
//
// Description:
//
//     A component which stacks on top of a file source (DEBUG_PRIVATE_SERVICE_DEBUGSOURCE / ISvcDebugSourceFile)
//     which does *NOT* support ISvcDebugSourceFileMapping and provides an implementation of "memory mapping" the
//     stream.  This memory mapping is done via a reserved VA space in which faults trigger a demand read of a
//     chunk of the stream.  Using this component may lead to asynchronous SEH exceptions flowing out of memory
//     accesses to the mapping if, for any reason, the calls to read the stream fail.
//
// Initializer Interface:
//
//     IComponentPseudoStreamMapperInitializer
//
// Services Provided:
//
//     DEBUG_PRIVATE_SERVICE_DEBUGSOURCE (ISvcDebugSourceFile)
//
// Services Depended On:
//
//     None
//
// Component GUID:
//
//     {06DE4D77-78E3-4e8b-916B-09A13FA91902}
//
DEFINE_GUID(DEBUG_COMPONENTSVC_PSEUDOSTREAMDEMANDMAPPER, 0x6de4d77, 0x78e3, 0x4e8b, 0x91, 0x6b, 0x9, 0xa1, 0x3f, 0xa9, 0x19, 0x2);

// {A325D2E2-39BB-48d9-875A-8DE64F62D282}
DEFINE_GUID(IID_IComponentPseudoStreamMapperInitializer, 0xa325d2e2, 0x39bb, 0x48d9, 0x87, 0x5a, 0x8d, 0xe6, 0x4f, 0x62, 0xd2, 0x82);
struct DECLSPEC_UUID("A325D2E2-39BB-48d9-875A-8DE64F62D282") IComponentPseudoStreamMapperInitializer;

#undef INTERFACE
#define INTERFACE IComponentPseudoStreamMapperInitializer
DECLARE_INTERFACE_(IComponentPseudoStreamMapperInitializer, IUnknown)
{
    // Initialize():
    //
    // Initializes the component.
    //
    STDMETHOD(Initialize)(
        THIS_
        ISvcDebugSourceFile *pUnderlyingFile
        ) PURE;
};

// {36994180-227B-4c58-A394-5484B761DDB0}
DEFINE_GUID(IID_IComponentVirtualMemoryFromFileInitializer, 0x36994180, 0x227b, 0x4c58, 0xa3, 0x94, 0x54, 0x84, 0xb7, 0x61, 0xdd, 0xb0);
struct DECLSPEC_UUID("36994180-227B-4c58-A394-5484B761DDB0") IComponentVirtualMemoryFromFileInitializer;

#undef INTERFACE
#define INTERFACE IComponentVirtualMemoryFromFileInitializer
DECLARE_INTERFACE_(IComponentVirtualMemoryFromFileInitializer, IUnknown)
{
    // Initialize():
    //
    // Initializes the DEBUG_COMPONENTSVC_VIRTUALMEMORY_FROM_FILE component.
    //
    STDMETHOD(Initialize)(
        THIS_
        _In_ ULONG64 mappingBaseAddress
        ) PURE;
};

// DEBUG_COMPONENTSVC_VIRTUALMEMORY_FROM_FILE:
//
// Description:
//
//     A component which provides a virtual memory service abstracted over a data file
//
// Services Provided:
//
//     DEBUG_SERVICE_VIRTUAL_MEMORY
//
// Component GUID:
//
//     {011810C7-63CE-4934-A5EA-18AF7C872DDA}
//
DEFINE_GUID(DEBUG_COMPONENTSVC_VIRTUALMEMORY_FROM_FILE, 0x11810c7, 0x63ce, 0x4934, 0xa5, 0xea, 0x18, 0xaf, 0x7c, 0x87, 0x2d, 0xda);

// DEBUG_COMPONENTSVC_KERNELFULLDUMP32_PHYSICALMEMORY:
//
// Description:
//
//     A component which provides a physical memory service for a kernel 32-bit full dump (on top of a file service)
//
// Services Provided:
//
//     DEBUG_SERVICE_PHYSICAL_MEMORY
//
// Services Depended On:
//
//     DEBUG_PRIVATE_SERVICE_DEBUGSOURCE (a file based debug source implementing ISvcDebugSourceFile and pointing at a 32-bit full kernel dump file)
//
// Component GUID:
//
//     {6728DFF0-D56D-454e-B9DA-77BA3E9C1E43}
//
DEFINE_GUID(DEBUG_COMPONENTSVC_KERNELFULLDUMP32_PHYSICALMEMORY, 0x6728dff0, 0xd56d, 0x454e, 0xb9, 0xda, 0x77, 0xba, 0x3e, 0x9c, 0x1e, 0x43);

// DEBUG_COMPONENTSVC_KERNELFULLDUMP32_MACHINE:
//
// Description:
//
//     A component which provides machine level services (config, machine debug) for a ekrnel 32-bit full dump (on top a file service
//     and virtual memory services.
//
// Services Provided:
//
//     DEBUG_SERVICE_MACHINE
//
// Services Depended On:
//
//     DEBUG_PRIVATE_SERVICE_DEBUGSOURCE (a file based debug source implementing ISvcDebugSourceFile and pointing at a 32-bit full kernel dump file)
//
// Component GUID:
//
//     {3011A1DD-932B-4bb9-A6A6-811154A62815}
DEFINE_GUID(DEBUG_COMPONENTSVC_KERNELFULLDUMP32_MACHINE, 0x3011a1dd, 0x932b, 0x4bb9, 0xa6, 0xa6, 0x81, 0x11, 0x54, 0xa6, 0x28, 0x15);

// DEBUG_COMPONENTSVC_KERNELFULLDUMP64_PHYSICALMEMORY:
//
// Description:
//
//     A component which provides a physical memory service for a kernel 64-bit full dump (on top a file service)
//
// Services Provided:
//
//     DEBUG_SERVICE_PHYSICAL_MEMORY
//
// Services Depended On:
//
//     DEBUG_PRIVATE_SERVICE_DEBUGSOURCE (a file based debug source implementing ISvcDebugSourceFile and pointing at a 64-bit full kernel dump file)
//
// Component GUID:
//
//     {8F57F3EB-1F84-4434-BA8D-77E6EB7A4EF1}
//
DEFINE_GUID(DEBUG_COMPONENTSVC_KERNELFULLDUMP64_PHYSICALMEMORY, 0x8f57f3eb, 0x1f84, 0x4434, 0xba, 0x8d, 0x77, 0xe6, 0xeb, 0x7a, 0x4e, 0xf1);

// DEBUG_COMPONENTSVC_KERNELFULLDUMP64_MACHINE:
//
// Description:
//
//     A component which provides machine level services (config, machine debug) for a ekrnel 64-bit full dump (on top a file service
//     and virtual memory services.
//
// Services Provided:
//
//     DEBUG_SERVICE_MACHINE
//
// Services Depended On:
//
//     DEBUG_PRIVATE_SERVICE_DEBUGSOURCE (a file based debug source implementing ISvcDebugSourceFile and pointing at a 64-bit full kernel dump file)
//
// Component GUID:
//
//     {41056A8F-A108-49d9-977B-A876E2615D64}
//
DEFINE_GUID(DEBUG_COMPONENTSVC_KERNELFULLDUMP64_MACHINE, 0x41056a8f, 0xa108, 0x49d9, 0x97, 0x7b, 0xa8, 0x76, 0xe2, 0x61, 0x5d, 0x64);

// DEBUG_COMPONENTSVC_VIRTUALMEMORY_TO_PHYSICALMEMORY
//
// Description:
//
//     A component which provides a virtual memory service for a stack that has a page table reader (VtoP) service and
//     an underlying physical memory service.  This component handles virtual memory requests by interpreting the page tables
//     and issuing physical memory requests.
//
//     Note that if a page table reader is in the service stack, any virtual addresses which are paged out will forward to the
//     page table reader.
//
// Services Provided:
//
//     DEBUG_SERVICE_VIRTUAL_MEMORY
//
// Services Depended On:
//
//     (Required) DEBUG_SERVICE_PHYSICAL_MEMORY
//     (Required) DEBUG_SERVICE_VIRTUAL_TO_PHYSICAL_TRANSLATION
//     (Optional) DEBUG_SERVICE_PAGEFILE_READER
//
// {2BB80CD4-BB10-46ea-98E3-33C576D2E205}
//
DEFINE_GUID(DEBUG_COMPONENTSVC_VIRTUALMEMORY_TO_PHYSICALMEMORY, 0x2bb80cd4, 0xbb10, 0x46ea, 0x98, 0xe3, 0x33, 0xc5, 0x76, 0xd2, 0xe2, 0x5);

// DEBUG_COMPONENTSVC_STACKUNWIND_CONTEXT
//
// Description:
//
//     A "component" which provides an implementation of ISvcStackUnwindContext for a stack unwind.  This component
//     is *NOT* a service which can be placed into the service manager; rather -- it is the context for a stack
//     unwind which can be passed amongst multiple service components.
//
// Services Provided:
//
//     **NONE**
//
// Services Depended On:
//
//     **NONE**
//
// {10C3F8E7-38CF-40e9-B906-D85229E872D1}
//
DEFINE_GUID(DEBUG_COMPONENTSVC_STACKUNWIND_CONTEXT, 0x10c3f8e7, 0x38cf, 0x40e9, 0xb9, 0x6, 0xd8, 0x52, 0x29, 0xe8, 0x72, 0xd1);

// {36A82767-6ED1-4e47-A7A7-D517A8691534}
DEFINE_GUID(IID_IComponentStackUnwindContextInitializer, 0x36a82767, 0x6ed1, 0x4e47, 0xa7, 0xa7, 0xd5, 0x17, 0xa8, 0x69, 0x15, 0x34);

struct DECLSPEC_UUID("36A82767-6ED1-4e47-A7A7-D517A8691534") IComponentStackUnwindContextInitializer;

#undef INTERFACE
#define INTERFACE IComponentStackUnwindContextInitializer
DECLARE_INTERFACE_(IComponentStackUnwindContextInitializer, IUnknown)
{
    // Initialize():
    //
    // Initializes the DEBUG_COMPONENTSVC_STACKUNWIND_CONTEXT component.
    //
    STDMETHOD(Initialize)(
        THIS_
        _In_opt_ ISvcProcess* unwindProcess,
        _In_opt_ ISvcThread* unwindThread
        ) PURE;
};

// {7FA6E76A-FEE4-44bf-82B9-E41B6FBC87DF}
DEFINE_GUID(IID_IComponentStackUnwindContextInitializer2, 0x7fa6e76a, 0xfee4, 0x44bf, 0x82, 0xb9, 0xe4, 0x1b, 0x6f, 0xbc, 0x87, 0xdf);

struct DECLSPEC_UUID("7FA6E76A-FEE4-44bf-82B9-E41B6FBC87DF") IComponentStackUnwindContextInitializer2;

#undef INTERFACE
#define INTERFACE IComponentStackUnwindContextInitializer2
DECLARE_INTERFACE_(IComponentStackUnwindContextInitializer2, IComponentStackUnwindContextInitializer)
{
    // Initialize2():
    //
    // Initializes the DEBUG_COMPONENTSVC_STACKUNWIND_CONTEXT component.
    //
    STDMETHOD(Initialize2)(
        THIS_
        _In_opt_ ISvcProcess* unwindProcess,
        _In_opt_ ISvcExecutionUnit *unwindExecUnit
        ) PURE;
};

// DEBUG_COMPONENTSVC_PEIMAGE_IMAGEPARSEPROVIDER
//
// Description:
//
//     A component which understands PE images and can parse them.
//
// Services Provided:
//
//     DEBUG_SERVICE_IMAGE_PARSE_PROVIDER
//
// Dependent Services:
//
//     (soft) DEBUG_SERVICE_VIRTUAL_MEMORY
//     (soft) DEBUG_SERVICE_PROCESS_ENUMERATOR
//
// {BE0E2781-4FF3-4c5c-B041-8EA029ED65E3}
//
DEFINE_GUID(DEBUG_COMPONENTSVC_PEIMAGE_IMAGEPARSEPROVIDER, 0xbe0e2781, 0x4ff3, 0x4c5c, 0xb0, 0x41, 0x8e, 0xa0, 0x29, 0xed, 0x65, 0xe3);

// DEBUG_COMPONENTSVC_PEIMAGE_IMAGEPROVIDER
//
// Description:
//
//     A component which understands how to find the original image on disk for a PE image in the target
//     address space.  Such PE will be found either in the client's search path or on the symbol server.
//     The identity is verified by the image size, timestamp, and checksum in the PE image headers.  Note that
//     the pages containing the image headers must be readable via a virtual memory service.
//
// Services Provided:
//
//     DEBUG_SERVICE_IMAGE_PROVIDER
//
// Dependent Services:
//
//     DEBUG_SERVICE_VIRTUAL_MEMORY
//
// {4ACED62F-CEF1-4f74-A1A1-994D61959A80}
//
DEFINE_GUID(DEBUG_COMPONENTSVC_PEIMAGE_IMAGEPROVIDER, 0x4aced62f, 0xcef1, 0x4f74, 0xa1, 0xa1, 0x99, 0x4d, 0x61, 0x95, 0x9a, 0x80);

// DEBUG_COMPONENTSVC_PEIMAGE_MODULEINDEXPROVIDER
//
// Description:
//
//     A component which understands how to find the indexing keys for PE images.  These indexing keys
//     (the time/date stamp and the size of the image) are read from the PE headers in the virtual address
//     space of the target.
//
// Services Provided:
//
//     DEBUG_SERVICE_MODULE_INDEX_PROVIDER
//
// Dependent Services:
//
//     DEBUG_SERVICE_VIRTUAL_MEMORY
//     DEBUG_SERVICE_PROCESS_ENUMERATOR
//
// {A32E9F81-74B4-4cec-9843-62ADE5889B01}
//
DEFINE_GUID(DEBUG_COMPONENTSVC_PEIMAGE_MODULEINDEXPROVIDER, 0xa32e9f81, 0x74b4, 0x4cec, 0x98, 0x43, 0x62, 0xad, 0xe5, 0x88, 0x9b, 0x1);

// DEBUG_COMPONENTSVC_IMAGEBACKED_VIRTUALMEMORY
//
// Description:
//
//     A component which stacks atop another virtual memory service and overlays pages of image files
//     (executables, DLLs, ELF shared objects, etc...) from disk images into the virtual address space.  If
//     pages are not available in the underlying virtual memory service (e.g.: the core file, dump file, etc...)
//     and the original image can be located by an image provider service, the disk image will be used to
//     provide those pages.
//
//     If the full requirements of this service are not met, it will operate as a pass through to the underlying
//     virtual memory service.
//
//     In order for this service to provide image pages, there must be:
//
//          - An image provider which can locate images from a search path or service (e.g.: symbol server)
//
//          - An image parse provider which understands how to parse the image format and can translate
//            between the on-disk file view and the in-memory loader view of the image format.
//
// Initializer Interface:
//
//     IComponentImageBackedVirtualMemoryInitializer
//
// Services Provided:
//
//     DEBUG_SERVICE_VIRTUAL_MEMORY
//
// Dependent Services:
//
//     (soft) DEBUG_SERVICE_IMAGE_PROVIDER
//     (soft) DEBUG_SERVICE_MODULE_ENUMERATOR
//     (soft) DEBUG_SERVICE_IMAGE_PARSE_PROVIDER
//
// {1E3DB962-FF60-4b28-99FC-0F9D121F1A21}
//
DEFINE_GUID(DEBUG_COMPONENTSVC_IMAGEBACKED_VIRTUALMEMORY, 0x1e3db962, 0xff60, 0x4b28, 0x99, 0xfc, 0xf, 0x9d, 0x12, 0x1f, 0x1a, 0x21);

DEFINE_GUID(IID_IComponentImageBackedVirtualMemoryInitializer, 0x2ad7f2cb, 0xe309, 0x4d5d, 0xb9, 0x7d, 0x41, 0x43, 0x63, 0x60, 0xb7, 0xd1);
struct DECLSPEC_UUID("2AD7F2CB-E309-4d5d-B97D-41436360B7D1") IComponentImageBackedVirtualMemoryInitializer;

#undef INTERFACE
#define INTERFACE IComponentImageBackedVirtualMemoryInitializer
DECLARE_INTERFACE_(IComponentImageBackedVirtualMemoryInitializer, IUnknown)
{
    //*************************************************
    // IComponentImageBackedVirtualMemoryInitializer:
    //

    // Initialize():
    //
    // Initializes the image backed virtual memory service with an underlying virtual memory service.
    // The given service must support ISvcMemoryAccess and *SHOULD* implement ISvcMemoryInformation.
    //
    // If the underlying service does not support ISvcMemoryInformation, the image backed virtual memory
    // service will operate in pass through mode only.
    //
    // If no pUnderlyingVirtualMemoryService is provided as 'nullptr' or the initializer is not called before
    // the component is inserted into the service container, it will stack on top of whatever virtual memory
    // service is already in the service container.
    //
    // 'projectNonFileMappedBytesAsZero' indicates whether bytes attributable to the image which are not
    // contained in the underlying virtual memory service *OR* the image file itself should be provided
    // by this service.  Such bytes would be things which are zero initialized (or uninitialized) but
    // allocated by a loader (e.g.: the .bss segment)
    //
    STDMETHOD(Initialize)(
        THIS_
        _In_opt_ IDebugServiceLayer *pUnderlyingVirtualMemoryService,
        _In_ bool projectNonFileMappedBytes
        ) PURE;
};

// DEBUG_COMPONENTSVC_STACKUNWINDER_STACKPROVIDER
//
// Description:
//
//     A default implementation of a stack provider which utilizes an underlying stack unwinder service to
//     provider higher level abstract frames.
//
//     This implementation will, by default, return one physical frame per frame returned from the unwinder.
//     It can optionally also place inline stack frames above each physical frame for each inline method.  Note
//     that such requires access to the symbol provider and symbols which provide inlining information
//     as a symbol set.  Note that PDBs are presently not accessible via a symbol set.
//
// Initializer Interface:
//
//     IComponentStackUnwinderStackProviderInitializer
//
// Services Provided:
//
//     DEBUG_SERVICE_STACK_PROVIDER
//
// Dependent Services:
//
//     (hard) DEBUG_SERVICE_STACK_UNWINDER
//     (hard) DEBUG_SERVICE_ARCHINFO
//     (soft) DEBUG_SERVICE_MODULE_ENUMERATOR
//     (soft) DEBUG_SERVICE_SYMBOL_PROVIDER
//
// {29B6F990-DFD4-4d75-A20C-5E85B630939B}
//
DEFINE_GUID(DEBUG_COMPONENTSVC_STACKUNWINDER_STACKPROVIDER, 0x29b6f990, 0xdfd4, 0x4d75, 0xa2, 0xc, 0x5e, 0x85, 0xb6, 0x30, 0x93, 0x9b);

// {E44474E7-99EC-40d5-9C94-7554EA45C4CF}
DEFINE_GUID(IID_IComponentStackUnwinderStackProviderInitializer, 0xe44474e7, 0x99ec, 0x40d5, 0x9c, 0x94, 0x75, 0x54, 0xea, 0x45, 0xc4, 0xcf);
struct DECLSPEC_UUID("E44474E7-99EC-40d5-9C94-7554EA45C4CF") IComponentStackUnwinderStackProviderInitializer;

#undef INTERFACE
#define INTERFACE IComponentStackUnwinderStackProviderInitializer
DECLARE_INTERFACE_(IComponentStackUnwinderStackProviderInitializer, IUnknown)
{
    //*************************************************
    // IComponentStackUnwinderStackProviderInitializer:
    //

    // Initialize():
    //
    // Initializes the stack provider.  If 'provideInlineFrames' is set to true, the stack provider will
    // directly look at symbols for each stack frame, ask about inline information at each call site, and
    // insert inline frames into the frames provided.
    //
    // The default value for 'provideInlineFrames' without the initializer called is false.
    //
    // NOTE: The stack provider can only provide inline frames for symbol formats which are exposed through
    // the use of a symbol provider.  PDBs do not yet meet that classification.
    //
    STDMETHOD(Initialize)(
        THIS_
        _In_ bool provideInlineFrames
        ) PURE;
};

// {93ABD785-449B-4C64-931D-A2D5B2488205}
DEFINE_GUID(IID_IComponentDwarfStackUnwinderInitializer, 0x93abd785, 0x449b, 0x4c64, 0x93, 0x1d, 0xa2, 0xd5, 0xb2, 0x48, 0x82, 0x05);

struct DECLSPEC_UUID("93ABD785-449B-4C64-931D-A2D5B2488205") IComponentDwarfStackUnwinderInitializer;

#undef INTERFACE
#define INTERFACE IComponentDwarfStackUnwinderInitializer
DECLARE_INTERFACE_(IComponentDwarfStackUnwinderInitializer, IUnknown)
{
    // Initialize():
    //
    // Initializes the DEBUG_COMPONENT_DWARF_STACK_UNWINDER component. It takes an optional stack unwinder
    // which can be used as a fallback by the DWARF stack unwinder. (This is used for ARM targets atm.)
    //
    STDMETHOD(Initialize)(
        THIS_
        _In_opt_ ISvcStackFrameUnwind* pSecondaryUnwinder
        ) PURE;
};

// DEBUG_COMPONENTSVC_IMAGEPROVIDER_FROM_FILE:
//
// Description:
//
//     A component which provides an image provider that is simply a redirect to the file source.  Such
//     component can be used if the target is simply an open image.
//
// Services Provided:
//
//     DEBUG_SERVICE_IMAGE_PROVIDER
//
// Component GUID:
//
//     {016315AA-3972-421f-8AFD-DB3DC0E4DD72}
//
DEFINE_GUID(DEBUG_COMPONENTSVC_IMAGEPROVIDER_FROM_FILE, 0x16315aa, 0x3972, 0x421f, 0x8a, 0xfd, 0xdb, 0x3d, 0xc0, 0xe4, 0xdd, 0x72);

//**************************************************************************
// Aggregating Components:
//

// DEBUG_COMPONENTSVC_AGGREGATING_MODULE_ENUMERATOR
//
// Description:
//
//     A component which aggregates multiple other module enumerator services to make a single module
//     enumerator service.  This component is registered as the standard aggregator for
//     DEBUG_SERVICE_MODULE_ENUMERATOR.
//
// Services Provided:
//
//     DEBUG_SERVICE_MODULE_ENUMERATOR
//
// Services Dependended On:
//
//     None (depends on what is aggregated)
//
// {CB00740B-CD89-40bd-A860-D648C24205F2}
//
DEFINE_GUID(DEBUG_COMPONENTSVC_AGGREGATING_MODULE_ENUMERATOR, 0xcb00740b, 0xcd89, 0x40bd, 0xa8, 0x60, 0xd6, 0x48, 0xc2, 0x42, 0x5, 0xf2);

// DEBUG_COMPONENTSVC_AGGREGATING_MODULE_INDEX_PROVIDER
//
// Description:
//
//     A component which aggregates multiple other module index provider services to make a single module
//     index provider service.  This component is registered as the standard aggregator for
//     DEBUG_SERVICE_MODULE_INDEX_PROVIDER.
//
// Services Provided:
//
//     DEBUG_SERVICE_MODULE_INDEX_PROVIDER
//
// Services Dependended On:
//
//     None (depends on what is aggregated)
//
// {37ADF532-778E-49D7-85DF-507A60E5A469}
//
DEFINE_GUID(DEBUG_COMPONENTSVC_AGGREGATING_MODULE_INDEX_PROVIDER, 0x37adf532, 0x778e, 0x49d7, 0x85, 0xdf, 0x50, 0x7a, 0x60, 0xe5, 0xa4, 0x69);

// DEBUG_COMPONENTSVC_AGGREGATING_STACK_UNWINDER
//
// Description:
//
//     A component which aggregates multiple stack unwinders to comprise a single stack unwind capability.
//
//     The unwinders which are placed in the aggregate must be placed in **PRIORITY** order.  The first unwinder
//     in the container is considered primary.  Each unwinder in the container has an opportunity to ask for a
//     transition away from another unwinder on a frame-by-frame basis by implementing the
//     ISvcStackFrameUnwinderTransition interface.
//
//     This component is registered as the standard aggregator for DEBUG_SERVICE_STACK_UNWINDER.
//
// Services Provided:
//
//     DEBUG_SERVICE_STACK_UNWINDER
//
// Services Depended On:
//
//     None (depends on what is aggregated)
//
// {1B391664-8128-42b4-A26A-0265B7CC177F}
//
DEFINE_GUID(DEBUG_COMPONENTSVC_AGGREGATING_STACK_UNWINDER, 0x1b391664, 0x8128, 0x42b4, 0xa2, 0x6a, 0x2, 0x65, 0xb7, 0xcc, 0x17, 0x7f);

// DEBUG_COMPONENTSVC_AGGREGATING_SYMBOL_PROVIDER
//
// Description:
//
//     A component which aggregates multiple symbol providers to comprise a single symbol provider capability.
//
//     Each symbol provider in the aggregate will be asked in turn to provide symbols for a given component
//     until one succeeds.
//
//     This component is registered as the standard aggregator for DEBUG_SERVICE_SYMBOL_PROVIDER.
//
// Services Provided:
//
//     DEBUG_SERVICE_SYMBOL_PROVIDER
//
// Services Depended On:
//
//     None (depends on what is aggregated)
//
// {380A71A1-669F-4612-B80F-677865DBE3AF}
//
DEFINE_GUID(DEBUG_COMPONENTSVC_AGGREGATING_SYMBOL_PROVIDER, 0x380a71a1, 0x669f, 0x4612, 0xb8, 0xf, 0x67, 0x78, 0x65, 0xdb, 0xe3, 0xaf);

// DEBUG_COMPONENTSVC_AGGREGATING_IMAGE_PARSE_PROVIDER
//
// Description:
//
//     A component which aggregates multiple image parse providers to comprise a single image parse provider
//     capability.
//
//     Each image parse provider in the aggregate will be asked in turn to parse an image until it succeeds.
//
//     This component is registered as the standard aggregator for DEBUG_SERVICE_IMAGE_PARSE_PROVIDER.
//
// Services Provided:
//
//     DEBUG_SERVICE_IMAGE_PARSE_PROVIDER
//
// Services Depended On:
//
//     None (depends on what is aggregated)
//
// {577ABB35-723C-4515-B59A-24CDED6468A7}
//
DEFINE_GUID(DEBUG_COMPONENTSVC_AGGREGATING_IMAGE_PARSE_PROVIDER, 0x577abb35, 0x723c, 0x4515, 0xb5, 0x9a, 0x24, 0xcd, 0xed, 0x64, 0x68, 0xa7);

// DEBUG_COMPONENTSVC_AGGREGATING_IMAGE_PROVIDER
//
// Description:
//
//     A component which aggregates multiple image providers to comprise a single image provider
//     capability.
//
//     Each image provider in the aggregate will be asked in turn to provide an image for a given module
//     until one succeeds.
//
//     This component is registered as the standard aggregator for DEBUG_SERVICE_IMAGE_PROVIDER.
//
// Services Provided:
//
//     DEBUG_SERVICE_IMAGE_PROVIDER
//
// Services Depended On:
//
//     None (depends on what is aggregated)
//
// {B945EEF5-85D7-4d51-AD75-8CD33EF04678}
//
DEFINE_GUID(DEBUG_COMPONENTSVC_AGGREGATING_IMAGE_PROVIDER, 0xb945eef5, 0x85d7, 0x4d51, 0xad, 0x75, 0x8c, 0xd3, 0x3e, 0xf0, 0x46, 0x78);

// DEBUG_COMPONENTSVC_AGGREGATING_NAME_DEMANGLER
//
// Description:
//
//     A component which aggregates multiple name demanglers to comprise a single name demangler.
//
//     Each name demangler in the aggregate will be asked in turn to attempt to demangle a given mangled name
//     until one succeeds.
//
//     This component is registered as the standard aggregator for DEBUG_SERVICE_NAME_DEMANGLER.
//
// Services Provided:
//
//     DEBUG_SERVICE_NAME_DEMANGLER
//
// Services Depended On:
//
//     None (depends on what is aggregated)
//
// {762317E6-8DD3-4112-9FF6-0971A5BFD227}
//
DEFINE_GUID(DEBUG_COMPONENTSVC_AGGREGATING_NAME_DEMANGLER, 0x762317e6, 0x8dd3, 0x4112, 0x9f, 0xf6, 0x9, 0x71, 0xa5, 0xbf, 0xd2, 0x27);

// DEBUG_COMPONENTSVC_AGGREGATING_THREAD_ENUMERATOR
//
// Description:
//
//     A component which aggregates multiple other thread enumerator services to make a single thread
//     enumerator service.  This component is registered as the standard aggregator for
//     DEBUG_SERVICE_THREAD_ENUMERATOR.
//
// Services Provided:
//
//     DEBUG_SERVICE_THREAD_ENUMERATOR
//
// Services Dependended On:
//
//     None (depends on what is aggregated)
//
// {1FF094AB-BBAB-4ba8-B965-B3332DAB6E2D}
//
DEFINE_GUID(DEBUG_COMPONENTSVC_AGGREGATING_THREAD_ENUMERATOR, 0x1ff094ab, 0xbbab, 0x4ba8, 0xb9, 0x65, 0xb3, 0x33, 0x2d, 0xab, 0x6e, 0x2d);

//**************************************************************************
// Forwarder Components:
//

// DEBUG_COMPONENTSVC_FORWARD_PHYSICALMEMORY:
//
// Description:
//
//     A component which forwards a physical memory request from one service manager to another.  This allows for the creation
//     of a 'view' of another target.
//
// Services Provided:
//
//     DEBUG_SERVICE_PHYSICAL_MEMORY
//
// Services Depended On:
//
//     DEBUG_PRIVATE_SERVICE_DEBUGSOURCE (a view debug source implementing ISvcDebugSourceView)
//
// Component GUID:
//
//     {0A9E8183-AF09-4f1c-A42D-D8DBA02AB27D}
//
DEFINE_GUID(DEBUG_COMPONENTSVC_FORWARD_PHYSICALMEMORY, 0xa9e8183, 0xaf09, 0x4f1c, 0xa4, 0x2d, 0xd8, 0xdb, 0xa0, 0x2a, 0xb2, 0x7d);

// DEBUG_COMPONENTSVC_FORWARD_VIRTUALMEMORY:
//
// Description:
//
//     A component which forwards a virtual memory request from one service manager to another.  This allows for the creation
//     of a 'view' of another target.
//
// Services Provided:
//
//     DEBUG_SERVICE_VIRTUAL_MEMORY
//
// Services Depended On:
//
//     DEBUG_PRIVATE_SERVICE_DEBUGSOURCE (a view debug source implementing ISvcDebugSourceView)
//
// Component GUID:
//
//     {490851F0-C058-4697-958B-D3BB5252BA60}
//
DEFINE_GUID(DEBUG_COMPONENTSVC_FORWARD_VIRTUALMEMORY, 0x490851f0, 0xc058, 0x4697, 0x95, 0x8b, 0xd3, 0xbb, 0x52, 0x52, 0xba, 0x60);

// DEBUG_COMPONENTSVC_FORWARD_IOSPACEMEMORY
//
// Description:
//
//     A component which forwards I/O space requests from one service manager to another.  This allows for the creation
//     of a 'view' of another target.
//
// Services Provided:
//
//     DEBUG_SERVICE_IOSPACE_MEMORY
//
// Services Dependended On:
//
//     DEBUG_PRIVATE_SERVICE_DEBUGSOURCE (a view debug source implementing ISvcDebugSourceView)
//
// Component GUID:
//
//     {B89FB326-DFBF-4273-A88B-0EF722F34157}
//
DEFINE_GUID(DEBUG_COMPONENTSVC_FORWARD_IOSPACEMEMORY, 0xb89fb326, 0xdfbf, 0x4273, 0xa8, 0x8b, 0xe, 0xf7, 0x22, 0xf3, 0x41, 0x57);

// DEBUG_COMPONENTSVC_FORWARD_IOSPACEENUMERATOR
//
// Description:
//
//     A component which forwards I/O space enumeration requests from one service manager to another.  This allows for
//     the creation of a 'view' of another target.
//
// Services Provided:
//
//     DEBUG_SERVICE_IOSPACE_ENUMERATOR
//
// Services Depended On:
//
//     DEBUG_PRIVATE_SERVICE_DEBUGSOURCE (a view debug source implementing ISvcDebugSourceView)
//
// Component GUID:
//
//     {99E056B7-C469-4ff5-9729-C9FA88790A27}
//
DEFINE_GUID(DEBUG_COMPONENTSVC_FORWARD_IOSPACEENUMERATOR, 0x99e056b7, 0xc469, 0x4ff5, 0x97, 0x29, 0xc9, 0xfa, 0x88, 0x79, 0xa, 0x27);

// DEBUG_COMPONENTSVC_FORWARD_MACHINEDEBUG
//
// Description:
//
//     A component which forwards machine and machine debug requests from one service manager to another.  This allows
//     for the creation of a 'view' of another target.
//
// Services Provided:
//
//     DEBUG_SERVICE_FORWARD_MACHINEDEBUG
//
// Services Dependended On:
//
//     DEBUG_PRIVATE_SERVICE_DEBUGSOURCE (a view debug source implementing ISvcDebugSourceView)
//
// Component GUID:
//
//     {DD096A59-A6A7-42ec-96BD-FDD9A558BCE4}
//
DEFINE_GUID(DEBUG_COMPONENTSVC_FORWARD_MACHINEDEBUG, 0xdd096a59, 0xa6a7, 0x42ec, 0x96, 0xbd, 0xfd, 0xd9, 0xa5, 0x58, 0xbc, 0xe4);

//**************************************************************************
// Stack Components:
//

// DEBUG_SERVICE_STACK_PROVIDER:
//
// Defines a higher level mechanism for getting at an abstract stack and its frames.  The default stack provider
// is a thin shim over a physical stack unwinder.  Other stack providers can present "logical call stacks" which
// have no relationship to a set of physical frames in memory unwound by traditional means.
//
DEFINE_GUID(DEBUG_SERVICE_STACK_PROVIDER, 0x62d97173, 0xa8dd, 0x44f7, 0x84, 0x87, 0xac, 0x9e, 0xe6, 0x26, 0x2e, 0xf4);

// DEBUG_SERVICE_STACK_UNWINDER:
//
// Defines the standard mecahnism for unwinding stack frames.
//
DEFINE_GUID(DEBUG_SERVICE_STACK_UNWINDER, 0xb84a9083, 0x8f92, 0x4783, 0xb6, 0xe1, 0x18, 0x7b, 0x53, 0xff, 0xda, 0xba);

//**************************************************************************
// Core "Public" Services:
//

// DEBUG_SERVICE_ARCHINFO:
//
// Defines the standard mechanism for getting an abstraction over architecture specific details
// of a debug target (e.g.: hardware page sizes, etc...).
//
// This service does not provide any configuration details (e.g.: number of CPUs) or hardware debug capabilities.
// Every composition stack MUST have this service.
//
// {1AAAE599-C167-42b5-B46F-D8B614DA622A}
//
DEFINE_GUID(DEBUG_SERVICE_ARCHINFO, 0x1aaae599, 0xc167, 0x42b5, 0xb4, 0x6f, 0xd8, 0xb6, 0x14, 0xda, 0x62, 0x2a);

// DEBUG_SERVICE_DISASSEMBLER:
//
// Defines access to the disassembler.
//
// This service must provide ISvcBasicDisassembly and may provide other stacked disassembly interfaces
// to indicate progressively more capability.
//
// {03EBFBBC-8C0E-423b-97AF-91EF24045933}
//
DEFINE_GUID(DEBUG_SERVICE_DISASSEMBLER, 0x3ebfbbc, 0x8c0e, 0x423b, 0x97, 0xaf, 0x91, 0xef, 0x24, 0x4, 0x59, 0x33);

// DEBUG_SERVICE_MACHINE:
//
// Defines the standard mechanism for getting an abstraction over a machine configuration, possible hardware
// debugging, and the details which govern it.
//
// {8514F5BC-5827-4794-BF0F-619C8FD2E84E}
//
DEFINE_GUID(DEBUG_SERVICE_MACHINE, 0x8514f5bc, 0x5827, 0x4794, 0xbf, 0xf, 0x61, 0x9c, 0x8f, 0xd2, 0xe8, 0x4e);

// DEBUG_SERVICE_VIRTUAL_MEMORY:
//
// Defines the standard mechanism for accessing the virtual memory
// associated with a given process / address space.
//
// This service is always available on a given debug target.  The implementation of this service
// may defer to a cache, may translate to physical addresses, or may issue remote read requests.
// It is entirely up to the service.
//
// {0E1096D0-9E8D-46fe-94A5-FCD06B38FF21}
//
// @NOTE: If you query for this service, you are always reading memory of a process or address space.  This means
//        that (on Windows), reading a user mode address passing a particular process will always perform that read
//        to the best of the ability of the debugger regardless of the break state of the CPU.  This may involve
//        doing a virtual->physical translation.
//
DEFINE_GUID(DEBUG_SERVICE_VIRTUAL_MEMORY, 0xe1096d0, 0x9e8d, 0x46fe, 0x94, 0xa5, 0xfc, 0xd0, 0x6b, 0x38, 0xff, 0x21);

// DEBUG_SERVICE_PHYSICAL_MEMORY:
//
// Defines the standard mechanism for accessing the physical memory
// associated with a given target.
//
// This service is only available on targets which speak in terms of physical memory.  A kernel debugger connection,
// a full kernel dump, and an EXDI connection are all examples of this.
//
// {0516BF7F-2644-4ea4-A151-B55AE016B213}
//
DEFINE_GUID(DEBUG_SERVICE_PHYSICAL_MEMORY, 0x516bf7f, 0x2644, 0x4ea4, 0xa1, 0x51, 0xb5, 0x5a, 0xe0, 0x16, 0xb2, 0x13);

// DEBUG_SERVICE_IOSPACE_MEMORY
//
// Defines the standard mechanism for accessing various I/O spaces.
//
// This service is only available on targets which have some notion (and access to) I/O spaces.
//
// {DAE9985B-DCC6-4eee-B5B0-FA39017D618D}
//
DEFINE_GUID(DEBUG_SERVICE_IOSPACE_MEMORY, 0xdae9985b, 0xdcc6, 0x4eee, 0xb5, 0xb0, 0xfa, 0x39, 0x1, 0x7d, 0x61, 0x8d);

// DEBUG_SERVICE_VIRTUAL_TO_PHYSICAL_TRANSLATION:
//
// Defines the standard mechanism for translating virtual addresses within a particular process
// or address space to physical addresses (if possible).
//
// This service is only available on targets which speak in terms of physical memory and have services available
// to interpret the page tables.
//
// {1B3DC04F-3027-4377-B440-7FA1146BDCFF}
//
DEFINE_GUID(DEBUG_SERVICE_VIRTUAL_TO_PHYSICAL_TRANSLATION, 0x1b3dc04f, 0x3027, 0x4377, 0xb4, 0x40, 0x7f, 0xa1, 0x14, 0x6b, 0xdc, 0xff);

// DEBUG_SERVICE_PAGEFILE_READER
//
// Defines the standard mechanism for reading data which has been paged out.  The data read may come from an in-memory compressed
// store or may come from the actual page file (if available to the target).
//
// This service is only available on targets which understand the paging hardware of the target (e.g.: kernel
// sessions).
//
// {32C258DC-14EE-487e-9499-96FDDB3D3369}
//
DEFINE_GUID(DEBUG_SERVICE_PAGEFILE_READER, 0x32c258dc, 0x14ee, 0x487e, 0x94, 0x99, 0x96, 0xfd, 0xdb, 0x3d, 0x33, 0x69);

// DEBUG_SERVICE_PROCESS_ENUMERATOR
//
// Defines the standard mechanism for enumerating processes which are actively "connected" (e.g.: being
// debugged).  DEBUG_SERVICE_PROCESS_CONNECTOR is the service which represents the ability to connect
// to or start processes (as might be represented by a dbgsrv or gdbserver --multi instance)
//
// {A3371693-C1EB-4acd-A459-891AD2354F7E}
//
DEFINE_GUID(DEBUG_SERVICE_PROCESS_ENUMERATOR, 0xa3371693, 0xc1eb, 0x4acd, 0xa4, 0x59, 0x89, 0x1a, 0xd2, 0x35, 0x4f, 0x7e);

// DEBUG_SERVICE_PROCESS_CONNECTOR
//
// Defines the standard mechanism for finding processes which are potential debug targets.  If a container
// has a process connector, it is assumed to be a "process server" with the capability of creating new
// processes, attaching to existing ones, and debugging multiple processes simultaneously.
//
// {9922FEF0-69EA-4ab0-8331-92361374CCCE}
//
DEFINE_GUID(DEBUG_SERVICE_PROCESS_CONNECTOR, 0x9922fef0, 0x69ea, 0x4ab0, 0x83, 0x31, 0x92, 0x36, 0x13, 0x74, 0xcc, 0xce);

// DEBUG_SERVICE_THREAD_ENUMERATOR
// Defines the standard mechanism for enumerating threads.
//
// {BFC2F315-AB73-4876-BCED-1D6CD5D3A8C3}
//
DEFINE_GUID(DEBUG_SERVICE_THREAD_ENUMERATOR, 0xbfc2f315, 0xab73, 0x4876, 0xbc, 0xed, 0x1d, 0x6c, 0xd5, 0xd3, 0xa8, 0xc3);

// DEBUG_SERVICE_IOSPACE_ENUMERATOR
// Defines the standard mechanism for enumerating I/O spaces.
//
// {9576818B-89A5-4a11-98AC-2D0421D23A9F}
//
DEFINE_GUID(DEBUG_SERVICE_IOSPACE_ENUMERATOR, 0x9576818b, 0x89a5, 0x4a11, 0x98, 0xac, 0x2d, 0x4, 0x21, 0xd2, 0x3a, 0x9f);

// DEBUG_SERVICE_MODULE_ENUMERATOR
// Defines the standard mechanism for enumerating modules.
//
// {DA9DCFAE-3CB4-48a8-A5EA-6B63ABCB5CE7}
//
DEFINE_GUID(DEBUG_SERVICE_MODULE_ENUMERATOR, 0xda9dcfae, 0x3cb4, 0x48a8, 0xa5, 0xea, 0x6b, 0x63, 0xab, 0xcb, 0x5c, 0xe7);

// DEBUG_SERVICE_MODULE_INDEX_PROVIDER
//
// Defines the standard mechanism for providing an index key for a given module.
//
// {3BB7A2F9-EC02-458F-AB46-1B0C66FCDDB8}
//
DEFINE_GUID(DEBUG_SERVICE_MODULE_INDEX_PROVIDER, 0x3bb7a2f9, 0xec02, 0x458f, 0xab, 0x46, 0x1b, 0xc, 0x66, 0xfc, 0xdd, 0xb8);

// DEBUG_SERVICE_THREAD_LOCAL_STORAGE_PROVIDER
//
// Defines the standard mechanism for providing access to thread-local storage.
//
// {4EFB2597-D280-4DDA-820B-14A07ED2D2D2}
//
DEFINE_GUID(DEBUG_SERVICE_THREAD_LOCAL_STORAGE_PROVIDER, 0x4efb2597, 0xd280, 0x4dda, 0x82, 0x0b, 0x14, 0xa0, 0x7e, 0xd2, 0xd2, 0xd2);

// DEBUG_SERVICE_OS_KERNELINFRASTRUCTURE
//
// Defines the standard mechanism for communicating with kernel infrastructure that is specific to the operating system
// of the machine.
//
// {BCBAC4B1-ED84-4326-B062-21FB57556F4F}
//
DEFINE_GUID(DEBUG_SERVICE_OS_KERNELINFRASTRUCTURE, 0xbcbac4b1, 0xed84, 0x4326, 0xb0, 0x62, 0x21, 0xfb, 0x57, 0x55, 0x6f, 0x4f);

// DEBUG_SERVICE_OS_KERNELLOCATOR
//
// Defines the standard mechanism for locating the kernel.
//
// {037AC304-09CF-472a-B2FD-C0E69C881B75}
//
DEFINE_GUID(DEBUG_SERVICE_OS_KERNELLOCATOR, 0x37ac304, 0x9cf, 0x472a, 0xb2, 0xfd, 0xc0, 0xe6, 0x9c, 0x88, 0x1b, 0x75);

// DEBUG_SERVICE_SYMBOL_PROVIDER
//
// Defines the standard mechanism for locating symbols for the given composition stack.
//
// {088C65CF-5950-4c41-9F2E-82FF1F93EFB3}
//
DEFINE_GUID(DEBUG_SERVICE_SYMBOL_PROVIDER, 0x88c65cf, 0x5950, 0x4c41, 0x9f, 0x2e, 0x82, 0xff, 0x1f, 0x93, 0xef, 0xb3);

// {F656EC69-9E28-41ba-BC6A-CAF8A5CEC8ED}
//
// Defines the standard mechanism for locating image files from information read from a target.
//
DEFINE_GUID(DEBUG_SERVICE_IMAGE_PROVIDER, 0xf656ec69, 0x9e28, 0x41ba, 0xbc, 0x6a, 0xca, 0xf8, 0xa5, 0xce, 0xc8, 0xed);

// {7B88E717-F162-4cfe-B643-54C1122D0670}
//
// Defines the standard mechanism for parsing various formats of image files in a target.
//
DEFINE_GUID(DEBUG_SERVICE_IMAGE_PARSE_PROVIDER, 0x7b88e717, 0xf162, 0x4cfe, 0xb6, 0x43, 0x54, 0xc1, 0x12, 0x2d, 0x6, 0x70);

// {C1E4D3BF-9F45-4f0c-B08D-1B993C438629}
//
// Defines the standard mechanism for trying to demangle mangled symbolic names (e.g.: C++ mangled names)
//
DEFINE_GUID(DEBUG_SERVICE_NAME_DEMANGLER, 0xc1e4d3bf, 0x9f45, 0x4f0c, 0xb0, 0x8d, 0x1b, 0x99, 0x3c, 0x43, 0x86, 0x29);

// DEBUG_SERVICE_EXECUTION_CONTEXT_TRANSLATION:
//
// Defines the standard mechanism for fetching context from execution units (software threads or physical cores)
// where that context might need to be translated.  Such translation may occur due to the debugger providing
// a view on the actual target (e.g.: emulator versus emulatee, WoW versus native, enclave versus host)
//
// The ::GetContext method on a given execution unit will *ALWAYS* return the *ACTUAL* context of the thread/core.
// It is expected that a client will fetch context through this service.  If not present in the service
// container, the underlying native context can be fetched directly from an execution unit.
//
// {AE987DC0-7D24-4c33-A5A6-312D96192C8E}
//
DEFINE_GUID(DEBUG_SERVICE_EXECUTION_CONTEXT_TRANSLATION, 0xae987dc0, 0x7d24, 0x4c33, 0xa5, 0xa6, 0x31, 0x2d, 0x96, 0x19, 0x2c, 0x8e);

// DEBUG_SERVICE_ACTIVE_EXCEPTIONS
//
// Defines a mechanism for fetching information about active exception like events (e.g.: exceptions, Linux
// signals, etc...)
//
// A post-mortem target can indicate information about the reason for the snapshot (dump, etc...) via this
// mechanism.
//
// {39B29A74-4608-4a1d-8102-D68F7391E8B5}
//
DEFINE_GUID(DEBUG_SERVICE_ACTIVE_EXCEPTIONS, 0x39b29a74, 0x4608, 0x4a1d, 0x81, 0x2, 0xd6, 0x8f, 0x73, 0x91, 0xe8, 0xb5);

// DEBUG_SERVICE_EXCEPTION_FORMATTER
//
// Defines a standard service for formatting exceptional events (e.g.: Win32 exceptions, Linux signals, etc...)
// from a target.
//
// {46BD1681-384A-4faa-B588-E5244E8BA65E}
//
DEFINE_GUID(DEBUG_SERVICE_EXCEPTION_FORMATTER, 0x46bd1681, 0x384a, 0x4faa, 0xb5, 0x88, 0xe5, 0x24, 0x4e, 0x8b, 0xa6, 0x5e);

// DEBUG_SERVICE_OS_INFORMATION:
//
// Defines a standardized way to get information about the underlying OS platform that a given target is/was
// executing upon.
//
// This service is *OPTIONAL* and is not required in any target.
//
// {43AFEC1D-7529-40e0-8BF3-F27469F40FEF}
//
DEFINE_GUID(DEBUG_SERVICE_OS_INFORMATION, 0x43afec1d, 0x7529, 0x40e0, 0x8b, 0xf3, 0xf2, 0x74, 0x69, 0xf4, 0xf, 0xef);

// DEBUG_SERVICE_STEP_CONTROLLER:
//
// Defines the standardized way of controlling motion of a live target.  A service container which contains
// DEBUG_SERVICE_STEP_CONTROLLER is considered to be a "live target"
//
// This service is *OPTIONAL*.  It is only required for targets which wish to present other than a static view.
//
// {D9FB31D3-5A02-49b5-8201-9F4365B70B2D}
//
DEFINE_GUID(DEBUG_SERVICE_STEP_CONTROLLER, 0xd9fb31d3, 0x5a02, 0x49b5, 0x82, 0x1, 0x9f, 0x43, 0x65, 0xb7, 0xb, 0x2d);

// DEBUG_SERVICE_BREAKPOINT_CONTROLLER:
//
// Defines the standardized way of controlling breakpoints within a live target.
//
// This service is *OPTIONAL*.  It *SHOULD* be present for targets which wish to present other than a static
// view; however, some targets may only provide run/stop/step and may not support breakpoints at all.
//
// {BDD79E78-891B-4857-A511-3D67C3B274B0}
//
DEFINE_GUID(DEBUG_SERVICE_BREAKPOINT_CONTROLLER, 0xbdd79e78, 0x891b, 0x4857, 0xa5, 0x11, 0x3d, 0x67, 0xc3, 0xb2, 0x74, 0xb0);

// DEBUG_SERVICE_SECURITY_CONFIGURATION:
//
// Defines a means of accessing certain "security configuration" for various objects required to debug.
//
// This service is *OPTIONAL*.  It *SHOULD* be present for targets which require a description of such configuration
// for successful debugging (e.g.: have PAC enabled on AArch64)
//
// {CF6C777B-A0C8-4f6f-A44E-70D56E74D739}
//
DEFINE_GUID(DEBUG_SERVICE_SECURITY_CONFIGURATION, 0xcf6c777b, 0xa0c8, 0x4f6f, 0xa4, 0x4e, 0x70, 0xd5, 0x6e, 0x74, 0xd7, 0x39);

// DEBUG_SERVICE_FILEFORMAT_PARSER:
//
// Defines a means of accessing the base level service for parsing a particular file format that a debugger opens
// (e.g.: minidumps, core dumps, KDUMPs, etc...).  This is expected to utilize DEBUG_PRIVATE_SERVICE_DEBUGSOURCE
// as an underlying file.
//
// This service is *OPTIONAL* and will only be present for targets which represent an underlying file format and
// not something like a connection to a live process or process server.
//
// The interfaces which are on this service are dependent upon the kind of file format.  Generalized interfaces which
// are likely to be present across format types:
//
//     ISvcFileFormatPrivateData -- A means of accessing private/custom data blobs attached to a file.
//
// {3575FEFB-81E6-4ca0-83C6-91D380FFF32E}
//
DEFINE_GUID(DEBUG_SERVICE_FILEFORMAT_PARSER, 0x3575fefb, 0x81e6, 0x4ca0, 0x83, 0xc6, 0x91, 0xd3, 0x80, 0xff, 0xf3, 0x2e);

//**************************************************************************
// Operating System Specific Services:
//

// DEBUG_SERVICE_WINDOWS_KERNELINFRASTRUCTURE
//
// Defines a set of services specific to the kernel of Windows.
//
// {355ED9B0-8AF4-4b91-8AD0-C71AF8ADF5EC}
//
DEFINE_GUID(DEBUG_SERVICE_WINDOWS_KERNELINFRASTRUCTURE, 0x355ed9b0, 0x8af4, 0x4b91, 0x8a, 0xd0, 0xc7, 0x1a, 0xf8, 0xad, 0xf5, 0xec);

// DEBUG_SERVICE_WINDOWS_EXECUTION_EXCEPTION_TRANSLATION
//
// Defines a means of translating from one exception record to another (e.g.: native to WoW, emulator
// to emulatee, etc...)
//
// {EB09BB33-9834-408a-B026-9B51EB901D1A}
//
DEFINE_GUID(DEBUG_SERVICE_WINDOWS_EXECUTION_EXCEPTION_TRANSLATION, 0xeb09bb33, 0x9834, 0x408a, 0xb0, 0x26, 0x9b, 0x51, 0xeb, 0x90, 0x1d, 0x1a);

//**************************************************************************
// Core "Private" Services:
//

// DEBUG_PRIVATE_SERVICE_DIAGNOSTIC_SINK:
//
// Defines a means by which other components in the service stack can send diagnostic warning
// or error messages.
//
// {455C5AF5-B697-48db-86FF-15E51920A136}
//
DEFINE_GUID(DEBUG_PRIVATE_SERVICE_DIAGNOSTIC_SINK, 0x455c5af5, 0xb697, 0x48db, 0x86, 0xff, 0x15, 0xe5, 0x19, 0x20, 0xa1, 0x36);

// DEBUG_PRIVATE_SERVICE_DEBUGSOURCE
//
// Defines the mechanism for communication with the underlying "target" or "debug source".  This may be an abstraction
// over a file, set of files, or set of streams (for a dump).  It may be an abstraction over a kernel transport
// connection.  It may be an abstraction for a connection to a process server.
//
// A few of the core services which sit low in the target composition stack (e.g.: reading and writing memory,
// getting thread context) are tightly bound to a particular debug source but present an abstract service.
//
// The debug source service is the very bottom of the target composition stack and provides a concrete interface.  No
// components outside the stack should EVER access the debug source service.  It should only be accessed by components
// within the service stack.
//
// {4268D211-058A-4afc-B5CD-68F1E210D03D}
//
DEFINE_GUID(DEBUG_PRIVATE_SERVICE_DEBUGSOURCE, 0x4268d211, 0x58a, 0x4afc, 0xb5, 0xcd, 0x68, 0xf1, 0xe2, 0x10, 0xd0, 0x3d);

// DEBUG_PRIVATE_SERVICE_HOST_CONFIGURATION
//
// Defines a mechanism for communication of certain configuration data with the host.  The interfaces which this
// supports are entirely host defined.  An example of data which *MAY* be available with this service is the
// search paths for symbols, etc...  via ISvcSearchPaths.
//
// NOTE: This service and any interfaces on it are *ENTIRELY* optional.
//
// {79ED793D-0659-443b-AC39-0123A488DD6F}
//
DEFINE_GUID(DEBUG_PRIVATE_SERVICE_HOST_CONFIGURATION, 0x79ed793d, 0x659, 0x443b, 0xac, 0x39, 0x1, 0x23, 0xa4, 0x88, 0xdd, 0x6f);

// DEBUG_SERVICE_CLR_DAC_AND_SOS_PROVIDER
//
// Defines the standard mechanism for providing an CLR DAC and SOS for a given (CLR) module.
//
// {8BBE9989-E330-4BDB-A774-35AD3547D583}
//
DEFINE_GUID(DEBUG_SERVICE_CLR_DAC_AND_SOS_PROVIDER, 0x8bbe9989, 0xe330, 0x4bdb, 0xa7, 0x74, 0x35, 0xad, 0x35, 0x47, 0xd5, 0x83);

// DEBUG_SERVICE_SOURCE_CODE_FILE_DOWNLOAD_URL_LINK_PROVIDER
//
// Defines the standard mechanism for providing download URL (or a list of URLs) for a source code file.
//
// {89C3AA95-385D-4C1C-95BB-EF294E5BFD76}
//
DEFINE_GUID(DEBUG_SERVICE_SOURCE_CODE_FILE_DOWNLOAD_URL_LINK_PROVIDER, 0x89c3aa95, 0x385d, 0x4c1c, 0x95, 0xbb, 0xef, 0x29, 0x4e, 0x5b, 0xfd, 0x76);

//**************************************************************************
// Secondary Services:
//

// DEBUG_SERVICE_VIRTUAL_MEMORY_UNCACHED:
//
// Defines a mechanism for accessing the virtual memory associated with a given process or
// address space with a guarantee that the reads and writes are not serviced via a cache.
//
// This service is always available on a given debug target.
//
// {C8ADD00A-A5C0-4ca2-8BD2-3D502443926C}
//
DEFINE_GUID(DEBUG_SERVICE_VIRTUAL_MEMORY_UNCACHED, 0xc8add00a, 0xa5c0, 0x4ca2, 0x8b, 0xd2, 0x3d, 0x50, 0x24, 0x43, 0x92, 0x6c);

// DEBUG_SERVICE_PHYSICAL_MEMORY_UNCACHED:
//
// Defines a mechanism for accessing the physical memory associated with a given target
// with a guarantee that the reads and writes are not serviced via a cache.
//
// This service is available on any target which supports DEBUG_SERVICE_PHYSICAL_MEMORY.
//
// {F98B6C17-09F1-45ec-B5A0-3B94682EBD8D}
//
DEFINE_GUID(DEBUG_SERVICE_PHYSICAL_MEMORY_UNCACHED, 0xf98b6c17, 0x9f1, 0x45ec, 0xb5, 0xa0, 0x3b, 0x94, 0x68, 0x2e, 0xbd, 0x8d);

// DEBUG_SERVICE_VIRTUAL_MEMORY_TRANSLATED:
//
// Denotes a service stack which accesses virtual memory via direct translation to physical
// memory addresses and physical reads.
//
// This service is only available on some debug targets.  In particular, kernel targets which have access
// to the underlying physical memory of the machine support this service.
//
DEFINE_GUID(DEBUG_SERVICE_VIRTUAL_MEMORY_TRANSLATED, 0xc8add00a, 0xa5c0, 0x4ca2, 0x8b, 0xd2, 0x3d, 0x50, 0x24, 0x43, 0x92, 0x6c);

//**************************************************************************
// Utility Services:
//

// DEBUG_SERVICE_TELEMETRY:
//
// A standard telemetry service to send diagnostic information.
//
// {91D9084F-A8AC-4d4f-88E1-5E65E8A64C60}
//
DEFINE_GUID(DEBUG_SERVICE_TELEMETRY, 0x91d9084f, 0xa8ac, 0x4d4f, 0x88, 0xe1, 0x5e, 0x65, 0xe8, 0xa6, 0x4c, 0x60);

// DEBUG_SERVICE_DIAGNOSTIC_LOGGING:
//
// A standard logging service to send diagnostic information.  The diagnostic logging service has special semantics
// placed upon it.  Any implementation of the diagnostic logging service must be prepared to receive *Log* calls
// on ISvcDiagnosticLogging **BEFORE** the service container is started and services are fully initialized.  The
// service manager itself will begin to write diagnostics to this service immediately after it is placed in the service
// container.
//
// {507C628C-DDC3-4829-91AF-01E1BF541B7B}
//
DEFINE_GUID(DEBUG_SERVICE_DIAGNOSTIC_LOGGING, 0x507c628c, 0xddc3, 0x4829, 0x91, 0xaf, 0x1, 0xe1, 0xbf, 0x54, 0x1b, 0x7b);

//**************************************************************************
// State Synchronization Services:
//

// DEBUG_SERVICE_SECONDARY_STATE_SYNCHRONIZATION:
//
// A service which aims to synchronize state between two clients (debuggers) refering to the same target (debuggee)
// so that a secondary client can perform queries while the primary one is busy.  The secondary state synchronization
// service provides two primary functions:
//
//     1) Indicating via a connection profile item how to reconnect (in a secondary way) to the same target.  A client
//        (debugger) which is targeting a dump file, may for instance, simply reopen the same file.  A client which is
//        targeting a live process cannot simply reattach to the same process; it may, for instance, require targeting
//        a process snapshot or full dump of the process in question.  Some clients may not be able to retarget their
//        underlying target and will fail this method.
//
//     2) Indicating via a state synchronization profile item how to synchronize state between the primary and secondary
//        clients.  For some targets, this may be a NOP (e.g.: a dump file).  For others (e.g.: a live process), it may
//        require more intricate operations (e.g.: retaking a snapshot / dump, moving the position of a time travel
//        debugger, etc...)
//
// {5A77DEB9-9DD8-42e5-BEE8-7B7ED7FC0DB7}
//
DEFINE_GUID(DEBUG_SERVICE_SECONDARY_STATE_SYNCHRONIZATION, 0x5a77deb9, 0x9dd8, 0x42e5, 0xbe, 0xe8, 0x7b, 0x7e, 0xd7, 0xfc, 0xd, 0xb7);

//*************************************************
// Conditional Services:
//

// DEBUG_SERVICE_REGISTERTRANSLATION
//
// A service which is able to translate between canonical register IDs and a domain specific register
// numbering.
//
// This service is *NEVER* canonical.  It is always conditional on two conditions:
//
// Primary  : The DEBUG_ARCHDEF_* GUID for the architecture of the context
// Secondary: The GUID which defines the domain specific context
//
// {95C5E296-C8CA-4ba2-A52A-FEF3C913AF8C}
//
DEFINE_GUID(DEBUG_SERVICE_REGISTERTRANSLATION, 0x95c5e296, 0xc8ca, 0x4ba2, 0xa5, 0x2a, 0xfe, 0xf3, 0xc9, 0x13, 0xaf, 0x8c);

// DEBUG_SERVICE_REGISTERCONTEXTTRANSLATION
//
// A service which is able to translate between the canonical context (ISvcRegisterContext) and a domain
// specific context (e.g.: the context record stored after a PRSTATUS record in a Linux ELF core dump)
//
// This service is *NEVER* canonical.  It is always conditional on two conditions:
//
// Primary  : The DEBUG_ARCHDEF_* GUID for the architecture of the context
// Secondary: The GUID which defines the domain specific context
//
// {7319EEDD-828F-4995-8994-ED694805E84C}
//
DEFINE_GUID(DEBUG_SERVICE_REGISTERCONTEXTTRANSLATION, 0x7319eedd, 0x828f, 0x4995, 0x89, 0x94, 0xed, 0x69, 0x48, 0x5, 0xe8, 0x4c);

// DEBUG_SERVICE_TRAPCONTEXTRESTORATION
//
// A service which is able to restore pre-trap state from the point of a trap handler (e.g.: a signal frame)
//
// This service is *NEVER* Canonical.  It is always conditional on two conditions:
//
// Primary  : The DEBUG_ARCHDEF_* GUID for the architecture of the context
// Secondary: The DEBUG_PLATFDEF_* GUID for the platform of the context
//
// {1AE71270-299C-417f-9608-E15912C229FB}
//
DEFINE_GUID(DEBUG_SERVICE_TRAPCONTEXTRESTORATION, 0x1ae71270, 0x299c, 0x417f, 0x96, 0x8, 0xe1, 0x59, 0x12, 0xc2, 0x29, 0xfb);

// DEBUG_SERVICE_USER_OPERATION_CONTROLLER
//
// A standard service to provide help and facitilitate user control like cancel long running operations, etc.
//
// {425D088E-EFA3-4D08-B23A-AD32E4637660}
//
DEFINE_GUID(DEBUG_SERVICE_USER_OPERATION_CONTROLLER, 0x425d088e, 0xefa3, 0x4d08, 0xb2, 0x3a, 0xad, 0x32, 0xe4, 0x63, 0x76, 0x60);

//**************************************************************************
// File Format Parsing APIs:
//

// SvcDataBlockMappingSegment:
//
// Defines a mapping from one block to its parent.
//
struct SvcDataBlockMappingSegment
{
    ULONG64 Offset;
    ULONG64 Size;
};

#undef INTERFACE
#define INTERFACE ISvcFileFormatDataBlock
DECLARE_INTERFACE_(ISvcFileFormatDataBlock, IUnknown)
{
    // GetSize():
    //
    // Gets the overall size of this data block.  If the data block is non-contiguous (comprised of disjoint
    // regions), this returns the overall size of all disjoint regions; otherwise, it returns the size of the
    // one and only contiguous region.
    //
    STDMETHOD_(ULONG64, GetSize)(
        THIS
        ) PURE;

    // GetMapping():
    //
    // Gets the association between this data block and its parent file/data block as an offset/size pair.
    // If this data block is non-contiguous, this method will return the first such pair and will return S_FALSE.
    //
    STDMETHOD(GetMapping)(
        THIS_
        _Out_ SvcDataBlockMappingSegment *pMapping
        ) PURE;

    // Read():
    //
    // Attempts to read the number of bytes specified by the 'readSize' argument from the
    // block offset supplied by 'byteOffset' into the buffer supplied by the 'buffer' argument.
    // Note that a partial read is a successful state of this method.  In such a case,
    // the 'bytesRead' argument will be set to the number of bytes actually read and
    // S_FALSE will be returned.
    //
    STDMETHOD(Read)(
        THIS_
        _In_ ULONG64 byteOffset,
        _Out_writes_to_(readSize, *bytesRead) PVOID buffer,
        _In_ ULONG64 readSize,
        _Out_ PULONG64 bytesRead
        ) PURE;
};

#undef INTERFACE
#define INTERFACE ISvcFileFormatPrivateData
DECLARE_INTERFACE_(ISvcFileFormatPrivateData, IUnknown)
{
    // GetDataBlob():
    //
    // Attempts to locate a private/custom data blob associated with the underlying file format.  What this actually
    // represents varies by format.  For a minidump, this might represent a custom minidump stream.  For an ELF core
    // dump, this might represent a custom ELF note.
    //
    // How the data blob is identified also varies by format.
    //
    //     For Windows minidumps -- pBlobUniqueId = nullptr, pwszBlobName = nullptr, blobId = <stream id>
    //     For ELF core notes    -- pBlobUniqueId = nullptr, pwszBlobName = <note name>, blobId = <note id>
    //
    STDMETHOD(GetDataBlob)(
        THIS_
        _In_opt_ GUID *pBlobUniqueId,
        _In_opt_ PCWSTR pwszBlobName,
        _In_opt_ ULONG64 *pBlobId,
        _COM_Outptr_ ISvcFileFormatDataBlock **ppBlobData
        ) PURE;
};

//**************************************************************************
// Debug Source APIs:
//

#undef INTERFACE
#define INTERFACE ISvcDebugSourceView
DECLARE_INTERFACE_(ISvcDebugSourceView, IUnknown)
{
    //*************************************************
    // ISvcDebugSourceView:
    //

    // GetViewSource():
    //
    // Gets the the source of this view.
    //
    STDMETHOD(GetViewSource)(_COM_Outptr_ IDebugServiceManager** viewSource) PURE;

};

#undef INTERFACE
#define INTERFACE ISvcDebugSourceFile
DECLARE_INTERFACE_(ISvcDebugSourceFile, IUnknown)
{
    //*************************************************
    // ISvcDebugSourceFile:

    // Read():
    //
    // Attempts to read the number of bytes specified by the 'readSize' argument from the
    // file offset supplied by 'byteOffset' into the buffer supplied by the 'buffer' argument.
    // Note that a partial read is a successful state of this method.  In such a case,
    // the 'bytesRead' argument will be set to the number of bytes actually read and
    // S_FALSE will be returned.
    //
    STDMETHOD(Read)(_In_ ULONG64 byteOffset,
                    _Out_writes_to_(readSize, *bytesRead) PVOID buffer,
                    _In_ ULONG64 readSize,
                    _Out_ PULONG64 bytesRead
                    ) PURE;

    // Write():
    //
    // Attempts to write the number of bytes specified by the 'writeSize' argument into the
    // file (or a copy-on-write mapping on top of the file as determined by the implementation)
    // at the offset supplied by the 'byteOffset' argument.  The contents written are from
    // the buffer supplied by the 'buffer' argument.  Note that a partial write is a successful
    // state of this method.  In such a case, the 'bytesWritten' argument will be set to the
    // number of bytes actually written and S_FALSE will be returned.
    //
    STDMETHOD(Write)(_In_ ULONG64 byteOffset,
                     _In_reads_(writeSize) PVOID buffer,
                     _In_ ULONG64 writeSize,
                     _Out_ PULONG64 bytesWritten
                     ) PURE;

};

#undef INTERFACE
#define INTERFACE ISvcDebugSourceFileMapping
DECLARE_INTERFACE_(ISvcDebugSourceFileMapping, IUnknown)
{
    //*************************************************
    // ISvcDebugSourceFileMapping:

    // MapFile():
    //
    // Returns a complete memory mapping of the file.  Note that this entire interface can only be used
    // in process and is in no way required of a source file implementation.
    //
    STDMETHOD(MapFile)(_Out_ PVOID *mapAddress,
                       _Out_ PULONG64 mapSize) PURE;

    // GetHandle():
    //
    // Gets the original handle associated with this file mapping.
    //
    STDMETHOD(GetHandle)(_Out_ HANDLE *pHandle) PURE;
};

#undef INTERFACE
#define INTERFACE ISvcDebugSourceFileInformation
DECLARE_INTERFACE_(ISvcDebugSourceFileInformation, IUnknown)
{
    //*************************************************
    // ISvcDebugSourceFileInformation:

    // GetName():
    //
    // Gets the name of the underlying file.
    //
    STDMETHOD(GetName)(_Out_ BSTR *fileName) PURE;

    // GetPath():
    //
    // Gets the path of the underlying file.
    //
    STDMETHOD(GetPath)(_Out_ BSTR *filePath) PURE;

    // GetSize():
    //
    // Gets the size of the underlying file.
    //
    STDMETHOD(GetSize)(_Out_ ULONG64 *fileSize) PURE;
};

// ISvcDebugSourceWindowsKernelDebug:
//
// Provides extremely limited access to a KD connection.  Most components and plug-ins should
// not directly touch anything at this level.
//
#undef INTERFACE
#define INTERFACE ISvcDebugSourceWindowsKernelDebug
DECLARE_INTERFACE_(ISvcDebugSourceWindowsKernelDebug, IUnknown)
{
    //*************************************************
    // ISvcDebugSourceWindowsKernelDebug:
    //

    // GetActiveProcessor():
    //
    // Gets the active processor that the debugger is communicating with on the debuggee.
    //
    STDMETHOD(GetActiveProcessor)(
        THIS_
        _Out_ ULONG *pActiveProcessor
        ) PURE;

    // SetActiveProcessor():
    //
    // Sets the active processor that the debugger is communicating with on the debuggee.
    //
    STDMETHOD(SetActiveProcessor)(
        THIS_
        _In_ ULONG activeProcessor
        ) PURE;
};

//**************************************************************************
// Core Service APIs:
//

// SvcSymbolRegisterDescription:
//
// Describes a register.  @TODO: This definition should have a careful look for XMM/YMM and elsewhere
//
struct SvcSymbolRegisterDescription
{
    //
    // The register number in the architecture's canonical register numbering domain (this is the numbering
    // scheme that is returned from ISvcRegisterInformation).  Any value above 0xfffffff0 is interpreted as
    // "invalid" -- that the symbol provider was unable to provide the information.
    //
    ULONG Number;

    //
    // The size of the register in bytes.
    //
    ULONG Size;
};

// SvcSymbolLocationKind:
//
// Describes the type of location for a symbol.  This does *NOT* correspond to definitions in the data model.
//
enum SvcSymbolLocationKind
{
    SvcSymbolLocationNone,

    //
    // The location is complex and cannot be described by another SvcLocation* constant.  Within a particular
    // scope frame, the location may be evaluated -- but it cannot be described in more simple terms.
    //
    // Complex.Opaque         : part of the opaque data used to identify the complex location
    // NonRegisterData.Opaque : second part of the opaque data used to identify the complex location
    //
    // If both Opaque and NonRegisterData.Opaque are zero, the complex location cannot be simplified.  Otherwise,
    // ISvcSymbolSetComplexLocationResolution can be QI'd and methods there can *POTENTIALLY* simplify the
    // complex location if given additional information (such as the full register context)
    //
    SvcSymbolLocationComplex,

    // The location is an offset within the image (an RVA)
    //
    // Offset : [unsigned] the offset (RVA) within the containing image.
    // RegInfo: unused
    //
    // ISvcSymbol::GetOffset() will return Offset in this case.
    //
    SvcSymbolLocationImageOffset,

    // The location is a register.  Offset is unused.  RegInfo.Number
    //
    // Offset : unused
    // RegInfo: Number = <opaque number>, Size = register size, ContextOffset = offset into context record
    //
    // ISvcSymbol::GetOffset() will fail in this case.
    //
    SvcSymbolLocationRegister,

    // The location is register relative
    //
    // Offset : [signed] offset from register described in RegInfo
    // RegInfo: Number = <opaque number>, Size = register size, ContextOffset = offset into context record
    //
    // ISvcSymbol::GetOffset() will fail in this case.
    //
    SvcSymbolLocationRegisterRelative,

    // The location is relative to the start of a data structure
    //
    // Offset : [unsigned] offset from the start of the structure (this pointer)
    // RegInfo: unused
    //
    // ISvcSymbol::GetOffset() will return the structure offset in this case.
    //
    SvcSymbolLocationStructureRelative,

    // The location is a virtual address computed by means that cannot be described in
    // a simple symbol location (this might be a linearlization of SvcLocationComplex)
    //
    // Offset : [unsigned] the virtual address
    // RegInfo: unused
    //
    // ISvcSymbol::GetOffset() will fail in this case.
    //
    SvcSymbolLocationVirtualAddress,

    // The symbol has no "location"; rather, it has a constant value.
    //
    // ISvcSymbol::GetOffset() will fail in this case.
    //
    SvcSymbolLocationConstantValue,

    // The location is offset from an indirect read of a register relative location.  In essence, the
    // location is [@reg + PreOffset] + PostOffset
    //
    // PreOffset : [signed] offset from the register described in RegInfo where the indirect read occurs
    // PostOffset: [signed] offset from the indirectly read value
    // RegInfo   : Number = <opaque number>, Size = register size, ContextOffset = offset into context record
    //
    SvcSymbolLocationRegisterRelativeIndirectOffset,

    // The location is relative to the start of a data structure but is a bitfield.
    //
    // BitField.Offset        : [unsigned] offset from the start of the structure (this pointer)
    // BitField.FieldPosition : [unsigned] the bit position within the type
    // BitField.FieldSize     : [unsigned] the number of bits in the field
    // BitField.Reserved      : Reserved.  Must be zero.
    //
    SvcSymbolLocationStructureRelativeBitField,

    // The location is an offset from the structure.  The offset is determined by an entry in a table.
    //
    // TableOffsets.TableOffset :  [signed] offset from the start of the structure (this pointer) where
    //                             the table is located
    // TableOffsets.TableSlot   :  [signed] slot in the table where the offset is located
    // TableOffsets.SlotSize    :  [signed] ABS(SlotSize) == size in bytes of the offset entry in the table
    //                                      <0: offsets are signed, >0: offsets are unsigned
    //
    // This form of description is often used to describe the offset of a virtual base class from its parent
    // class in lieu of an SvcSymbolLocationComplex descriptor.
    //
    SvcSymbolLocationStructureRelativeTableOffset,

    // The location is an offset within the TLS block
    //
    // Offset : [unsigned] the offset (RVA) within the TLS block.
    // RegInfo: unused
    //
    // ISvcSymbol::GetOffset() will return Offset in this case.
    //
    SvcSymbolLocationTLSOffset,

    // The symbol is described by multiple locations. To enumerate them, the symbol should implement ISvcSymbolMultipleLocations.
    //
    // Offset : unused
    // RegInfo: unused
    //
    SvcSymbolLocationMultipleLocations
};

// SvcSymbolLocation:
//
// Describes the location of a symbol in abstract terms.  This does *NOT* correspond to definitions in
// the data model.
//
struct SvcSymbolLocation
{
    SvcSymbolLocationKind Kind;             // Determines how the remainder of the fields are interpreted
    union
    {
        ULONG64 Offset;                     // This may be interpreted as a signed or unsigned offset
        struct
        {
            ULONG Pre;                      // This may be interpreted as a signed or unsigned offset
            ULONG Post;                     // This may be interpreted as a signed or unsigned offset
        } Offsets;
        struct
        {
            LONG TableOffset;               // Offset from structure where table pointer is located
            LONG TableSlot: 24;             // Slot (signed) in the table where offset is located
            LONG SlotSize: 8;               // ABS(SlotSize) == size in bytes of the offset
                                            //     <0: slot is signed, >0: slot is unsigned
        } TableOffsets;
        struct
        {
            ULONG Offset;                   // The offset
            ULONG FieldPosition:12;         // The bitfield position
            ULONG FieldSize:12;             // The bitfield size
            ULONG Reserved:8;               // Reserved for future use.  Currently must be zeroed.
        } BitField;
        struct
        {
            ULONG64 Opaque;                 // 64-bits of opaque data associated with the complex location
        } Complex;
    };
    union
    {
        SvcSymbolRegisterDescription RegInfo;   // Information about the register that the location utilizes
        struct
        {
            ULONG64 Opaque;                     // 64-bits of opaque data which can be used in lieu of RegInfo
        } NonRegisterData;
    };
};

//
// For architectures which allow for multiple page directories, (e.g.: ARM64 TTBR0/TTBR1), this defines
// which page directory a given query refers to.
//
enum DirectoryBaseKind
{
    // DirectoryBaseDefault:
    //
    // The "default" page directory for the type of target.  If the target is generally debugging a hardware
    // oriented view (e.g.: kernel, JTAG, etc...), this would refer to a kernel page directory; otherwise,
    // it would refer to the user page directory.
    //
    DirectoryBaseDefault,

    // DirectoryBaseUser:
    //
    // Refers to the user page directory.
    //
    DirectoryBaseUser,

    // DirectoryBaseKernel:
    //
    // refers to the kernel page directory.
    //
    DirectoryBaseKernel
};

enum AddressContextKind
{
    //
    // This address context refers to the address context of a particular *execution unit* which
    // can be queried for the directory base via a hardware register (e.g.: CR3 on AMD64)
    //
    // Such context must QI for ISvcExecutionUnitHardware successfully.
    //
    AddressContextHardware,

    //
    // This address context refers to a process.  The OS service may be able to query for the directory
    // base or may not and this may only be valid to query virtual memory against.
    //
    // Such context must QI for ISvcProcess successfully.
    //
    AddressContextProcess,

    //
    // This address context refers to some I/O space.
    //
    // Such context must QI for ISvcIoSpace
    //
    AddressContextIoSpace
};

//
// ISvcAddressContext:
//
// This interface represents an address context.  From many user's perspective, this is a largely opaque
// construct which is passed from place to place.
//
// An object which implements this interface can be several different types of address context (as indicated
// by AddressContextKind above).  The object will either QI for ISvcProcess of ISvcAddressContextHardware/
// ISvcExecutionUnitHardware.
//
#undef INTERFACE
#define INTERFACE ISvcAddressContext
DECLARE_INTERFACE_(ISvcAddressContext, IUnknown)
{
    //*************************************************
    // ISvcAddressContext
    //

    // GetAddressContextKind():
    //
    // Gets the kind of address context.
    //
    STDMETHOD_(AddressContextKind, GetAddressContextKind)(
        THIS
        ) PURE;
};

//
// ISvcAddressContextHardware:
//
#undef INTERFACE
#define INTERFACE ISvcAddressContextHardware
DECLARE_INTERFACE_(ISvcAddressContextHardware, IUnknown)
{
    //*************************************************
    // ISvcAddressContextHardware
    //

    // GetDirectoryBase():
    //
    // Gets the directory base for this address context (represented as hardware -- e.g.: a processor)
    //
    // e.g.: For a AMD64 processor, this interface would return the CR3 value.
    //
    STDMETHOD(GetDirectoryBase)(
        THIS_
        _In_ DirectoryBaseKind dirKind,
        _Out_ ULONG64 *directoryBase
        ) PURE;

    // GetPagingLevels():
    //
    // Gets the number of paging levels mode that the hardware is utilizing
    //
    STDMETHOD(GetPagingLevels)(
        THIS_
        _Out_ ULONG *pagingLevels
        ) PURE;
};

//
// ISvcProcess:
//
// Defines a means of accessing or identifying aspects of a process.  Note that this
// represents a process whether that is a user mode process or a kernel mode process.
//
// This interface is intended to be a minimal core of information about a process.
// Further ISvcProcess* interfaces can be added to provide further functionality.
//
// @NOTE: For now, this is likely to be very tied to ProcessInfo (user mode) or the implicit
//        process data (kernel mode).
//
#undef INTERFACE
#define INTERFACE ISvcProcess
DECLARE_INTERFACE_(ISvcProcess, IUnknown)
{
    //*************************************************
    // ISvcProcess:
    //

    // GetKey():
    //
    // Gets the unique "per-target" process key.  The interpretation of this key is dependent upon
    // the service which provides this interface.  For Windows Kernel, this may be the address of
    // an EPROCESS in the target.  For Windows User, this may be the PID.
    //
    STDMETHOD(GetKey)(
        THIS_
        _Out_ PULONG64 processKey
        ) PURE;

    // GetId():
    //
    // Gets the process' ID as defined by the underlying platform.  This may or may not be the same
    // value as returned from GetKey.
    //
    STDMETHOD(GetId)(
        THIS_
        _Out_ PULONG64 processId
        ) PURE;

};

//
// Interface  : ISvcProcessBasicInformation
//
// Defines basic information about a particular process.  This interface is optional to implement by
// any implementation of ISvcProcess.  Not every provider implements this.
//
#undef INTERFACE
#define INTERFACE ISvcProcessBasicInformation
DECLARE_INTERFACE_(ISvcProcessBasicInformation, IUnknown)
{
    //*************************************************
    // ISvcProcessBasicInformation:
    //

    // GetName():
    //
    // Gets the name of the process.  This may or may not be the same as the name of the main
    // executable (or may be truncated) depending on the underlying platform.
    //
    // An implementation for a process which does not have a name will return E_NOT_SET.
    //
    STDMETHOD(GetName)(
        THIS_
        _Out_ BSTR *processName
        ) PURE;

    // GetArguments():
    //
    // Gets the start arguments of the process.
    //
    // An implementation for a process which does not have available arguments will return E_NOT_SET.
    //
    STDMETHOD(GetArguments)(
        THIS_
        _Out_ BSTR *processArguments
        ) PURE;

    // GetParentId():
    //
    // Gets the PID of the parent process.
    //
    // An implementation for a process which does not have an available parent ID will return E_NOT_SET.
    //
    STDMETHOD(GetParentId)(
        THIS_
        _Out_ ULONG64 *parentId
        ) PURE;
};

//
// Interface  : ISvcSecurityConfiguration
//
// Defines "security configuration" about various objects.
//
#undef INTERFACE
#define INTERFACE ISvcSecurityConfiguration
DECLARE_INTERFACE_(ISvcSecurityConfiguration, IUnknown)
{
    //*************************************************
    // ISvcSecurityConfiguration:
    //

    // GetPointerAuthenticationMask():
    //
    // Only relevant when running on ARM64 (AArch64) targets, this allows access to the pointer-authentication (PAC)
    // configuration for the process.
    //
    // On non-ARM64 targets, this should return E_NOTIMPL if the service/interface is implemented.
    //
    // For user mode targets, 'pProcess' should always point to the process for which to query the PAC mask.  For
    // kernel mode targets, 'pProcess' can point to a particular process for which to query the *USER MODE* PAC mask.
    // If 'pProcess' is nullptr on a kernel mode target, it indicates a query for the *KERNEL MODE* PAC mask.
    //
    STDMETHOD(GetPointerAuthenticationMask)(
        THIS_
        _In_opt_ ISvcProcess *pProcess,
        _In_ ULONG64 ptr,
        _Out_ ULONG64 *pDataMask,
        _Out_ ULONG64 *pInstructionMask
        ) PURE;
};

//
// Interface  : ISvcSecurityConfiguration2
//
// Defines "security configuration" about various objects.
//
#undef INTERFACE
#define INTERFACE ISvcSecurityConfiguration
DECLARE_INTERFACE_(ISvcSecurityConfiguration2, ISvcSecurityConfiguration)
{
    //*************************************************
    // ISvcSecurityConfiguration2:
    //

    // GetPointerTagMask():
    //
    // Only relevant when running on an architecture that supports some form of pointer tagging, this allows
    // access to the pointer tag mask.
    //
    // On architectures which do not support taagging, this should return E_NOTIMPL if the service/interface is
    // implemented.
    //
    // For user mode targets, 'pProcess' should always point to the process for which to query the tag mask.  For
    // kernel mode targets, 'pProcess' can point to a particular process for which to query the *USER MODE* tag mask.
    // If 'pProcess' is nullptr on a kernel mode target, it indicates a query for the *KERNEL MODE* tag mask.
    //
    STDMETHOD(GetPointerTagMask)(
        THIS_
        _In_opt_ ISvcProcess *pProcess,
        _In_ ULONG64 ptr,
        _Out_ ULONG64 *pTagMask
        ) PURE;
};

//
// SvcContextFlags:
//
// Flags that define types of registers (including categories that a given context might contain)
//
enum SvcContextFlags
{
    //*************************************************
    // Categorization Flags (lower 16-bits):
    //

    SvcContextCategorizationMask = 0x0000ffff,

    // Indicates integer & general purpose registers
    SvcContextIntegerGPR = 0x00000001,

    // Floating point registers
    SvcContextFloatingPoint = 0x00000002,

    // Extended (AVX/SSE)
    SvcContextExtended = 0x00000004,

    // Control registers
    SvcContextControl = 0x00000008,

    // Debug registers
    SvcContextDebug = 0x00000010,

    // Special context
    SvcContextSpecial = 0x00000020,

    //*************************************************
    // Information Flags (upper 16-bits):
    //

    SvcContextInformationMask = 0xffff0000,

    // Register is a part of another register (e.g.: eax of rax, ah/al of ax, etc...)
    SvcContextSubRegister = 0x00010000,

    // Register is a flags register.  This may indicate that the entire register is a flags register
    // (every bit) or that part of the register is a flags register (e.g.: some bits are control flags
    // and others are data).  If this flag is set, queries about flags can be made via ISvcRegisterInformation.
    SvcContextFlagsRegister = 0x00020000,

};

//
// Interface  : ISvcRegisterFlagInformation:
//
// The ISvcRegisterFlagInformation interface describes details about a particular control/status flag within
// a register (e.g.: the zero flag, the carry flag, etc...)
//
#undef INTERFACE
#define INTERFACE ISvcRegisterFlagInformation
DECLARE_INTERFACE_(ISvcRegisterFlagInformation, IUnknown)
{
    //*************************************************
    // ISvcRegisterFlagInformation
    //

    // GetName():
    //
    // Gets the name of the flag (e.g.: carry, overflow, etc...)
    //
    STDMETHOD(GetName)(
        THIS_
        _Out_ BSTR *flagName
        ) PURE;

    // GetAbbreviation():
    //
    // Gets a short abbreviation of the flag (e.g.: cf, zf, of, etc...)
    //
    STDMETHOD(GetAbbreviation)(
        THIS_
        _Out_ BSTR *abbrevName
        ) PURE;

    // GetPosition():
    //
    // Gets the bit position of this flag within its containing register.
    //
    STDMETHOD_(ULONG, GetPosition)(
        THIS
        ) PURE;

    // GetSize():
    //
    // Gets the size of the flag information.  Typically, this would be one bit.  If this is not one,
    // the flag is assumed to go from [ GetPosition(lsb), 'GetPosition + GetSize'(msb) )
    //
    STDMETHOD_(ULONG, GetSize)(
        THIS
        ) PURE;
};

//
// Interface  : ISvcRegisterFlagsEnumerator
//
// Provided By:
//
// The ISvcRegisterFlagsEnumerator interface enumerates the flags bits of a flags register.
//
#undef INTERFACE
#define INTERFACE ISvcRegisterFlagsEnumerator
DECLARE_INTERFACE_(ISvcRegisterFlagsEnumerator, IUnknown)
{
    //*************************************************
    // ISvcRegisterFlagsEnumerator:
    //

    // GetNext():
    //
    // Gets the next flag in the register.  Returns E_BOUNDS if there are no more.
    //
    STDMETHOD(GetNext)(
        THIS_
        _COM_Outptr_ ISvcRegisterFlagInformation **flagInfo
        ) PURE;

    // Reset():
    //
    // Resets the enumerator.
    //
    STDMETHOD(Reset)(
        THIS
        ) PURE;
};

//
// Interface  : ISvcRegisterInformation
//
// Provided By:
//
// The ISvcRegisterInformation interface describes details about a particular machine register.
//
#undef INTERFACE
#define INTERFACE ISvcRegisterInformation
DECLARE_INTERFACE_(ISvcRegisterInformation, IUnknown)
{
    //*************************************************
    // ISvcRegisterInformation:
    //

    // GetName():
    //
    // Gets the name of the register.
    //
    STDMETHOD(GetName)(
        THIS_
        _Out_ BSTR *registerName
        ) PURE;

    // GetId():
    //
    // Gets the ID of this register.  This is the canonical register number for the architecture.  If the architecture
    // is a custom architecture, this ID can be custom.  The *default behavior* of a symbol provider without explicit
    // knowledge of a given architecture is to directly map register numbers in debug information to the register ID
    // returned here.
    //
    // The DWARF symbol provider, for instance, will directly map a register number N in DWARF debug information
    // to the register in the context whose GetId returns N unless it has explicit knowledge about the architecture
    // and/or ABI being targeted.
    //
    // Providing a custom mapping to particular formats requres implementing interfaces beyond ISvcMachineArchitecture.
    // It requires supporting a DEBUG_SERVICE_REGISTERTRANSLATION conditional service whose primary condition is
    // the architecture GUID and whose secondary condition is a GUID describing the debug format.
    //
    STDMETHOD_(ULONG, GetId)(
        THIS
        ) PURE;

    // GetFlags():
    //
    // Gets the set of flags describing the category, etc... of this register.
    //
    STDMETHOD_(SvcContextFlags, GetFlags)(
        THIS
        ) PURE;

    // GetSize():
    //
    // Gets the size of this register.
    //
    STDMETHOD_(ULONG, GetSize)(
        THIS
        ) PURE;

    // GetSubRegisterInformation();
    //
    // Gets the sub-register mapping for this register.  This will fail with E_NOT_SET if the register is NOT part
    // of another register; otherwise, the parent register and the least/most significant bits of the mapping
    // are returned.  For instance, 'ah' would return a parent id of 'ax' and bits 0-7.  Likewise, 'ax' would
    // return 'eax' as a parent id and bits 0-15.
    //
    STDMETHOD(GetSubRegisterInformation)(
        THIS_
        _Out_ ULONG *parentRegisterId,
        _Out_ ULONG *lsbOfMapping,
        _Out_ ULONG *msbOfMapping
        ) PURE;

    // EnumerateRegisterFlags():
    //
    // Enumerates all of the control flags within the register.  This will fail with E_NOT_SET if the register is
    // NOT a flags register.
    //
    STDMETHOD(EnumerateRegisterFlags)(
        THIS_
        _COM_Outptr_ ISvcRegisterFlagsEnumerator **flagsEnum
        ) PURE;

    // GetRegisterFlagInformation():
    //
    // Gets the flag information for a particular bit of a flags register.  This will fail with E_NOT_SET if the
    // register is NOT a flags register.  This will fail with E_BOUNDS if the bit position within the register
    // is not a valid flag bit.
    //
    STDMETHOD(GetRegisterFlagInformation)(
        THIS_
        _In_ ULONG position,
        _COM_Outptr_ ISvcRegisterFlagInformation **flagInfo
        ) PURE;
};

#undef INTERFACE
#define INTERFACE ISvcRegisterEnumerator
DECLARE_INTERFACE_(ISvcRegisterEnumerator, IUnknown)
{
    //*************************************************
    // ISvcRegisterEnumerator:
    //

    // GetNext():
    //
    // Gets the next register for the architecture.  Returns E_BOUNDS if there are no more.
    //
    STDMETHOD(GetNext)(
        THIS_
        _COM_Outptr_ ISvcRegisterInformation **registerInfo
        ) PURE;

    // Reset():
    //
    // Resets the enumerator.
    //
    STDMETHOD(Reset)(
        THIS
        ) PURE;
};

// SvcAbstractRegister:
//
// Defines common "abstractions" for a few select processor registers.  Not every processor need actually
// have a mapping for such.  For instance, the return address register is 'LR' in ARM architectures and does
// not exist in X86 architectures.
//
enum SvcAbstractRegister
{
    // An abstract way to refer to the instruction pointer of any architecture
    SvcAbstractRegisterInstructionPointer,

    // An abstract way to refer to the stack pointer of any architecture
    SvcAbstractRegisterStackPointer,

    // An abstract way to refer to the frame pointer of any architecture
    SvcAbstractRegisterFramePointer,

    // An abstract way to refer to the return address register of any architecture
    SvcAbstractRegisterReturnAddress
};

//
// Interface  : ISvcMachineArchitecture
//
// Provided By: DEBUG_SERVICE_ARCHINFO
//
// The ISvcMachineArchitecture interface provides access to architecture specific capabilities
// that are general information about a given architecture (bitness, pointer sizes, disassembly,
// page sizes, etc...).
//
// The service which provides this interface must be in every target composition stack regardless
// of whether it is debugging user mode processes, an OS kernel, or a hardware connection (e.g.: JTAG)
//
#undef INTERFACE
#define INTERFACE ISvcMachineArchitecture
DECLARE_INTERFACE_(ISvcMachineArchitecture, IUnknown)
{
    //*************************************************
    // General architectural attributes:
    //

    // GetArchitecture():
    //
    // Gets an IMAGE_FILE_MACHINE_* constant definining the architecture described by
    // this interface.  Note that some machines cannot be described by an IMAGE_FILE_MACHINE constant and would
    // return IMAGE_CUSTOM from this.  With such a return value, the architecture must be understood via
    // the architecture GUID returned from GetArchitectureGuid.
    //
    STDMETHOD_(ULONG, GetArchitecture)(
        THIS
        ) PURE;

    // GetArchitectureGuid():
    //
    // Returns the architecture GUID defining the architecture.  This is either a
    // DEBUG_ARCHDEF_* standard GUID or is a GUID defining a custom architecture.  The GUID returned here *MUST*
    // also be a component GUID for the architecture specific components.
    //
    STDMETHOD(GetArchitectureGuid)(
        THIS_
        _Out_ GUID* architecture
        ) PURE;

    // GetBitness():
    //
    // Gets the bitness of the architecture (32/64/etc...).
    //
    STDMETHOD_(ULONG64, GetBitness)(
        THIS
        ) PURE;

    // GetPageSize():
    //
    // Gets the standard page size of the machine.
    //
    STDMETHOD_(ULONG64, GetPageSize)(
        THIS
        ) PURE;

    // GetPageShift():
    //
    // Gets the standard bit shift to get the page number from a given
    // physical offset.
    //
    STDMETHOD_(ULONG64, GetPageShift)(
        THIS
        ) PURE;

    //*************************************************
    // Register Abstractions for this architecture.
    //

    // EnumerateRegisters():
    //
    // Returns an enumerator which enumerates all registers for this architecture that are covered by
    // the inpassed set of flags.
    //
    STDMETHOD(EnumerateRegisters)(
        THIS_
        _In_ SvcContextFlags flags,
        _COM_Outptr_ ISvcRegisterEnumerator **registerEnumerator
        ) PURE;

    // GetRegisterInformation():
    //
    // Gets the register information for a particular register by its canonical id.
    //
    STDMETHOD(GetRegisterInformation)(
        THIS_
        _In_ ULONG registerId,
        _COM_Outptr_ ISvcRegisterInformation **registerInformation
        ) PURE;

    // GetIdForAbstractRegister():
    //
    // Gets the canonical register number for a given abstract register.  If the architecture does not have
    // such register (e.g.: the return address register is queried for X86), E_BOUNDS is returned.
    //
    STDMETHOD(GetIdForAbstractRegister)(
        THIS_
        _In_ SvcAbstractRegister abstractId,
        _Out_ ULONG *canonicalId
        ) PURE;

    // CreateRegisterContext():
    //
    // Creates an empty register context.  While the canonical ISvcMachineArchitecture implementation is required
    // to implement a "standard register record" that supports get/set of all registers in the architecture, there
    // is **ABSOLUTELY NO REQUIREMENT** that this is the record returned by any call to get register state.  Plug-ins
    // are free to implement ISvcRegisterContext on their own.
    //
    STDMETHOD(CreateRegisterContext)(
        THIS_
        _COM_Outptr_ ISvcRegisterContext **ppArchRegisterContext
        ) PURE;

    //*************************************************
    // Other Core Abstractions:
    //

    // GetDirectoryBase():
    //
    // From special registers, get the directory base (zero extended to 64-bit)
    //
    STDMETHOD_(ULONG64, GetDirectoryBase)(
        THIS_
        _In_ DirectoryBaseKind dirKind,
        _In_ ISvcRegisterContext *pSpecialContext
        ) PURE;

    // GetPagingLevels():
    //
    // From special registers, get the number of paging levels the hardware is configured to utilize.
    //
    STDMETHOD_(ULONG, GetPagingLevels)(
        THIS_
        _In_ ISvcRegisterContext *pSpecialContext
        ) PURE;

};

enum SvcSegmentSelectorSource
{
    // Unknown
    SegmentSelectorUnknown,

    // X86/AMD64 (cs)
    SegmentSelectorCode,

    // X86/AMD64 (ds)
    SegmentSelectorData,

    // X86/AMD64 (ss)
    SegmentSelectorStack,

    // X86/AMD64 (es)
    SegmentSelectorExtra1,

    // X86/AMD64 (fs)
    SegmentSelectorExtra2,

    // X86/AMD64 (gs)
    SegmentSelectorExtra3,
};

enum SvcSegmentFlags
{
    // Indicates that the segment is a code segment.
    SvcSegmentCode = 0x00000001,

    // Indicate the segment is readable
    SvcSegmentRead = 0x00000002,

    // Indicates the segment is writeable
    SvcSegmentWrite = 0x00000004,

    // Indicates the segment is executable
    SvcSegmentExecute = 0x00000008,

    // Indicate sthe segment is only "supervisor" accessible (e.g.: ring 0)
    SvcSegmentSupervisor = 0x00000010,

    //
    // Any flags above 0x8000 are reserved for architecture specific meanings.
    //
};

// SvcSegmentDescription:
//
// A description of a particular segment.
//
struct SvcSegmentDescription
{
    ULONG SizeOfDescription;            // Defines the size of this data structure.
    ULONG Flags;                        // Flags (as per SvcSegmentFlags -- undefined bits set to zero)
    ULONG64 SegmentBase;                // Linear address of the base of the segment
    ULONG64 SegmentSize;                // Size/limit of the segment in bytes
    ULONG SegmentBitness;               // 16/32/64 -- indicates the bitness of the segment
};

//
// Interface  : ISvcSegmentTranslation
//
// Provided By:
//
// The ISvcSegmentationContext interface is (optionally) provided by execution contexts in order to translate
// segment selectors into flat addresses.
//
#undef INTERFACE
#define INTERFACE ISvcSegmentTranslation
DECLARE_INTERFACE_(ISvcSegmentTranslation, IUnknown)
{
    //*************************************************
    // ISvcSegmentTranslation:
    //

    // TranslateSelector():
    //
    // Translates a selector into a given linear address description.  The caller must fill in
    // the size of the descriptor request in SizeOfDescription.  The implementation must set the resulting
    // descirption validity.
    //
    STDMETHOD(TranslateSelector)(
        THIS_
        _In_ SvcSegmentSelectorSource segmentSelectorSource,
        _In_ ULONG64 selector,
        _Inout_ SvcSegmentDescription *pDescription
        ) PURE;
};

//
// Interface  : ISvcBasicDisassembly
//
// Provided By: DEBUG_SERVICE_DISASSEMBLER
//
// The ISvcBasicDisassembly interface is required on every disassembler.  It provides basic textual disassembly
// from memory or a provided buffer.  More complicated disassembly interfaces may be provided to allow
// introspection of instruction types, operands, registers, etc...
//
#undef INTERFACE
#define INTERFACE ISvcBasicDisassembly
DECLARE_INTERFACE_(ISvcBasicDisassembly, IUnknown)
{
    //*************************************************
    // ISvcBasicDisassembly:
    //

    // GetInstructionDisassemblyText():
    //
    // For an instruction/bundle at 'address' in a given address context (and with a given instructionNumber
    // within the bundle), perform a disassembly and return a textual representation of the machine instruction.
    //
    // If the given instruction/bundle address is in the middle of an instruction/bundle and the diassembler is capable
    // of correcting for that, the actual instruction/bundle address may be returned in 'startAddress'.
    //
    // For non-bundled architectures:
    //     - On input, instructionNumber should always be zero
    //     - On output, byteCount is the size in bytes of the instruction
    //     - On output, instructionCount is one
    //
    // For bundled architectures:
    //     - On input, instructionNumber should be within (0, instructionsInBundle].  The initial call should
    //       always provide 0 for the instructionNumber.
    //     - On output, byteCount is the size in bytes of the bundle
    //     - On output, instructionCount is the number of instructions within the bundle
    //
    STDMETHOD(GetInstructionDisassemblyText)(
        THIS_
        _In_ ISvcAddressContext *addressContext,
        _In_ ULONG64 address,
        _In_ ULONG64 instructionNumber,
        _Out_ BSTR *disassembledInstruction,
        _Out_ ULONG64 *byteCount,
        _Out_opt_ ULONG64 *instructionCount,
        _Out_opt_ ULONG64 *startAddress
        ) PURE;

    // GetInstructionDisassemblyTextForBuffer():
    //
    // For an instruction/bundle within a memory buffer, perform a disassembly and return a textual representation
    // of the machine instruction.  Otherwise, this operates as GetInstructionDisassemblyText with a few
    // caveats:
    //
    //     - An implementation of ISvcBasicDisassembly may legally E_NOTIMPL this method.
    //     - Most frequently, 'addressContext and address' are nullptr/0.  In such cases, the disassembler may
    //       not symbolicate the instruction.
    //     - If 'addressContext/address' are not nullptr, the disassembler may utilize the image/symbol provider
    //       to symbolicate the instruction.
    //     - Even if 'addressContext/address' are not nullptr, the disassembler must read the instruction/bundle
    //       bytes from the given buffer and never utilize a memory service to read (or delegate to
    //       the GetInstructionDisassemblyText method).
    //
    STDMETHOD(GetInstructionDisassemblyTextForBuffer)(
        THIS_
        _In_reads_(bufferSize) PVOID buffer,
        _In_ ULONG64 bufferSize,
        _In_opt_ ISvcAddressContext *addressContext,
        _In_ ULONG64 address,
        _In_ ULONG64 instructionNumber,
        _Out_ BSTR *disassembledInstruction,
        _Out_ ULONG64 *byteCount,
        _Out_opt_ ULONG64 *instructionCount,
        _Out_opt_ ULONG64 *startAddress
        ) PURE;
};

// RegisterInformationQuery:
//
// An array of these structures defines a query for multiple registers in a single method call to a context.
//
struct RegisterInformationQuery
{
    ULONG CanonicalId;              // The canonical ID of the register
    ULONG DataOffset;               // The offset of the register data to get/set
    ULONG DataSize;                 // The size of the buffer for this register value
};

//
// Interface  : ISvcRegisterContext
//
// Provided By:
//
// The ISvcRegisterContext unit describes a set of registers and their values.  A register context for
// a standard supported platform can optionally support ISvcClassicRegisterContext where the given register
// context can be represented by a platform specific Windows CONTEXT structure.  In addition, a register
// context which holds a set of "special context" for a standard supported platform can optionally support
// ISvcClassicSpecialContext where that part of the register context can be presented by a platform
// specific Windows KSPECIAL_REGISTERS structure.
//
#undef INTERFACE
#define INTERFACE ISvcRegisterContext
DECLARE_INTERFACE_(ISvcRegisterContext, IUnknown)
{
    //*************************************************
    // ISvcRegisterContext:
    //

    // GetArchitectureGuid():
    //
    // Returns the architecture of the registers that this register context holds.  This is either a
    // DEBUG_ARCHDEF_* standard GUID or is a GUID defining a custom architecture.
    //
    STDMETHOD(GetArchitectureGuid)(
        THIS_
        _Out_ GUID* architecture
        ) PURE;

    // GetRegisterValue()
    //
    // Gets the value of a register as given by its canonical register number.  The following error codes
    // carry special meaning:
    //
    //     E_INSUFFICIENT_BUFFER: The in-passed buffer is not large enough to hold the register value.
    //                            The actual size of the register is returned in registerSize.
    //
    //     E_NOT_SET            : The register context does not contain a value for the given register and such
    //                            cannot be retrieved.
    //
    STDMETHOD(GetRegisterValue)(
        THIS_
        _In_ ULONG registerId,
        _Out_writes_(bufferSize) void *buffer,
        _In_ ULONG bufferSize,
        _Out_ ULONG *registerSize
        ) PURE;

    // GetRegisterValue64():
    //
    // Similar to GetRegisterValue, this is a convenience method for integer/GPR registers of 64-bits or less
    // where the value of the register will be zero extended to 64-bits and returned.
    //
    STDMETHOD(GetRegisterValue64)(
        THIS_
        _In_ ULONG registerId,
        _Out_ ULONG64 *pRegisterValue
        ) PURE;

    // GetAbstractRegisterValue64():
    //
    // Behaves as GetRegisterValue64 but on an abstract ID.
    //
    STDMETHOD(GetAbstractRegisterValue64)(
        THIS_
        _In_ SvcAbstractRegister abstractId,
        _Out_ ULONG64 *pRegisterValue
        ) PURE;

    // SetRegisterValue():
    //
    // Sets the value of a register as given by its canonical register number.  The following error codes
    // carry special meaning:
    //
    //     E_INSUFFICIENT_BUFFER: The in-passed buffer is not large enough for the register's value.
    //                            The required size of the register value is returned in registerSize.
    //
    //     E_NOTIMPL            : The context does not allow the setting of this register value.
    //
    STDMETHOD(SetRegisterValue)(
        THIS_
        _In_ ULONG registerId,
        _In_reads_(bufferSize) void *buffer,
        _In_ ULONG bufferSize,
        _Out_ ULONG *registerSize
        ) PURE;

    // SetRegisterValue64():
    //
    // Similar to SetRegisterValue, this is a convenience method for integer/GPR registers of 64-bits or less
    // where the value of the register will be set from a (presumed) zero extended 64-bit value.
    //
    STDMETHOD(SetRegisterValue64)(
        THIS_
        _In_ ULONG registerId,
        _In_ ULONG64 registerValue
        ) PURE;

    // SetAbstractRegisterValue64():
    //
    // Behaves as SetRegisterValue64 but on an abstract ID.
    //
    STDMETHOD(SetAbstractRegisterValue64)(
        THIS_
        _In_ SvcAbstractRegister abstractId,
        _In_ ULONG64 registerValue
        ) PURE;

    // GetRegisterValues():
    //
    // Gets the value of multiple registers in a single call.  Registers are given by a structure
    // defining their canonical register number and the position the value should be placed within an output
    // structure.
    //
    STDMETHOD(GetRegisterValues)(
        THIS_
        _In_ ULONG registerCount,
        _In_reads_(registerCount) RegisterInformationQuery *pRegisters,
        _In_ ULONG bufferSize,
        _Out_writes_(bufferSize) void *buffer,
        _Out_writes_opt_(registerCount) ULONG *registerSizes
        ) PURE;

    // SetRegisterValues():
    //
    // Sets the value of multiple registers in a single call.  Registers are given by a structure
    // defining their canonical register number and the position the value should be retrieved from within
    // an input structure.
    //
    STDMETHOD(SetRegisterValues)(
        THIS_
        _In_ ULONG registerCount,
        _In_reads_(registerCount) RegisterInformationQuery *pRegisters,
        _In_ ULONG bufferSize,
        _In_reads_(bufferSize) void *buffer,
        _Out_writes_opt_(registerCount) ULONG *registerSizes
        ) PURE;

    // SetToContext():
    //
    // Copies the values of one register context into this register context.
    //
    STDMETHOD(SetToContext)(
        THIS_
        _In_ ISvcRegisterContext *registerContext
        ) PURE;

    // Duplicate():
    //
    // Creates a duplicate copy of the register context.  Changes made to the duplicate copy do not affect
    // the original.
    //
    STDMETHOD(Duplicate)(
        THIS_
        _COM_Outptr_ ISvcRegisterContext **duplicateContext
        ) PURE;
};

//
// Interface  : ISvcClassicRegisterContext
//
// The ISvcClassicRegisterContext interface is provided by register contexts whose backing store is a platform
// specific CONTEXT structure.
//
// No register context is required to support this interface.  Any register context which supports this interface
// *IS REQUIRED* to support ISvcRegisterContext.
//
// Note that one can achieve the same thing by getting the DEBUG_SERVICE_REGISTERCONTEXTTRANSLATION for the
// Windows platform domain.  This is just faster for contexts that support such.
//
#undef INTERFACE
#define INTERFACE ISvcClassicRegisterContext
DECLARE_INTERFACE_(ISvcClassicRegisterContext, IUnknown)
{
    //*************************************************
    // ISvcClassicRegisterContext:
    //

    // GetContextSize():
    //
    // Gets the size of the context structure (CONTEXT for the given architecture that this ISvcClassicRegisterContext
    // represents).
    //
    STDMETHOD_(ULONG64, GetContextSize)(
        THIS
        ) PURE;

    // GetContext():
    //
    // Fills in a Win32 CONTEXT structure for the given machine architecture.
    //
    STDMETHOD(GetContext)(
        THIS_
        _In_ ULONG64 bufferSize,
        _Out_writes_(bufferSize) void *contextBuffer,
        _Out_ ULONG64 *contextSize
        ) PURE;

    // SetContext():
    //
    // Changes the values in this register context to the ones given by the incoming Win32 CONTEXT structure.
    //
    STDMETHOD(SetContext)(
        THIS_
        _In_ ULONG64 bufferSize,
        _In_reads_(bufferSize) void *contextBuffer
        ) PURE;

};

//
// Interface  : ISvcClassicSpecialContext
//
// The ISvcClassicSpecialContext interface is provided by register contexts have a portion of their backing store
// given by a platform specific KSPECIAL_REGISTERS structure.
//
// No register context is required to support this interface.  Any register context which supports this interface
// *IS REQUIRED* to support ISvcRegisterContext.
//
#undef INTERFACE
#define INTERFACE ISvcClassicSpecialContext
DECLARE_INTERFACE_(ISvcClassicSpecialContext, IUnknown)
{
    //*************************************************
    // ISvcClassicSpecialContext:
    //

    // GetSpecialContextSize():
    //
    // Gets the size of the special context structure (KSPECIAL_REGISTERS for the given architecture that this
    // ISvcClassicSpecialContext represents).
    //
    STDMETHOD_(ULONG64, GetSpecialContextSize)(
        THIS
        ) PURE;

    // GetSpecialContext():
    //
    // Fills in a KSPECIAL_REGISTERS structure for the given machine architecture.
    //
    STDMETHOD(GetSpecialContext)(
        THIS_
        _In_ ULONG64 bufferSize,
        _Out_writes_(bufferSize) void *contextBuffer,
        _Out_ ULONG64 *contextSize
        ) PURE;

    // SetSpecialContext():
    //
    // Changes the values in this register context to the ones given by the incoming KSPECIAL_REGISTERS structure.
    //
    STDMETHOD(SetSpecialContext)(
        THIS_
        _In_ ULONG64 bufferSize,
        _In_reads_(bufferSize) void *contextBuffer
        ) PURE;
};

// DEBUG_REGISTERDOMAIN_CODEVIEW:
//
// Describes the register numbering domain for CodeView identifiers.
//
// {5C9CE1FF-CAE7-459c-A0F8-00A34B146133}
//
DEFINE_GUID(DEBUG_REGISTERDOMAIN_CODEVIEW, 0x5c9ce1ff, 0xcae7, 0x459c, 0xa0, 0xf8, 0x0, 0xa3, 0x4b, 0x14, 0x61, 0x33);

// DEBUG_REGISTERDOMAIN_DWARF:
//
// Describes the register numbering domain for DWARF identifiers.
//
// {530B23F0-0E37-458f-A4C7-93B0254A9F8E}
//
DEFINE_GUID(DEBUG_REGISTERDOMAIN_DWARF, 0x530b23f0, 0xe37, 0x458f, 0xa4, 0xc7, 0x93, 0xb0, 0x25, 0x4a, 0x9f, 0x8e);

//
// Interface  : ISvcRegisterTranslation
//
// Provided By: DEBUG_SERVICE_REGISTERTRANSLATION
//
// The ISvcRegisterTranslation interface provides translation between register numbering domains.  This can be utilized,
// for instance, to translate from a canonical register ID to a register ID specific to some ABI definition
// (e.g.: DWARF information for a platform on Linux).
//
#undef INTERFACE
#define INTERFACE
DECLARE_INTERFACE_(ISvcRegisterTranslation, IUnknown)
{
    // TranslateFromCanonicalId():
    //
    // Translates from a canonical register ID to a domain specific register ID.  The canonical register ID is
    // whatever the architecture service defines for a given architecture.  A domain specific register ID may be how
    // register numbers are stored in a PDB for a given architecture (e.g.: CodeView identifiers) or how register
    // numbers are stored in DWARF for a given architecture, etc...
    //
    // If there is no mapping from the canonical ID to a domain ID, E_BOUNDS is returned.
    //
    STDMETHOD(TranslateFromCanonicalId)(
        THIS_
        _In_ ULONG canonicalId,
        _Out_ ULONG *domainId
        ) PURE;

    // TranslateToCanonicalId():
    //
    // Translates from a domain specific register ID to a canonical register ID.  The canonical register ID is whatever
    // the architecture services defines for a given architecture.  A domain specific register ID may be how register
    // numbers are stored in a PDB for a given architecture (e.g.: CodeView identifiers) or how register numbers
    // are stored in DWARF for a given architecture, etc...
    //
    // If there is no mapping from the domain specific ID to a canonical ID, E_BOUNDS is returned.
    //
    STDMETHOD(TranslateToCanonicalId)(
        THIS_
        _In_ ULONG domainId,
        _Out_ ULONG *canonicalId
        ) PURE;
};

//
// Interface  : ISvcDwarfRegisterTranslation
//
// Provided By: DEBUG_SERVICE_REGISTERTRANSLATION
//
// The ISvcDwarfRegisterTranslation interface provides an extension to ISvcRegisterTranslation required for
// register translations and stack unwinding specific to DWARF.  Any implementation of this interface *MUST*
// implement ISvcRegisterTranslation.  This is above and beyond.
//
// Note that while this interface can be optional for adapting to the DWARF unwinder, it is *HIGHLY* recommended.
// For any architecture that does *NOT* have a physical return address register (e.g.: ARM's @lr), it is
// *MANDATORY*.
//
#undef INTERFACE
#define INTERFACE
DECLARE_INTERFACE_(ISvcDwarfRegisterTranslation, IUnknown)
{
    // TranslateFromAbstractId():
    //
    // Translates from an abstract ID to a DWARF ID.  Normally, one could take an abstract ID, translate it to
    // a canonical one via ISvcMachineArchitecture and then ask ISvcRegisterTranslation to translate it to
    // a DWARF ID via TranslateFromCanonicalId.  There are, however, some concepts in DWARF to which this may not
    // apply.  All architectures for DWARF have a return address register whether the architecture has one or not.
    // On ARM platforms, this is the @lr register.  On x86/x64, this is a synthetic register in the FDE table.
    // Asking for the @ra abstract ID to be translated to a canonical ID will fail because the architecture does
    // not have the concept.  DWARF, however, does.  You can ask for the direct translation via this method.
    //
    STDMETHOD(TranslateFromAbstractId)(
        THIS_
        _In_ SvcAbstractRegister abstractId,
        _Out_ ULONG *domainId
        ) PURE;

    // TranslateTypicalCfa():
    //
    // Translates from the abstract DWARF concept of a CFA (canonical frame address) to concrete information
    // that an unwinder can use (e.g.: an offset from a potentially dereferenced register).  This returns
    // such information for the *TYPICAL* CFA as defined by the DWARF specification: "the stack pointer at the call
    // site in the caller's frame" for a call frame with a *TYPICAL* prologue.
    //
    // This method is used to help the stack unwinder in some circumstances (e.g.: when private DWARF unwind
    // data is not available and components are compiled with frame pointers but DWARF debug information is
    // present).
    //
    // The returned "symbol location" will typically take one of three forms:
    //
    //     - @reg           : cfaLocation == SvcSymbolLocationRegister
    //     - @reg + offset  : cfaLocation == SvcSymbolLocationRegisterRelative
    //     - [@reg + offset]: cfaLocation == SvcSymbolLocationRegisterRelativeIndirectOffset
    //
    // While implementation of this method is optional, it is highly recommended.
    //
    STDMETHOD(TranslateTypicalCfa)(
        THIS_
        _Out_ SvcSymbolLocation *cfaLocation
        ) PURE;
};

// DEBUG_REGISTERCONTEXTDOMAIN_WINDOWSPLATFORM:
//
// Describes the register context domain for the Windows platform.  In specific, this refers to the use of
// architecture specific CONTEXT structures to store a register context.
//
// {A50BD040-289D-492a-9C9A-FB14B3A32325}
//
DEFINE_GUID(DEBUG_REGISTERCONTEXTDOMAIN_WINDOWSPLATFORM, 0xa50bd040, 0x289d, 0x492a, 0x9c, 0x9a, 0xfb, 0x14, 0xb3, 0xa3, 0x23, 0x25);

// DEBUG_REGISTERCONTEXTDOMAIN_LINUXPRSTATUS:
//
// Describes the register context domain for the Linux platform.  In specific, this refers to the use of
// architecture specific PRSTATUS structures to store a register context in places such as core dumps and KDUMPs.
//
// {C8BAF6C4-B964-45dd-9D81-45FD50DB9279}
//
DEFINE_GUID(DEBUG_REGISTERCONTEXTDOMAIN_LINUXPRSTATUS, 0xc8baf6c4, 0xb964, 0x45dd, 0x9d, 0x81, 0x45, 0xfd, 0x50, 0xdb, 0x92, 0x79);

// DEBUG_REGISTERCONTEXTDOMAIN_LINUXSIGNALCONTEXT:
//
// Describes the register context domain for signal records on the Linux platform.  In specific, this refers
// to the use of architecture specific ucontext structures that store a register context on the stack
// when a signal handler is invoked.
//
// {3F330F59-3A39-46ee-9D06-67FA5FA84065}
//
DEFINE_GUID(DEBUG_REGISTERCONTEXTDOMAIN_LINUXSIGNALCONTEXT, 0x3f330f59, 0x3a39, 0x46ee, 0x9d, 0x6, 0x67, 0xfa, 0x5f, 0xa8, 0x40, 0x65);

// DEBUG_REGISTERCONTEXTDOMAIN_LINUXKERNELTRANSITIONCONTEXT:
//
// Describes the register context domain for the user mode context preserved on the kernel stack for syscall/sysenter
// transitions into the Linux kernel.
//
// {79B0BDF5-3A1E-44f0-B644-008143B214F7}
//
DEFINE_GUID(DEBUG_REGISTERCONTEXTDOMAIN_LINUXKERNELTRANSITIONCONTEXT, 0x79b0bdf5, 0x3a1e, 0x44f0, 0xb6, 0x44, 0x0, 0x81, 0x43, 0xb2, 0x14, 0xf7);

// DEBUG_REGISTERCONTEXTDOMAIN_MACTHREADSTATE:
//
// Describes the register context domain for the *thread_state*_t commands stored in LC_THREAD load commands
// within Mac OS core dumps.
//
// {9B602ACF-4AA6-4FB7-B0F2-2DE8DEACD650}
//
DEFINE_GUID(DEBUG_REGISTERCONTEXTDOMAIN_MACTHREADSTATE, 0x9b602acf, 0x4aa6, 0x4fb7, 0xb0, 0xf2, 0x2d, 0xe8, 0xde, 0xac, 0xd6, 0x50);

//
// Interface  : ISvcRegisterContextTranslation
//
// Provided By: DEBUG_SERVICE_REGISTERCONTEXTTRANSLATION
//
// The ISvcRegisterContextTranslation interface provides translation between register context domains.  This can be
// utilized, for instance, to translate from Windows context record (struct CONTEXT / AMD64_CONTEXT, etc...) to
// a canonical ISvcRegisterContext or vice-versa.  It can also be used to translate from a custom context record
// (e.g.: a custom architecture's user mode register context stored in a core dump) to a canonical ISvcRegisterContext
// or vice-versa.
//
#undef INTERFACE
#define INTERFACE
DECLARE_INTERFACE_(ISvcRegisterContextTranslation, IUnknown)
{
    // TranslateToCanonicalContext():
    //
    // Translates from a domain specific context record to a canonical context record.
    //
    STDMETHOD(TranslateToCanonicalContext)(
        THIS_
        _In_ ULONG domainContextSize,
        _In_reads_(domainContextSize) void *domainContext,
        _Inout_ ISvcRegisterContext *canonicalContext
        ) PURE;

    // GetDomainContextSize():
    //
    // Gets the size of the domain specific context record.
    //
    STDMETHOD_(ULONG, GetDomainContextSize)(
        THIS
        ) PURE;

    // TranslateFromCanonicalContext():
    //
    // Translates from a canonical context record to a domain specific context record.
    //
    STDMETHOD(TranslateFromCanonicalContext)(
        THIS_
        _In_ ISvcRegisterContext *canonicalContext,
        _In_ ULONG domainRecordSize,
        _Out_writes_(domainRecordSize) void *domainContext
        ) PURE;

};

// TrapContextKind:
//
// Indicates a particular type of trap context from which to restore underlying register context.
//
enum TrapContextKind
{
    //
    // Indicates restoration from a signal frame.  The inbound register context is the unwound context
    // record of a signal frame.  The context of the signal point must be restored in the output record.
    //
    TrapContextSignalFrame,

    //
    // Indicates restoration from a kernel transition frame (e.g.: where a syscall/sysenter lands).  The
    // inbound register context is the unwound context record of the transition frame.  The context of the
    // (user) syscall/sysenter must be restored in the output record.
    //
    TrapContextKernelTransitionFrame,
};

#undef INTERFACE
#define INTERFACE ISvcTrapContextRestoration
DECLARE_INTERFACE_(ISvcTrapContextRestoration, IUnknown)
{
    // ReadTrapContext():
    //
    // Given a register context of a trap handler (e.g.: a signal frame), restores the register context
    // at the trap point.
    //
    // This operates in one of two modes:
    //     - trapContext == 0: the input context is effectively for a stack frame and the location of the
    //                         trap context should be determined from the trapKind and the input context.
    //                         The restored context is a copy of the input context overwritten with the register
    //                         values of the trap context.
    //
    //     - trapContext != 0: the location of the trap context is given by trapContext.  The restored context
    //                         is a copy of the input context (which may just be an empty register context for
    //                         the architecture) overwritten with the register values of the rap context.
    //
    STDMETHOD(ReadTrapContext)(
        THIS_
        _In_ TrapContextKind trapKind,
        _In_ ISvcAddressContext *pAddressContext,
        _In_ ISvcRegisterContext *pInContext,
        _In_ ULONG64 trapContext,
        _COM_Outptr_ ISvcRegisterContext **ppOutContext
        ) PURE;
};

//
// Interface  : ISvcExecutionUnit
//
// Provided By:
//
// The ISvcExecutionUnit interface is provided by a debug primitive which is capable of execution of code.
// This may be a thread.  It may be a processor core.
//
#undef INTERFACE
#define INTERFACE ISvcExecutionUnit
DECLARE_INTERFACE_(ISvcExecutionUnit, IUnknown)
{
    //*************************************************
    // ISvcExecutionUnit:
    //

    // GetContext():
    //
    // Gets the register context of the execution unit.  Which categories of registers are retrieved is
    // dependent upon the flags passed in.
    //
    // If the method returns S_OK, all registers of the given categories were retrieved.  If the method returns
    // S_FALSE, some registers of the given categories were retrieved.  S_FALSE may indicate that an entire
    // category was not retrieved (e.g.: a dump or core contains no record of SSE/AVX registers) or it may
    // indicate that some registers of a category were retrieved and some were not.
    //
    STDMETHOD(GetContext)(
        THIS_
        _In_ SvcContextFlags contextFlags,
        _COM_Outptr_ ISvcRegisterContext **ppRegisterContext
        ) PURE;

    // SetContext():
    //
    // Sets the register context of the execution unit.  Which categories of registers are written is
    // dependent upon the flags passed in.
    //
    // The S_OK/S_FALSE definitions mirror GetContextEx.  Note that registers which are not contained
    // in the register context will not be written regardless of what SvcContextFlags indicates.
    //
    STDMETHOD(SetContext)(
        THIS_
        _In_ SvcContextFlags contextFlags,
        _In_ ISvcRegisterContext *pRegisterContext
        ) PURE;
};

//
// Interface  : ISvcExecutionUnitHardware
//
// @TODO: This name isn't right.  This factoring isn't right.  Fix this...
#undef INTERFACE
#define INTERFACE ISvcExecutionUnitHardware
DECLARE_INTERFACE_(ISvcExecutionUnitHardware, IUnknown)
{
    //*************************************************
    // ISvcExecutionUnitHardware:
    //

    // GetSpecialContext():
    //
    // NOTE: This is effectively an "ISvcExecutionUnit::SetContext" with ContextFlags set to only
    //       SvcContextSpecial.  Such can be explicitly written back with the standard "ISvcExecutionUnit::SetContext"
    //       method on targets which support special context (e.g.: kernel / hardware connections)
    //
    STDMETHOD(GetSpecialContext)(
        THIS_
        _COM_Outptr_ ISvcRegisterContext **specialContext
        ) PURE;

    // GetProcessorNumber():
    //
    // Gets the processor number assigned to this execution unit.  Calling ISvcMachineDebug::GetProcessor with
    // this number should get back to the same execution unit.
    //
    STDMETHOD_(ULONG64, GetProcessorNumber)(
        THIS
        ) PURE;

};

//
// Interface  : ISvcMachineDebug /* @TODO: Name */
//
// Provided By: DEBUG_SERVICE_MACHINE (where applicable)
//
// The ISvcMachineDebug interface is provided only for configurations which are debugging at a hardware or
// kernel level where the debug primitives are in terms of processors and their contexts rather than threads
// and processes.
//
#undef INTERFACE
#define INTERFACE ISvcMachineDebug
DECLARE_INTERFACE_(ISvcMachineDebug, IUnknown)
{
    //*************************************************
    // ISvcMachineDebug
    //

    // GetDefaultAddressContext():
    //
    // If a default address context is available, this returns it.  The machine implementor
    // can decide what constitues a defualt address context.  If automatic kernel discovery is to take place
    // this must be an address context in which that can occur.
    //
    STDMETHOD(GetDefaultAddressContext)(
        THIS_
        _COM_Outptr_ ISvcAddressContext** defaultAddressContext
        ) PURE;

    // GetNumberOfProcessors();
    //
    // Returns the number of processors on the machine.
    //
    STDMETHOD_(ULONG64, GetNumberOfProcessors)(
        THIS
        ) PURE;

    // GetProcessor():
    //
    // Gets an interface for the given processor.
    //
    STDMETHOD(GetProcessor)(
        THIS_
        _In_ ULONG64 processorNumber,
        _COM_Outptr_ ISvcExecutionUnit** processor
        ) PURE;
};

//
// Interface  : ISvcMachineDebug2
//
// Provided By: DEBUG_SERVICE_MACHINE
//
// An extension of the ISvcMachineDebug interface.
//
#undef INTERFACE
#define INTERFACE ISvcMachineDebug2
DECLARE_INTERFACE_(ISvcMachineDebug2, ISvcMachineDebug)
{
    //*************************************************
    // ISvcMachineDebug2:
    //

    // GetDefaultIoSpace():
    //
    // If a default I/O space is available, this returns it.  The machine and architecture should define this.
    // For Intel x86/x64 machines, this would represent the system port I/O space (in/out instructions)
    //
    // For machines/architectures without any notion of a default I/O space, this should return E_NOTIMPL.
    //
    STDMETHOD(GetDefaultIoSpace)(
        _COM_Outptr_ ISvcIoSpace** ioSpace
        ) PURE;
};

//
// Interface  : ISvcMachineConfiguration /* @TODO: Name */
//
// Provided By: DEBUG_SERVICE_MACHINE (always)
//
// The ISvcMachineConfiguration interface is provided by the machine service.
//
#undef INTERFACE
#define INTERFACE ISvcMachineConfiguration
DECLARE_INTERFACE_(ISvcMachineConfiguration, IUnknown)
{
    //*************************************************
    // ISvcMachineConfiguration

    // GetArchitecture():
    //
    // Returns the archtiecture of the machine as an IMAGE_FILE_MACHINE_* constant.
    //
    STDMETHOD_(ULONG, GetArchitecture)(
        THIS
        ) PURE;
};

//
// Interface  : ISvcMachineConfiguration2 /* @TODO: Name */
//
// Provided By: DEBUG_SERVICE_MACHINE
//
// The ISvcMachineConfiguration interface is provided by the machine service.
//
#undef INTERFACE
#define INTERFACE ISvcMachineConfiguration2
DECLARE_INTERFACE_(ISvcMachineConfiguration2, ISvcMachineConfiguration)
{
    //*************************************************
    // ISvcMachineConfiguration2
    //

    // GetArchitectureGuid():
    //
    // Returns the architecture of the machine as a DEBUG_ARCHDEF_* guid.  This supports
    // the notion of a custom architecture.  If such is utilized, the returned GUID *MUST*
    // also be the component aggregate for the architecture.
    //
    STDMETHOD(GetArchitectureGuid)(
        THIS_
        _Out_ GUID* architecture
        ) PURE;
};

//
// Interface  : ISvcOSKernelLocator
//
// Provided By: DEBUG_SERVICE_OS_KERNELLOCATOR
//
#undef INTERFACE
#define INTERFACE ISvcOSKernelLocator
DECLARE_INTERFACE_(ISvcOSKernelLocator, IUnknown)
{
    //*************************************************
    // ISvcOSKernelLocator:
    //

    // GetKernelBase():
    //
    // Gets the base address of the kernel.
    //
    STDMETHOD(GetKernelBase)(
        THIS_
        _Out_ ULONG64 *pKernelBase
        ) PURE;


    // CreateOSKernelComponent():
    //
    // Creates the component aggregate for whatever operating system kernel was identified.
    //
    STDMETHOD(CreateOSKernelComponent)(
        THIS_
        _COM_Outptr_result_maybenull_ IDebugServiceLayer **ppServiceLayer
        ) PURE;

};

//
// Interface  : ISvcOSKernelInfrastructure
//
// Provided By: DEBUG_SERVICE_OS_KERNELINFRASTRUCTURE
//
// @TODO: Where this goes needs to be thought out significantly more!
//
#undef INTERFACE
#define INTERFACE ISvcOSKernelInfrastructure
DECLARE_INTERFACE_(ISvcOSKernelInfrastructure, IUnknown)
{
    //*************************************************
    // ISvcOSKernelInfrastructure:
    //

    // GetDirectoryBase():
    //
    // Gets the pointer to the top level paging structures for a particular process (e.g.: The PDE base that would
    // go into CR3 on AMD64).
    //
    // If these structures are not in memory, an error will be returned.
    //
    STDMETHOD(GetDirectoryBase)(
        THIS_
        _In_ DirectoryBaseKind dirKind,
        _In_ ISvcProcess *pProcess,
        _Out_ ULONG64 *pDirectoryBase
        ) PURE;

    // GetPagingLevels():
    //
    // Gets the number of paging levels that a particular process will use.
    //
    STDMETHOD(GetPagingLevels)(
        THIS_
        _In_ ISvcProcess *pProcess,
        _Out_ ULONG *pPagingLevels
        ) PURE;

    // GetExecutionState():
    //
    // For a hardware execution unit (a CPU), return information about the process/thread that is
    // running on that particular CPU.
    //
    STDMETHOD(GetExecutionState)(
        THIS_
        _In_ ISvcExecutionUnit *pProcessor,
        _COM_Outptr_opt_result_maybenull_ ISvcThread **ppExecutingThread,
        _COM_Outptr_opt_result_maybenull_ ISvcProcess **ppExecutingProcess
        ) PURE;
};

//
// Interface  : ISvcOSKernelTypes
//
// Provided By: DEBUG_SERVICE_OS_KERNELINFRASTRUCTURE
//
// @TODO: Where this goes needs to be thought out significantly more!
//
#undef INTERFACE
#define INTERFACE ISvcOSKernelTypes
DECLARE_INTERFACE_(ISvcOSKernelTypes, IUnknown)
{
    //*************************************************
    // ISvcOSKernelTypes:
    //

    // GetProcessType():
    //
    // If the kernel describes the notion of processes from a process enumerator and such objects have
    // an object in the kernel associated with them, that object is of this type.
    //
    // For Windows, this would be EPROCESS.
    //
    // A return of E_NOT_SET indicates that no such type exists.
    //
    STDMETHOD(GetProcessType)(
        THIS_
        _COM_Outptr_ ISvcSymbol **ppProcessType
        ) PURE;

    // GetThreadType():
    //
    // If the kernel describes the notion of threads from a thread enumerator and such objects have
    // an object in the kernel associated with them, that object is of this type.
    //
    // For Windows, this would be ETHREAD.
    //
    // A return of E_NOT_SET indicates that no such type exists.
    //
    STDMETHOD(GetThreadType)(
        THIS_
        _COM_Outptr_ ISvcSymbol **ppThreadType
        ) PURE;

    // GetModuleType():
    //
    // If the kernel describes the notion of a module (SO / DLL / driver) from a module enumerator and such
    // objects have an object in the kernel associated with them, that object is of this type.
    //
    // A return of E_NOT_SET indicates that no such type exists.
    //
    STDMETHOD(GetModuleType)(
        THIS_
        _COM_Outptr_ ISvcSymbol **ppModuleType
        ) PURE;
};

//
// Interface  : ISvcOSKernelTransitions
//
// Provided By: DEBUG_SERVICE_OS_KERNELINFRASTRUCTURE
//
#undef INTERFACE
#define INTERFACE ISvcOSKernelTransitions
DECLARE_INTERFACE_(ISvcOSKernelTransitions, IUnknown)
{
    //*************************************************
    // ISvcOSKernelTransitions:
    //

    // IsKernelTransitionFrame():
    //
    // Indicates if the particular frame given by an unwound register context 'pRegisterContext' is the entry
    // frame to the kernel (e.g.: the syscall/sysenter frame) which preserves user mode register context on the
    // stack.
    //
    // If this particular method succeeds and *pIsKernelTransitionFrame is true, several other things are expected
    // of the service providing this result:
    //
    //     1) There is a conditional service registered to translate from the register context saved in such frame
    //        to a canonical context.  For Linux, the context would be given by the domain GUID
    //        DEBUG_REGISTERCONTEXTDOMAIN_LINUXKERNELTRANSITIONCONTEXT
    //
    //     2) There is a conditional DEBUG_SERVICE_TRAPCONTEXTRESTORATION service registered conditioned on
    //        the architecture and platform GUID which can handle a restoration of the TrapContextKernelTransitionFrame
    //        kind.  Such service makes use of 1) above
    //
    // Note that if there is unwinder data for the transition frame whose interpretation will restore user mode
    // context, this is unnecessary for the kernel infrastructure service to provide.
    //
    STDMETHOD(IsKernelTransitionFrame)(
        THIS_
        _In_ ISvcRegisterContext *pRegisterContext,
        _Out_ bool *pIsKernelTransitionFrame
        ) PURE;
};

//
// Interface  : ISvcOSKernelObject
//
// Provided By: Various objects (processes, threads, modules, etc...)
//
// If an object is exposed by an enumerator for a kernel and has an associated construct in the kernel, this
// can map the conceptual object to a physical structure in the kernel.  Its presence is optional.
//
#undef INTERFACE
#define INTERFACE ISvcOSKernelObject
DECLARE_INTERFACE_(ISvcOSKernelObject, IUnknown)
{
    //*************************************************
    // ISvcOSKernelObject:
    //

    // GetAssociatedKernelObject():
    //
    // For any given object, this gets an object in the kernel that is used to manage such object.
    //
    STDMETHOD(GetAssociatedKernelObject)(
        THIS_
        _Out_ ULONG64 *kernelObjectAddress,
        _COM_Outptr_opt_ ISvcAddressContext** kernelAddressContext,
        _COM_Outptr_opt_ ISvcModule** kernelModule,
        _COM_Outptr_opt_ ISvcSymbol** kernelObjectType
        ) PURE;
};

//
// Interface  : ISvcOSKernelObjectAccessor
//
// Provided By: Various enumeration services (process enumeration services, thread enumeration services,
//              module enumeration services, etc...)
//
#undef INTERFACE
#define INTERFACE ISvcOSKernelObjectAccessor
DECLARE_INTERFACE_(ISvcOSKernelObjectAccessor, IUnknown)
{
    //*************************************************
    // ISvcOSKernelObjectAccessor:
    //

    // GetObjectFromAssociatedKernelObject():
    //
    // From the address of a kernel object as returned from ISvcOSKernelObject::GetAssociatedKernelObject,
    // return the ISvc* interface (* = Process, Thread, Module, etc...) for that object.
    //
    // The given address must be valid in the default address context.
    //
    STDMETHOD(GetObjectFromAssociatedKernelObject)(
        THIS_
        _In_ ULONG64 kernelObjectAddress,
        _COM_Outptr_opt_ IUnknown** serviceObject /* QIs for ISvcThread, ISvcProcess, ISvcModule, etc... */
        ) PURE;
};

// SvcOSPlatform:
//
// Defines the platform
//
enum SvcOSPlatform
{
    SvcOSPlatUnknown = 0,

    //
    // Low values match defined VER_PLATFORM_* definitions.
    //
    SvcOSPlatWindows    = 2,                // Windows (2000+)
    SvcOSPlatUNIX       = 10,               // Generic UNIX
    SvcOSPlatMacOS      = 11,               // MacOS
    SvcOSPlatiOS        = 12,               // iOS
    SvcOSPlatChromeOS   = 21,               // ChromeOS/ChromiumOS
    SvcOSPlatAndroid    = 22,               // Android

    //
    // High values are not defined by a VER_PLATFORM_* constant.
    //
    SvcOSPlatLinux = 0x80000001,             // Linux
};

// Interface   : ISvcOSPlatformInformation:
//
// Provided By : DEBUG_SERVICE_OS_INFORMATION
//
#undef INTERFACE
#define INTERFACE ISvcOSPlatformInformation
DECLARE_INTERFACE_(ISvcOSPlatformInformation, IUnknown)
{
    //*************************************************
    // ISvcOSPlatformInformation:
    //

    // GetOSPlatform():
    //
    // Gets the high level infromation about the platform that the target is running on.  A component
    // which runs on a platform that is not described by SvcOSPlatform may return SvcOSPlatUnknown.
    //
    STDMETHOD(GetOSPlatform)(
        THIS_
        _Out_ SvcOSPlatform *pOSPlatform
        ) PURE;
};

// Interface   : ISvcOSPlatformInformation:
//
// Provided By : DEBUG_SERVICE_OS_INFORMATION
//
#undef INTERFACE
#define INTERFACE ISvcOSPlatformInformation2
DECLARE_INTERFACE_(ISvcOSPlatformInformation2, ISvcOSPlatformInformation)
{
    //*************************************************
    // ISvcOSPlatformInformation2:
    //

    // GetOSVersion():
    //
    // Gets the 1-4 digit version of the platform. When digits are not appropriate for the platform, use a 0 default.
    // If the implementation cannot make a determination of the OS Version Number, E_NOT_SET may legally be returned.
    // If the implementation doesn't support the concept of an OS Version Number, E_NOTIMPL may legally be returned.
    //
    STDMETHOD(GetOSVersion)(
        THIS_
        _Out_ USHORT *pMajor,
        _Out_opt_ USHORT *pMinor,
        _Out_opt_ USHORT *pBuild,
        _Out_opt_ USHORT *pRevision
        ) PURE;

    // GetOSBuildLab():
    //
    // Gets the string that represents the Build Lab (environment) that built this version of the platform.
    // If the implementation cannot make a determination of the Build Lab, E_NOT_SET may legally be returned.
    // If the implementation doesn't support the concept of a Build Lab, E_NOTIMPL may legally be returned.
    //
    STDMETHOD(GetOSBuildLab)(
        THIS_
        _Out_ BSTR *pBuildLab
        ) PURE;
};

// Interface   : ISvcTelemetry
//
// Provided By : DEBUG_SERVICE_TELEMETRY
//
#undef INTERFACE
#define INTERFACE ISvcTelemetry
DECLARE_INTERFACE_(ISvcTelemetry, IUnknown)
{
    //*************************************************
    // ISvcTelemetry:
    //

    // NotifyUsage():
    //
    // Notify usage of a particular feature (with an optional "action" and "parameter")
    //
    STDMETHOD(NotifyUsage)(
        THIS_
        _In_ PCWSTR product,
        _In_ PCWSTR feature,
        _In_opt_ PCWSTR action
        ) PURE;

};

// DiagnosticLogLevel:
//
// Defines a level of diagnostic output to a log sink.
//
enum DiagnosticLogLevel
{
    DiagnosticLevelVerboseInfo = 0,
    DiagnosticLevelInfo,
    DiagnosticLevelWarning,
    DiagnosticLevelError,
};

// Interface   : ISvcDiagnosticLogging
//
// Provided By : DEBUG_SERVICE_DIAGNOSTIC_LOGGING
//
#undef INTERFACE
#define INTERFACE ISvcDiagnosticLogging
DECLARE_INTERFACE_(ISvcDiagnosticLogging, IUnknown)
{
    //*************************************************
    // ISvcDiagnosticLogging:
    //

    // Log():
    //
    // Sends a message to a diagnostic logging sink.  What the host does with the log message is entirely
    // up to it.
    //
    STDMETHOD(Log)(
        THIS_
        _In_ DiagnosticLogLevel level,
        _In_ PCWSTR logMessage,
        _In_opt_ PCWSTR component,
        _In_opt_ PCWSTR category
        ) PURE;
};

// Interface   : ISvcDiagnosticLoggingXmlPassthrough
//
// Provided By : DEBUG_SERVICE_DIAGNOSTIC_LOGGING
//
// Note that this interface is not intended for clients to manually create XML status logs.  It is intended
// to allow a client which makes use of other APIs which funnel XML status messages to appropriately funnel them
// back to the host.  An example of this is embedded usage of DbgHelp and funneling any CBA_XML_LOG directly back
// to the host.
//
#undef INTERFACE
#define INTERFACE ISvcDiagnosticLoggingXmlPassthrough
DECLARE_INTERFACE_(ISvcDiagnosticLoggingXmlPassthrough, IUnknown)
{
    //*************************************************
    // ISvcDiagnosticLoggingXmlPassthrough:
    //

    // LogXml():
    //
    // Forwards an existing XML status/log message to a diagnostic logging sink.  What the host does with the log
    // message is entirely up to it.
    //
    STDMETHOD(LogXml)(
        THIS_
        _In_ PCWSTR xmlLog
        ) PURE;
};

// Interface   : ISvcDiagnosticLoggableControl
//
// Provided By : (Various Components)
//
#undef INTERFACE
#define INTERFACE ISvcDiagnosticLoggableControl
DECLARE_INTERFACE_(ISvcDiagnosticLoggableControl, IUnknown)
{
    //*************************************************
    // ISvcDiagnosticLoggableControl:
    //

    // GetLoggingLevel():
    //
    // Gets the current diagnostic logging level for this service.
    //
    STDMETHOD_(DiagnosticLogLevel, GetLoggingLevel)(
        THIS
        ) PURE;

    // SetLoggingLevel():
    //
    // Sets the current diagnostic logging level for this service.
    //
    STDMETHOD_(void, SetLoggingLevel)(
        THIS_
        _In_ DiagnosticLogLevel level
        ) PURE;
};

//**************************************************************************
// Kernel Service APIs:
//

//
// @Q: How do the Flags from ReadPhysical* propagate into this world.  Current APIs allow you
//    to request what mapping Mm provides for the physical read (regular cached, uncached, or
//    write combined)
//
// @PA: This is likely to be one of the following:
//
//      - A different service (DEBUG_SERVICE_PHYSICAL_MEMORY_*)
//      - A different interface on the physical memory service (other than ISvcMemoryAccess)
//
// ISvcMemoryAccess should be as BASIC as we can get in order to allow for the maximum ease of implementation
// and the maximum breadth of scenarios.
//


//
// Interface  : ISvcMemoryAccess
//
// Provided By: DEBUG_SERVICE_VIRTUAL_MEMORY
//              DEBUG_SERVICE_PHYSICAL_MEMORY
//              DEBUG_SERVICE_VIRTUAL_MEMORY_UNCACHED
//              DEBUG_SERVICE_PHYSICAL_MEMORY_UNCACHED
//              DEBUG_SERVICE_VIRTUAL_MEMORY_TRANSLATED
//              DEBUG_SERVICE_IOSPACE_MEMORY
//
// Defines a means of access to an address space -- physical, virtual, cached,
// or uncached.  The exact semantics of the interface depend on what service
// was queried for ISvcMemoryAccess.
//
#undef INTERFACE
#define INTERFACE ISvcMemoryAccess
DECLARE_INTERFACE_(ISvcMemoryAccess, IUnknown)
{
    //*************************************************
    // ISvcMemoryAccess:

    // ReadMemory()
    //
    // Reads a series of bytes from the memory type this interface represents in the address
    // space given by the first argument.  Nearly every target will have some concept of address
    // context (processor, process address space, etc...) that must be passed to this method.  Some
    // (e.g.: image targets) may choose not to represent any "address context".  It is the responsibility
    // of the service to ensure it has an appropriate context if needed.
    //
    // This method will return S_FALSE if a partial read is successful and S_OK if a full read
    // occurs.  In the case of a partial read, the 'BytesRead' argument will be set to the number
    // of bytes actually read.
    //
    STDMETHOD(ReadMemory)(
        THIS_
        _In_opt_ ISvcAddressContext* AddressContext,
        _In_ ULONG64 Offset,
        _Out_writes_to_(BufferSize, *BytesRead) PVOID Buffer,
        _In_ ULONG64 BufferSize,
        _Out_ PULONG64 BytesRead
        ) PURE;

    // WriteMemory()
    //
    // Writes a series of bytes to the memory type this interface represents in the address
    // space given by the first argument.
    //
    // This method will return S_FALSE if a partial write is successful and S_OK if a full write
    // occurs.  In the case of a partial write, the 'BytesWritten' argument will be set to the number
    // of bytes actually written.
    //
    STDMETHOD(WriteMemory)(
        THIS_
        _In_opt_ ISvcAddressContext* AddressContext,
        _In_ ULONG64 Offset,
        _In_reads_bytes_(BufferSize) PVOID Buffer,
        _In_ ULONG64 BufferSize,
        _Out_ PULONG64 BytesWritten
        ) PURE;
};

enum MemoryAccessCacheControl
{
    // The cache behavior around the memory access should be the "default" for the service.  Calling
    // ISvcMemoryAccessCacheControl variants with this argument is equivalent to calling ISvcMemoryAccess
    // variants with no cache control specified.
    MemoryAccessCacheDefault,

    // The read/write should be cached *IF* the service provides a mechanism of caching.
    MemoryAccessCacheEnabled,

    // The read/write should *NOT* be cached whether the service provides a mechanism of caching or not.
    MemoryAccessCacheDisabled
};

//
// Interface  : ISvcMemoryAccessCacheControl
//
// An optional interface provided by any service which provides ISvcMemoryAccess.  This variant of memory
// access interfaces allows an explicit specification of the caching behavior for reads and writes if the underlying
// services perform any kind of read/write caching.
//
#undef INTERFACE
#define INTERFACE ISvcMemoryAccessCacheControl
DECLARE_INTERFACE_(ISvcMemoryAccessCacheControl, IUnknown)
{
    //*************************************************
    // ISvcMemoryAccessCacheControl:

    // ReadMemoryCacheControl()
    //
    // As ISvcMemoryAccess::ReadMemory but with an explicit cache behavior specified.
    //
    STDMETHOD(ReadMemoryCacheControl)(
        THIS_
        _In_opt_ ISvcAddressContext* AddressContext,
        _In_ ULONG64 Offset,
        _In_ MemoryAccessCacheControl CacheControl,
        _Out_writes_to_(BufferSize, *BytesRead) PVOID Buffer,
        _In_ ULONG64 BufferSize,
        _Out_ PULONG64 BytesRead
        ) PURE;

    // WriteMemoryCacheControl()
    //
    // As ISvcMemoryAccess::WriteMemory but with an explicit cache behavior specified.
    //
    STDMETHOD(WriteMemoryCacheControl)(
        THIS_
        _In_opt_ ISvcAddressContext* AddressContext,
        _In_ ULONG64 Offset,
        _In_ MemoryAccessCacheControl CacheControl,
        _In_reads_bytes_(BufferSize) PVOID Buffer,
        _In_ ULONG64 BufferSize,
        _Out_ PULONG64 BytesWritten
        ) PURE;
};

// SvcAddressRange:
//
// Defines a contiguous range of addresses in an address space.
//
struct SvcAddressRange
{
    ULONG64 RangeStart;
    ULONG64 RangeLength;
};

// Interface  : ISvcMemoryRegion
//
// Describes a contiguous region of memory within an address space.
//
#undef INTERFACE
#define INTERFACE ISvcMemoryRegion
DECLARE_INTERFACE_(ISvcMemoryRegion, IUnknown)
{
    // GetRange():
    //
    // Gets the bounds of this memory region.
    //
    STDMETHOD(GetRange)(
        THIS_
        _Out_ SvcAddressRange *Range
        ) PURE;

    // IsReadable():
    //
    // Indicates whether this region of memory is readable.  If the implementation cannot make a determination
    // of whether the range is readable or not, E_NOTIMPL may legally be returned.
    //
    STDMETHOD(IsReadable)(
        THIS_
        _Out_ bool *IsReadable
        ) PURE;

    // IsWriteable():
    //
    // Indicates whether this region of memory is writeable.  If the implementation cannot make a determination
    // of whether the range is writeable or not, E_NOTIMPL may legally be returned.
    //
    STDMETHOD(IsWriteable)(
        THIS_
        _Out_ bool *IsWriteable
        ) PURE;

    // IsExecutable():
    //
    // Indicates whether this region of memory is executable.  If the implementation cannot make a determination
    // of whether the range is executable or not, E_NOTIMPL may legally be returned.
    //
    STDMETHOD(IsExecutable)(
        THIS_
        _Out_ bool *IsExecutable
        ) PURE;
};

//
// Interface  : ISvcMemoryRegionEnumerator
//
// Enumerates address regions.
//
#undef INTERFACE
#define INTERFACE ISvcMemoryRegionEnumerator
DECLARE_INTERFACE_(ISvcMemoryRegionEnumerator, IUnknown)
{

    //*************************************************
    // ISvcMemoryRegionEnumerator:
    //

    // Reset():
    //
    // Resets the enumerator back to its initial creation state.
    //
    STDMETHOD(Reset)(
        THIS
        ) PURE;

    // GetNext():
    //
    // Gets the next memory region.
    //
    STDMETHOD(GetNext)(
        THIS_
        _COM_Outptr_ ISvcMemoryRegion **Region
        ) PURE;

};

//
// Interface  : ISvcMemoryInformation
//
// Provided By: DEBUG_SERVICE_VIRTUAL_MEMORY
//              DEBUG_SERVICE_PHYSICAL_MEMORY
//              DEBUG_SERVICE_VIRTUAL_MEMORY_UNCACHED
//              DEBUG_SERVICE_PHYSICAL_MEMORY_UNCACHED
//              DEBUG_SERVICE_VIRTUAL_MEMORY_TRANSLATED
//
// An *OPTIONAL* interface on a memory provider (virtual, physical, or otherwise) which describes the
// address space.
//
#undef INTERFACE
#define INTERFACE ISvcMemoryInformation
DECLARE_INTERFACE_(ISvcMemoryInformation, IUnknown)
{
    //*************************************************
    // ISvcMemoryInformation:
    //

    // FindMemoryRegion():
    //
    // If Offset is contained within a valid memory region in the given address space, an ISvcMemoryRegion
    // describing that memory region is returned along with an S_OK result.  If, on the other hand, Offset
    // is not within a valid memory region in the given address space, the implementation will find the
    // next valid memory region with a starting address greater than Offset within the address space and
    // return an ISvcMemoryRegion describing that along with an S_FALSE result.  If there is no "next higher"
    // address region, E_BOUNDS will be returned.
    //
    STDMETHOD(FindMemoryRegion)(
        THIS_
        _In_opt_ ISvcAddressContext *AddressContext,
        _In_ ULONG64 Offset,
        _COM_Outptr_ ISvcMemoryRegion **Region
        ) PURE;

    // EnumerateMemoryRegions():
    //
    // Enumerates all memory regions in the address space in *ARBITRARY ORDER*.  One can achieve a monotonically
    // increasing enumeration by repeatedly calling FindMemoryRegion starting with an Offset of zero.
    //
    STDMETHOD(EnumerateMemoryRegions)(
        THIS_
        _In_opt_ ISvcAddressContext *AddressContext,
        _COM_Outptr_ ISvcMemoryRegionEnumerator **RegionEnum
        ) PURE;

};

//
// Interface  : ISvcMemoryTranslation
//
// Provided By: DEBUG_SERVICE_VIRTUAL_TO_PHYSICAL_TRANSLATION
//
// Defines a translation from one address space to another (e.g.: the translation of virtual
// addresses to physical addresses by a target or by interpretation of the page tables of
// a target).
//
#undef INTERFACE
#define INTERFACE ISvcMemoryTranslation
DECLARE_INTERFACE_(ISvcMemoryTranslation, IUnknown)
{
    //*************************************************
    // ISvcMemoryTranslation:

    // TranslateAddress():
    //
    // Translates an address from one address space to another.  A service which provides virtual to physical
    // memory mappings would implement this interface to do so.
    //
    // The following special error codes may be returned from this method:
    //
    //     HR_TRANSLATION_NOT_PRESENT:
    //         The address specified by the 'Offset' argument is not present in the target address space.  If there
    //         is a PTE for the address, its value is returned in TranslationEntry.  Such may be queried against
    //         the page table reader service which can attempt to read the page data from a compressed memory
    //         store or from the page file.
    //
    // If there is a "translation entry" (e.g.: PTE) for the given address, it is returned in the 'TranslationEntry'
    // output argument.  If not, such is set to zero at the exit of the method.
    //
    STDMETHOD(TranslateAddress)(
        THIS_
        _In_ ISvcAddressContext* addressContext,
        _In_ ULONG64 offset,
        _In_ ULONG64 contiguousByteCount,
        _Out_ ULONG64 *translatedOffset,
        _Out_opt_ ULONG64 *translatedContiguousByteCount,
        _Out_opt_ ULONG64 *translationEntry   // (PTE) @TODO: <-- not sure this is sufficient.  I want to completely abstract the
                                              //        whole compressed store / page file reader notion from read virtual memory
                                              //        and from address translation.  You shouldn't have to understand ANYTHING
                                              //        but H/W semantics to write a V->P layer.  This shouldn't require knowing about
                                              //        system reserved bits, compressed stores, or other goo.  I want this to be able
                                              //        to be pointed at an x64 Linux VM target without exploding.
        ) PURE;
};

//
// Interface  : ISvcIoSpaceEnumeration
//
// Represents a means of accessing (or eventually enumerating) available I/O spaces.
//
#undef INTERFACE
#define INTERFACE ISvcIoSpaceEnumeration
DECLARE_INTERFACE_(ISvcIoSpaceEnumeration, IUnknown)
{
    //*************************************************
    // ISvcIoSpaceEnumeration

    // FindIoSpace():
    //
    // Acquires a reference to an I/O space for use reading/writing the I/O space.
    //
    STDMETHOD(FindIoSpace)(
        THIS_
        _In_opt_ ULONG *pInterface,
        _In_opt_ ULONG *pBus,
        _In_opt_ ULONG *pAddressSpace,
        _COM_Outptr_ ISvcIoSpace **ppIoSpace) PURE;

    //
    // @TODO: There is limited use of this right now (mostly for accessing port I/O on x86/x64 KD or accessing
    //        special VM data), so there isn't an explicit "enumeration of I/O spaces" yet provided here.
    //
};

//
// Interface  : ISvcIoSpace
//
// Represents a particular I/O space from which to issue I/O read/write requests.
//
#undef INTERFACE
#define INTERFACE ISvcIoSpace
DECLARE_INTERFACE_(ISvcIoSpace, IUnknown)
{
    // GetInterface():
    //
    // Specifies the interface type of the I/O bus. This output may take values in the INTERFACE_TYPE
    // enumeration defined in wdm.h.
    //
    // If this is not relevant, E_NOT_SET is returned.
    //
    STDMETHOD(GetInterface)(
        THIS_
        _Out_ PULONG pInterfaceType) PURE;

    // GetBus():
    //
    // Specifies the system-assigned number of the bus. This is usually zero, unless the system has more than one
    // bus of the same interface type.
    //
    // If this is not relevant, E_NOT_SET is returned.
    //
    STDMETHOD(GetBus)(
        THIS_
        _Out_ PULONG pBusNumber) PURE;

    // GetAddressSpace():
    //
    // Identifies a particular address space.  This is typically 1.
    //
    // If this is not relevant, E_NOT_SET is returned.
    //
    STDMETHOD(GetAddressSpace)(
        THIS_
        _Out_ PULONG pAddressSpace) PURE;
};

//
// Interface  : ISvcPageFileReader
//
// Provided By: DEBUG_SERVICE_PAGEFILE_READER
//
// Defines a means of reading a page (or partial page) of data out of the pagefile or whatever
// the underlying system's backing store for paged out data is.
//

// @Q: Is this machine specific?  Memory compression probably isn't...  but the interpretation of the PTE
//     information which leads to it probably is.  Is there a better way to abstract this?
//
#undef INTERFACE
#define INTERFACE ISvcPageFileReader
DECLARE_INTERFACE_(ISvcPageFileReader, IUnknown)
{
    //*************************************************
    // ISvcPageFileReader:
    //

    // IsPageAvailable():
    //
    // Indicates whether a page can be read by the page file reader.
    //
    STDMETHOD(IsPageAvailable)(
        THIS_
        _In_ ISvcAddressContext* AddressContext,
        _In_ ULONG64 TranslationEntry,
        _Out_ bool* PageIsAvailable
        ) PURE;

    // ReadPage():
    //
    // Reads data from the page file (or another backing store).
    //
    STDMETHOD(ReadPage)(
        THIS_
        _In_ ISvcAddressContext* AddressContext,
        _In_ ULONG64 TranslationEntry,
        _In_ ULONG64 ByteCount,
        _Out_writes_(ByteCount) PVOID* Buffer
        ) PURE;

};

//
// Interface  : ISvcProcessEnumerator
//
// Provided By:
//
#undef INTERFACE
#define INTERFACE ISvcProcessEnumerator
DECLARE_INTERFACE_(ISvcProcessEnumerator, IUnknown)
{
    //*************************************************
    // ISvcProcessEnumerator

    // Reset():
    //
    // Resets the enumerator.
    //
    STDMETHOD(Reset)(
        THIS
        ) PURE;

    // GetNext():
    //
    // Gets the next process from the enumerator.
    //
    STDMETHOD(GetNext)(
        THIS_
        _COM_Outptr_ ISvcProcess** targetProcess
        ) PURE;
};

//
// Interface  : ISvcProcessEnumeration
//
// Provided By:
//
//
#undef INTERFACE
#define INTERFACE ISvcProcessEnumeration
DECLARE_INTERFACE_(ISvcProcessEnumeration, IUnknown)
{
    //*************************************************
    // ISvcProcessEnumeration

    // FindProcess():
    //
    // Finds a process by a unique key.  The interpretation and semantic meaning of the key is specific
    // to the service which provides this.  For Windows Kernel mode, this may be a service which returns o
    // an ISvcProcess from a target EPROCESS pointer.  For user mode, it might be the process ID.
    //
    STDMETHOD(FindProcess)(
        THIS_
        _In_ ULONG64 processKey,
        _COM_Outptr_ ISvcProcess** targetProcess
        ) PURE;

    // EnumerateProcesses():
    //
    // Returns an enumerator object which is capable of enumerating all processes on the target and
    // creating an ISvcProcess for them.
    //
    STDMETHOD(EnumerateProcesses)(
        THIS_
        _COM_Outptr_ ISvcProcessEnumerator** targetProcessEnumerator
        ) PURE;
};

// Interface  : ISvcConnectableProcess
//
// Provided By:
//
#undef INTERFACE
#define INTERFACE ISvcConnectableProcess
DECLARE_INTERFACE_(ISvcConnectableProcess, IUnknown)
{
    //*************************************************
    // ISvcConnectableProcess:
    //

    // GetExecutablePath()
    //
    // Gets the full path to the process executable.
    //
    STDMETHOD(GetExecutablePath)(
        THIS_
        _Out_ BSTR *executablePath
        ) PURE;

    // GetArguments():
    //
    // Gets the arguments to the executable (if available).  A connectable process may return
    // E_NOTIMPL here if this cannot be determined for the given platform.
    //
    STDMETHOD(GetArguments)(
        THIS_
        _Out_ BSTR *executableArguments
        ) PURE;

    // GetId():
    //
    // Gets the process ID as identified by the underlying system.
    //
    STDMETHOD(GetId)(
        THIS_
        _Out_ ULONG64 *processId
        ) PURE;

    // GetUser():
    //
    // Gets the user name as identified by the underlying system.  A connectable process may return
    // E_NOTIMPL here if this cannot be determined for the given platform.
    //
    STDMETHOD(GetUser)(
        THIS_
        _Out_ BSTR *user
        ) PURE;
};

// Interface  : ISvcConnectableProcessEnumerator
//
// Provided By:
//
#undef INTERFACE
#define INTERFACE
DECLARE_INTERFACE_(ISvcConnectableProcessEnumerator, IUnknown)
{
    //*************************************************
    // ISvcConnectableProcessEnumerator:
    //

    // Reset():
    //
    // Resets the enumerator to the first process.
    //
    STDMETHOD(Reset)(
        THIS
        ) PURE;

    // GetNext():
    //
    // Gets the next connectable process in the list.
    //
    STDMETHOD(GetNext)(
        THIS_
        _COM_Outptr_ ISvcConnectableProcess **connectableProcess
        ) PURE;
};

// SvcAttachFlags:
//
// Flags that define behaviors of attaching to (or creating) a new process.
//
enum SvcAttachFlags
{
    // No flags
    SvcAttachNone = 0x00000000,

    // Indicates that child processes of the given process should automatically be debugged.
    SvcAttachChildProcesses = 0x00000001
};

// Interface  : ISvcProcessConnector
//
// Provided By: A process connector service which acts as a "process server" similar to a DbgSrv or
//              "gdbserver --multi" instance.
//
#undef INTERFACE
#define INTERFACE ISvcProcessConnector
DECLARE_INTERFACE_(ISvcProcessConnector, IUnknown)
{
    //*************************************************
    // ISvcProcessConnection:
    //

    // EnumerateConnectableProcesses():
    //
    // Enumerates all of the processes on the server which are connectable.
    //
    STDMETHOD(EnumerateConnectableProcesses)(
        THIS_
        _COM_Outptr_ ISvcConnectableProcessEnumerator **connectableProcessEnum
        ) PURE;

    // AttachProcess():
    //
    // Attaches to a process on the process server.  After a successful call to this method, the process
    // enumeration service is expected to enumerate the process.
    //
    STDMETHOD(AttachProcess)(
        THIS_
        _In_ ULONG64 pid,
        _In_ SvcAttachFlags attachFlags,
        _COM_Outptr_ ISvcProcess **ppProcess
        ) PURE;

    // CreateProcess():
    //
    // Creates a process on the process server.  After a successful call to this method, the process
    // enumeration service is expected to enumerate the process.
    //
    // The 'executablePath' and 'commandLine' arguments behave similarly to Windows CreateProcess* call.
    //
    // If both are specified, 'executablePath' is the path to the executable and 'commandLine' is the full
    // command line (which a plug-in may or may not need to parse/separate depending on the underlying system)
    //
    // If 'executablePath' is nullptr and 'commandLine' is not, the first argument of 'commandLine' is the executable
    // to utilize.  Such argument must be separated by standard means (white space separated allowing for the
    // use of quotation marks)
    //
    // If 'executablePath' is not nullptr and 'commandLine' is, it is assumed that 'executablePath' is also the
    // command line.
    //
    STDMETHOD(CreateProcess)(
        THIS_
        _In_opt_ PCWSTR executablePath,
        _In_opt_ PCWSTR commandLine,
        _In_ SvcAttachFlags attachFlags,
        _In_opt_ PCWSTR workingDirectory,
        _COM_Outptr_ ISvcProcess **ppProcess
        ) PURE;
};

//
// Interface  : ISvcThread
//
// Provided By:
//
// It is expected that any implementation of ISvcThread will successfully QI for ISvcExecutionUnit in order
// to read thread context and provide other core attributes of something which can successfully "step"
//
#undef INTERFACE
#define INTERFACE ISvcThread
DECLARE_INTERFACE_(ISvcThread, IUnknown)
{
    //*************************************************
    // ISvcThread:
    //

    // GetContainingProcessKey():
    //
    // Gets the unique key of the process to which this thread belongs.  This is the same key returned
    // from the containing ISvcProcess's GetKey method.
    //
    STDMETHOD(GetContainingProcessKey)(
        _Out_ PULONG64 containingProcessKey
        ) PURE;

    // GetKey():
    //
    // Gets the unique "per-process" thread key.  The interpretation of this key is dependent upon
    // the service which provides this interface.  For Windows Kernel, this may be the address of
    // an ETHREAD in the target.  For Windows User, this may be the TID.
    //
    STDMETHOD(GetKey)(
        THIS_
        _Out_ PULONG64 threadKey
        ) PURE;

    // GetId():
    //
    // Gets the thread's ID as defined by the underlying platform.  This may or may not be the same
    // value as returned from GetKey.
    //
    STDMETHOD(GetId)(
        THIS_
        _Out_ PULONG64 threadId
        ) PURE;

};

//
// Interface  : ISvcThreadEnumerator
//
// Provided By:
//
#undef INTERFACE
#define INTERFACE ISvcThreadEnumerator
DECLARE_INTERFACE_(ISvcThreadEnumerator, IUnknown)
{
    //*************************************************
    // ISvcThreadEnumerator

    // Reset():
    //
    // Resets the enumerator.
    //
    STDMETHOD(Reset)(
        THIS
        ) PURE;

    // GetNext():
    //
    // Gets the next thread from the enumerator.
    //
    STDMETHOD(GetNext)(
        THIS_
        _COM_Outptr_ ISvcThread** targetThread
        ) PURE;
};

//
// Interface  : ISvcThreadEnumeration
//
// Provided By:
//
//
#undef INTERFACE
#define INTERFACE ISvcThreadEnumeration
DECLARE_INTERFACE_(ISvcThreadEnumeration, IUnknown)
{
    //*************************************************
    // ISvcThreadEnumeration

    // FindThread():
    //
    // Finds a thread by a unique key.  The interpretation and semantic meaning of the key is specific
    // to the service which provides this.  For Windows Kernel mode, this may be a service which returns o
    // an ISvcThread from a target ETHREAD pointer.  For user mode, it might be the thread ID.
    //
    STDMETHOD(FindThread)(
        THIS_
        _In_ ISvcProcess* process,
        _In_ ULONG64 threadKey,
        _COM_Outptr_ ISvcThread** targetThread
        ) PURE;

    // EnumerateThreads():
    //
    // Returns an enumerator object which is capable of enumerating all processes on the target and
    // creating an ISvcProcess for them.
    //
    STDMETHOD(EnumerateThreads)(
        THIS_
        _In_ ISvcProcess* process,
        _COM_Outptr_ ISvcThreadEnumerator** targetThreadEnumerator
        ) PURE;
};

//
// Interface  : ISvcThreadLocalStorageProvider
//
// Provided By:
//
//
#undef INTERFACE
#define INTERFACE ISvcThreadLocalStorageProvider
DECLARE_INTERFACE_(ISvcThreadLocalStorageProvider, IUnknown)
{
    //*************************************************
    // ISvcThreadLocalStorageProvider

    // GetTLSBlockAddress():
    //
    // Returns the base address of a module's TLS block for a given thread.
    //
    STDMETHOD(GetTLSBlockAddress)(
        THIS_
        _In_ ISvcModule* pModule,
        _In_ ISvcThread* pThread,
        _Out_ PULONG64 pAddress
        ) PURE;
};

//
// Interface  : ISvcAddressRangeEnumerator
//
// Enumerates a set of one or more address ranges.
//
#undef INTERFACE
#define INTERFACE ISvcAddressRangeEnumerator
DECLARE_INTERFACE_(ISvcAddressRangeEnumerator, IUnknown)
{
    // Reset():
    //
    // Resets the enumerator.
    //
    STDMETHOD(Reset)(
        THIS
        ) PURE;

    // GetNext():
    //
    // Gets the next address range from the enumerator.
    //
    STDMETHOD(GetNext)(
        THIS_
        _Out_ SvcAddressRange *pAddressRange
        ) PURE;
};

//
// Interface  : ISvcModule
//
// Provided By:
//
#undef INTERFACE
#define INTERFACE ISvcModule
DECLARE_INTERFACE_(ISvcModule, IUnknown)
{
    //*************************************************
    // ISvcModule:
    //

    // GetContainingProcessKey():
    //
    // Gets the unique key of the process to which this thread belongs.  This is the same key returned
    // from the containing ISvcProcess's GetKey method.
    //
    // This method may return S_FALSE and a process key of zero for modules which do not logically belong
    // to any process (e.g.: they are kernel modules / drivers that are mapped into every process)
    //
    STDMETHOD(GetContainingProcessKey)(
        _Out_ PULONG64 containingProcessKey
        ) PURE;

    // GetKey():
    //
    // Gets the unique "per-process" module key.  The interpretation of this key is dependent upon
    // the service which provides this interface.  This may be the base address of the module.
    //
    STDMETHOD(GetKey)(
        THIS_
        _Out_ PULONG64 moduleKey
        ) PURE;

    // GetBaseAddress():
    //
    // Gets the base address of the module.
    //
    STDMETHOD(GetBaseAddress)(
        THIS_
        _Out_ PULONG64 moduleBaseAddress
        ) PURE;

    // GetSize():
    //
    // Gets the size of the module.
    //
    STDMETHOD(GetSize)(
        THIS_
        _Out_ PULONG64 moduleSize
        ) PURE;

    // GetName():
    //
    // Gets the name of the module.
    //
    STDMETHOD(GetName)(
        THIS_
        _Out_ BSTR *moduleName
        ) PURE;

    // GetPath():
    //
    // Gets the load path of the module.
    //
    STDMETHOD(GetPath)(
        THIS_
        _Out_ BSTR *modulePath
        ) PURE;
};

//
// Interface  : ISvcModuleWithTimestampAndChecksum
//
// TODO: MSFT:ISvcModuleWithTimestampAndChecksum-Remove or edit ISvcModuleWithTimestampAndChecksum
// This is a temporary interface due to the urgency of the fix it helped address.
// It will change or be removed.
//
#undef INTERFACE
#define INTERFACE ISvcModuleWithTimestampAndChecksum
DECLARE_INTERFACE_(ISvcModuleWithTimestampAndChecksum, ISvcModule)
{
    //*************************************************
    // ISvcModule:
    //

    // GetContainingProcessKey():
    //
    // Gets the unique key of the process to which this thread belongs.  This is the same key returned
    // from the containing ISvcProcess's GetKey method.
    //
    // This method may return S_FALSE and a process key of zero for modules which do not logically belong
    // to any process (e.g.: they are kernel modules / drivers that are mapped into every process)
    //
    STDMETHOD(GetContainingProcessKey)(
        _Out_ PULONG64 containingProcessKey
        ) PURE;

    // GetKey():
    //
    // Gets the unique "per-process" module key.  The interpretation of this key is dependent upon
    // the service which provides this interface.  This may be the base address of the module.
    //
    STDMETHOD(GetKey)(
        THIS_
        _Out_ PULONG64 moduleKey
        ) PURE;

    // GetBaseAddress():
    //
    // Gets the base address of the module.
    //
    STDMETHOD(GetBaseAddress)(
        THIS_
        _Out_ PULONG64 moduleBaseAddress
        ) PURE;

    // GetSize():
    //
    // Gets the size of the module.
    //
    STDMETHOD(GetSize)(
        THIS_
        _Out_ PULONG64 moduleSize
        ) PURE;

    // GetName():
    //
    // Gets the name of the module.
    //
    STDMETHOD(GetName)(
        THIS_
        _Out_ BSTR *moduleName
        ) PURE;

    // GetPath():
    //
    // Gets the load path of the module.
    //
    STDMETHOD(GetPath)(
        THIS_
        _Out_ BSTR *modulePath
        ) PURE;

    //*************************************************
    // ISvcModuleWithTimestampAndChecksum:
    //

    // GetTimeDateStamp():
    //
    // Gets the time date stamp of the module.
    //
    STDMETHOD(GetTimeDateStamp)(
        THIS_
        _Out_ PULONG moduleTimeDateStamp
        ) PURE;

    // GetCheckSum():
    //
    // Gets the check sum of the module.
    //
    STDMETHOD(GetCheckSum)(
        THIS_
        _Out_ PULONG moduleCheckSum
        ) PURE;
};

//
// Interface   : ISvcAddressRangeEnumeration
//
#undef INTERFACE
#define INTERFACE ISvcAddressRangeEnumeration
DECLARE_INTERFACE_(ISvcAddressRangeEnumeration, IUnknown)
{
    //*************************************************
    // ISvcAddressRangeEnumeration:
    //

    // EnumerateAddressRanges():
    //
    // Enumerates a set of address ranges which define a memory layout.
    //
    // For modules:
    //
    // Enumerates the set of address ranges which define the memory layout of the module.  The first
    // enumerated range *MUST* be the range returned from GetBaseAddress() and GetSize() for the module.
    //
    // It is legal for this method to return E_NOTIMPL for modules which are defined by a contiguous linear
    // range of addresses [baseAddress, baseAddress + size).  Any module which is defined by more than one
    // range *MUST* return the *LOWEST* address range in GetBaseAddress() and GetSize() and must return
    // S_FALSE from those two methods.
    //
    // Likewise, the implementation of the module enumeration service should be able to map any address returned
    // here to the given module.
    //
    STDMETHOD(EnumerateAddressRanges)(
        THIS_
        _COM_Outptr_ ISvcAddressRangeEnumerator **ppEnum
        ) PURE;
};

// SvcMappingForm:
//
// Indicates the form in which some object is memory mapped.
//
enum SvcMappingForm
{
    // SvcMappingUnknown:
    //
    // Indicates that no determination can be made.
    //
    SvcMappingUnknown,

    // SvcMappingLoaded:
    //
    // Indicates that the object is loaded.  This usually indicates something like a PE image
    // or an ELF image was mapped into memory the way a PE or ELF loader would map it.
    //
    SvcMappingLoaded,

    // SvcMappingFlat:
    //
    // Indicates that the object is mapped flat.  This indicates pages of memory correspond 1:1
    // to pages of the object.  This would be a regular memory mapped file.  For something like a PE image
    // or an ELF image that was mapped into memory, it would indicate it was mapped as if any other file
    // and not placing image pages according to section header addresses or program header addresses.
    //
    SvcMappingFlat,
};

//
// Interface  : ISvcMappingInformation
//
// Provided By :
//
// Indicates information about a file or image and how it was mapped into memory.  An implemtnation of
// ISvcModule can optionally support this interface to indicate how the image was placed into memory.
//
// If this interface is *NOT* implemented on an ISvcModule, callers should assume that the module is
// a standard load (e.g.: SvcMappingLoaded).
//
#undef INTERFACE
#define INTERFACE ISvcMappingInformation
DECLARE_INTERFACE_(ISvcMappingInformation, IUnknown)
{
    //*************************************************
    // ISvcMappingInformation:
    //

    // GetMappingForm():
    //
    // Gets the manner in which the object QI'd for this interface is mapped into memory.
    //
    STDMETHOD_(SvcMappingForm, GetMappingForm)(
        THIS
        ) PURE;
};

//
// Interface  : ISvcModuleEnumerator
//
// Provided By:
//
#undef INTERFACE
#define INTERFACE ISvcModuleEnumerator
DECLARE_INTERFACE_(ISvcModuleEnumerator, IUnknown)
{
    //*************************************************
    // ISvcModuleEnumerator

    // Reset():
    //
    // Resets the enumerator.
    //
    STDMETHOD(Reset)(
        THIS
        ) PURE;

    // GetNext():
    //
    // Gets the next module from the enumerator.
    //
    STDMETHOD(GetNext)(
        THIS_
        _COM_Outptr_ ISvcModule** targetModule
        ) PURE;
};

//
// Interface  : ISvcModuleEnumeration
//
// Provided By:
//
//
#undef INTERFACE
#define INTERFACE ISvcModuleEnumeration
DECLARE_INTERFACE_(ISvcModuleEnumeration, IUnknown)
{
    //*************************************************
    // ISvcModuleEnumeration

    // FindModule():
    //
    // Finds a module by a unique key.  The interpretation and semantic meaning of the key is specific
    // to the service which provides this.  This may be the base address of the module.
    //
    STDMETHOD(FindModule)(
        THIS_
        _In_opt_ ISvcProcess* process,
        _In_ ULONG64 moduleKey,
        _COM_Outptr_ ISvcModule** targetModule
        ) PURE;

    // FindModuleAtAddress():
    //
    // Finds a module by an address.
    //
    STDMETHOD(FindModuleAtAddress)(
        THIS_
        _In_opt_ ISvcProcess* process,
        _In_ ULONG64 moduleAddress,
        _COM_Outptr_ ISvcModule** targetModule
        ) PURE;

    // EnumerateModules():
    //
    // Returns an enumerator object which is capable of enumerating all modules in the given process and
    // creating an ISvcModule for them.
    //
    STDMETHOD(EnumerateModules)(
        THIS_
        _In_opt_ ISvcProcess* process,
        _COM_Outptr_ ISvcModuleEnumerator** targetModuleEnumerator
        ) PURE;
};

//
// Interface  : ISvcPrimaryModules
//
// Provided By: [Optional] Module enumeration service
//
// The ISvcPrimaryModules (and derivative) interface(s) may optionally be provided on the module enumeration service to
// indicate key modules of a process.  Typically, this is used to determine the main executable image of a given
// process.
//
#undef INTERFACE
#define INTERFACE ISvcPrimaryModules
DECLARE_INTERFACE_(ISvcPrimaryModules, IUnknown)
{
    //*************************************************
    // ISvcPrimaryModules:
    //

    // FindExecutableModule():
    //
    // Finds the main executable module for the given process.  This is the executable image which started
    // the given process.  For a non-process context (e.g.: a kernel), this may be defined as the kernel
    // image.
    //
    STDMETHOD(FindExecutableModule)(
        THIS_
        _In_opt_ ISvcProcess* process,
        _COM_Outptr_ ISvcModule** executableModule
        ) PURE;
};

//
// Interface  : ISvcModuleIndexProvider
//
// Provided By:
//
//
#undef INTERFACE
#define INTERFACE ISvcModuleIndexProvider
DECLARE_INTERFACE_(ISvcModuleIndexProvider, IUnknown)
{

    //*************************************************
    // ISvcModuleIndexProvider

    // GetModuleIndexKey():
    //
    // Gets a key for the given module which is used as an index on the symbol server.
    //
    STDMETHOD(GetModuleIndexKey)(
        THIS_
        _In_ ISvcModule *pModule,
        _Out_ BSTR *pModuleIndex,
        _Out_ GUID *pModuleIndexKind
        ) PURE;
};

//
// Interface  : ISourceCodeDownloadUrlLinkProvider
//
// Provider By:
//
//
#undef INTERFACE
#define INTERFACE ISourceCodeDownloadUrlLinkProvider
DECLARE_INTERFACE_(ISourceCodeDownloadUrlLinkProvider, IUnknown)
{

    //*************************************************
    // ISourceCodeDownloadUrlLinkProvider

    // ProvideSourceCodeFileUrlList():
    //
    // Retrieves the list of download URLs for the specified file.
    // To the best knowledge of the provider this list is the location
    // where the source file might be found. It is the responsibility of
    // the caller to determine exactly where the source file is located
    // (by trying to download the file from the provided url list).
    //
    // The returned list is a one dimentional SAFEARRAY where
    // the type of the elements is VT_BSTR or VT_VARIANT of type VT_BSTR
    // The URLs can be "full" URL - something like "http://...." or "https://www....",
    // or can be a "partial/suffix" URL - something like name1/name2/name3, and the debugger will
    // build the final "full" URL by adding the suffix to a URL.
    //
    // The method receives the following parameters:
    // - sourceCodeFileSpec - The file spacification of the file to be downloade (for ex:shell\osshell\accesory\notepad\notepad.cpp)
    //                        The separator may be '\' or '/' character
    // - algorithmRetrievalName - it may be something like "DebugInfoD", "srv", etc.
    // - algorithmParameters - optional parameters needed for the regrieval alroithm
    //
    STDMETHOD(ProvideSourceCodeFileUrlList)(
        THIS_
        _In_ ISvcModule * pModule,
        _In_ PCWSTR sourceCodeFileSpec,
        _In_ PCWSTR algorithmRetrievalName,
        _In_opt_ PCWSTR algorithmParameters,
        _Out_ SAFEARRAY ** ppUrlList
        ) PURE;
};

//
// Interface  : IClrDacAndSosProvider
//
// Provider By:
//
//
#undef INTERFACE
#define INTERFACE IClrDacAndSosProvider
DECLARE_INTERFACE_(IClrDacAndSosProvider, IUnknown)
{

    //*************************************************
    // IClrDacAndSosProvider

    // IsClrImage():
    //
    // Determines if an image/module is a CLR image and if
    // it can provide (retrieve/download/etc.) the CLR DAC and SOS for it.
    //
    STDMETHOD(IsClrImage)(
        THIS_
        _In_ ISvcModule* module,
        _Out_ bool *pIsClrImage,
        _Out_opt_ bool *pbCanProvideClrDac,
        _Out_opt_ bool *pbCanProvideClrSos
        ) PURE;

    // ProvideClrDac():
    //
    // Retrieves/downloads/etc. the CLR DAC.
    //
    STDMETHOD(ProvideClrDac)(
        THIS_
        _In_ ISvcModule* pModule,
        _In_opt_ PCTSTR forcePath,
        _Out_ BSTR* pDacPath
        ) PURE;

    // ProvideClrSos():
    //
    // Retrieves/downloads/etc. the CLR SOS.
    //
    STDMETHOD(ProvideClrSos)(
        THIS_
        _In_ ISvcModule* pModule,
        _In_opt_ PCTSTR forcePath,
        _Out_ BSTR* pSosPath
        ) PURE;
};

//
// Interface  : IClrDacDbiAndSosProvider
//
// Provided By:
//
#undef INTERFACE
#define INTERFACE IClrDacDbiAndSosProvider
DECLARE_INTERFACE_(IClrDacDbiAndSosProvider, IClrDacAndSosProvider)
{
    //*************************************************
    // IClrDacAndSosProvider

    // IsClrImage():
    //
    // Determines if an image/module is a CLR image and if
    // it can provide (retrieve/download/etc.) the CLR DAC and SOS for it.
    //
    STDMETHOD(IsClrImage)(
        THIS_
        _In_ ISvcModule* module,
        _Out_ bool *pIsClrImage,
        _Out_opt_ bool *pbCanProvideClrDac,
        _Out_opt_ bool *pbCanProvideClrSos
        ) PURE;

    // ProvideClrDac():
    //
    // Retrieves/downloads/etc. the CLR DAC.
    //
    STDMETHOD(ProvideClrDac)(
        THIS_
        _In_ ISvcModule* pModule,
        _In_opt_ PCTSTR forcePath,
        _Out_ BSTR* pDacPath
        ) PURE;

    // ProvideClrSos():
    //
    // Retrieves/downloads/etc. the CLR SOS.
    //
    STDMETHOD(ProvideClrSos)(
        THIS_
        _In_ ISvcModule* pModule,
        _In_opt_ PCTSTR forcePath,
        _Out_ BSTR* pSosPath
        ) PURE;

    //*************************************************
    // IClrDacDbiAndSosProvider
    //

    // IsClrImageEx():
    //
    // Determines if an image/module is a CLR image and if
    // it can provide (retrieve/download/etc.) the CLR DAC, DBI, and SOS for it.
    //
    STDMETHOD(IsClrImageEx)(
        THIS_
        _In_ ISvcModule* module,
        _Out_ bool *pIsClrImage,
        _Out_opt_ bool *pbCanProvideClrDac,
        _Out_opt_ bool *pbCanProvideClrDbi,
        _Out_opt_ bool *pbCanProvideClrSos
        ) PURE;

    // ProvideClrDbi():
    //
    // Retrieves/downloads/etc. the CLR DBI.
    //
    STDMETHOD(ProvideClrDbi)(
        THIS_
        _In_ ISvcModule* pModule,
        _In_opt_ PCTSTR forcePath,
        _Out_ BSTR* pDbiPath
        ) PURE;
};

//
// Interface  : ISvcContextTranslation
//
// Provided By: DEBUG_SERVICE_EXECUTION_CONTEXT_TRANSLATION
//
// Defines a means of translating from one context to another (e.g.: native to WoW, emulator to emulatee, etc...)
//
#undef INTERFACE
#define INTERFACE ISvcContextTranslation
DECLARE_INTERFACE_(ISvcContextTranslation, IUnknown)
{
    // GetTranslatedContext():
    //
    // Gets a translated context record for the given execution unit (thread or core).
    //
    STDMETHOD(GetTranslatedContext)(
        THIS_
        _In_ ISvcExecutionUnit* execUnit,
        _In_ SvcContextFlags contextFlags,
        _COM_Outptr_ ISvcRegisterContext** context
        ) PURE;

    // SetTranslatedContext():
    //
    // Sets a translated context record to the given execution unit (thread or core).
    //
    STDMETHOD(SetTranslatedContext)(
        THIS_
        _In_ ISvcExecutionUnit* execUnit,
        _In_ SvcContextFlags contextFlags,
        _In_ ISvcRegisterContext* context
        ) PURE;
};

//
// Interface: ISvcActiveExceptions
//
// Provided By: DEBUG_SERVICE_ACTIVE_EXCEPTIONS
//
// Defines a means of getting the currently active exceptions on execution units or stored within post-mortem
// data associated with a process.
//
#undef INTERFACE
#define INTERFACE ISvcActiveExceptions
DECLARE_INTERFACE_(ISvcActiveExceptions, IUnknown)
{
    // GetLastExceptionEvent()
    //
    // Gets the last exception event for a particular process.  For a post-mortem target, this is often
    // the "reason" for a snapshot.  Such exceptional event is represented by an ISvcExceptionInformation
    // interface but may represent a Win32 exception, a Linux signal, or something else entirely.
    //
    // If there is no "last exception event", E_NOT_SET may be returned.
    //
    STDMETHOD(GetLastExceptionEvent)(
        THIS_
        _In_opt_ ISvcProcess *pProcess,
        _COM_Outptr_ ISvcExceptionInformation** exceptionInfo
        ) PURE;

    // GetActiveExceptionEvent():
    //
    // Gets the active exception event for a particular execution unit.  As with GetLastExceptionEvent,
    // such exceptional event is represented by an ISvcExceptionInformation interface but may represent
    // a Win32 exception, a Linux signal, or something else entirely.
    //
    // If there is no "active exception event", E_NOT_SET may be returned.
    //
    STDMETHOD(GetActiveExceptionEvent)(
        THIS_
        _In_ ISvcExecutionUnit *pExecutionUnit,
        _COM_Outptr_ ISvcExceptionInformation** exceptionInfo
        ) PURE;
};


// SvcExceptionKind:
//
// Defines the kind of exceptional event.
//
enum SvcExceptionKind
{
    // Unknown exception type
    SvcException,

    // Exception is a Win32 exception.
    //
    // Canonical data representation (optionally provided) is an EXCEPTION_RECORD64
    //
    SvcExceptionWin32,

    // Exception is a Linux signal.  ISvcLinuxSignalInformation is supported.
    //
    // Canonical data representation (optionally provided) is a 64-bit siginfo_t
    //
    SvcExceptionLinuxSignal,

    // Exception is a Linux kernel panic.
    //
    SvcExceptionLinuxKernelPanic,

    // Exception is a Windows kernel bugcheck.  ISvcWindowsBugCheckInformation is supported.
    //
    SvcExceptionWindowsBugCheck
};

//
// Interface  : ISvcExceptionInformation
//
// Provided By:
//
#undef INTERFACE
#define INTERFACE ISvcExceptionInformation
DECLARE_INTERFACE_(ISvcExceptionInformation, IUnknown)
{
    // GetExceptionKind():
    //
    // Gets the kind of exception this represents.
    //
    STDMETHOD(GetExceptionKind)(
        THIS_
        _Out_ SvcExceptionKind *pExceptionKind
        ) PURE;

    // GetAddress():
    //
    // Gets the address associated with the exception.  Some exceptions (e.g.: Win32 exceptions and Linux
    // fault type signals) have an address associated with them and some don't.
    //
    // This method will return E_NOT_SET if an address is unavailable for the exceptional event.
    //
    STDMETHOD(GetAddress)(
        THIS_
        _Out_ ULONG64 *pSignalAddress
        ) PURE;

    // GetContext():
    //
    // Gets the register context associated with the signal.  This may legitimately return E_NOT_SET in
    // many (particularly post-mortem) cases.
    //
    STDMETHOD(GetContext)(
        THIS_
        _In_ SvcContextFlags contextFlags,
        _COM_Outptr_ ISvcRegisterContext **ppRegisterContext
        ) PURE;

    // GetExecutionUnit():
    //
    // Gets the execution unit on which the exceptional event occurred.
    //
    STDMETHOD(GetExecutionUnit)(
        THIS_
        _COM_Outptr_ ISvcExecutionUnit** executionUnit
        ) PURE;

    // GetDataRecordSize():
    //
    // Gets the size of any data structure associated with this exception (e.g.: an EXCEPTION_RECORD64, a siginfo_t,
    // or whatever a specific architecture/platform define)
    //
    // If there is no available data associated, 0 is returned.  It is entirely optional for a given implementation
    // to provide this.
    //
    STDMETHOD_(ULONG64, GetDataRecordSize)(
        THIS
        ) PURE;

    // FillDataRecord():
    //
    // Fills a supplied buffer with a copy of the canonicalized data record for this given exception type.  If no such
    // record is defined, GetDataRecordSize will return 0 and this method will return E_NOTIMPL.
    //
    // If there is no available data associated, E_NOTIMPL is returned.  It is entirely optional for a given
    // implementation to provide this.  Each given exception kind has a specific interface
    // (e.g.: ISvcLinuxSignalInformation) which provides more detailed information based on potentially parsing the
    // given data record.  The vast majority of consumers should rely on those interfaces and not try to get
    // the underlying data record that a service provider understands.
    //
    STDMETHOD(FillDataRecord)(
        THIS_
        _In_ ULONG64 bufferSize,
        _Out_writes_(bufferSize) PVOID buffer,
        _Out_ ULONG64 *bytesWritten
        ) PURE;
};

//
// Interface  : ISvcExceptionControl
//
// Provided By:
//
// Notes:
//
//     If a target which supports live debugging issues a state change notification to the halted
//     state for an "exception", that "exception" should support both ISvcExceptionInformation *AND*
//     ISvcExceptionControl.  This interface is only necessary for controlling exception flow
//     within a live target.
//
#undef INTERFACE
#define INTERFACE ISvcExceptionControl
DECLARE_INTERFACE_(ISvcExceptionControl, IUnknown)
{
    // IsFirstChance():
    //
    // Indicates whether this exception is the first or second chance.  If the target cannot make a
    // determination of first/second chance, E_NOTIMPL should be returned.
    //
    STDMETHOD(IsFirstChance)(
        THIS_
        _Out_ bool *isFirstChance
        ) PURE;

    // WillPassToTarget():
    //
    // Indicates whether this exception will be passed onto the target or will be considered handled
    // by the halt.
    //
    STDMETHOD_(bool, WillPassToTarget)(
        THIS
        ) PURE;

    // PassToTarget():
    //
    // Indicates that this exception should be passed to the target.  Flags are currently reserved
    // and should be set to zero.
    //
    // If this exception is a form that CANNOT be passed to the target, E_ILLEGAL_METHOD_CALL should
    // be returned.  If the target is incapable of passing the exception on, E_NOTIMPL should
    // be returned.
    //
    // NOTE: The exception is not *ACTUALLY* passed to the target until the target resumes execution via
    //       a call to the step controller.
    //
    STDMETHOD(PassToTarget)(
        THIS_
        _In_ ULONG flags
        ) PURE;

    // Handle():
    //
    // Indicates that this exception should *NOT* be passed to the target and should be considered handled
    // by the debugger.  Flags are currently reserved and should be set to zero.
    //
    // If this exception is a form that CANNOT be passed to the target, E_ILLEGAL_METHOD_CALL should
    // be returned.  If the target is incapable of handling exceptions without passing them on,
    // E_NOTIMPL should be returned.
    //
    // NOTE: The excepiton is not *ACTUALLY* handled and dismissed until the target resumes execution via
    //       a call to the step controller.
    //
    STDMETHOD(Handle)(
        THIS_
        _In_ ULONG flags
        ) PURE;
};

//
// Interface  : ISvcExceptionFormatter
//
// Provided By: DEBUG_SERVICE_EXCEPTION_FORMATTER
//
#undef INTERFACE
#define INTERFACE ISvcExceptionFormatter
DECLARE_INTERFACE_(ISvcExceptionFormatter, IUnknown)
{
    // GetDescription():
    //
    // Gets a description of the given exceptional event (Win32 exception, Linux signal, etc...)
    //
    STDMETHOD(GetDescription)(
        THIS_
        _In_ ISvcExceptionInformation* exceptionInformation,
        _Out_ BSTR* exceptionDescription
        ) PURE;
};

//
// Interface  : ISvcDescription
//
// Provided By: Various objects returned from services (processes, threads, symbol sets, etc...)
//
#undef INTERFACE
#define INTERFACE ISvcDescription
DECLARE_INTERFACE_(ISvcDescription, IUnknown)
{
    // GetDescription():
    //
    // Gets a description of the object on which the interface exists.  This is intended for short textual
    // display in some UI element.
    //
    STDMETHOD(GetDescription)(
        THIS_
        _Out_ BSTR* objectDescription
        ) PURE;
};

//
// Interface  : ISvcPrivateProperties
//
// Provided By: Various services
//
#undef INTERFACE
#define INTERFACE ISvcPrivateProperties
DECLARE_INTERFACE_(ISvcPrivateProperties, IUnknown)
{
    // HasProperty():
    //
    // Indicates whether this object supports a private property.
    //
    STDMETHOD(HasProperty)(
        THIS_
        _In_ REFGUID set,
        _In_ ULONG id,
        _Out_ bool *hasProperty
        ) PURE;

    // GetProperty():
    //
    // Gets a private property.
    //
    STDMETHOD(GetProperty)(
        THIS_
        _In_ REFGUID set,
        _In_ ULONG id,
        _In_ ULONG bufferSize,
        _Out_writes_(bufferSize) PVOID buffer
        ) PURE;

    // SetProperty():
    //
    // Sets a private property.
    //
    STDMETHOD(SetProperty)(
        THIS_
        _In_ REFGUID set,
        _In_ ULONG id,
        _In_ ULONG valueSize,
        _In_reads_(valueSize) PVOID valueBuffer
        ) PURE;
};

//**************************************************************************
// Operating System Specific Services:
//

//
// Interface  : ISvcWindowsKdInfrastructure
//
// Provided By:
//
#undef INTERFACE
#define INTERFACE ISvcWindowsKdInfrastructure
DECLARE_INTERFACE_(ISvcWindowsKdInfrastructure, IUnknown)
{
    //
    // FindKdVersionBlock():
    //
    // Finds the KD version block and returns its address.  If the version block is not located within
    // the address space of the debug source, this may fail.  In such cases, GetKdVersionBlock may be called.
    //
    STDMETHOD(FindKdVersionBlock)(
        THIS_
        _Out_ ULONG64* kdVersionBlockAddress
        ) PURE;

    //
    // FindKdDebuggerDataBlock():
    //
    // Finds the KD debugger data block and returns its address.  If the debugger data block is not located within
    // the address space of the debug source, this may fail.  In such cases, GetKdDebuggerDataBlock may be called.
    //
    STDMETHOD(FindKdDebuggerDataBlock)(
        THIS_
        _Out_ ULONG64* kdDebuggerDataBlockAddress
        ) PURE;

    // @TODO: GetKdVersionBlock

    //
    // GetKdDebuggerDataBlock():
    //
    // Retrieves a pointer to the read debugger data block in memory.  The valid size of the block is returned as well.
    // This pointer is guaranteed to be valid until the virtual memory service in the service stack changes.
    //
    // In this case, any cached copy of this pointer must be flushed and reread.
    //
    STDMETHOD(GetKdDebuggerDataBlock)(
        THIS_
        _Out_ KDDEBUGGER_DATA64 **kdDebuggerDataBlock,
        _Out_ ULONG64 *dataBlockSize
        ) PURE;
};

//
// Interface  : ISvcWindowsKernelInfrastructure
//
// Provided By:
//
#undef INTERFACE
#define INTERFACE ISvcWindowsKernelInfrastructure
DECLARE_INTERFACE_(ISvcWindowsKernelInfrastructure, IUnknown)
{
    //*************************************************
    // Core Data Structures:
    //

    //
    // FindKpcrForProcessor():
    //
    // Finds the KPCR for a given processor.
    //
    STDMETHOD(FindKpcrForProcessor)(
        THIS_
        _In_ ULONG64 processorNumber,
        _Out_ ULONG64 *kpcrAddress
        ) PURE;

    // FindKprcbForProcessor():
    //
    // Finds the KPRCB for a given processor.
    //
    STDMETHOD(FindKprcbForProcessor)(
        THIS_
        _In_ ULONG64 processorNumber,
        _Out_ ULONG64 *kprcbAddress
        ) PURE;

    // FindThreadForProcessor():
    //
    // Finds the KTHREAD which is executing on a given processor.
    //
    STDMETHOD(FindThreadForProcessor)(
        THIS_
        _In_ ULONG64 processorNumber,
        _Out_ ULONG64 *kthreadAddress
        ) PURE;

    //*************************************************
    // Abstractions:
    //

    // ReadContextForProcessor():
    //
    // Reads a context record from the KPRCB for a given processor.
    //
    STDMETHOD(ReadContextForProcessor)(
        THIS_
        _In_ ULONG64 processorNumber,
        _In_ SvcContextFlags contextFlags,
        _COM_Outptr_ ISvcRegisterContext **ppRegisterContext
        ) PURE;

    // ReadSpecialContextForProcessor():
    //
    // Reads the special registers from the KPRCB for a given processor.
    //
    STDMETHOD(ReadSpecialContextForProcessor)(
        THIS_
        _In_ ULONG64 processorNumber,
        _COM_Outptr_ ISvcRegisterContext **ppSpecialContext
        ) PURE;
};

//
// Interface  : ISvcWindowsExceptionTranslation
//
// Provided By:
//
#undef INTERFACE
#define INTERFACE ISvcWindowsExceptionTranslation
DECLARE_INTERFACE_(ISvcWindowsExceptionTranslation, IUnknown)
{
    // TranslateException():
    //
    // Translates the exception from one record to another.  It is legal for this method to do absolutely
    // nothing other than succeed (or return an S_FALSE indication of no translation)
    //
    STDMETHOD(TranslateException)(
        THIS_
        _In_ ISvcExecutionUnit *execUnit,
        _Inout_ EXCEPTION_RECORD64 *exceptionRecord
        ) PURE;
};

//
// Interface  : ISvcWindowsBugCheckInformation
//
// Provided By:
//
// Notes:
//     - All implementations of ISvcWindowsBugCheckInformation must also implement ISvcExceptionInformation
//
#undef INTERFACE
#define INTERFACE ISvcWindowsBugCheckInformation
DECLARE_INTERFACE_(ISvcWindowsBugCheckInformation, IUnknown)
{
    // GetBugCheckCode():
    //
    // Gets the bugcheck code.
    //
    STDMETHOD_(ULONG, GetBugCheckCode)(
        THIS
        ) PURE;

    // GetBugCheckData():
    //
    // Gets the bugcheck data.
    //
    STDMETHOD_(void, GetBugCheckData)(
        THIS_
        _Out_writes_(4) ULONG64 *pBugCheckData
        ) PURE;
};

//
// Interface  : ISvcWindowsThreadInformation
//
// Provided By:
//
#undef INTERFACE
#define INTERFACE ISvcWindowsThreadInformation
DECLARE_INTERFACE_(ISvcWindowsThreadInformation, IUnknown)
{
    // GetEnvironmentBlockAddress():
    //
    // Gets the address of the TEB for the given thread.
    //
    STDMETHOD(GetEnvironmentBlockAddress)(
        _Out_ ULONG64 *pTebAddress
        ) PURE;
};

//
// Interface  : ISvcWindowsProcessInformation
//
// Provided By:
//
#undef INTERFACE
#define INTERFACE ISvcWindowsProcessInformation
DECLARE_INTERFACE_(ISvcWindowsProcessInformation, IUnknown)
{
    // GetEnvironmentBlockAddress():
    //
    // Gets the address of the PEB for the given process.
    //
    STDMETHOD(GetEnvironmentBlockAddress)(
        _Out_ ULONG64 *pPebAddress
        ) PURE;
};

//
// Interface  : ISvcLinuxSignalInformation
//
// Provided By:
//
// Notes:
//     - All implementations of ISvcLinuxSignalInformation must also implement ISvcExceptionInformation
//
#undef INTERFACE
#define INTERFACE ISvcLinuxSignalInformation
DECLARE_INTERFACE_(ISvcLinuxSignalInformation, IUnknown)
{
    // GetSignalNumber():
    //
    // Gets the Linux signal number associated with the signal represented by this interface.
    //
    STDMETHOD_(int, GetSignalNumber)(
        THIS
        ) PURE;

    // GetErrorNumber():
    //
    // Gets the errno associated with this signal (if applicable; otherwise 0).
    //
    STDMETHOD_(int, GetErrorNumber)(
        THIS
        ) PURE;

    // GetSignalCode():
    //
    // Gets the signal code associated with this signal.
    //
    STDMETHOD_(int, GetSignalCode)(
        THIS
        ) PURE;

    // GetSourcePid():
    //
    // Gets the source PID for the origin of the signal if such information is included within the signal
    // record.  Otherwise, E_NOT_SET is returned.
    //
    STDMETHOD(GetSourcePid)(
        THIS_
        _Out_ ULONG64* sourcePid
        ) PURE;
};

//**************************************************************************
// Symbol Services:
//

//
// Symbol services provides a mechanism to define how symbols are acquired and what capabilities
// are expressed by them.
//
// A few key definitions of the abstract set of symbol services:
//
// Symbol Provider:
//     The symbol provider is a service which can look at an image, and return "the best" symbol set for the symbols
//     of the image.  A symbol provider may be an abstraction over a "symbol server" or may be some other mechanism.
//
// Symbol Set:
//     A symbol set is a grouping of symbolic information (often associated with a particular image).
//
// The interfaces that the implementer of a symbol set must provide in order to get functionality within the debugger
// are designed to be layered.  A simple symbol provider may only be able to provide a mapping from addresses to symbolic
// names and vice-versa.  Each layer requires the implementation of a progressively more complex (set of) interface(s).
//
// ISvcSymbol: the basic symbol interface
//     ISvcSymbol<...>: further query of symbolic information
//
// ISvcSymbolSet: the basic set interface
//     ISvcSymbolSet<...>: further query of symbolic information
//

// SvcSymbolKind:
//
// Defines the kind of a symbol and what it will respond to.  While the interfaces are somewhat different
// in this layer, the definitions here mirror the data model's "debug host" definitions
//
enum SvcSymbolKind
{
    // Unspecified symbol type.
    SvcSymbol,

    // Reserved: Unused (no "module level symbol" here)
    SvcSymbolReserved1,

    // The symbol is a type
    SvcSymbolType,

    // The symbol is a field
    SvcSymbolField,

    // The symbol is a constant
    SvcSymbolConstant,

    // The symbol is data which is not a field of a structure and is QI'able for IDebugHostData
    SvcSymbolData,

    // The symbol is a base class
    SvcSymbolBaseClass,

    // The symbol is a public symbol
    SvcSymbolPublic,

    // The symbol is a function symbol
    SvcSymbolFunction,

    //*************************************************
    // PRESENTLY NON MATCHING:
    //

    // The symbol is data which is a parameter to a function
    SvcSymbolDataParameter,

    // The symbol is data which is a function local
    SvcSymbolDataLocal,

    // The symbol is a namespace
    SvcSymbolNamespace,

    // The symbol is an inline function (other than being inlined, this behaves much like SvcSymbolFunction)
    SvcSymbolInlinedFunction,

    // The symbol is a compilation unit / compiland
    SvcSymbolCompilationUnit,

    // The symbol is a case of a tagged union UDT
    SvcSymbolTaggedUnionCase,
};

// SvcSymbolTypeKind:
//
// Defines the kind of type that a given type is.  While the interfaces are somewhat different in this layer,
// the definitions here mirror the data model's "debug host" definitions.
//
enum SvcSymbolTypeKind
{
    // The type is a UDT (user defined type -- a struct, class, etc...)
    SvcSymbolTypeUDT,

    // The type is a pointer
    //
    // The base type of a pointer as returned by GetBaseType() is the type pointed to.
    //
    SvcSymbolTypePointer,

    // The type is a member pointer
    SvcSymbolTypeMemberPointer,

    // The type is an array
    //
    // The base type of an array as returned by GetBaseType() is the type of each element
    // of the array.
    //
    SvcSymbolTypeArray,

    // The type is a function
    SvcSymbolTypeFunction,

    // The type is a typedef
    //
    // The base type of a typedef as returned by GetBaseType() is the type of the definition.
    //
    SvcSymbolTypeTypedef,

    // The type is an enum
    SvcSymbolTypeEnum,

    // The type is an intrinsic (basic type)
    //
    SvcSymbolTypeIntrinsic
};

// SvcSymbolIntrinsicKind:
//
// Defines the kind of intrinsic that an intrinsic type is.  While the interfaces are somewhat different in this layer,
// the definitions here mirror the data model's "debug host" definitions.
//
enum SvcSymbolIntrinsicKind
{
    // void
    SvcSymbolIntrinsicVoid,

    // bool
    SvcSymbolIntrinsicBool,

    // char
    SvcSymbolIntrinsicChar,

    // wchar_t
    SvcSymbolIntrinsicWChar,

    // signed int (of some size -- not necessarily 4 bytes)
    SvcSymbolIntrinsicInt,

    // unsigned int (of some size -- not necessarily 4 bytes)
    SvcSymbolIntrinsicUInt,

    // long (of some size -- not necessarily 4 bytes)
    SvcSymbolIntrinsicLong,

    // unsigned long (of some size -- not necessarily 4 bytes)
    SvcSymbolIntrinsicULong,

    // floating point (of some size -- not necessarily 4 bytes)
    SvcSymbolIntrinsicFloat,

    // HRESULT
    SvcSymbolIntrinsicHRESULT,

    // char16_t
    SvcSymbolIntrinsicChar16,

    // char32_t
    SvcSymbolIntrinsicChar32,

    // unsigned char
    SvcSymbolIntrinsicUChar
};


enum SvcSymbolPointerKind
{
    // *
    SvcSymbolPointerStandard,

    // &
    SvcSymbolPointerReference,

    // &&
    SvcSymbolPointerRValueReference,

    // ^
    SvcSymbolPointerCXHat,

    // CLI reference (invisible to the user)
    SvcSymbolPointerManagedReference
};

enum ArrayDimensionFlags
{
    //
    // Indicates that the "Length" field of the array dimension is an offset from the base address of the array
    // as to where to find a dynamic size
    //
    SvcArrayLengthIsOffset32 = 0x00000001,
    SvcArrayLengthIsOffset64 = 0x00000002,
    SvcArrayLengthIsOffset   = 0x00000003,

    //
    // Indicates that the "LowerBound" field of the array dimension is an offset from the base address of the array
    // as to where to find a dynamic bound
    //
    SvcArrayLowerBoundIsOffset32 = 0x00000004,
    SvcArrayLowerBoundIsOffset64 = 0x00000008,
    SvcArrayLowerBoundIsOffset   = 0x0000000C,

    //
    // Indicates that the "Stride" field of the array dimension is an offset from the base address of the array
    // as to where to find a dynamic stride
    //
    SvcArrayStrideIsOffset32 = 0x00000010,
    SvcArrayStrideIsOffset64 = 0x00000020,
    SvcArrayStrideIsOffset   = 0x00000030,

    //
    // Indicates that the "Stride" field is computed from the element size and the computed sizes of each
    // dimension as indicated by other fields.
    //
    // Next indicates that the stride of this dimension is based on the stride of the next (e.g.: dim[0] is the largest)
    // Previous indicates that the stride of this dimension is based on the stride of the previous (e.g.: dim[0] is the smallest)
    //
    SvcArrayStrideIsComputedByNextRank     = 0x00000040,
    SvcArrayStrideIsComputedByPreviousRank = 0x00000080,
    SvcArrayStrideIsComputed               = 0x000000C0
};

// SvcSymbolArrayDimension:
//
// Describes a dimension of an array.
//
struct SvcSymbolArrayDimension
{
    // Information about how to interpret the remainder of the information in the array dimension
    // Presently, these are reserved and should always be set to zero.
    ULONG64 DimensionFlags;

    // The lower bounds of the array.  For C style zero based arrays, this will always be zero.  There is no
    // uniform restriction that all arrays represented by these interfaces are zero based.
    LONG64 LowerBound;

    // Defines the length of the dimension.  The dimension is considered to be of the form i
    // [LowerBound, LowerBound + Length)
    ULONG64 Length;

    // Defines how many bytes to move forward in memory to walk from index N of the dimension to index N + 1
    ULONG64 Stride;
};

// SvcSymbolSearchOptions:
//
// Describes search options for symbol enumeration.  This directly corresponds to definitions in the
// data model.
//
enum SvcSymbolSearchOptions
{
    SvcSymbolSearchNone = 0x00000000,
    SvcSymbolSearchQualifiedName = 0x00000002
};

// SvcSymbolSearchInfo:
//
// Defines options and properties for a symbol search.  This struct is always given at <HeaderSize>.  An optional
// per search type struct follows of InfoSize.
//
struct SvcSymbolSearchInfo
{
    ULONG HeaderSize;
    ULONG InfoSize;
    ULONG SearchOptions;
};

// SvcTypeSearchInfo:
//
// An optional record passed in a search info which restricts the type search further.
//
struct SvcTypeSearchInfo
{
    SvcSymbolTypeKind SearchType;
};

//
// Interface   : ISvcSymbolChildren
//
// Any symbol which supports the enumeration of children supports this interface.  Simple symbol providers
// which only do basic address -> name and name -> address mapping need not implement this interface.
//
#undef INTERFACE
#define INTERFACE ISvcSymbolChildren
DECLARE_INTERFACE_(ISvcSymbolChildren, IUnknown)
{
    // EnumerateChildren():
    //
    // Enumerates all children of the given symbol.
    //
    STDMETHOD(EnumerateChildren)(
        THIS_
        _In_ SvcSymbolKind kind,
        _In_opt_z_ PCWSTR name,
        _In_opt_ SvcSymbolSearchInfo *pSearchInfo,
        _COM_Outptr_ ISvcSymbolSetEnumerator **childEnum
        ) PURE;
};

//
// Interface   : ISvcSymbolChildrenByRegEx
//
// Any symbol which supports the enumeration of children by regular expression supports this interface.
// Simple symbol providers which only do basic address -> name and name -> address mapping need not implement
// this interface.
//
// This interface should be considered *OPTIONAL* -- even in the presence of ISvcSymbolChildren.  It is intended
// for providers which can provide for optimization of regular expression lookups.
//
#undef INTERFACE
#define INTERFACE ISvcSymbolChildrenByRegEx
DECLARE_INTERFACE_(ISvcSymbolChildrenByRegEx, IUnknown)
{
    // EnumerateChildrenByRegEx():
    //
    // Enumerates all children of the given symbol whose name matches a given regular expression.
    //
    STDMETHOD(EnumerateChildrenByRegEx)(
        THIS_
        _In_ SvcSymbolKind kind,
        _In_opt_z_ PCWSTR regEx,
        _In_opt_ SvcSymbolSearchInfo *pSearchInfo,
        _COM_Outptr_ ISvcSymbolSetEnumerator **childEnum
        ) PURE;
};

//
// Interface   : ISvcSymbolParents
//
// Any symbol which supports finding its parent (lexical or otherwise) supports this interface.  Simple symbol
// providers which only do basic address -> name and name -> address mapping need not implement this interface.
//
// This interface should be considered *OPTIONAL* -- even in the presence of ISvcSymbolChildren
//
#undef INTERFACE
#define INTERFACE ISvcSymbolParents
DECLARE_INTERFACE_(ISvcSymbolParents, IUnknown)
{
    // GetLexicalParent():
    //
    // Gets the lexical parent of the given symbol.
    //
    STDMETHOD(GetLexicalParent)(
        THIS_
        _COM_Outptr_ ISvcSymbol **lexicalParent
        ) PURE;
};

enum IndexSearchFlags
{
    // IndexSearchImmediateChildrenAreOrContainDescendent:
    //
    // Indicates that the search of X will contain the immediate children of X which either are or have
    // descendents that match the search criteria.
    //
    IndexSearchImmediateChildrenAreOrContainDescendent = 0x00000001,

    // IndexSearchImmediateChildrenOnlyContainDescendent:
    //
    // Indicates that the search of X will contain the immediate children of X which have descendents
    // that match the search criteria.  The immediate children themselves are not returned.
    //
    IndexSearchImmediateChildrenOnlyContainDescendent = 0x00000002,

    // IndexSearchDescendents:
    //
    // Indicates that the search of X will contain descendents of X which match the search criteria.  The
    // results may or may not be immediate children of X.  They are, however, always contained in the sub-tree
    // rooted at X.
    //
    IndexSearchDescendents = 0x00000004
};

//
// Interface   : ISvcSymbolNameIndexedDescendents
//
// A symbol provider which implements a full name index can implement this interface on symbols (and scopes)
// in order to speed certain classes of name lookups.  This interface is **ENTIRELY OPTIONAL**.
//
// Symbol providers which only do basic address -> name and name -> address mapping need not implement this interface.
// Symbol providers which implement this interface **MUST** also implement ISvcSymbolChildren on any object which
// implements ISvcSymbolNameIndexedDescendents.
//
#undef INTERFACE
#define INTERFACE ISvcSymbolNameIndexedDescendents
DECLARE_INTERFACE_(ISvcSymbolNameIndexedDescendents, IUnknown)
{
    // EnumerateIndexedDescendents():
    //
    // Enumerates the sub-tree rooted at the object implementing this interface for search criteria similar
    // to ISvcSymbolChildren::EnumerateChildren.
    //
    // This method, however, enumerates all of the descendents of the given node and either returns immediate
    // children which contain a match in their sub-tree (IndexSearchContainingImmediateChildren) or returns
    // descendents in the sub-tree which are a match but are not necessarily immediate children
    // (IndexSearchDescendents).
    //
    // This method may return E_NOTIMPL in a variety of cases.  Some symbol providers may support general
    // name indexed query but not qualified name indexed query, for instance.  In such cases, E_NOTIMPL
    // indicates that the given type of query is not supported.  The caller must go back to utilization
    // of ISvcSymbolChildren.
    //
    STDMETHOD(EnumerateIndexedDescendents)(
        THIS_
        _In_ SvcSymbolKind kind,
        _In_ IndexSearchFlags searchFlags,
        _In_ PCWSTR name,
        _In_ SvcSymbolSearchInfo *pSearchInfo,
        _COM_Outptr_ ISvcSymbolSetEnumerator **childEnum
        ) PURE;
};

//
// Interface   : ISvcSymbolRegExIndexedDescendents
//
// A symbol provider which implements a full name index (and also supports regular expression matching against
// that index) can implement this interface on symbols (and scopes) in order to speed certain classes of name
// lookups by regular expression.  This interface is **ENTIRELY OPTIONAL**.
//
// Symbol providers which only do basic address -> name and name -> address mapping need not implement this interface.
// Symbol providers which implement this interface **MUST** also implement ISvcSymbolChildren on any object which
// implements ISvcSymbolRegExIndexedDescendents.
//
#undef INTERFACE
#define INTERFACE ISvcSymbolRegExIndexedDescendents
DECLARE_INTERFACE_(ISvcSymbolRegExIndexedDescendents, IUnknown)
{
    // EnumerateIndexedDescendentsByRegEx():
    //
    // Enumerates the sub-tree rooted at the object implementing this interface for search criteria similar
    // to ISvcSymbolChildren::EnumerateChildren.  Names with this method are matched not by a constant string
    // but rather by a regular expression.
    //
    // This method, however, enumerates all of the descendents of the given node and either returns immediate
    // children which contain a match in their sub-tree (IndexSearchContainingImmediateChildren) or returns
    // descendents in the sub-tree which are a match but are not necessarily immediate children
    // (IndexSearchDescendents).
    //
    // This method may return E_NOTIMPL in a variety of cases.  Some symbol providers may support general
    // name indexed query but not qualified name indexed query, for instance.  In such cases, E_NOTIMPL
    // indicates that the given type of query is not supported.  The caller must go back to utilization
    // of ISvcSymbolChildren.
    //
    STDMETHOD(EnumerateIndexedDescendentsByRegEx)(
        THIS_
        _In_ SvcSymbolKind kind,
        _In_ IndexSearchFlags searchFlags,
        _In_ PCWSTR regEx,
        _In_ SvcSymbolSearchInfo *pSearchInfo,
        _COM_Outptr_ ISvcSymbolSetEnumerator **childEnum
        ) PURE;
};

#define SVC_REGISTER_NONE static_cast<ULONG>(-1);

// SvcSymbolAttribute:
//
// Defines a set of extensibile and simple "attributes" of symbols which can be queried.
//
enum SvcSymbolAttribute
{
    SvcSymbolAttributeNone = 0,

    // SvcSymbolAttributeConst:    (VT_BOOL) Indicates that the symbol has a const modifier
    SvcSymbolAttributeConst,

    // SvcSymbolAttributeVolatile: (VT_BOOL) Indicates that the symbol has a volatile modifier
    SvcSymbolAttributeVolatile,

    // SvcSymbolAttributeVirtual:  (VT_BOOL) Indicates that the symbol is virtual (or pure virtual)
    SvcSymbolAttributeVirtual,

    // SvcSymbolAttributeVariant:  (VT_BOOL) Indicates that the symbol has variant information
    SvcSymbolAttributeVariant,

    // SvcSymbolAttributeCachePrevention: (VT_UI8) A flags field indicating whether the symbol can be cached
    // in certain ways.  If this attribute is missing, it is assumed the symbol can be cached in *ANY* way
    // that the caller sees fit.  The bits here are described by SvcSymbolCachePreventionFlags
    //
    // Any bit in this value being '0' indicates that it is legal to cache the symbol via the described means.
    // Values of '1' indicate that a client should not cache the symbol by such means.
    SvcSymbolAttributeCachePrevention
};

// SvcSymbolCachePreventionFlags:
//
// A set of flags which describe ways that a symbol should *NOT* be cached by a client.  This is completely
// *OPTIONAL* to implement and should be treated as a hint to clients.
//
enum SvcSymbolCachePreventionFlags
{
    SvcSymbolCachePreventionNone = 0,

    // SvcSymbolCachePreventionByAddress: Do not cache the symbol by address
    SvcSymbolCachePreventionByAddress,

    // SvcSymbolCachePreventionByName: Do not cache the symbol by name (lacking qualification)
    SvcSymbolCachePreventionByName,

    // SvcSymbolCachePreventionByQualifiedName: Do not cache the symbol by qualified name
    SvcSymbolCachePreventionByQualifiedName
};

//
// Interface   : ISvcSymbolAddressMapping
//
// Any symbol which has an address mapping (e.g.: code symbols, functions, lexical blocks, etc...) which
// can be described by one or more ranges implements this interface.
//
// This interface does *NOT* represent locations for things like variables which describe enregistered or
// register relative locations.
//
#undef INTERFACE
#define INTERFACE ISvcSymbolAddressMapping
DECLARE_INTERFACE_(ISvcSymbolAddressMapping, IUnknown)
{
    // GetAddressRange():
    //
    // Gets the base address range of this symbol.  If the symbol is defined by a **SINGLE** linear address
    // range, this method *MUST* return such address range and S_OK.  If the symbol is defined by **MULTIPLE**
    // linear address ranges (e.g.: a BBT'd or otherwise such optimized function), this method *MUST* return
    // the base address range and S_FALSE.
    //
    // In either case, EnumerateAddressRanges() includes **ALL** address ranges of the symbol.
    //
    STDMETHOD(GetAddressRange)(
        THIS_
        _Out_ SvcAddressRange *addressRange
        ) PURE;

    // EnumerateAddressRanges():
    //
    // Enumerates the set of address ranges which define this symbol.
    //
    STDMETHOD(EnumerateAddressRanges)(
        THIS_
        _Out_ ISvcAddressRangeEnumerator **rangeEnum
        ) PURE;
};

//
// Interface   : ISvcSymbolInfo
//
// Any symbol which is typed, has type information, or more advanced location capability (other than a simple
// linear offset within the image) supports this interface.  Simple symbol providers
// which only do basic address -> name and name -> address mapping need not implement this interface.
//
#undef INTERFACE
#define INTERFACE ISvcSymbolInfo
DECLARE_INTERFACE_(ISvcSymbolInfo, IUnknown)
{
    // GetType():
    //
    // Gets the type of the symbol.
    //
    STDMETHOD(GetType)(
        THIS_
        _COM_Outptr_ ISvcSymbol **symbolType // @TODO:
        ) PURE;

    // GetLocation()
    //
    // Gets the location of the symbol.
    //
    STDMETHOD(GetLocation)(
        THIS_
        _Out_ SvcSymbolLocation *pLocation
        ) PURE;

    // GetValue()
    //
    // Gets the value of a constant value symbol.  GetLocation will return an indication that the symbol
    // has a constant value.
    //
    // If this method is called on a symbol without a constant value, it will fail.
    //
    STDMETHOD(GetValue)(
        THIS_
        _Out_ VARIANT *pValue
        ) PURE;

    // GetAttribute():
    //
    // Gets a simple attribute of the symbol.  The type of a given attribute is defined by the attribute
    // itself.   If the symbol cannot logically provide a value for the attribute, E_NOT_SET should be returned.
    // If the provider does not implement the attribute for any symbol, E_NOTIMPL should be returned.
    //
    STDMETHOD(GetAttribute)(
        THIS_
        _In_ SvcSymbolAttribute attr,
        _Out_ VARIANT *pAttributeValue
        ) PURE;

};

//
// Interface   : ISvcSymbolMultipleLocations
//
// This is used to enumerate the locations that describe a symbol, when they support being described in terms
// of multiple locations, such as enregistered structs in DWARF.
//
// When this interface is supported and there is, in fact, a symbol with more than one location, said symbol's
// ISvcSymbolInfo::GetLocation returns a location of kind SvcSymbolLocationMultipleLocations.
//
// All of a symbol's locations form a contiguous memory region, in the sense that each individual location is at some offset
// within the whole. Note that gaps within this region are allowed.
//
#undef INTERFACE
#define INTERFACE ISvcSymbolMultipleLocations
DECLARE_INTERFACE_(ISvcSymbolMultipleLocations, IUnknown)
{
    // GetLocations()
    //
    // Gets up to `maxSize` locations for this symbol. Returns the number of locations read via `pSize`.
    // If `maxSize` is zero, `pLocation` may be null.
    //
    STDMETHOD(GetLocations)(
        THIS_
        _In_ ULONG64 maxSize,
        _Out_writes_to_opt_(maxSize,*pSize) SvcSymbolLocation *pLocation,
        _Out_ PULONG64 pSize
        ) PURE;

    // GetLocationCount()
    //
    // Returns the number of locations this symbol has.
    //
    STDMETHOD(GetLocationCount)(
        THIS_
        _Out_ PULONG64 pCount
        ) PURE;

    // GetLocationAtIndex()
    //
    // Returns the location at a given index, if it exists.
    //
    STDMETHOD(GetLocationAtIndex)(
        THIS_
        _In_ ULONG64 index,
        _Out_ SvcSymbolLocation *pLocation
        ) PURE;

    // GetLocationOffsetAtIndex()
    //
    // Returns the offset for the location at the given index, if it exists.
    // This is the offset within the "memory region" represented by the group of locations.
    //
    STDMETHOD(GetLocationOffsetAtIndex)(
        THIS_
        _In_ ULONG64 index,
        _Out_ PULONG64 pOffset
        ) PURE;

    // GetConstantValueAtIndex()
    //
    // Returns the value of a constant location at the given index, if it exists.
    //
    STDMETHOD(GetConstantValueAtIndex)(
        THIS_
        _In_ ULONG64 index,
        _Out_ VARIANT* pValue
        ) PURE;
};

//
// Interface   : ISvcSymbolDiscriminatorValuesEnumerator
//
// Provided By :
//
#undef INTERFACE
#define INTERFACE ISvcSymbolDiscriminatorValuesEnumerator
DECLARE_INTERFACE_(ISvcSymbolDiscriminatorValuesEnumerator, IUnknown)
{
    // Reset():
    //
    // Resets the enumerator.
    //
    STDMETHOD(Reset)(
        THIS
        ) PURE;

    // GetNext():
    //
    // Gets the next range of discriminator values in the enumerator.  Note that this has identical semantics
    // to ISvcSymbolVariantInfo::GetDescriminatorValues in terms of pLowValue and pHighValue.
    //
    STDMETHOD(GetNext)(
        THIS_
        _Out_ VARIANT *pLowValue,
        _Out_ VARIANT *pHighValue
        ) PURE;
};

//
// Interface   : ISvcSymbolVariantInfo
//
// Any symbol which represents a variant part of a data structure (whether the discriminator or a discriminant)
// should implement ISvcSymbolVariantInfo.
//
#undef INTERFACE
#define INTERFACE ISvcSymbolVariantInfo
DECLARE_INTERFACE_(ISvcSymbolVariantInfo, IUnknown)
{
    // HasVariantMembers():
    //
    // Indicates whether this *TYPE* has variant members or is a variant record.
    //
    STDMETHOD(HasVariantMembers)(
        THIS_
        _Out_ bool *pHasVariantMembers
        ) PURE;

    // IsDiscriminator():
    //
    // Indicates whether this member/field is a discriminator for a variant record.
    //
    STDMETHOD(IsDiscriminator)(
        THIS_
        _Out_ bool *pIsDiscriminator
        ) PURE;

    // IsDiscriminated():
    //
    // Indicates whether this member/field is conditional based on the value of the discriminator.  This can
    // also optionally return the discriminator symbol.
    //
    STDMETHOD(IsDiscriminated)(
        THIS_
        _Out_ bool *pIsDiscriminated,
        _COM_Outptr_opt_ ISvcSymbol **ppDiscriminator
        ) PURE;

    // GetDiscriminatorValues():
    //
    // Indicates the set of discriminator values for which this field/member is valid.  This can return one of
    // several things:
    //
    // - Two variants that are both empty: The discriminator is a default discriminator (used if no other discriminator
    //       matches)
    //
    // - One variant (pLowRange) and one empty variant: The discriminator is a single value "pLowRange"
    //
    // - Two variants of identical type:  The discriminator values are a range [pLowRange, pHighRange)
    //
    // Either of the above with a return value of S_FALSE: The set of discriminator values is disjoint and cannot
    // be expressed by a single range.  In this case, you must call EnumerateDiscriminatorValues to get a full
    // accounting of discriminator values for which this field/member is valid.
    //
    STDMETHOD(GetDiscriminatorValues)(
        THIS_
        _Out_ VARIANT *pLowRange,
        _Out_ VARIANT *pHighRange
        ) PURE;

    // EnumerateDiscriminatorValues():
    //
    // Enumerates all discriminator values for which this field/member is valid.  While this function always works,
    // it only NEEDS to be used if GetDiscriminatorValues returns S_FALSE as an indication that there are
    // disjoint values.
    //
    STDMETHOD(EnumerateDiscriminatorValues)(
        THIS_
        _COM_Outptr_ ISvcSymbolDiscriminatorValuesEnumerator **ppEnum
        ) PURE;
};

#undef INTERFACE
#define INTERFACE ISvcSymbol
DECLARE_INTERFACE_(ISvcSymbol, IUnknown)
{
    // GetSymbolKind():
    //
    // Gets the kind of symbol that this is (e.g.: a field, a base class, a type, etc...)
    //
    STDMETHOD(GetSymbolKind)(
        THIS_
        _Out_ SvcSymbolKind *kind
        ) PURE;

    // GetName():
    //
    // Gets the name of the symbol (e.g.: MyMethod)
    //
    STDMETHOD(GetName)(
        THIS_
        _Out_ BSTR *symbolName
        ) PURE;

    // GetQualifiedName():
    //
    // Gets the qualified name of the symbol (e.g.: MyNamespace::MyClass::MyMethod)
    //
    STDMETHOD(GetQualifiedName)(
        THIS_
        _Out_ BSTR *qualifiedName
        ) PURE;

    // GetId():
    //
    // Gets an identifier for the symbol which can be used to retrieve the same symbol again.  The
    // identifier is opaque and has semantics only to the underlying symbol set.
    //
    STDMETHOD(GetId)(
        THIS_
        _Out_ ULONG64 *
        ) PURE;

    // GetOffset():
    //
    // Gets the offset of the symbol (if said symbol has such).  Note that if the symbol has multiple
    // disjoint address ranges associated with it, this method may return S_FALSE to indicate that the symbol
    // does not necessarily have a simple "base address" for an offset.
    //
    STDMETHOD(GetOffset)(
        THIS_
        _Out_ ULONG64 *symbolOffset
        ) PURE;
};

// SvcSourceLanguage:
//
// Defines the source language of a CU or other symbol.
//
enum SvcSourceLanguage
{
    SvcSourceLanguageUnknown = 0,

    SvcSourceLanguageC,

    SvcSourceLanguageCPlusPlus,

    SvcSourceLanguageAssembly,

    SvcSourceLanguageRust
};

#undef INTERFACE
#define INTERFACE ISvcSymbolCompilationUnit
DECLARE_INTERFACE_(ISvcSymbolCompilationUnit, IUnknown)
{
    // GetPrimarySource():
    //
    // Gets the primary source file of the CU, if available.
    //
    STDMETHOD(GetPrimarySource)(
        THIS_
        _COM_Outptr_ ISvcSourceFile **primarySourceFile
        ) PURE;

    // GetLanguage():
    //
    // Gets the language of the CU, if available.  If there are multiple versions (e.g.: C++03, C++07, C++11, C++17,
    // etc...), the version field can optionally indicate such.  If the version is not available, the
    // return value is static_cast<ULONG>(-1)
    //
    STDMETHOD(GetLanguage)(
        THIS_
        _Out_ SvcSourceLanguage *language,
        _Out_opt_ ULONG *version
        ) PURE;

    // GetProducer():
    //
    // Gets the producer / compiler identification string for the CU, if available.
    //
    STDMETHOD(GetProducer)(
        THIS_
        _Out_ BSTR *producerString
        ) PURE;
};

#undef INTERFACE
#define INTERFACE ISvcSymbolCompilationUnitSources
DECLARE_INTERFACE_(ISvcSymbolCompilationUnitSources, IUnknown)
{
    // EnumerateSourceFiles():
    //
    // Enumerates all of the source files which contribute to this compilation unit.
    //
    STDMETHOD(EnumerateSourceFiles)(
        THIS_
        _In_opt_z_ PCWSTR fileName,
        _In_opt_ SvcSymbolSearchInfo *pSearchInfo,
        _COM_Outptr_ ISvcSourceFileEnumerator **sourceFileEnum
        ) PURE;
};

#undef INTERFACE
#define INTERFACE ISvcSymbolType
DECLARE_INTERFACE_(ISvcSymbolType, IUnknown)
{
    // GetTypeKind():
    //
    // Gets the kind of type symbol that this is (e.g.: base type, struct, array, etc...)
    //
    STDMETHOD(GetTypeKind)(
        THIS_
        _Out_ SvcSymbolTypeKind *kind
        ) PURE;

    // GetSize():
    //
    // Gets the overall size of the type as laid out in memory.
    //
    STDMETHOD(GetSize)(
        THIS_
        _Out_ ULONG64 *size
        ) PURE;

    // GetBaseType():
    //
    // If the type is a derivation of another single type (e.g.: as "MyStruct *" is derived from "MyStruct"),
    // this returns the base type of the derivation.  For pointers, this would return the type pointed to.
    // For arrays, this would return what the array is an array of.  If the type is not such a derivative
    // type, an error is returned.
    //
    // Note that this method has nothing to do with C++ base classes.  Such are symbols which can be enumerated
    // from the derived class.
    //
    STDMETHOD(GetBaseType)(
        THIS_
        _Out_ ISvcSymbol **baseType
        ) PURE;

    // GetUnmodifiedType():
    //
    // If the type is a qualified form (const/volatile/etc...) of another type, this returns a type symbol
    // with all qualifiers stripped.
    //
    STDMETHOD(GetUnmodifiedType)(
        THIS_
        _Out_ ISvcSymbol **unmodifiedType
        ) PURE;

    //*************************************************
    // Intrinsic Information
    //

    // GetIntrinsicType():
    //
    // If the type kind as reported by GetTypeKind is an intrinsic, this returns more information about
    // the particular kind of intrinsic.
    //
    STDMETHOD(GetIntrinsicType)(
        THIS_
        _Out_opt_ SvcSymbolIntrinsicKind *kind,
        _Out_opt_ ULONG *packingSize
        ) PURE;

    //*************************************************
    // Pointer Information:
    //

    // GetPointerKind():
    //
    // Returns what kind of pointer the type is (e.g.: a standard pointer, a pointer to member,
    // a reference, an r-value reference, etc...
    //
    STDMETHOD(GetPointerKind)(
        THIS_
        _Out_ SvcSymbolPointerKind *kind
        ) PURE;

    // GetMemberType():
    //
    // If the pointer is a pointer-to-class-member, this returns the type of such class.
    //
    STDMETHOD(GetMemberType)(
        THIS_
        _COM_Outptr_ ISvcSymbolType **memberType
        ) PURE;

    //*************************************************
    // Array Information (GetTypeKind returns SvcTypeArray):
    //

    // GetArrayDimensionality():
    //
    // Returns the dimensionality of the array.  There is no guarantee that every array type representable by
    // these interfaces is a standard zero-based one dimensional array as is standard in C.
    //
    STDMETHOD(GetArrayDimensionality)(
        THIS_
        _Out_ ULONG64 *arrayDimensionality
        ) PURE;

    // GetArrayDimensions():
    //
    // Fills in information about each dimension of the array including its lower bound, length, and
    // stride.
    //
    STDMETHOD(GetArrayDimensions)(
        THIS_
        _In_ ULONG64 dimensions,
        _Out_writes_(dimensions) SvcSymbolArrayDimension *pDimensions
        ) PURE;

    // GetArrayHeaderSize():
    //
    // Gets the size of any header of the array (this is the offset of the first element of the array as
    // described by the dimensions).
    //
    // This should *ALWAYS* return 0 for a C style array.
    //
    STDMETHOD(GetArrayHeaderSize)(
        THIS_
        _Out_ ULONG64 *arrayHeaderSize
        ) PURE;

    //*************************************************
    // Function Information (GetTypeKind returns SvcTypeFunction)
    //

    // GetFunctionReturnType():
    //
    // Returns the return type of a function.  Even non-value returning functions (e.g.: void) should return
    // a type representing this.
    //
    STDMETHOD(GetFunctionReturnType)(
        THIS_
        _COM_Outptr_ ISvcSymbol **returnType
        ) PURE;

    // GetFunctionParameterTypeCount():
    //
    // Returns the number of parameters that the function takes.
    //
    STDMETHOD(GetFunctionParameterTypeCount)(
        THIS_
        _Out_ ULONG64 *count
        ) PURE;

    // GetFunctionParameterTypeAt():
    //
    // Returns the type of the "i"-th argument to the function as a new ISvcSymbol
    //
    STDMETHOD(GetFunctionParameterTypeAt)(
        THIS_
        _In_ ULONG64 i,
        _COM_Outptr_ ISvcSymbol **parameterType
        ) PURE;
};

//
// Interface   : ISvcSymbolSetSimpleNameResolution
//
// Represents a "simple interface" around the mapping of symbol names to addresses within the image and vice-versa.  All symbol sets
// are required to support this basic level of symbol resolution.  Interfaces beyond this are optional depending on the capabilities
// of the provider.
//
#undef INTERFACE
#define INTERFACE ISvcSymbolSetSimpleNameResolution
DECLARE_INTERFACE_(ISvcSymbolSetSimpleNameResolution, IUnknown)
{
    // FindSymbolByName():
    //
    // Finds symbolic information for a given name.  The method fails if the symbol cannot be located.
    //
    STDMETHOD(FindSymbolByName)(
        THIS_
        _In_ PCWSTR symbolName,
        _COM_Outptr_ ISvcSymbol **symbol
        ) PURE;

    // FindSymbolByOffset():
    //
    // Finds symbolic information for a given offset.  If the "exactMatchOnly" parameter is true, this will only return
    // a symbol which is exactly at the offset given.  If the "exactMatchOnly" parameter is false, this will return the
    // closest symbol before the given offset.  If no such symbol can be found, the method fails.
    //
    // Note that if a given symbol (e.g.: a function) has multiple disjoint address ranges and one of those address
    // ranges has been moved to *BELOW* the base address of the symbol, the returned "symbolOffset" may be
    // interpreted as a signed value (and S_FALSE should be returned in such a case).  This can be confirmed
    // by querying the symbol for its address ranges.
    //
    STDMETHOD(FindSymbolByOffset)(
        THIS_
        _In_ ULONG64 moduleOffset,
        _In_ bool exactMatchOnly,
        _COM_Outptr_ ISvcSymbol **symbol,
        _Out_ ULONG64 *symbolOffset
        ) PURE;
};

//
// Interface   : ISvcSymbolSetSimpleSourceLineResolution
//
// Represents a "simple interface" around the mapping of lines of code to addresses within the image and vice-versa.
// This is an optional interface for symbol sets to implement.
//
#undef INTERFACE
#define INTERFACE ISvcSymbolSetSimpleSourceLineResolution
DECLARE_INTERFACE_(ISvcSymbolSetSimpleSourceLineResolution, IUnknown)
{
    // FindOffsetBySourceLine():
    //
    // Finds the offset for the given line within the image.  If there are multiple mappings for the
    // given line, this will return the first/best (depending on the underlying provider) and return
    // S_FALSE as an indication that a more in-depth query with more advanced interfaces are required.
    //
    // If there are no mappings for the given line but are for later lines in source, this will return
    // the nearest matching source line (after the given one).  The actual mapped line of the offset
    // will be optionally returned to the caller.
    //
    // The *sourceFileName* argument may pass either:
    //
    //     - A path (full or relative) to the source file as returned from the symbol information
    //       in a call to FindSourceLineByOffset.
    //
    //     - The file name.  If the file name is not unique in the symbolic information, this method will
    //       fail and requires an explicit path.
    //
    // The actual name recorded in symbols (potentially a full path) can also optionally be returned in
    // actualSourceFileName.
    //
    STDMETHOD(FindOffsetBySourceLine)(
        THIS_
        _In_ PCWSTR sourceFileName,
        _In_ ULONG64 line,
        _Out_ PULONG64 moduleOffset,
        _Out_opt_ BSTR *actualSourceFileName,
        _Out_opt_ PULONG64 returnedLine
        ) PURE;

    // FindSourceLineByOffset():
    //
    // Finds the source line for a given offset within the image.  If there are multiple mappings for the
    // given line, this will return the first/best (depending on the underlying provider) and return
    // S_FALSE as an indication that a more in-depth query with more advanced interfaces are required.
    //
    // The returned *sourceFileName* may be a file name or a path depending on what was actually recorded
    // in the symbolic information by the original compiler which produced symbols.
    //
    // The returned lineDisplacement value is the number of bytes that 'moduleOffset' is from the first
    // code byte of the given source line.
    //
    // In the event that the symbol provider has information for the given offset but it is unattributable
    // to user code (e.g.: it is compiler generated), the special HRESULT S_UNATTRIBUTABLE_RESULT should be
    // returned from the method.  In this case:
    //
    //     sourceFileName  : This may be set to nullptr
    //     sourceLine      : This should be zero
    //     lineDisplacement: This may be valid to indicate an offset from the start of some compiler generated
    //                       instructions, etc...  It may also simply be zero.
    //
    STDMETHOD(FindSourceLineByOffset)(
        THIS_
        _In_ ULONG64 moduleOffset,
        _Out_ BSTR *sourceFileName,
        _Out_ PULONG64 sourceLine,
        _Out_ PULONG64 lineDisplacement
        ) PURE;
};

//
// Interface   : ISvcSymbolSetSimpleInlineSourceLineResolution
//
// Represents a "simple interface" around the mapping of addresses to lines of code within the image
// for inlined locations.
//
// This is an optional interface for symbol sets to implement.  A symbol set which handles inlined frames
// should always implement this interface.
//
// Reverse mappings require the more advanced ISvcSymbolSetLineResolution interface (not as yet defined)
// as there are nearly always multiple mappings for an inlined method.
//
#undef INTERFACE
#define INTERFACE ISvcSymbolSetSimpleInlineSourceLineResolution
DECLARE_INTERFACE_(ISvcSymbolSetSimpleInlineSourceLineResolution, IUnknown)
{
    // FindSourceLineByOffsetAndInlineSymbol
    //
    // Works similarly to ISvcSymbolSetSimpleLineResolution::FindSourceLineByOffset excepting that it
    // passes a specific inline frame to indicate which of multiply nested inline functions to return
    // the line of code for.
    //
    // If no inline symbol is provided or the outer function symbol is provided, this operates identically
    // to FindSourceLineByOffset.
    //
    STDMETHOD(FindSourceLineByOffsetAndInlineSymbol)(
        THIS_
        _In_ ULONG64 moduleOffset,
        _In_opt_ ISvcSymbol *inlineSymbol,
        _Out_ BSTR *sourceFileName,
        _Out_ PULONG64 sourceLine,
        _Out_ PULONG64 lineDisplacement
        ) PURE;
};

// SvcHashAlgorithm:
//
// Defines the hash algorithm for source files (among other things)
//
enum SvcHashAlgorithm
{
    HashAlgorithmMD5,
    HashAlgorithmSHA1,
    HashAlgorithmSHA256
};

//
// Interface   : ISvcSourceFile
//
// Represents a source file that contributes to the code in a binary.
//
#undef INTERFACE
#define INTERFACE ISvcSourceFile
DECLARE_INTERFACE_(ISvcSourceFile, IUnknown)
{
    // GetId():
    //
    // Gets a unique identifier for the source file
    //
    STDMETHOD_(ULONG64, GetId)(
        THIS
        ) PURE;

    // GetName():
    //
    // Gets the name of the source file.
    //
    STDMETHOD(GetName)(
        THIS_
        _Out_ BSTR *name
        ) PURE;

    // GetPath():
    //
    // Gets the path of the source file.
    //
    STDMETHOD(GetPath)(
        THIS_
        _Out_ BSTR *path
        ) PURE;

    // GetHashDataSize():
    //
    // Gets the size of the source file hash stored in symbolic information.  If the symbolic information
    // has no source file hash, this should return zero.
    //
    STDMETHOD_(ULONG64, GetHashDataSize)(
        THIS
        ) PURE;

    // GetHashData():
    //
    // Gets the hash data associated with the source file.  If there is no such information stored in
    // the symbolic information, this will return E_NOT_SET.
    //
    STDMETHOD(GetHashData)(
        THIS_
        _In_ ULONG64 hashDataSize,
        _Out_writes_(hashDataSize) unsigned char *pHashData,
        _Out_ SvcHashAlgorithm *pHashAlgorithm
        ) PURE;

    // GetCompilationUnits():
    //
    // Gets all the compilation units which reference this particular source file.
    //
    STDMETHOD(GetCompilationUnits)(
        THIS_
        _COM_Outptr_ ISvcSymbolSetEnumerator **cuEnumerator
        ) PURE;
};

//
// Interface   : ISvcSourceFileEnumerator
//
// Provided By :
//
#undef INTERFACE
#define INTERFACE ISvcSourceFileEnumerator
DECLARE_INTERFACE_(ISvcSourceFileEnumerator, IUnknown)
{
    STDMETHOD(Reset)(
        THIS
        ) PURE;

    STDMETHOD(GetNext)(
        THIS_
        _COM_Outptr_ ISvcSourceFile **sourceFile
        ) PURE;
};

//
// Interface   : ISvcSymbolSetSimpleSourceFileInformation
//
// Represents a "simple interface" around the enumeration of source files that contribute to a particular
// binary and their association to compilation units / compilands.
//
// This is an optional interface for symbol sets to implement.
//
#undef INTERFACE
#define INTERFACE ISvcSymbolSetSimpleSourceFileInformation
DECLARE_INTERFACE_(ISvcSymbolSetSimpleSourceFileInformation, IUnknown)
{
    // GetSourceFileById():
    //
    // Gets a source file by its unique identifier.
    //
    STDMETHOD(GetSourceFileById)(
        THIS_
        _In_ ULONG64 id,
        _COM_Outptr_ ISvcSourceFile **sourceFile
        ) PURE;

    // EnumerateSourceFiles():
    //
    // Enumerates all of the source files which contribute to the image.
    //
    STDMETHOD(EnumerateSourceFiles)(
        THIS_
        _In_opt_z_ PCWSTR fileName,
        _In_opt_ SvcSymbolSearchInfo *pSearchInfo,
        _COM_Outptr_ ISvcSourceFileEnumerator **sourceFileEnum
        ) PURE;
};

//
// Interface   : ISvcSymbolSetEnumerator
//
// Provided By :
//
#undef INTERFACE
#define INTERFACE ISvcSymbolSetEnumerator
DECLARE_INTERFACE_(ISvcSymbolSetEnumerator, IUnknown)
{
    STDMETHOD(Reset)(
        THIS
        ) PURE;

    STDMETHOD(GetNext)(
        THIS_
        _COM_Outptr_ ISvcSymbol **symbol
        ) PURE;
};

//
// Interface   : ISvcSymbolSetScope
//
// Represents a lexical scope within code.  A scope can implement ISvcSymbolChildren to allow
// query of other children underneath the scope.
//
#undef INTERFACE
#define INTERFACE ISvcSymbolSetScope
DECLARE_INTERFACE_(ISvcSymbolSetScope, IUnknown)
{
    // EnumerateArguments():
    //
    // If the scope is a function scope (or is a lexical sub-scope of a function), this enumerates
    // the arguments of the function.
    //
    // This will fail for a scope for which arguments are inappropriate.
    //
    STDMETHOD(EnumerateArguments)(
        THIS_
        _COM_Outptr_ ISvcSymbolSetEnumerator **enumerator
        ) PURE;

    // EnumerateLocals():
    //
    // Enumerates the locals within the scope.
    //
    STDMETHOD(EnumerateLocals)(
        THIS_
        _COM_Outptr_ ISvcSymbolSetEnumerator **enumerator
        ) PURE;
};

//
// Interface   : ISvcSymbolSetScopeFrame
//
// Represents a lexical scope within code at a particular stack frame defined by its context record.
// An implementation of ISvcSymbolSetScopeFrame *MUST* QI for ISvcSymbolSetScope
//
#undef INTERFACE
#define INTERFACE ISvcSymbolSetScopeFrame
DECLARE_INTERFACE_(ISvcSymbolSetScopeFrame, IUnknown)
{
    // GetContext():
    //
    // Gets the context for the scope frame.
    //
    STDMETHOD(GetContext)(
        THIS_
        _In_ SvcContextFlags contextFlags,
        _COM_Outptr_ ISvcRegisterContext **registerContext
        ) PURE;
};

//
// Interface   : ISvcSymbolSetScopeResolution
//
// Represents a way to discover scopes and their contents (variables and arguments).  Symbol sets which support
// the enumeration of locals and arguments must support this interface.
//
#undef INTERFACE
#define INTERFACE ISvcSymbolSetScopeResolution
DECLARE_INTERFACE_(ISvcSymbolSetScopeResolution, IUnknown)
{
    // GetGlobalScope():
    //
    // Returns a scope representing the global scope of the module the symbol set represents.  This
    // may be an aggregation of other symbols one could discover through fully enumerating the symbol
    // set.
    //
    STDMETHOD(GetGlobalScope)(
        THIS_
        _COM_Outptr_ ISvcSymbolSetScope **scope
        ) PURE;

    // FindScopeByOffset():
    //
    // Finds a scope by an offset within the image (which is assumed to be an offset within
    // a function or other code area)
    //
    STDMETHOD(FindScopeByOffset)(
        THIS_
        _In_ ULONG64 moduleOffset,
        _COM_Outptr_ ISvcSymbolSetScope **scope
        ) PURE;

    // FindScopeFrame():
    //
    // Finds a scope by the unwound context record for a stack frame.
    //
    STDMETHOD(FindScopeFrame)(
        THIS_
        _In_opt_ ISvcProcess *process,                  // @TODO: address context?
        _In_ ISvcRegisterContext *registerContext,
        _COM_Outptr_ ISvcSymbolSetScopeFrame **scopeFrame
        ) PURE;
};

//
// Interface   : ISvcSymbolSetInlineScopeResolution
//
// Represents a way to discover scopes and their contents (variables and arguments) including that of
// inlined functions.  Symbol sets which support inline frame resolution along with the enumeration of
// locals and arguments must support this interface.
//
#undef INTERFACE
#define INTERFACE ISvcSymbolSetInlineScopeResolution
DECLARE_INTERFACE_(ISvcSymbolSetInlineScopeResolution, IUnknown)
{
    //
    // FindScopeByOffsetAndInlineSymbol()
    //
    // Finds a scope by an offset within the image and the inline function symbol representing a certain
    // level of inlining at that location.
    //
    // A caller which passes nullptr for the inlineSymbol or passes a function symbol which does not represent
    // an inlined function instance will get the behavior of the ISvcSymbolSetScopeResolution variant of this method.
    //
    STDMETHOD(FindScopeByOffsetAndInlineSymbol)(
        THIS_
        _In_ ULONG64 moduleOffset,
        _In_opt_ ISvcSymbol *inlineSymbol,
        _COM_Outptr_ ISvcSymbolSetScope **scope
        ) PURE;

    //
    // FindScopeFrameForInlineSymbol:
    //
    STDMETHOD(FindScopeFrameForInlineSymbol)(
        THIS_
        _In_opt_ ISvcProcess *process,                  // @TODO: address context?
        _In_ ISvcRegisterContext *frameContext,
        _In_opt_ ISvcSymbol *inlineSymbol,
        _COM_Outptr_ ISvcSymbolSetScopeFrame **scopeFrame
        ) PURE;
};

//
// Interface   : ISvcSymbolSetTypeDerivations
//
// Represents a way to create type representations which do not exist in the symbols (e.g.: arrays of things that
// are in symbols, etc...).  Such can act as an aide to a higher level expression evaluator, etc...
//
#undef INTERFACE
#define INTERFACE ISvcSymbolSetTypeDerivations
DECLARE_INTERFACE_(ISvcSymbolSetTypeDerivations, IUnknown)
{
    // CreateArrayType():
    //
    // Returns an ISvcSymbolType representing an array from a partial description of what that array may look
    // like at a linguistic level.  The only mandatory piece of information to this method is the number of
    // dimensions of the array.  Languages for which array types are otherwise dynamic (e.g.: C#) require only
    // this bit of information.  Other languages may require an explicit specification of the sizes and/or lower
    // bounds of dimensions.
    //
    // There is no guarantee that this method will succeed.
    //
    STDMETHOD(CreateArrayType)(
        THIS_
        _In_ ISvcSymbolType *baseType,
        _In_ ULONG64 dimensions,
        _In_reads_opt_(dimensions) ULONG64 *dimensionSizes,
        _In_reads_opt_(dimensions) LONG64 *lowerBounds,
        _COM_Outptr_ ISvcSymbolType **arrayType
        ) PURE;
};

//
// Interface   : ISvcSymbolSetRuntimeTypeInformation
//
// Represents a way to abstract runtime type information (whether RTTI based or based upon another type system)
//
#undef INTERFACE
#define INTERFACE ISvcSymbolSetRuntimeTypeInformation
DECLARE_INTERFACE_(ISvcSymbolSetRuntimeTypeInformation, IUnknown)
{
    // GetRuntimeType():
    //
    // For an object of a given type at a given address within a specified address context (e.g.: process),
    // utilize RTTI or other type system information to determine the actual runtime type of the object and its
    // location.
    //
    // This method can arbitrarily fail.
    //
    STDMETHOD(GetRuntimeType)(
        THIS_
        _In_ ISvcAddressContext *addressContext,
        _In_ ULONG64 staticObjectOffset,
        _In_ ISvcSymbolType *staticObjectType,
        _Out_ ULONG64 *runtimeObjectOffset,
        _COM_Outptr_ ISvcSymbolType **runtimeObjectType
        ) PURE;
};

//
// Interface   : ISvcSymbolSetComplexLocationResolution
//
// Represents a way to simplify symbol complex locations into other non-complex forms given additional
// information.
//
// *NOTE*: This interface is likely to undergo some changes prior to being finalized and its IID will change
//         at that point.  Do **NOT** take any dependency on this outside of the core debugger.
//
#undef INTERFACE
#define INTERFACE ISvcSymbolSetComplexLocationResolution
DECLARE_INTERFACE_(ISvcSymbolSetComplexLocationResolution, IUnknown)
{
    // ResolveComplexLocation():
    //
    // Given a complex location and additional information, attempt to take the complex location and resolve
    // it into a non-complex form.  If it cannot be resolved into a non-complex form, this method will fail.
    // If the location resolves to a constant value, *pConstantValue will be set to that constant value as if
    // ISvcSymbolInfo::GetValue were called.
    //
    // Complex locations are typically the result of complicated means to access local variables or parameters
    // within functions.  Resolving them requires several things:
    //
    //     - The full register context for the frame in which the location is relevant.  This frame *MUST*
    //       still be on the stack.
    //
    //     - The address context in which memory reads for that stack (see above) or other data are
    //       relative to.
    //
    STDMETHOD(ResolveComplexLocation)(
        THIS_
        _In_ SvcSymbolLocation *pComplexLocation,
        _In_ ISvcAddressContext *pAddressContext,
        _In_ ISvcRegisterContext *pRegisterContext,
        _Out_ SvcSymbolLocation *pResolvedLocation,
        _Out_opt_ VARIANT *pConstantValue
        ) PURE;
};

//
// Interface   : ISvcSymbolSetInlineFrameResolution
//
// Represents a way to describe how a compiler/optimizer has inlined functions at a particular location
// in the the module.
//
#undef INTERFACE
#define INTERFACE ISvcSymbolSetInlineFrameResolution
DECLARE_INTERFACE_(ISvcSymbolSetInlineFrameResolution, IUnknown)
{
    // GetInlineDepthAtOffset():
    //
    // For a given offset representing a code location within the image, return the depth of inlining at
    // this particular offset.
    //
    STDMETHOD(GetInlineDepthAtOffset)(
        THIS_
        _In_ ULONG64 moduleOffset,
        _Out_ ULONG64 *inlineDepth
        ) PURE;

    // GetInlinedFunctionAtOffset():
    //
    // For a given offset representing a code location within the image, return the N-th inline function
    // at this particular offset.  If there was nested inlining such as:
    //
    // inlined_bat()
    // {
    //     ...
    // }
    //
    // inlined_bar()
    // {
    //     noninlined_baz();
    //     inlined_bat();
    // }
    //
    // foo()
    // {
    //     inlined_bar();
    // }
    //
    // A call to GetInlineDepthAtOffset for an instruction in foo which was actually inlined from
    // inlined_bat via inlined_bar would return 2.  Similarly, GetInlinedFunctionAtOffset() passing
    // an inlineDepth of
    //
    //     1: Would return inlined_bar
    //     2: Would return inlined_bat
    //
    // This method returns a SvcSymbolInlinedFunction which represents the inlined function.
    //
    STDMETHOD(GetInlinedFunctionAtOffset)(
        THIS_
        _In_ ULONG64 moduleOffset,
        _In_ ULONG64 inlineDepth,
        _COM_Outptr_ ISvcSymbol **inlineFunction
        ) PURE;
};

//
// Interface   : ISvcSymbolSet
//
// Provided By :
//
// Represents an abstract set of symbols.  This may represent all symbols in a PDB.  It may represent the
// "export symbols" of an image.  It may represent a subset of the symbols in a PDB.  There is no requirement
// that a symbol set represent a single "file".  It may represent, in aggregate, multiple sources of symbolic
// information for a given set of functionality (often represented by an image).
//
#undef INTERFACE
#define INTERFACE ISvcSymbolSet
DECLARE_INTERFACE_(ISvcSymbolSet, IUnknown)
{
    //
    // GetSymbolById():
    //
    // Returns the symbol for a given symbol ID (returned by ISvcSymbol::GetId)
    //
    STDMETHOD(GetSymbolById)(
        THIS_
        _In_ ULONG64 symbolId,
        _COM_Outptr_ ISvcSymbol **ppSymbol
        ) PURE;

    //
    // EnumerateAllSymbols():
    //
    // Enumerates all symbols in the set.
    //
    STDMETHOD(EnumerateAllSymbols)(
        THIS_
        _COM_Outptr_ ISvcSymbolSetEnumerator **ppEnumerator
        ) PURE;

};

// DEBUG_SYMBOLSETCAPS_GENERAL:
//
// A set of capabilities that defines the general capabilities of a symbol set.  The identifiers within
// this set are given by the SvcSymbolSetGeneralCaps enumeration.
//
// GUID: {591037BC-1C2C-4a0e-87EA-59F53581E787}
//
DEFINE_GUID(DEBUG_SYMBOLSETCAPS_GENERAL, 0x591037bc, 0x1c2c, 0x4a0e, 0x87, 0xea, 0x59, 0xf5, 0x35, 0x81, 0xe7, 0x87);

enum SvcSymbolSetGeneralCaps
{
    // SvcSymbolSetGeneralCapPassByValueStructLocations:
    //
    // Describes how the symbol set deals with the reporting of "pass-by-value" structs (or other UDTs
    // such as C++ classes).  The calling convention on some platforms (e.g.: Windows AMD64) requires that
    // any "pass-by-value" UDTs over an arbitrary size must be passed by reference.  Some formats (e.g.: PDB)
    // put the language semantics (pass-by-value) in the debug info stating things like (the parameter
    // itself -- a size N UDT -- is passed in a register 'rcx') and rely on the debugger to implicitly
    // understand the calling convention means that the debugger must *INTERPRET* the debug information not as
    // it is written into the format but as a reference instead (e.g.: it's not the parameter itself passed
    // in 'rcx'; rather the address of it).
    //
    // This, unfortunately, makes it impossible to express the notion of an *ACTUAL* passed-by-value large-struct
    // (e.g.: on the stack or split into multiple registers) because one cannot differentiate between cases
    // where the meaning is "really pass by value" and "should add an indirection to the debug info as written".
    //
    // The value of this capability is a boolean (expressed as a one-byte data value) which carries the following
    // meaning:
    //
    //     true (non-zero): Trust the debug information.  If a location implies pass-by-value, it is pass-by-value.
    //                      For a pass-by-reference, the location must be *EXPLICIT* in carrying this meaning.
    //
    //     false (zero)   : Do not always trust the debug information.  Alter the information to assume implicit
    //                      references for large structs.
    //
    // The default value here is *true*.  Callers must always assume the debug information is correct unless they
    // are told otherwise explicitly by this capability.
    //
    SvcSymbolSetGeneralCapPassByValueStructLocations
};

//
// Interface  : ISvcSymbolSetCapabilities
//
// Provided By: Optionally provided by any symbol set
//
// Represents a way to query the capabilities (and some key properties) of a symbol set.  This interface
// is *ENTIRELY* optional.  If it is not present, the default value of any capability queried must be assumed.
//
#undef INTERFACE
#define INTERFACE ISvcSymbolSetCapabilities
DECLARE_INTERFACE_(ISvcSymbolSetCapabilities, IUnknown)
{
    // QueryCapability():
    //
    // Asks the symbol set about a particular capability as identified by a set GUID and an ID within
    // that set.  Each GUID/ID identifies the type of data returned in the resulting buffer.
    //
    // The following error codes carry special semantics with this API:
    //
    //     E_NOT_SET: The symbol set does not understand the capability.  Assume default behavior.
    //
    STDMETHOD(QueryCapability)(
        THIS_
        _In_ REFGUID set,
        _In_ ULONG id,
        _In_ ULONG bufferSize,
        _Out_writes_(bufferSize) PVOID buffer
        ) PURE;
};

//
// Interface   :  ISvcSymbolProvider
//
// Provided By :
//
// Defines a mechanism by which an abstract "symbol set" is located for a given module.  An abstract "symbol set"
// is described by an ISvcSymbolSet.  While a "symbol set" may refer to an arbitrary grouping of symbols, the set
// returned from the LocateSymbolsForImage method represents the symbolic (debug) information for a given image
// in some address space.  That symbol set may be backed by a PDB, the "export symbols" of the image, some side
// description of the symbolic information, or simply be an abstraction materialized out of thin air.
//
#undef INTERFACE
#define INTERFACE ISvcSymbolProvider
DECLARE_INTERFACE_(ISvcSymbolProvider, IUnknown)
{
    // LocateSymbolsForImage():
    //
    // For a given image (identified by an ISvcModule), find the set of symbolic information available for the image
    // and return a symbol set.
    //
    // To provide a better user experience around potentially long running operations, a provider should check:
    //    * if the client specified specific symbols to skip (before downloading)
    //    * if the client attempted to cancel the request (periodically)
    //
    // These checks can be performed via the ISvcUserOperationController interface using the methods:
    //    ISvcUserOperationController::IsSymbolDownloadDisabled
    //    ISvcUserOperationController::IsOperationCancelled.
    //
    STDMETHOD(LocateSymbolsForImage)(
        THIS_
        _In_ ISvcModule *image,
        _COM_Outptr_ ISvcSymbolSet **symbolSet
        ) PURE;
};

#define SVC_DEFAULTBASE_COMPUTE static_cast<ULONG64>(-1ll)

//
// Interface   : ISvcSymbolProvider2
//
// Provided By :
//
// An extension of ISvcSymbolProvider that allows for manual opening of symbols.
//
#undef INTERFACE
#define INTERFACE ISvcSymbolProvider2
DECLARE_INTERFACE_(ISvcSymbolProvider2, ISvcSymbolProvider)
{
    // OpenSymbols():
    //
    // Manually opens symbols.  There should be an image parser in the service container which can parse the
    // symbol file (and optionally image file) and get requisite sections from it.
    //
    // Note that if the symbols and image are separate and data is needed from the image file itself
    // (e.g.: export symbols or unwinder data), the image file should be passed; otherwise, any such data will
    // be missing from the provided symbol set.
    //
    // The base of the image (where the loader actually put the image and where any module enumerator will enumerate
    // the image) should be provided in the event that any symbol expressions require an actual memory read to resolve
    // instead of just returning RVAs.  The 'pImageBaseContext' is the address context in which that imageBase is valid.
    // Note that many symbol providers expect that the definition of "base of image" here is the lowest virtual address
    // at which any portion of the image is mapped into memory.  If the particular usage of symbols does not match
    // that definition, the "default image base" may be provided; otherwise, it may be left as the expected
    // SVC_DEFAULTBASE_COMPUTE.
    //
    // It is important to note that this method typically does absolutely no caching whatsoever.  Each call to this
    // method will open the symbols anew.  Callers should not repeatedly make calls to OpenSymbols for the same
    // set of symbols.
    //
    STDMETHOD(OpenSymbols)(
        THIS_
        _In_ ISvcDebugSourceFile *symbolFile,
        _In_opt_ ISvcDebugSourceFile *imageFile,
        _In_opt_ ISvcAddressContext *pImageBaseContext,
        _In_ ULONG64 loadedImageBase,
        _In_ ULONG64 defaultImageBase,
        _COM_Outptr_ ISvcSymbolSet **symbolSet
        ) PURE;
};

//
// Interface   : ISvcJITSymbolProvider
//
// Provided By :
//
// Defines a mechanism by which an abstract "symbol set" is located for JIT (or otherwise dynamic) code.  Such
// location is given by an address within an address context.
//
// A symbol set which supports JIT should have the ISvcSymbolProvider interface queryable for ISvcJITSymbolProvider.
// In addition, the symbol set may be called for symbols that it **DOES NOT DEAL WITH**.  If there are multiple
// JIT providers aggregated together, this may frequently occur.  In such cases, the locator methods *MUST* return
// the special E_UNHANDLED_REQUEST_TYPE error indicating this.
//
// All *JIT SYMBOLS* are still given as an RVA from the base address of the module.  Such RVA may, in effect,
// lead to an address OUTSIDE the bounds of the module pointing to a dynamically allocated JIT segment.
// If the JIT code is located below the address of the module, the offset will be sufficient to cause a 64-bit
// overflow, producing a 64-bit VA when added to the base address of the module.
//
#undef INTERFACE
#define INTERFACE ISvcJITSymbolProvider
DECLARE_INTERFACE_(ISvcJITSymbolProvider, IUnknown)
{
    // LocateSymbolsForJITSegment
    //
    // For a given address within an address context (often a process), find a symbol set representing
    // the JIT and (potentially) the module to which it belongs.
    //
    // If the JIT code is associated with a given loaded module (e.g.: an CLR assembly with IL code),
    // the module will be returned and all RVA style offsets within the symbol set are relative to the
    // base address of the given module.
    //
    // If the JIT code is *NOT* associated with a given loaded module (e.g.: JIT'ted script from a loaded
    // script file), the resulting image will be NULL *AND* all RVA style offsets within the symbol set
    // are absolute (they are zero based -- an absolute virtual address within the address space)
    //
    STDMETHOD(LocateSymbolsForJITSegment)(
        THIS_
        _In_ ISvcAddressContext *addressContext,
        _In_ ULONG64 address,
        _COM_Outptr_ ISvcSymbolSet **symbolSet,
        _COM_Outptr_result_maybenull_ ISvcModule **image
        ) PURE;
};

//
// Interface   : ISvcImageProvider
//
// Provided By :
//
// Defines a mechanism by which the original binary image for a module/image mapped into the debug target can
// be located from the limited information available from the debug target.  A given debug target may, for example,
// represent a minidump which only has image headers or a core file which only has a subset of the image pages
// mapped into the core.  This interface will attempt to find the original image file and return a file abstraction
// over it such that the entire module/image is available for debugging.
//
#undef INTERFACE
#define INTERFACE ISvcImageProvider
DECLARE_INTERFACE_(ISvcImageProvider, IUnknown)
{
    // LocateImage():
    //
    // Locate the file for a given image within the target.
    //
    // Downloading large image files could be a long running (slow) operation. For such cases you may also need to check periodically
    // the ISvcUserOperationController::IsOperationCancelled.
    //
    STDMETHOD(LocateImage)(
        THIS_
        _In_ ISvcModule *image,
        _COM_Outptr_ ISvcDebugSourceFile **ppFile
        ) PURE;
};

//
// Interface   : ISvcSearchPaths
//
//
#undef INTERFACE
#define INTERFACE ISvcSearchPaths
DECLARE_INTERFACE_(ISvcSearchPaths, IUnknown)
{
    // SetAllPaths():
    //
    // Provides a semicolon separated list of paths to the provider in which to search for the
    // appropriate images/symbols.  Note that this accepts symbol server syntax.
    //
    STDMETHOD(SetAllPaths)(
        THIS_
        _In_ PCWSTR searchPaths
        ) PURE;

    // GetAllPaths():
    //
    // Provides a semicolon separated list of paths from which the provider will search for the
    // appropriate images/symbols.  Note that this will return symbol server syntax.
    //
    STDMETHOD(GetAllPaths)(
        THIS_
        _Out_ BSTR *searchPaths
        ) PURE;

    //
    // @TODO: Individual
    //
};

//
// Interface   : ISvcUserOperationController
//
// The service interface is intended to be used by any service which may run a long operation.
// It would help determine if the user requested operation termination.
//
#undef INTERFACE
#define INTERFACE ISvcUserOperationController
DECLARE_INTERFACE_(ISvcUserOperationController, IUnknown)
{
    // IsOperationCancelled():
    //
    // Used to check if the user requested operation cancellation
    //
    STDMETHOD_(BOOL, IsOperationCancelled)(
        THIS
        ) PURE;

    // IsSymbolDownloadDisabled():
    //
    // Used to check if downloading symbols for image is disabled
    //
    STDMETHOD_(BOOL, IsSymbolDownloadDisabled)(
        THIS_
        _In_ ISvcModule *image
        ) PURE;
};

//*************************************************
// Related / Other Linguistic:
//

enum SvcDemanglerFlags
{
    //
    // Indicates that only the name should be returned and not potential return types and function
    // parameter types, etc...
    //
    DemangleNameOnly = 0x00000001
};

//
// Interface   : ISvcNameDemangler
//
// Defines a means by which C++ mangled names can be demangled.
//
#undef INTERFACE
#define INTERFACE ISvcNameDemangler
DECLARE_INTERFACE_(ISvcNameDemangler, IUnknown)
{
    // DemangleName():
    //
    // Takes a (potentially) mangled name (e.g.: a C++ mangled name) and demangles it given a set of options.
    // If this mangled name is not recognized, the demangler should return E_UNHANDLED_REQUEST_TYPE as it is often
    // the case that multiple demanglers will be aggregated in one container.
    //
    // NOTE: The source language is often unspecified and will be SvcSourceLanguageUnknown.  In addition, the
    //       machine architecture is often unspecified and will be GUID_NULL.
    //
    //       These parameters are optional and provide hints to the demangler if present.
    //
    STDMETHOD(DemangleName)(
        _In_ SvcDemanglerFlags demangleFlags,
        _In_ SvcSourceLanguage sourceLanguage,
        _In_ REFGUID machineArch,
        _In_ PCWSTR pwszMangledName,
        _Out_ BSTR *pDemangledName
        ) PURE;
};

//**************************************************************************
// Stack Services:
//

// SvcStackUnwindFlags:
//
// Flags in SVC_STACK_FRAME that define attributes of the unwind information.
//
enum SvcStackUnwindFlags
{
    // Indicates that ReturnAddress of the stack frame should be considered invalid -- it could
    // not be determined.
    StackUnwindUnknownReturn = 0x00000001,

    // On entry -- indicates that "FrameMachine" specifies an alternate input architecture to the unwinder.
    // On exit  -- indicates that "UnwoundMachine" specifies that the architecture of the stack changed.
    StackUnwindArchitectureSpecified = 0x00000002,

    // Indicates that the Parameters array is populated and valid; otherwise -- it should be considered
    // invalid.
    StackUnwindParametersSpecified = 0x00000004,

    // Indicates that the unwinder has determined that the unwound return address is outside the bounds of
    // the function with the containing call site because the call site was a [[noreturn]] tail call.
    //
    // It is optional for an unwinder to populate this information.  It is extra information which can be
    // used as a hint to the caller.
    StackUnwindTailCallReturn = 0x00000008,

    // Indicates that there may be skipped stack frames between the prior frame and the one on which this flag
    // is returned.
    //
    StackUnwindSkippedFrames = 0x00000010,

    // On entry -- this flag should be *PRESERVED* from a prior unwind when unwinding the next frame
    // On exit -- indicates that this particular frame was the result of unwinding an exception/signal frame.
    //
    // Callers to the unwinder should never set this flag themselves.  They should, however, preserve this
    // flag when unwinding a subseuqent frame.  It is entirely possible that the unwind from an exception/signal
    // frame yields a leaf function or other circumstance which would not be possible with a normal unwind.
    // Not preserving this flag across unwinds can cause premature termination of a stack unwind in some
    // circumstances.
    //
    StackUnwindFromExceptionOrSignalFrame = 0x00000020
};

// SVC_STACK_FRAME:
//
// Abstraction for an architecture neutral stack frame.
//
struct SVC_STACK_FRAME
{
    //*************************************************
    // v1 Fields:
    //
    ULONG SizeOfStruct;             // sizeof(SVC_STACK_FRAME) on entry to unwinder
    ULONG UnwindFlags;              // See SvcStackUnwindFlags re: non-zero flags on entry, many will be set on exit

    ULONG64 InstructionPointer;
    ULONG64 StackPointer;
    ULONG64 FramePointer;
    ULONG64 ReturnAddress;

    //*************************************************
    // v2 Fields (any field beyond this point must come with a SizeOfStruct >= FIELD_OFFSET() check in order
    // to determine whether the field is present in the structure or not).
    //

    // For stack unwinds that can span machine/register architectures (e.g.: CHPE), this allows specification of
    // the "architecture" of both the frame of InstructionPointer and the frame of ReturnAddress.
    //
    // These fields are only valid if StackUnwindArchitectureSpecified is set.  On input to ->UnwindFrame(),
    // StackUnwindArchitectureSpecified may be set with "FrameMachine" set to a specific architecture to indicate
    // an "alternate input architecture" to the unwinder.  In such cases, UnwoundMachine should be initialized to zero.
    // On exit from unwind, if StackUnwindArchitectureSpecified is set, both fields must be valid.
    //
    // Normally, both of these will indicate the architecture of the machine.
    //
    ULONG FrameMachine;             // Indicates the architecture (IMAGE_FILE_MACHINE_*) of this frame
    ULONG UnwoundMachine;           // Indicates the architecture (IMAGE_FILE_MACHINE_*) of the unwound frame

    //*************************************************
    // v3 Fields
    //

    ULONG64 Parameters[4];          // Optional: parameters (StackUnwindParametersSpecified must be set)

};

// ISvcStackUnwindContext:
//
// Context information for a stack unwind.  Such an interface must always be passed to all components involved
// in a stack unwind.
//
#undef INTERFACE
#define INTERFACE ISvcStackUnwindContext
DECLARE_INTERFACE_(ISvcStackUnwindContext, IUnknown)
{
    // GetProcess():
    //
    // Gets the process that the stack unwind is occuring for.  This method may legally return null/S_FALSE in
    // cases where there is no associated process for the stack walk.
    //
    STDMETHOD(GetProcess)(
        THIS_
        _COM_Outptr_result_maybenull_ ISvcProcess** process
        ) PURE;

    // GetThread():
    //
    // Gets the thread that the stack unwind is occurring for.  This method may legally return null/S_FALSE in
    // cases where there is no associated thread for the stack walk.
    //
    STDMETHOD(GetThread)(
        THIS_
        _COM_Outptr_result_maybenull_ ISvcThread** thread
        ) PURE;

    // SetContextData():
    //
    // Sets a piece of context data for a component involved in the stack walk which can be fetched later
    // with GetContextData.
    //
    STDMETHOD(SetContextData)(
        THIS_
        _In_ IUnknown* component,
        _In_ IUnknown* contextData
        ) PURE;

    // GetContextData():
    //
    // Gets a piece of context data for a component involved in the stack walk.  Such data must have been
    // set earlier via a call to SetContextData.
    //
    STDMETHOD(GetContextData)(
        THIS_
        _In_ IUnknown* component,
        _COM_Outptr_ IUnknown** contextData
        ) PURE;
};

// ISvcStackUnwindContext2:
//
// Context information for a stack unwind.  Such an interface must always be passed to all components involved
// in a stack unwind.
//
#undef INTERFACE
#define INTERFACE ISvcStackUnwindContext2
DECLARE_INTERFACE_(ISvcStackUnwindContext2, ISvcStackUnwindContext)
{
    // GetExecutionUnit():
    //
    // Gets the execution unit that the stack unwind is occuring for.  This method may legally return null/S_FALSE
    // in cases where there is no associated execution unit for the stack walk.
    //
    STDMETHOD(GetExecutionUnit)(
        THIS_
        _COM_Outptr_result_maybenull_ ISvcExecutionUnit** execUnit
        ) PURE;
};

// ISvcStackUnwindContext3:
//
// Context information for a stakc unwind.  Such interface must always be passed to all component involved
// in a stack unwind.
//
#undef INTERFACE
#define INTERFACE ISvcStackUnwindContext3
DECLARE_INTERFACE_(ISvcStackUnwindContext3, ISvcStackUnwindContext2)
{
    // GetAddressContext():
    //
    // Gets the address context for reading the stack and appropriate data.  If the unwind context
    // has a particular process context, this is the process context.  If it does not, this is
    // the context of the execution unit (assuming that such represents a processor or other
    // unit that has an associated address context).
    //
    STDMETHOD(GetAddressContext)(
        THIS_
        _COM_Outptr_ ISvcAddressContext** addressContext
        ) PURE;
};

#undef INTERFACE
#define INTERFACE ISvcStackFrameUnwind
DECLARE_INTERFACE_(ISvcStackFrameUnwind, IUnknown)
{
    // UnwindFrame():
    //
    // Unwinds the stack frame given the architecture specific register context.  A stack unwind context
    // must have been created and initialized prior to calling this method.  It is important to note that
    // ownership of the input context is semantically being given to UnwindFrame.  The operation may either
    // modify the input register context and simply return the modified register context as the output
    // context or it may create a new register context as the output context.  Either is a valid implementation.
    //
    // If the architecture of the unwound frame changes for any reason (e.g.: CHPE/ARM64X), the output register
    // context is guaranteed to be a new register context with the registers of the new architecture.
    //
    // A setup for calling this method for stack unwind includes:
    //
    //     - Setting stackFrame.SizeOfStruct to sizeof(SVC_STACK_FRAME)
    //     - Setting stackFrame.Flags to 0
    //     - Getting the actual register context of the thread/stack to unwind
    //     - Calling UnwindFrame()
    //
    // After a call to UnwindFrame:
    //
    //     - The instruction pointer / stack pointer / frame pointer are copied out of
    //       the architecture specific register context into SVC_STACK_FRAME in an architecture
    //       neutral manner.
    //     - The return address for the unwound frame is placed into SVC_STACK_FRAME.  If it cannot
    //       be determined, zero is placed in said value and the StackUnwindUnknownReturn flag is set.
    //     - The values in the architecture specific register context are those of the unwound frame
    //       (including the instruction pointer / stack pointer / frame pointer)
    //
    // The return value from UnwindFrame has significance:
    //
    //     - E_BOUNDS: The end of stack unwind has been reached
    //     - S_OK    : Everything successfully unwound -- the register context is full
    //     - S_FALSE : The frame successfully unwound  -- not all register context successfully unwound
    //     - E_*     : Another error occurred that prevented stack unwind.
    //
    STDMETHOD(UnwindFrame)(
        THIS_
        _In_ ISvcStackUnwindContext *pUnwindContext,
        _Inout_ SVC_STACK_FRAME *pStackFrame,
        _In_ ISvcRegisterContext *pInRegisterContext,
        _COM_Outptr_ ISvcRegisterContext **ppOutRegisterContext
        ) PURE;
};

// UnwinderTransitionKind:
//
// Defines the kind of transition from one stack unwinder to another when there are multiple unwinders in
// an aggregate service.
//
enum UnwinderTransitionKind
{
    // The given unwinder is not requesting a transition from the currently active stack unwinder.
    UnwinderTransitionNone,

    // Indicates that the given unwinder would like control of stack unwinding.  The stack frame and register
    // context have been adjusted.  In addition, they have been adjusted to the TOP of the stack for the given
    // unwinder.  Such should be utilized as a stack frame prior to calling the unwinder to unwind a frame.
    UnwinderTransitionAddFrame,

    // Indicates that the given unwinder would like control of stack unwinding.  The stack frame and register
    // context may or may not have been adjusted.  The client should call the transitioned unwinder to get
    // the next frame.  The stack frame/register context output arguments from the RequestsTransition call
    // should not be used as an independent stack frame.
    UnwinderTransitionUnwindFrame
};

// ISvcStackFrameUnwinderTransition:
//
// If a given stack unwinder service implements this interface and is in an aggregate container, this interface
// will be asked if the stack unwinder wants to "take over" unwinding -- even if the currently delegated stack
// unwinder would continue.
//
// This allows a given unwind service to transition between two unwinders or stacks or otherwise inject
// stack frames for a variety of purposes.
//
#undef INTERFACE
#define INTERFACE ISvcStackFrameUnwinderTransition
DECLARE_INTERFACE_(ISvcStackFrameUnwinderTransition, IUnknown)
{
    // RequestsEntryTransition():
    //
    // Given the information that would normally be passed to UnwindFrame, this asks an alternate unwinder
    // if it would like to "take over" unwinding at a particular point.  The implementation can either leave
    // the _Inout_ arguments alone and return UnwinderTransition none in the 'pTransitionKind' argument (indicating
    // that no transition should occur) or it can adjust the _Inout_ arguments and indicate that it would like
    // control of the unwind with specific behaviors as indicated by the 'pTransitionKind' argument.
    //
    // If multiple stack unwinders in an aggregate container indicate they want to take over unwinding, the request
    // is passed to the highest priority unwinder.  Such priority is given by linear insertion order into the
    // container.
    //
    STDMETHOD(RequestsEntryTransition)(
        _In_ ISvcStackUnwindContext *pUnwindContext,
        _Inout_ SVC_STACK_FRAME *pStackFrame,
        _Inout_ ISvcRegisterContext *pRegisterContext,
        _Out_ UnwinderTransitionKind *pTransitionKind
        ) PURE;

    // RequestsExitTransition():
    //
    // Given the information that would normally be passed to UnwindFrame, this asks the current unwinder
    // whether it would like to stop "taking over" unwinding at a particular point and give the unwinding
    // to another unwinder.  The unwinder should have previously taken over via RequestsEntryTransition.
    //
    // The behaviors of the transition kind are identical to RequestsEntryTransition with the exception that
    // the yes/no is opposite (UnwinderTransitionNone indicates continuation of use; others requests that the
    // aggregate unwinder stop using the called unwinder)
    //
    STDMETHOD(RequestsExitTransition)(
        _In_ ISvcStackUnwindContext *pUnwindContext,
        _Inout_ SVC_STACK_FRAME *pStackFrame,
        _Inout_ ISvcRegisterContext *pRegisterCotnext,
        _Out_ UnwinderTransitionKind *pTransitionKind
        ) PURE;

    // RequestsTerminalTransition():
    //
    // Given the information that would normally be passed to UnwindFrame after the *CURRENT* unwinder has
    // reached the end of the stack, this asks an alternate unwinder if it would like to "take over" unwinding
    // at this particular point.
    //
    // If the callee returns UnwinderTransitionAddFrame, the adjusted stack frame and context record are presented
    // as a new stack frame *BEFORE* unwinding.  If the callee returns UnwinderTransitionUnwindFrame, the returned
    // register context is unwound as the next entry in the stack.
    //
    // If multiple stack unwinders in an aggregate container indicate that they want a terminal transition, the
    // request is passed to the unwinder which returns a register context that has a stack pointer closest to
    // the stack pointer of the unwinder which terminated.
    //
    STDMETHOD(RequestsTerminalTransition)(
        _In_ ISvcStackUnwindContext *pUnwindContext,
        _Inout_ SVC_STACK_FRAME *pStackFrame,
        _Inout_ ISvcRegisterContext *pRegisterContext,
        _Out_ UnwinderTransitionKind *pTransitionKind
        ) PURE;

};

// ISvcStackFrameInjection:
//
// If a given stack unwinder service implements this interface, other components involved in unwind can inject
// a frame during the unwinder.  The injected frame becomes the NEXT frame regardless of other Unwind* calls
// that may or may not be in progress.
//
#undef INTERFACE
#define INTERFACE ISvcStackFrameInjection
DECLARE_INTERFACE_(ISvcStackFrameInjection, IUnknown)
{
    // InjectStackFrame:
    //
    // Adds a stack frame with the given information and register context as the immediately next frame
    // from the unwind.
    //
    STDMETHOD(InjectStackFrame)(
        _In_ ISvcStackUnwindContext *pUnwindContext,
        _In_ SVC_STACK_FRAME *pStackFrame,
        _In_ ISvcRegisterContext *pRegisterContext
        ) PURE;
};

//*************************************************
// Stack Providers:
//

// StackProviderFrameKind:
//
// Details what kind of stack frame has been returned.
//
enum StackProviderFrameKind
{
    // Indicates that the frame is generic.  There must be an implementation of ISvcStackProviderFrameAttributes
    StackProviderFrameGeneric,

    // Indicates that the frame is a physical frame from an underlying stack unwinder.  The frame interface
    // must QI for ISvcStackProviderPhysicalFrame and must be able to provide a SVC_STACK_FRAME structure
    // and an unwound register context for the stack frame.
    StackProviderFramePhysical,

    // Indicates that the frame is an inline frame on top of another type of stack frame.  The frame interface
    // must QI for ISvcStackProviderInlineFrame and must be able to return another frame which represents the
    // "underlying" frame (the non-inline one).
    StackProviderFrameInline,

    // Indicates that the frame is a partial physical frame.  The frame interface must QI for
    // ISvcStackProviderPartialPhysicalFrame and must be able to return, at minimum, an instruction pointer.
    // Other values are optional.
    StackProviderFramePartialPhysical,

};

// ISvcStackProviderFrame:
//
// Represents a single frame from a stack provider.  The base interface only provides detection of the frame
// kind.  Other interfaces may be required depending on the frame type.  Some interfaces are optional for
// any type of stack frame.
//
#undef INTERFACE
#define INTERFACE ISvcStackProviderFrame
DECLARE_INTERFACE_(ISvcStackProviderFrame, IUnknown)
{
    // GetFrameKind():
    //
    // Gets the kind of stack frame that this ISvcStackProviderFrame represents.
    //
    STDMETHOD_(StackProviderFrameKind, GetFrameKind)(
        THIS
        ) PURE;
};


#undef INTERFACE
#define INTERFACE ISvcStackProviderPhysicalFrame
DECLARE_INTERFACE_(ISvcStackProviderPhysicalFrame, IUnknown)
{
    // GetFrame():
    //
    // Gets the underlying SVC_STACK_FRAME and register context for the frame.  This would be equivalent
    // to having called ISvcStackFrameUnwind::UnwindFrame and gotten the same values out.
    //
    STDMETHOD(GetFrame)(
        THIS_
        _Inout_ SVC_STACK_FRAME *pStackFrame,
        _COM_Outptr_ ISvcRegisterContext **ppRegisterContext
        ) PURE;
};

#undef INTERFACE
#define INTERFACE ISvcStackProviderPartialPhysicalFrame
DECLARE_INTERFACE_(ISvcStackProviderPartialPhysicalFrame, IUnknown)
{
    // GetInstructionPointer():
    //
    // Gets the instruction pointer for this partial physical frame.  This is the *MINIMUM MUST* implement
    // for a partial physical frame.  All other Get* methods within ISvcStackProviderPartialPhysicalFrame
    // may legally return E_NOT_SET.
    //
    STDMETHOD(GetInstructionPointer)(
        THIS_
        _Out_ ULONG64 *instructionPointer
        ) PURE;

    // GetStackPointer():
    //
    // Gets the stack pointer for this partial physical frame.  This may return E_NOT_SET indicating that there
    // is no available stack pointer value for this partial frame.  All users of a partial physical frame must
    // be able to deal with such.
    //
    STDMETHOD(GetStackPointer)(
        THIS_
        _Out_ ULONG64 *stackPointer
        ) PURE;

    // GetFramePointer():
    //
    // Gets the frame pointer for this partial physical frame.  This may return E_NOT_SET indicating that there
    // is no available frame pointer value for this partial frame.  All users of a partial physical frame must
    // be able to deal with such.
    //
    STDMETHOD(GetFramePointer)(
        THIS_
        _Out_ ULONG64 *framePointer
        ) PURE;
};

#undef INTERFACE
#define INTERFACE ISvcStackProviderInlineFrame
DECLARE_INTERFACE_(ISvcStackProviderInlineFrame, IUnknown)
{
    // GetUnderlyingFrame():
    //
    // Represents an inline stack frame within a physical frame.
    //
    STDMETHOD(GetUnderlyingFrame)(
        THIS_
        _COM_Outptr_ ISvcStackProviderFrame **ppFrame
        ) PURE;

    // GetInlineDepth():
    //
    // Gets the inline depth of this particular stack frame.
    //
    STDMETHOD_(ULONG64, GetInlineDepth)(
        THIS
        ) PURE;

    // GetMaximalInlineDepth():
    //
    // Gets the maximal inline depth of the stack at this particular inline frame's location.
    // In other words, for a given @pc, if there are 3 nested inlne frames at this point, all three
    // frames would return 3 for GetMaximalInlineDepth() and would return 3, 2, and 1 respectively (going
    // through an unwind) for GetInlineDepth().
    //
    STDMETHOD_(ULONG64, GetMaximalInlineDepth)(
        THIS
        ) PURE;
};

// ISvcStackProviderFrameAttributes:
//
// Returns certain attributes of the stack.  This interface is optional on most frame types.  It is mandatory
// on any generic frame and optional on other types.
//
#undef INTERFACE
#define INTERFACE ISvcStackProviderFrameAttributes
DECLARE_INTERFACE_(ISvcStackProviderFrameAttributes, IUnknown)
{
    // GetFrameText():
    //
    // Gets the "textual representation" of this stack frame.  The meaning of this can vary by stack provider.
    // Conceptually, this is what a debugger would place in a "call stack" window representing this frame.
    //
    // Anyone who implements ISvcStackProviderFrameAttributes *MUST* implement GetFrameText.
    //
    STDMETHOD(GetFrameText)(
        THIS_
        _Out_ BSTR *frameText
        ) PURE;

    // GetSourceAssociation():
    //
    // Gets the "source association" for this stack frame (e.g.: the source file, line number, and column
    // number).  This is an optional attribute.  It is legal for any implementation to E_NOTIMPL this.
    // The line number and column number are optional (albeit a column cannot be provided without a line).
    // A client may legally return a value of zero for either of these indicating that it is not available or not
    // relevant (e.g.: compiler generated code which does not necessarily map to a line of code may legally
    // return 0 for the source line).
    //
    STDMETHOD(GetSourceAssociation)(
        THIS_
        _Out_ BSTR *sourceFile,
        _Out_ ULONG64 *sourceLine,
        _Out_ ULONG64 *sourceColumn
        ) PURE;
};

// ISvcStackProviderFrameSetEnumerator:
//
// Defines a set of stack frames which can be linearly enumerated from a "top" to a "bottom"
// (typically retrieved from a stack walk).  The set of frames can, however, represent some portion of a physical
// stack or a logical call chain which doesn't necessarily relate to a physical stack in memory.
//
// While a stack provider can return a stack walk as a single "frame set", it is entirely possible to have
// aggregate stack providers that compose an interleaved number of frame sets into a single frame set.
//
#undef INTERFACE
#define INTERFACE ISvcStackProviderFrameSetEnumerator
DECLARE_INTERFACE_(ISvcStackProviderFrameSetEnumerator, IUnknown)
{
    // GetUnwindContext():
    //
    // Gets the unwinder context which is associated with this frame set.
    //
    STDMETHOD(GetUnwindContext)(
        THIS_
        _COM_Outptr_ ISvcStackUnwindContext **unwindContext
        ) PURE;

    // Reset();
    //
    // Resets the enumerator back to the top of the set of frames which it represents.
    //
    STDMETHOD(Reset)(
        THIS
        ) PURE;

    // GetCurrentFrame():
    //
    // Returns the current frame of the set.  If there is no current frame, this will return E_BOUNDS.
    //
    STDMETHOD(GetCurrentFrame)(
        THIS_
        _COM_Outptr_ ISvcStackProviderFrame **currentFrame
        ) PURE;

    // MoveNext():
    //
    // Moves the enumerator to the next frame.  This will return E_BOUNDS at the end of enumeration.
    //
    STDMETHOD(MoveNext)(
        THIS
        ) PURE;
};

// ISvcStackProvider:
//
// Describes an abstract stack provider.  Semantically, this is a layer above a stack unwinder which returns
// physical frames on a stack and register contexts.  Frames from a stack provider can be physical frames provided
// by a stack unwinder...  or they can be inline frames on top of those physical frames...  or they can be entirely
// synthetic constructs that represent some logical form of call chain.
//
#undef INTERFACE
#define INTERFACE ISvcStackProvider
DECLARE_INTERFACE_(ISvcStackProvider, IUnknown)
{
    // StartStackWalk():
    //
    // Starts a stack walk for the execution unit given by the unwind context and returns a frame set enumerator
    // representing the frames within that stack walk.
    //
    STDMETHOD(StartStackWalk)(
        THIS_
        _In_ ISvcStackUnwindContext *unwindContext,
        _COM_Outptr_ ISvcStackProviderFrameSetEnumerator **frameEnum
        ) PURE;

    // StartStackWalkForAlternateContext():
    //
    // Starts a stack walk given an alternate starting register context.  Other than assuming a different
    // initial register context than StartStackWalk, the method operates identically.  Stack providers which deal
    // in physical frames *SHOULD* implement this method.  Stack providers which do not may legally E_NOTIMPL
    // this method.
    //
    STDMETHOD(StartStackWalkForAlternateContext)(
        THIS_
        _In_ ISvcStackUnwindContext *unwindContext,
        _In_ ISvcRegisterContext *registerContext,
        _COM_Outptr_ ISvcStackProviderFrameSetEnumerator **frameEnum
        ) PURE;
};

//*************************************************
// Image Services:
//

// ServiceImageByteMapping:
//
// Defines a mapping for byte(s) of memory in an image.
//
enum ServiceImageByteMapping
{
    SvcImageByteMappingUnmapped,                // Not valid
    SvcImageByteMappingZero,                    // Zero bytes
    SvcImageByteMappingUninitialized,           // Uninitialized
};

// ISvcImageFileViewRegion:
//
// Describes a "file view region" of an executable.  This might be called a "section" in some parlances.
//
#undef INTERFACE
#define INTERFACE ISvcImageFileViewRegion
DECLARE_INTERFACE_(ISvcImageFileViewRegion, IUnknown)
{
    // GetFileOffset():
    //
    // Gets the file offset of the file region.
    //
    STDMETHOD_(ULONG64, GetFileOffset)(
        THIS
        ) PURE;

    // GetSize():
    //
    // Gets the size of the file region.
    //
    STDMETHOD_(ULONG64, GetSize)(
        THIS
        ) PURE;

    // GetName():
    //
    // Gets the name of the region.  If the region has no name, E_NOT_SET is returned.
    //
    STDMETHOD(GetName)(
        _Out_ BSTR *pRegionName
        ) PURE;

    // GetMemoryViewAssociation():
    //
    // Gets the association of this file view region to the memory view.  If this file section is *NOT* associated
    // with the memory view (it is not mapped by a loader), S_FALSE is returned with a 0/0 mapping and
    // pExtraByteMapping filled in.
    //
    // By default, this will return a singular mapping (of the start of the file view region).
    //
    STDMETHOD(GetMemoryViewAssociation)(
        _Out_ ULONG64 *pMemoryViewOffset,
        _Out_ ULONG64 *pMemoryViewSize,
        _Out_ ServiceImageByteMapping *pExtraByteMapping            // What is meant by GetSize() - *pMemoryViewSize
        ) PURE;
};

// ISvcImageFileViewRegionEnumerator:
//
// An enumerator for "file view regions" of an executable.
//
#undef INTERFACE
#define INTERFACE ISvcImageFileViewRegionEnumerator
DECLARE_INTERFACE_(ISvcImageFileViewRegionEnumerator, IUnknown)
{
    // Reset():
    //
    // Resets the enumerator.
    //
    STDMETHOD(Reset)(
        THIS
        ) PURE;

    // GetNext():
    //
    // Gets the next "file view region".
    //
    STDMETHOD(GetNext)(
        THIS_
        _Out_ ISvcImageFileViewRegion **ppRegion
        ) PURE;
};

// ISvcImageMemoryRegion:
//
// Describes a "memory veiw region" of an executable.  This might be called a "segment" in some parlances.
//
#undef INTERFACE
#define INTERFACE ISvcImageMemoryViewRegion
DECLARE_INTERFACE_(ISvcImageMemoryViewRegion, IUnknown)
{
    // GetMemoryOffset():
    //
    // Gets the memory offset of the memory region.  This corresponds to an offset from the load base
    // of the image (or a "relative virtual address" as some might call it)
    //
    STDMETHOD_(ULONG64, GetMemoryOffset)(
        THIS
        ) PURE;

    // GetSize():
    //
    // Gets the size of the memory region.
    //
    STDMETHOD_(ULONG64, GetSize)(
        THIS
        ) PURE;

    // GetId():
    //
    // Gets a numeric id for the region.  This may correspond to a segment number or may simply be
    // an invented ID by the provider (e.g.: an index into the program header table)
    //
    STDMETHOD_(ULONG64, GetId)(
        THIS
        ) PURE;

    // IsReadable():
    //
    // Indicates whether this region of the image is mapped as readable.  If the implementation cannot make a
    // determination of whether the range is readable or not, E_NOTIMPL may legally be returned.
    //
    STDMETHOD(IsReadable)(
        THIS_
        _Out_ bool *IsReadable
        ) PURE;

    // IsWriteable():
    //
    // Indicates whether this region of the image is mapped as writeable.  If the implementation cannot make a
    // determination of whether the range is writeable or not, E_NOTIMPL may legally be returned.
    //
    STDMETHOD(IsWriteable)(
        THIS_
        _Out_ bool *IsWriteable
        ) PURE;

    // IsExecutable():
    //
    // Indicates whether this region of the image is mapped as executable.  If the implementation cannot make a
    // determination of whether the range is executable or not, E_NOTIMPL may legally be returned.
    //
    STDMETHOD(IsExecutable)(
        THIS_
        _Out_ bool *IsExecutable
        ) PURE;

    // GetAlignment():
    //
    // Gets the required alignment for this mapping.  If the implementation cannot make a determination of
    // alignment, E_NOTIMPL may legally be returned.
    //
    STDMETHOD(GetAlignment)(
        THIS_
        _Out_ ULONG *Alignment
        ) PURE;

    // GetFileViewAssociation():
    //
    // Gets the association of this memory view region to the file view.  If this memory section is *NOT* associated
    // with the file view (it is uninitialized data, zero-fill, etc...), S_FALSE is returned with a 0/0 mapping
    // and pExtraByteMapping filled in.
    //
    // By default, this will return a singular mapping (of the start of the memory view region).
    //
    STDMETHOD(GetFileViewAssociation)(
        THIS_
        _Out_ ULONG64 *pFileViewOffset,
        _Out_ ULONG64 *pFileViewSize,
        _Out_ ServiceImageByteMapping *pExtraByteMapping            // What is meant by GetSize() - *pFileViewSize
        ) PURE;
};

// ISvcImageMemoryRegionEnumerator:
//
// An enumerator for "memory view regions" of an executable.
//
#undef INTERFACE
#define INTERFACE ISvcImageMemoryViewRegionEnumerator
DECLARE_INTERFACE_(ISvcImageMemoryViewRegionEnumerator, IUnknown)
{
    // Reset():
    //
    // Resets the enumerator.
    //
    STDMETHOD(Reset)(
        THIS
        ) PURE;

    // GetNext():
    //
    // Gets the next "memory view region".
    //
    STDMETHOD(GetNext)(
        THIS_
        _Out_ ISvcImageMemoryViewRegion **ppRegion
        ) PURE;
};

// ISvcImageParser:
//
// General service for parsing an executable image of some generic format which may be on disk, may be
// memory mapped (as a file), or may be memory mapped (as a loaded image), or may be in the VA space of the target
// (as either a flat map or a loaded image).
//
#undef INTERFACE
#define INTERFACE ISvcImageParser
DECLARE_INTERFACE_(ISvcImageParser, IUnknown)
{
    // GetImageArchitecture():
    //
    // Gets the architecture of the image.  If the image is a multi-architecture image (for any definition of
    // such -- whether a "fat binary", a "CHPE image", etc..., this method will return S_FALSE to indicate
    // that it returned the *DEFAULT ARCHITECTURE* but that another "view" of the binary is available.
    //
    STDMETHOD(GetImageArchitecture)(
        THIS_
        _Out_ ULONG *pImageArch
        ) PURE;

    // ReparseForAlternateArchitecture():
    //
    // Maps an alternate view of the image for a secondary architecture.  If the image is not a
    // multi-architecture image, this will return E_NOTIMPL.
    //
    STDMETHOD(ReparseForAlternateArchitecture)(
        THIS_
        _In_ ULONG altArch,
        _Out_ ISvcImageParser **ppAltParser
        ) PURE;

    // GetImageLoadSize():
    //
    // Gets the load size of the image as determined from the headers of the format.
    //
    STDMETHOD(GetImageLoadSize)(
        THIS_
        _Out_ ULONG64 *pImageLoadSize
        ) PURE;

    // EnumerateFileViewRegions:
    //
    // Enumerates every "file view region" within the file.  This often corresponds to what an executable
    // image format would call a section.
    //
    STDMETHOD(EnumerateFileViewRegions)(
        THIS_
        _Out_ ISvcImageFileViewRegionEnumerator **ppEnum
        ) PURE;

    // FindFileViewRegion:
    //
    // Locate a "file view region" within the file by its given name (e.g.: ".text", etc...).  If there is no
    // such named region, E_BOUNDS is returned.
    //
    STDMETHOD(FindFileViewRegion)(
        THIS_
        _In_ PCWSTR pwsRegionName,
        _Out_ ISvcImageFileViewRegion **ppRegion
        ) PURE;

    // FindFileViewRegionByOffset:
    //
    // Locate a "file view region" given an offset within the file view.
    //
    STDMETHOD(FindFileViewRegionByOffset)(
        THIS_
        _In_ ULONG64 offset,
        _Out_ ISvcImageFileViewRegion **ppRegion
        ) PURE;

    // EnumerateMemoryViewRegions:
    //
    // Enumerates every "memory view region" within the file.  This often corresponds to what an executable
    // image format would call a segment.  For ELF, this would correspond to program headers with a VA/PA
    // mapping.
    //
    STDMETHOD(EnumerateMemoryViewRegions)(
        THIS_
        _Out_ ISvcImageMemoryViewRegionEnumerator **ppEnum
        ) PURE;

    // FindMemoryViewRegionByOffset:
    //
    // Locate a "memory view region" given an offset within the VA space of the loaded module (what
    // some parlances might call a relative virtual address or RVA).
    //
    STDMETHOD(FindMemoryViewRegionByOffset)(
        THIS_
        _In_ ULONG64 offset,
        _Out_ ISvcImageMemoryViewRegion **ppRegion
        ) PURE;

    // FindMemoryViewRegionById():
    //
    // Locate a "memory view region" given its id.
    //
    STDMETHOD(FindMemoryViewRegionById)(
        THIS_
        _In_ ULONG64 id,
        _Out_ ISvcImageMemoryViewRegion **ppRegion
        ) PURE;

    // TranslateFileViewOffsetToMemoryViewOffset:
    //
    // Translates an offset into the file view of the image into an offset in the memory view of the image.
    // An offset out of bounds of the file view will return E_BOUNDS.  An offset which does not map to
    // anything in the memory view (it is only in the file and not put in memory by the loader) will
    // return E_NOT_SET.
    //
    // If a mapping is returned, the number of contiguous bytes of the mapping can optionally be returned.
    //
    STDMETHOD(TranslateFileViewOffsetToMemoryViewOffset)(
        THIS_
        _In_ ULONG64 fileViewOffset,
        _Out_ ULONG64 *pMemoryViewOffset,
        _Out_opt_ ULONG64 *pMappedByteCount
        ) PURE;

    // GetMemoryViewOffset:
    //
    // For an offset into the **CURRENT VIEW** of the image (depending on how the image was parsed), this
    // will translate that offset into an offset in the memory view of the image.  This may either be a no-op
    // or may be equivalent to calling TranslateFileViewOffsetToMemoryViewOffset depending on how
    // the image was originally parsed.
    //
    STDMETHOD(GetMemoryViewOffset)(
        THIS_
        _In_ ULONG64 currentViewOffset,
        _Out_ ULONG64 *pMemoryViewOffset,
        _Out_opt_ ULONG64 *pMappedByteCount
        ) PURE;

    // TranslateMemoryViewOffsetToFileViewOffset:
    //
    // Translates an offset into the memory view of the image into an offset in the file view of the image.
    // An offset out of bounds of the memory view will return E_BOUNDS.  An offset which does not map to
    // anything in the file view (e.g.: it is .bss or other uninitialized data) will return E_NOT_SET.
    //
    // If a mapping is returned, the number of contiguous bytes of the mapping can optionally be returned.
    //
    STDMETHOD(TranslateMemoryViewOffsetToFileViewOffset)(
        THIS_
        _In_ ULONG64 memoryViewOffset,
        _Out_ ULONG64 *pFileViewOffset,
        _Out_opt_ ULONG64 *pMappedByteCount
        ) PURE;

    // GetFileViewOffset:
    //
    // For an offset into the **CURRENT VIEW** of the image (depending on how the image was parsed), this
    // will translate that offset into an offset in the file view of the image.  This may either be a no-op
    // or may be equivalent to calling TranslateMemoryViewOffsetToFileViewOffset depending on how
    // the image was originally parsed.
    //
    STDMETHOD(GetFileViewOffset)(
        THIS_
        _In_ ULONG64 currentViewOffset,
        _Out_ ULONG64 *pFileViewOffset,
        _Out_opt_ ULONG64 *pMappedByteCount
        ) PURE;
};

// DEBUG_IMAGEFORMAT_PE:
//
// Identifies the PE (portable executable) image format
//
// GUID: {DFBEA201-C5AB-4a63-BCEA-60A7ABBFAB3F}
//
DEFINE_GUID(DEBUG_IMAGEFORMAT_PE, 0xdfbea201, 0xc5ab, 0x4a63, 0xbc, 0xea, 0x60, 0xa7, 0xab, 0xbf, 0xab, 0x3f);

// DEBUG_IMAGEFORMAT_ELF:
//
// Identifies the ELF (executable and linking format) image format
//
// GUID: {FA5CA7B2-3CFB-4e3c-B8D1-65AC38776933}
//
DEFINE_GUID(DEBUG_IMAGEFORMAT_ELF, 0xfa5ca7b2, 0x3cfb, 0x4e3c, 0xb8, 0xd1, 0x65, 0xac, 0x38, 0x77, 0x69, 0x33);

// DEBUG_IMAGEFORMAT_MACHO
//
// Identifies the MachO image format
//
// {2D4E8A8D-7199-4715-B831-1C0F7DEB0E92}
//
DEFINE_GUID(DEBUG_IMAGEFORMAT_MACHO, 0x2d4e8a8d, 0x7199, 0x4715, 0xb8, 0x31, 0x1c, 0xf, 0x7d, 0xeb, 0xe, 0x92);

// ISvcImageParser2:
//
// General service for parsing an executable image of some generic format which may be on disk, may be
// memory mapped (as a file), or may be memory mapped (as a loaded image), or may be in the VA space of the target
// (as either a flat map or a loaded image).
//
#undef INTERFACE
#define INTERFACE ISvcImageParser2
DECLARE_INTERFACE_(ISvcImageParser2, ISvcImageParser)
{
    // GetImageFormat:
    //
    // Returns a GUID which identifies the format of the image (PE, ELF, MachO, etc...)
    //
    STDMETHOD(GetImageFormat)(
        THIS_
        _Out_ GUID *pImageFormat
        ) PURE;
};

// VersionKind:
//
enum VersionKind
{
    // Leave it to the provider to interpret what kind of version information to return.
    VersionGeneric,

    // The version information associated with the image file itself
    VersionFile,

    // The verison information associated with the package that the image file belongs to
    VersionPackage,

    // The version information associated with the distribution / product that the image file shipped with
    VersionDistribution
};

// DEBUG_VERSIONIDENTIFIER_PACKAGENAME:
//
// Identifies the package name associated with the image.
//
// GUID: {F779EDF9-2F05-4e9d-A3DE-479BD2FCA1AC}
//
DEFINE_GUID(DEBUG_VERSIONIDENTIFIER_PACKAGENAME, 0xf779edf9, 0x2f05, 0x4e9d, 0xa3, 0xde, 0x47, 0x9b, 0xd2, 0xfc, 0xa1, 0xac);

// DEBUG_VERSIONIDENTIFIER_COPYRIGHT:
//
// Identifies the copyright information associated with the image.
//
// GUID: {00C9CB55-2134-455c-BD7A-A106A9F71884}
//
DEFINE_GUID(DEBUG_VERSIONIDENTIFIER_COPYRIGHT, 0xc9cb55, 0x2134, 0x455c, 0xbd, 0x7a, 0xa1, 0x6, 0xa9, 0xf7, 0x18, 0x84);

// DEBUG_VERSIONIDENTIFIER_DISTRIBUTION:
//
// Identifies the distribution/product associated with the image.
//
// GUID: {3A51BE14-3AD5-481f-871D-6F37CFFEEBA3}
//
DEFINE_GUID(DEBUG_VERSIONIDENTIFIER_DISTRIBUTION, 0x3a51be14, 0x3ad5, 0x481f, 0x87, 0x1d, 0x6f, 0x37, 0xcf, 0xfe, 0xeb, 0xa3);

// DEBUG_VERSIONIDENTIFIER_REPOSITORY:
//
// Identifies the repository associated with the image.
//
// GUID: {2B32B734-ABC0-413f-973A-C2F114C8B40B}
//
DEFINE_GUID(DEBUG_VERSIONIDENTIFIER_REPOSITORY, 0x2b32b734, 0xabc0, 0x413f, 0x97, 0x3a, 0xc2, 0xf1, 0x14, 0xc8, 0xb4, 0xb);

// DEBUG_VERSIONIDENTIFIER_BRANCH:
//
// Identifies the branch associated with the image.
//
// GUID: {A1C282C0-54D8-4aa7-BB18-3B83744DA9F7}
//
DEFINE_GUID(DEBUG_VERSIONIDENTIFIER_BRANCH, 0xa1c282c0, 0x54d8, 0x4aa7, 0xbb, 0x18, 0x3b, 0x83, 0x74, 0x4d, 0xa9, 0xf7);

// DEBUG_VERSIONIDENTIFIER_DESCRIPTION:
//
// Identifies description information associated with the image.
//
// GUID: {218F0E9D-8B59-436a-AEEB-DF31B1A1A924}
//
DEFINE_GUID(DEBUG_VERSIONIDENTIFIER_DESCRIPTION, 0x218f0e9d, 0x8b59, 0x436a, 0xae, 0xeb, 0xdf, 0x31, 0xb1, 0xa1, 0xa9, 0x24);

// DEBUG_VERSIONIDENTIFIER_COMMIT_HASH:
//
// Identifies a commit hash associated with the image.
//
// GUID: {365C64DE-26C5-469d-8698-0E41A7492AEB}
//
DEFINE_GUID(DEBUG_VERSIONIDENTIFIER_COMMIT_HASH, 0x365c64de, 0x26c5, 0x469d, 0x86, 0x98, 0xe, 0x41, 0xa7, 0x49, 0x2a, 0xeb);

// ISvcImageVersionParser:
//
// An optional QI off an ISvcImageParser.  This parses any version data on the image.
//
#undef INTERFACE
#define INTERFACE ISvcImageVersionParser
DECLARE_INTERFACE_(ISvcImageVersionParser, IUnknown)
{
    // GetVersionString():
    //
    // Returns a string representation of the version of the image the parser was created for.
    // If such version information does not exist for the given file type, E_NOT_SET can be returned.
    //
    // A provider should always attempt to map some semantic onto VersionGeneric.  VersionFile/VersionProduct
    // has specific meaning for Windows and may or may not for other platforms.
    //
    STDMETHOD(GetVersionString)(
        _In_ VersionKind kind,
        _Out_ BSTR *pVersion
        ) PURE;

    // GetVersionNumber():
    //
    // Returns a numeric representation of the version of the image the parser was created for.
    // If such version information does not exist for the given file type, E_NOT_SET can be returned.
    //
    // If the given version request cannot be mapped to 4 numeric a.b.c.d values, this can return
    // E_NOTIMPL.  If the given version request maps to less than 4 numeric values, non-existant values
    // should always be set to zero.
    //
    STDMETHOD(GetVersionNumber)(
        _In_ VersionKind kind,
        _Out_opt_ ULONG64 *p1,
        _Out_opt_ ULONG64 *p2,
        _Out_opt_ ULONG64 *p3,
        _Out_opt_ ULONG64 *p4
        ) PURE;

    // GetVersionDataString():
    //
    // Gets additional information stamped into the version record for a particular platform.  The version
    // data string can be identified by either GUID or by name.  The other argument should be nullptr.
    //
    // An unrecognized string/GUID should return E_NOT_SET.
    //
    STDMETHOD(GetVersionDataString)(
        _In_opt_ const GUID *pVersionDataIdentifierGuid,
        _In_opt_ PCWSTR pVersionDataIdentifierString,
        _Out_ BSTR *pVersionDataString
        ) PURE;
};

// ISvcImageVersionParser2:
//
// An optional QI off an ISvcImageParser.  This parses any version data on the image.
//
#undef INTERFACE
#define INTERFACE ISvcImageVersionParser2
DECLARE_INTERFACE_(ISvcImageVersionParser2, ISvcImageVersionParser)
{
    // EnumerateVersionData():
    //
    // Enumerates all version data records that are returnable via ISvcImageVersionParser::GetVersionDataString
    //
    STDMETHOD(EnumerateVersionData)(
        _COM_Outptr_ ISvcImageVersionDataEnumerator **enumerator
        ) PURE;
};

// ISvcImageVersionDataEnumerator:
//
// Enumerates version data strings which are returned from an image parser via
// ISvcImageVersionParser2::EnumerateVersionData.
//
#undef INTERFACE
#define INTERFACE ISvcImageVersionDataEnumerator
DECLARE_INTERFACE_(ISvcImageVersionDataEnumerator, IUnknown)
{
    // Reset():
    //
    // Resets the enumerator so that the first version datum in the collection is returned from the subsequent
    // GetNext call.
    //
    STDMETHOD(Reset)(
        THIS
        ) PURE;

    // GetNext():
    //
    // Gets the next version datum in the collection.  At the end of this call:
    //
    //     - *pVersionDataIdentifierGuid is set to the GUID used to retrieve the version data in a call
    //       to ISvcImageVersionParser::GetVersionDataString.  Such should be a standard
    //       DEBUG_VERSIONIDENTIFIER_* GUID defined in this header.  If there is no standard GUID defining
    //       this datum, GUID_NULL should be returned.
    //
    //     - *pVersionDataIdentifierString is set to the string used to retrieve the version data in a call
    //       to ISvcImageVersionParser::GetVersionDataString.
    //
    //     - *pVersionDataString is set to the actual data.
    //
    //     - *pVersionDataDescription is a human readable short description of the value suitable for display
    //       in the debugger
    //
    //     - *pVersionKind is set to the VersionKind from which a call to ISvcImageVersionParser::GetVersionString
    //       will yield this item.  If ISvcImageVersionParser::GetVersionString will never yield this data,
    //       VersionGeneric should be returned.
    //
    STDMETHOD(GetNext)(
        THIS_
        _Out_opt_ GUID *pVersionDataIdentifierGuid,
        _Out_opt_ BSTR *pVersionDataIdentifierString,
        _Out_opt_ BSTR *pVersionDataString,
        _Out_opt_ BSTR *pVersionDataDescription,
        _Out_opt_ VersionKind *pVersionKind
        ) PURE;
};

// ISvcImageDataLocationParser
//
// An optional QI off an ISvcImageParser.  This parses arbitrary image data blobs (structures) and
// provides pointers to such data.  Data is identified by GUIDs.
//
#undef INTERFACE
#define INTERFACE ISvcImageDataLocationParser
DECLARE_INTERFACE_(ISvcImageDataLocationParser, IUnknown)
{
    // LocateDataBlob():
    //
    // Locates an arbitrary data blob identified by GUID and returns both the memory and file offset of
    // the data.  If the data has no memory or file offset (but has the opposite), zero is returned
    // in the appropriate field.
    //
    STDMETHOD(LocateDataBlob)(
        _In_ REFGUID dataBlob,
        _Out_ ULONG64 *pFileOffset,
        _Out_ ULONG64 *pMemoryOffset,
        _Out_ ULONG64 *pBlobSize
        ) PURE;
};

// DEBUG_SVCDATABLOB_RUNTIME_LINKER_DEBUGGER_RENDEZVOUS:
//
// A GUID which can be passed to ISvcImageDataLocationParser::LocateDataBlob in order to find
// the address of the runtime linker debugger rendezvous (r_debug) structure POINTER within
// an ELF executable on Linux (this is the effective address of the r_debug pointer within the DT_DEBUG
// dynamic entry)
//
// {9A42D659-3D92-4a5a-A166-A06DB9F02E6F}
//
DEFINE_GUID(DEBUG_SVCDATABLOB_RUNTIME_LINKER_DEBUGGER_RENDEZVOUS, 0x9a42d659, 0x3d92, 0x4a5a, 0xa1, 0x66, 0xa0, 0x6d, 0xb9, 0xf0, 0x2e, 0x6f);

// DEBUG_SVCDATABLOB_ENTRY_ADDRESS:
//
// A GUID which can be passed to ISvcImageDataLocationParser::LocateDataBlob in order to find
// the address of the entry point within an executable.
//
// {16E51259-6DBB-4c47-8D28-8AA7BB5F93D2}
//
DEFINE_GUID(DEBUG_SVCDATABLOB_ENTRY_ADDRESS, 0x16e51259, 0x6dbb, 0x4c47, 0x8d, 0x28, 0x8a, 0xa7, 0xbb, 0x5f, 0x93, 0xd2);

// ISvcImageParseProvider:
//
// The image parse provider provides an image parser for recognized formats in one of several manners.
//
#undef INTERFACE
#define INTERFACE ISvcImageParseProvider
DECLARE_INTERFACE_(ISvcImageParseProvider, IUnknown)
{
    // ParseLoadedImage():
    //
    // Parses an image which is in the target VA space of the process and is given by an ISvcModule.  Not
    // every method will work on an image parsed directly out of target VA space.  The ELF section table is
    // often not pulled into the loaded image and hence enumerating sections will outright fail.
    //
    STDMETHOD(ParseLoadedImage)(
        _In_ ISvcModule *pImage,
        _Out_ ISvcImageParser **ppImageParser
        ) PURE;

    // ParseImageFile():
    //
    // Parses an image which is from a file on disk.
    //
    STDMETHOD(ParseImageFile)(
        _In_ ISvcDebugSourceFile *pImageFile,
        _Out_ ISvcImageParser **ppImageParser
        ) PURE;

    // ParseTargetMappedImage():
    //
    // Parses an image which is memory mapped into a target VA space as a flat memory map (and not as
    // a loaded image).
    //
    STDMETHOD(ParseTargetMappedImage)(
        _In_ ISvcAddressContext *pImageContext,
        ULONG64 imageOffset,
        ULONG64 imageSize,
        _Out_ ISvcImageParser **ppImageParser
        ) PURE;

    // ParseLocalLoadedImage():
    //
    // Parsea an image which is loaded into the address space of the caller.  Not every method will work
    // on an image parsed from a loaded view.  The ELF section table is often not pulled into the loaded
    // image and hence enumerating sections will outright fail.
    //
    STDMETHOD(ParseLocalLoadedImage)(
        _In_ void *pImageMap,
        _In_ ULONG64 imageSize,
        _Out_ ISvcImageParser **ppImageParser
        ) PURE;

    // ParseLocalMappedImage():
    //
    // Parses an image which is memory mapped into the address space of the caller as a flat memory map
    // (and not as a loaded image).
    //
    STDMETHOD(ParseLocalMappedImage)(
        _In_ void *pImageMap,
        _In_ ULONG64 imageSize,
        _Out_ ISvcImageParser **ppImageParser
        ) PURE;
};

//**************************************************************************
// Live Target Control Interfaces:
//

//
// Target operations happen at two different levels:
//
// 1) The step manager level
//
//    The step manager is represents the logical layer of controlling a target.  Operations at the step manager
//    level may represent high level operations that do not directly correspond to physical hardware or emulator
//    operations.  Source level step operations are done at the step manager level, for instance.
//
//    A *CLIENT* that wishes to control a target utilizes the step manager to get such control.  A step manager
//    itself utilizes a lower level step controller to perform its operations.
//
//    It is not typical for a plug-in to implement a step manager.
//
//    An example of a step manager would be the debugger engine itself which uses the step controller to implement
//    source level stepping (and other high level operations) on top of a step controller (such as one for a GDB
//    server)
//
// 2) The step controller level
//
//    The step controller represents the physical layer of controlling a target.  Operations at the step controller
//    represent basic physical operations that correspond to physical hardware or emulator operations.  Instruction
//    level step operations are done at the step controller level.  A step controller is *INCAPABLE* of performing
//    actions like source level stepping.  Such are represented at the higher level step manager level.
//
//    Clients do not typically directly interact with a step controller.  They will instead communicate with the
//    step manager.
//
//    Plug-ins which want to represent "live targets" would typically implement a step controller and leave
//    step management to the debugger engine itself.
//
//    An example of a step controller would be the motion controls of a GDB server.
//

// TargetStatus:
//
// Describes the current "status" of a live target.
//
enum TargetStatus
{
    // TargetRunPending: The target is expected to start running.  Such has not compelted.
    TargetRunPending,

    // TargetRunning: The target is running
    TargetRunning,

    // TargetHaltPending: The target is expected to start halting.  Such has not completed.
    TargetHaltPending,

    // TargetHalted: The target is halted and is not actively running instructions/threads
    TargetHalted,

    // TargetFaulted: The target is faulted and cannot be resumed (it may not function properly)
    TargetFaulted
};

// HaltReason:
//
// Describes why a live target is halted.
//
enum HaltReason
{
    // HaltUnknown: the target is halted for an unknown reason
    HaltUnknown,

    // HaltRequested: the target is halted because of an explicit request from a client
    HaltRequested,

    // HaltStepComplete: the target is halted because a step operation completed
    HaltStepComplete,

    // HaltBreakpoint: the target is halted because a breakpoint was hit
    HaltBreakpoint,

    // HaltException: the target is halted because an exception occurred
    HaltException,

    // HaltProcessExit: the target is halted because the process exited or was terminated
    HaltProcessExit,
};

// TargetOperationKind:
//
// Defines a kind of operation
//
enum TargetOperationKind
{
    // OperationStep: This represents a step operation
    OperationStep,

    // OperationRun: This represents a run operation
    OperationRun,

    // OperationHalt: This represents a halt operation
    OperationHalt,
};

// TargetOperationStatus:
//
// Defines the current status of an operation
//
enum TargetOperationStatus
{
    // OperationCompleted: the requested operation has completed
    OperationCompleted,

    // OperationCanceled: the requested operation has been canceled.
    OperationCanceled,

    // OperationPending: the requested operation is still pending.
    OperationPending,

    // OperationError: the requested operation cannot be completed due to an error
    OperationError
};

enum TargetOperationDirection
{
    DirectionNone,
    DirectionForward,
    DirectionBackward
};

// ISvcTargetOperationStatusNotification:
//
//
#undef INTERFACE
#define INTERFACE ISvcTargetOperationStatusNotification
DECLARE_INTERFACE_(ISvcTargetOperationStatusNotification, IUnknown)
{
    // NotifyOperationChange():
    //
    // Called by the step controller or step manager to notify a "client" that a requested operation
    // has changed state (e.g.: completed or been canceled, etc...)
    //
    // The semantics of "pAffectedUnit" and "affectedAddress" depend on the type of operation.  For a halt
    // operation, this would be the "thread" or "core" that took the halt signal and the program counter
    // at the point of the halt.
    //
    STDMETHOD_(void, NotifyOperationChange)(
        _In_ ISvcTargetOperation *pOperation,
        _In_ TargetOperationStatus opStatus,
        _In_opt_ ISvcExecutionUnit *pAffectedUnit,
        _In_opt_ ULONG64 affectedAddress
        ) PURE;
};

#undef INTERFACE
#define INTERFACE ISvcTargetStateChangeNotification
DECLARE_INTERFACE_(ISvcTargetStateChangeNotification, IUnknown)
{
    //
    // NotifyStateChange():
    //
    // Called by the step controller or step manager to notify a "client" that a state change has occurred.
    // This may or may not be the result of a particular operation.
    //
    // If the halt is associated with a particular operation, the operation is passed here.
    //
    // *NOTE*: If a state change is associated with an operation and callbacks are registered for both, the
    //         step controller/manager's general state change notification *MUST* happen *BEFORE* the operation's
    //         notification.
    //
    // pArgs is defined as follows (currentStatus / haltReason):
    //
    //     - TargetHalted / HaltBreakpoint: The ISvcBreakpoint which was hit
    //     - TargetHalted / HaltProcessExit: The ISvcProcess which terminated
    //     - Otherwise: Undefined
    //
    STDMETHOD_(void, NotifyStateChange)(
        _In_ TargetStatus currentStatus,
        _In_ HaltReason haltReason,
        _In_opt_ ISvcTargetOperation *pOperation,
        _In_opt_ ISvcExecutionUnit *pAffectedUnit,
        _In_opt_ ULONG64 affectedAddress,
        _In_opt_ IUnknown *pArgs
        ) PURE;
};

// ISvcTargetOperation:
//
// This interface represents a handle to a
//
#undef INTERFACE
#define INTERFACE ISvcTargetOperation
DECLARE_INTERFACE_(ISvcTargetOperation, IUnknown)
{
    // GetKind():
    //
    // Returns what kind of operation this is.
    //
    STDMETHOD_(TargetOperationKind, GetKind)(THIS) PURE;

    // GetDirection():
    //
    // Returns what direction of operation this is.
    //
    STDMETHOD_(TargetOperationDirection, GetDirection)(THIS) PURE;

    // GetStatus():
    //
    // Returns the status of the operation (e.g.: whether it is compelted, canceled, etc...)
    //
    STDMETHOD_(TargetOperationStatus, GetStatus)(THIS) PURE;

    // Cancel():
    //
    // If the operation can be canceled, it will be canceled.  The semantic meaning of a cancellation depends
    // on the operation in question.  For instance:
    //
    //     For a halt      : the target will no longer be halted
    //     For a breakpoint: the breakpoint will be cleared
    //
    STDMETHOD_(bool, Cancel)(THIS) PURE;

    // WaitForChange():
    //
    // Waits for the status of the operation to change.  This may indicate that the operation was canceled,
    // completed, or was otherwise triggered.
    //
    STDMETHOD(WaitForChange)(
        THIS_
        _Out_ TargetOperationStatus *pOpStatus
        ) PURE;

    // NotifyOnChange():
    //
    // Called to setup a callback on state change of the operation.  If the operation has changed state to anything
    // other than pending prior to the call, such notification will be made immediately.
    //
    // Note that more than one notification can be registered on any particular operation (though one is most typical)
    //
    STDMETHOD(NotifyOnChange)(
        THIS_
        _In_ ISvcTargetOperationStatusNotification *pNotify
        ) PURE;

    // RemoveNotifyOnChange():
    //
    // Called to remove a notification callback as registered via NotifyOnChange.
    //
    STDMETHOD(RemoveNotifyOnChange)(
        THIS_
        _In_ ISvcTargetOperationStatusNotification *pNotify
        ) PURE;
};

#undef INTERFACE
#define INTERFACE ISvcStepController
DECLARE_INTERFACE_(ISvcStepController, IUnknown)
{
    // NotifyOnChange():
    //
    // Called to setup a callback on state change of the step controller more generally.  Such a state change
    // may or may not be the result of an operation.
    //
    // Note that more than one notification can be registered (though one is most typical)
    //
    STDMETHOD(NotifyOnChange)(
        THIS_
        _In_ ISvcTargetStateChangeNotification *pNotify
        ) PURE;

    // RemoveNotifyOnChange():
    //
    // Called to remove a notification callback as registered via NotifyOnChange.
    //
    STDMETHOD(RemoveOnChange)(
        THIS_
        _In_ ISvcTargetStateChangeNotification *pNotify
        ) PURE;

    // GetStatus():
    //
    // Gets the current status of the target.
    //
    STDMETHOD_(TargetStatus, GetStatus)(THIS) PURE;

    // GetHaltReason():
    //
    // Gets the reason why the target is halted.  This call may only legally be made while GetStatus() returns
    // that the target is halted.  Calling otherwise will always return HaltUnknown.
    //
    STDMETHOD_(HaltReason, GetHaltReason)(THIS) PURE;

    // Run():
    //
    // Causes the underlying target to resume execution.  A handle to the run operation
    // is returned.  If the requested operation cannot be performed (e.g.: a requested "Run backward" call
    // is made on a target which can only "Run forward"), the implementation may legally return E_NOTIMPL.
    //
    // A run operation is considered completed when the underlying target has *STARTED* running.
    //
    // This call may only be made when the target is in a halted status.  Calling in other circumstnaces will
    // result in E_ILLEGAL_METHOD_CALL.
    //
    STDMETHOD(Run)(
        THIS_
        _In_ TargetOperationDirection dir,
        _COM_Outptr_ ISvcTargetOperation **ppRunHandle,
        _In_opt_ ISvcTargetOperationStatusNotification *pNotify
        ) PURE;

    // Halt():
    //
    // Causes the underlying target to halt execution (break in).  A handle to the halt operation
    // is returned.
    //
    // A halt operation is considered completed when the underlying target has completely halted.
    //
    // This call may only be made when the target is in a running status.  Calling in other circumstances will
    // result in E_ILLEGAL_METHOD_CALL.
    //
    STDMETHOD(Halt)(
        THIS_
        _COM_Outptr_ ISvcTargetOperation **ppHaltHandle,
        _In_opt_ ISvcTargetOperationStatusNotification *pNotify
        ) PURE;

    // Step():
    //
    // Causes the underlying target to step a particular execution unit by 'steps' fundamental
    // units (e.g.: instructions).  If the requested operation cannot be performed (e.g.: a requeted "Step backward"
    // call is made on a target which can only "Step forward"), the implementation may legally return E_NOTIMPL.
    //
    // A step operation is considered completed when the step has completed and the target has successfully
    // halted.
    //
    // This call may only be made when the target is in a halted status.  Calling in other circumstances will result
    // in E_ILLEGAL_METHOD_CALL.
    //
    STDMETHOD(Step)(
        THIS_
        _In_ ISvcExecutionUnit *pStepUnit,
        _In_ TargetOperationDirection dir,
        _In_ ULONG64 steps,
        _COM_Outptr_ ISvcTargetOperation **ppStepHandle,
        _In_opt_ ISvcTargetOperationStatusNotification *pNotify
        ) PURE;
};

// BreakpointKind:
//
// Defines the kind of breakpoint.
//
enum BreakpointKind
{
    BreakpointCode,
    BreakpointData
};

// DataAccessFlags:
//
// Defines a particular type of data access.
//
enum DataAccessFlags
{
    DataNone    = 0x00000000,
    DataRead    = 0x00000001,
    DataWrite   = 0x00000002,
    DataExecute = 0x00000004
};

#undef INTERFACE
#define INTERFACE ISvcBreakpoint
DECLARE_INTERFACE_(ISvcBreakpoint, IUnknown)
{
    //*************************************************
    // General Breakpoints:
    //

    // GetKind():
    //
    // Gets the kind of breakpoint that this ISvcBreakpoint represents.
    //
    STDMETHOD_(BreakpointKind, GetKind)(
        THIS
        ) PURE;

    // GetProcessKey():
    //
    // Gets the process key which this breakpoint is set within.
    //
    STDMETHOD_(ULONG64, GetProcessKey)(
        THIS
        ) PURE;

    // GetAddress():
    //
    // Gets the address for this breakpoint.
    //
    STDMETHOD_(ULONG64, GetAddress)(
        THIS
        ) PURE;

    //*************************************************
    // Common Operations:
    //

    // Delete():
    //
    // Deletes the breakpoint.
    //
    STDMETHOD(Delete)(
        THIS
        ) PURE;

    // Disable():
    //
    // Disables the breakpoint.  Disable is an on/off operation.  You cannot disable a disabled
    // breakpoint.  Calling Disable on a disabled breakpoint will return S_FALSE as an indication
    // that the breakpoint is disabled BUT that the Disable call was not the actor which performed
    // the operation.
    //
    STDMETHOD(Disable)(
        THIS
        ) PURE;

    // Enable():
    //
    // Enables the breakpoint.  Enable is an on/off operation.  You cannot enable an enabled
    // breakpoint.  Calling Enable on an enabled breakpoint will return S_FALSE as an indication
    // that the breakpoint is enabled BUT that the Enable call was not the actor which performed
    // the operation.
    //
    STDMETHOD(Enable)(
        THIS
        ) PURE;

    //*************************************************
    // Data Breakpoint Only:
    //

    // GetDataAccessFlags():
    //
    // Gets the data access flags for this breakpoint.  This method will fail when called on
    // a breakpoint which is not a data breakpoint.
    //
    STDMETHOD(GetDataAccessFlags)(
        THIS_
        _Out_ DataAccessFlags *pFlags
        ) PURE;

    // GetDataWidth():
    //
    // Gets the data access width for this breakpoint.  This method will fail when called on
    // a breakpoint which is not a data brakpoint.
    //
    STDMETHOD(GetDataWidth)(
        THIS_
        _Out_ ULONG64 *pWidth
        ) PURE;
};

// ISvcBreakpointEnumerator:
//
// Enumerates breakpoints.
//
#undef INTERFACE
#define INTERFACE ISvcBreakpointEnumerator
DECLARE_INTERFACE_(ISvcBreakpointEnumerator, IUnknown)
{
    // Reset():
    //
    // Resets the enumerator so that the first breakpoint in the collection is returned from the subsequent
    // GetNext call.
    //
    STDMETHOD(Reset)(
        THIS
        ) PURE;

    // GetNext():
    //
    // Gets the next breakpoint in the collection.
    //
    STDMETHOD(GetNext)(
        THIS_
        _COM_Outptr_ ISvcBreakpoint **ppBreakpoint
        ) PURE;
};

// ISvcBreakpointController:
//
// The low level interface exposed from a DEBUG_SERVICE_BREAKPOINT_CONTROLLER which handles the fundamental
// low level breakpoint operations.  Higher level breakpoint operations (e.g.: source level / deferred / etc...)
// are handled at the breakpoint manager level.
//
#undef INTERFACE
#define INTERFACE ISvcBreakpointController
DECLARE_INTERFACE_(ISvcBreakpointController, IUnknown)
{
    // EnumerateBreakpoints():
    //
    // Enumerates all breakpoints known to the breakpoint controller.  Note that this will *ONLY* enumerate
    // breakpoints known to the controller.  There may be logically higher level breakpoints which are not
    // realized as a single underlying breakpoint and are handled at the manager level.
    //
    STDMETHOD(EnumerateBreakpoints)(
        THIS_
        _In_opt_ ISvcProcess *pProcess,
        _COM_Outptr_ ISvcBreakpointEnumerator **ppBreakpointEnum
        ) PURE;

    // CreateCodeBreakpoint():
    //
    // Creates a new code breakpoint at a given address.
    //
    STDMETHOD(CreateCodeBreakpoint)(
        THIS_
        _In_opt_ ISvcProcess *pProcess,
        _In_ ULONG64 address,
        _COM_Outptr_ ISvcBreakpoint **ppBreakpoint
        ) PURE;

    // CreateDataBreakpoint():
    //
    // Creates a new data breakpoint at a given address.
    //
    STDMETHOD(CreateDataBreakpoint)(
        THIS_
        _In_opt_ ISvcProcess *pProcess,
        _In_ ULONG64 address,
        _In_ ULONG64 dataWidth,
        _In_ DataAccessFlags accessFlags,
        _COM_Outptr_ ISvcBreakpoint **ppBreakpoint
        ) PURE;
};

// ISvcBreakpointControllerAdvanced:
//
// Advanced information from the breakpoint controller.
//
#undef INTERFACE
#define INTERFACE ISvcBreakpointControllerAdvanced
DECLARE_INTERFACE_(ISvcBreakpointControllerAdvanced, IUnknown)
{
    // DoesBreakpointTrapAddressReflectHardware();
    //
    // Indicates whether or not the register context retrieved for a breakpoint trap reflects @pc as
    // reported by the underlying hardware trap/fault.  This should normally return *true* and, if this
    // interface is not present, the assumption is that the value is true.
    //
    // On ARM64, the "BRK ..." instruction used for software breakpoints represents a fault where the
    // address points *AT* the "BRK ..." instruction.  This is unlike the "int 3" trap on X64 where the
    // address points *AFTER* the "int 3" instruction.
    //
    // For ARM64, the Windows kernel adjusts the program counter of the corresponding trap frame to match
    // the X64 semantics.  That is, the address of the exception points at "BRK ..." but the context record
    // for the thread (& trap frame) refer to a @pc which is *AFTER* the "BRK ..." instruction.  Other platforms
    // (e.g.: Linux) **DO NOT** make this adjustment.  The debugger needs to know whether this has happened
    // or not.  This method returning "true" indicates that the values returned reflect the hardware without
    // any such "adjustments" applied.  This method returning "false" indicates the Windows behavior where
    // the context record (& trap frame) @pc refer to an instruction *AFTER* the "BRK ...".
    //
    STDMETHOD_(bool, DoesBreakpointTrapAddressReflectHardware)(
        THIS
        ) PURE;
};

// ISvcBreakpointControllerAdvanced2:
//
// Advanced information from the breakpoint controller.
//
#undef INTERFACE
#define INTERFACE ISvcBreakpointControllerAdvanced2
DECLARE_INTERFACE_(ISvcBreakpointControllerAdvanced2, ISvcBreakpointControllerAdvanced)
{
    // GetSoftwareBreakpointAddressDelta():
    //
    // This method is optional and may legally return E_NOTIMPL.  If this method is implemented, it supercedes
    // any implementation of ISvcBreakpointControllerAdvanced::DoesBreakpointTrapAddressReflectHardware.
    //
    // If a breakpoint is set with CreateCodeBreakpoint on the controller and such breakpoint is hit on a given
    // thread or processor X, and the register context of 'X' is fetched and @pc interrogated, this returns the
    // number of bytes @pc is past the breakpoint instruction.  This may be zero (indicating that @pc will be
    // reported as the address of the breakpoint or it maybe a positive value indicating that @pc will be reported
    // past the breakpoint instruction).
    //
    // On X64, it is typical that a software breakpoint will result in a context which is "past" the instruction
    // (e.g.: an int 3) which generates the trap.  On ARM64, the "BRK ..." instruction is a fault and it is typical
    // that this results in a context which is "at" the instruction.  Thus, for "X64", this would typically return
    // "1" (the size of an "int 3" encoding) and for ARM64, it would typically return "0".  On Windows, the kernel
    // will make "ARM64" look like X64 and adjust the context record.  Thus, on Windows ARM64, this would return
    // "4" (the size of a "BRK ..." encoding).  The same is not true of a GDBServer running on Linux (where this
    // would return "0" for ARM64).  Even on X64, an RR GDBServer will return a register contexct that pointed
    // at the breakpoint instruction (and hence, this would return "0").
    //
    // Because of the variety of ways this can manifest, if this API is supported, the debugger trusts this value
    // when looking at the register context after a breakpoint is reported.
    //
    STDMETHOD(GetSoftwareBreakpointAddressDelta)(
        _Out_ ULONG64 *pByteCountPastInstruction
        ) PURE;
};

//**************************************************************************
// State Synchronization Services:
//

enum SvcSecondaryStateSynchronizationProfileItemKind
{
    SvcSynchronizationProfileUnspecified = 0,   // Private: details via QI of private interfaces
    SvcSynchronizationProfileGenerationCounter  // ISvcSecondaryStateSynchronizationGenerationCounterProfileItem
};

// ISvcSecondaryStateSynchronizationProfileItem:
//
// Describes one aspect of how to synchronize state between a primary and secondary client.
//
#undef INTERFACE
#define INTERFACE ISvcSecondaryStateSynchronizationProfileItem
DECLARE_INTERFACE_(ISvcSecondaryStateSynchronizationProfileItem, IUnknown)
{
    // GetKind():
    //
    // Returns a SecondaryStateSynchronzationProfileItemKind enumerant which indicates what kind of item
    // this particular item is (and what primary interface it supports).  A "private" item may return "Unspecified"
    // and it is entirely up to user-defined QueryInterface calls to determine the appropriate behavior.
    //
    STDMETHOD_(SvcSecondaryStateSynchronizationProfileItemKind, GetKind)(
        ) PURE;
};

// ISvcSecondaryStateSynchronizationGenerationCounterProfileItem:
//
// A generation counter which describes a certain "version" of state between a primary and secondary client.
//
#undef INTERFACE
#define INTERFACE ISvcSecondaryStateSynchronizationGenerationCounterProfileItem
DECLARE_INTERFACE_(ISvcSecondaryStateSynchronizationGenerationCounterProfileItem, IUnknown)
{
    // GetValue():
    //
    // Returns the value of the generation counter.  A generation counter is conceptually a 128-bit value
    // given as two 64-bit values: a "primary" value which would logically be thought of as the "most significant"
    // part of the value and a "secondary" value which would logically be though of as the "least significant"
    // part of the value.  Note that it is perfectly legal for an implementation of a generation counter to be
    // 64-bit (or less).  If such is done, the secondary value should be left as 0 and only the primary value
    // used.
    //
    STDMETHOD(GetValue)(
        THIS_
        _Out_ ULONG64 *pPrimaryValue,
        _Out_ ULONG64 *pSecondaryValue
        ) PURE;
};

// ISvcSecondaryStateSynchronizationProfiles:
//
// Controls aspects of synchronizing state between a primary and secondary client.
//
#undef INTERFACE
#define INTERFACE ISvcSecondaryStateSynchronizationProfiles
DECLARE_INTERFACE_(ISvcSecondaryStateSynchronizationProfiles, IUnknown)
{
    // EnumerateSynchronizationItems():
    //
    // RESERVED for future.  Current implementations should E_NOTIMPL this.
    //
    STDMETHOD(EnumerateSynchronizationItems)(
        THIS_
        _COM_Outptr_ ISvcSecondaryStateSynchronizationProfileItemEnumerator **ppEnumerator
        ) PURE;

    // ApplySynchronizationItem():
    //
    // Applies a secondary state synchronization item to this target.
    //
    STDMETHOD(ApplySynchronizationItem)(
        THIS_
        _COM_Outptr_ ISvcSecondaryStateSynchronizationProfileItem *pItem
        ) PURE;
};

// ISvcSecondaryStateSynchronizationProfileItemEnumerator:
//
// An enumerator which enumerates secondary state synchronization profile items.
//
#undef INTERFACE
#define INTERFACE ISvcSecondaryStateSynchronizationProfileItemEnumerator
DECLARE_INTERFACE_(ISvcSecondaryStateSynchronizationProfileItemEnumerator, IUnknown)
{
    // Reset():
    //
    // Resets the enumerator.
    //
    STDMETHOD(Reset)(
        THIS
        ) PURE;

    // GetNext():
    //
    // Gets the next secondary state synchronization profile item.
    //
    STDMETHOD(GetNext)(
        THIS_
        _COM_Outptr_ ISvcSecondaryStateSynchronizationProfileItem **ppProfileItem
        ) PURE;
};

//**************************************************************************
// Events:
//

// DEBUG_SVCEVENT_SERVICEMANAGERINITIALIZED:
//
// An event which is fired when the service manager container is initialized.
//
// Event Argument:
//
//     [Reserved] Currently, always nullptr
//
// Event Guid:
//
//     966E5F1F-C1DD-45b0-8C39-112EFF58D996
//
DEFINE_GUID(DEBUG_SVCEVENT_SERVICEMANAGERINITIALIZED, 0x966e5f1f, 0xc1dd, 0x45b0, 0x8c, 0x39, 0x11, 0x2e, 0xff, 0x58, 0xd9, 0x96);

// DEBUG_SVCEVENT_HOSTINITIALIZED:
//
// An optional event which is fired when the host is initialized.
//
// Event Argument:
//
//     [Reserved] Currently, always nullptr
//
// Event Guid:
//
//     5A7C9472-E576-4d1f-A0E2-DA602F5EEBEF
//
DEFINE_GUID(DEBUG_SVCEVENT_HOSTINITIALIZED, 0x5a7c9472, 0xe576, 0x4d1f, 0xa0, 0xe2, 0xda, 0x60, 0x2f, 0x5e, 0xeb, 0xef);

// DEBUG_SVCEVENT_SERVICEMANAGERUNINITIALIZING:
//
// An event which is fired when the service manager container is uninitialized (immediately before
// any uninitialization actions)
//
// Event Argument:
//
//     [Reserved] Currently, always nullptr
//
// Event Guid:
//
//     189FFEA7-FE84-4e66-A41F-2F31839D7C4B
//
DEFINE_GUID(DEBUG_SVCEVENT_SERVICEMANAGERUNINITIALIZING, 0x189ffea7, 0xfe84, 0x4e66, 0xa4, 0x1f, 0x2f, 0x31, 0x83, 0x9d, 0x7c, 0x4b);

// DEBUG_SVCEVENT_CONTEXTINVALIDATE:
//
// An event which is fired when, for any reason, context information (e.g.: registers, etc...) needs to be invalidated.
// Any service which caches context information must flush its cache upon receipt of this event.
//
// Event Argument:
//
//     [Reserved] Currently, always nullptr
//
// Event Guid:
//
//     F89FEFFD-EF5D-4f04-AB62-943E0402B2EC
//
DEFINE_GUID(DEBUG_SVCEVENT_CONTEXTINVALIDATE, 0xf89feffd, 0xef5d, 0x4f04, 0xab, 0x62, 0x94, 0x3e, 0x4, 0x2, 0xb2, 0xec);

// DEBUG_SVCEVENT_SEARCHPATHSCHANGED:
//
// An event which is fired when the search paths for images or symbols is changed.
//
// Event Argument:
//
//     ISvcEventArgumentsSearchPathsChanged: Please note that the ISvcEventArgumentsSearchPathsChanged argument
//     was added in a later version of this event.  If you are not on a sufficiently new debugger engine,
//     the event is still raised but with a nullptr argument.
//
// Event Guid:
//
//     53E3027B-535E-4e21-972E-F76FE605A1B0}
//
DEFINE_GUID(DEBUG_SVCEVENT_SEARCHPATHSCHANGED, 0x53e3027b, 0x535e, 0x4e21, 0x97, 0x2e, 0xf7, 0x6f, 0xe6, 0x5, 0xa1, 0xb0);

#undef INTERFACE
#define INTERFACE ISvcEventArgumentsSearchPathsChanged
DECLARE_INTERFACE_(ISvcEventArgumentsSearchPathsChanged, IUnknown)
{
    // GetAllPaths():
    //
    // Provides a semicolon separated list of paths from which the provider will search for the
    // appropriate images/symbols.  Note that this will return symbol server syntax.
    //
    STDMETHOD(GetAllPaths)(
        THIS_
        _Out_ BSTR *searchPaths
        ) PURE;
};

// DEBUG_SVCEVENT_SYMBOLLOAD:
//
// Symbols have been successfully loaded for a given module.
//
// Event Argument:
//
//     ISvcEventArgumentsSymbolLoad
//
// {6A8ABDFC-9607-4ab7-B3D2-75AFFA1A2B02}
//
DEFINE_GUID(DEBUG_SVCEVENT_SYMBOLLOAD, 0x6a8abdfc, 0x9607, 0x4ab7, 0xb3, 0xd2, 0x75, 0xaf, 0xfa, 0x1a, 0x2b, 0x2);

#undef INTERFACE
#define INTERFACE ISvcEventArgumentsSymbolLoad
DECLARE_INTERFACE_(ISvcEventArgumentsSymbolLoad, IUnknown)
{
    // GetModule():
    //
    // Gets the module for which symbols were loaded.
    //
    STDMETHOD(GetModule)(
        THIS_
        _COM_Outptr_ ISvcModule **module
        ) PURE;

    // GetSymbols():
    //
    // Gets the symbols which were loaded for the module.  The caller should check the output result for nullptr
    // for symbol formats which are not (currently) expressable as a symbol set.
    //
    STDMETHOD(GetSymbols)(
        THIS_
        _COM_Outptr_ ISvcSymbolSet **symbols
        ) PURE;
};

// DEBUG_SVCEVENT_SYMBOLUNLOAD
//
// Fired immediately before symbols are unloaded for a given module.  This allows any components which are caching
// information outside the context of a symbol set to flush caches as appropriate.  Such event may be fired
// immediately before loading symbols again in the context of a reload of symbols (e.g.: after changing
// symbol search paths, etc...)
//
// Event Argument:
//
//     ISvcEventArgumentsSymbolUnload
//
// {507FD081-9C6A-45e0-9762-51D0F62914F3}
//
DEFINE_GUID(DEBUG_SVCEVENT_SYMBOLUNLOAD, 0x507fd081, 0x9c6a, 0x45e0, 0x97, 0x62, 0x51, 0xd0, 0xf6, 0x29, 0x14, 0xf3);

#undef INTERFACE
#define INTERFACE ISvcEventArgumentsSymbolUnload
DECLARE_INTERFACE_(ISvcEventArgumentsSymbolUnload, IUnknown)
{
    // GetModule():
    //
    // Gets the module for which symbols are being unloaded.
    //
    STDMETHOD(GetModule)(
        THIS_
        _COM_Outptr_ ISvcModule **module
        ) PURE;

    // GetSymbols():
    //
    // Gets the symbols which were loaded for the module.  The caller should check the output result for nullptr
    // for symbol formats which are not (currently) expressable as a symbol set.
    //
    STDMETHOD(GetSymbols)(
        THIS_
        _COM_Outptr_ ISvcSymbolSet **symbols
        ) PURE;
};

// DEBUG_SVCEVENT_MODULEARRIVAL
//
// A new module has arrived or been detected.  This may indicate that a module was "loaded",
// that a JIT module was allocated, or that some other mechanism detected a previously unknown module.
//
// This event may *ONLY* be fired by the module enumeration service which is responsible for the initial
// presentation of the module.  At the time the event is fired (as seen by any listener), the module enumeration
// service must already present the given module.
//
// Event Argument:
//
//     ISvcEventArgumentsModuleDiscovery
//
// {08DA6258-3D12-45c7-BCF9-BC88E6E5049A}
//
DEFINE_GUID(DEBUG_SVCEVENT_MODULEARRIVAL, 0x8da6258, 0x3d12, 0x45c7, 0xbc, 0xf9, 0xbc, 0x88, 0xe6, 0xe5, 0x4, 0x9a);

// DEBUG_SVCEVENT_MODULEDISAPPEARANCE
//
// A module which was previously discovered is no longer present.  This may indicate that a module was "unloaded",
// that a JIT module was deallocated, or that some other mechanism decided that the module is no longer relevant
// to the target system.
//
// This event may *ONLY* be fired by the module enumeration service which was responsible for the initial
// presentation of the module.  At the time the event is fired (as seen by any listener), the module enumeration
// service must already have removed the given module.
//
// Event Argument:
//
//     ISvcEventArgumentsModuleDiscovery
//
// {A849133A-56E6-4878-9A0F-71152554EA02}
//
DEFINE_GUID(DEBUG_SVCEVENT_MODULEDISAPPEARANCE, 0xa849133a, 0x56e6, 0x4878, 0x9a, 0xf, 0x71, 0x15, 0x25, 0x54, 0xea, 0x2);

#undef INTERFACE
#define INTERFACE ISvcEventArgumentsModuleDiscovery
DECLARE_INTERFACE_(ISvcEventArgumentsModuleDiscovery, IUnknown)
{
    // GetModule():
    //
    // Gets the module which is (dis)appearing.
    //
    // For a module arrival event, the returned module must already be in the enumerator as of the firing
    // of this event and must be fully valid.
    //
    // For a module disappearance event, the interfaces on the returned module *MUST* continue to operate
    // as if the module were loaded until the event notification has completed.  This means fetching the name,
    // base address, size, etc...  must function during the event notification.  After the event notification
    // is complete, the module may be considered detached/orphaned for anyone continuing to hold the
    // ISvcModule interface.
    //
    STDMETHOD(GetModule)(
        THIS_
        _COM_Outptr_ ISvcModule **module
        ) PURE;
};

// DEBUG_SVCEVENT_SOURCEMAPPINGS_CHANGED
//
// If there is a provider which demand provides source mappings akin to a symbol server, it should fire this
// event if the source mappings for a particular module change in order that any listener can update necessary
// caches.
//
// Event Argument:
//
//     ISvcEventArgumentsSourceMappingsChanged
//
// {B476344D-7EB1-4eb7-AD4C-AA19A83059C1}
//
DEFINE_GUID(DEBUG_SVCEVENT_SOURCEMAPPINGS_CHANGED, 0xb476344d, 0x7eb1, 0x4eb7, 0xad, 0x4c, 0xaa, 0x19, 0xa8, 0x30, 0x59, 0xc1);

#undef INTERFACE
#define INTERFACE ISvcEventArgumentsSourceMappingsChanged
DECLARE_INTERFACE_(ISvcEventArgumentsSourceMappingsChanged, IUnknown)
{
    // GetModule():
    //
    // Gets the module for which source mappings are changing.
    //
    STDMETHOD(GetModule)(
        THIS_
        _COM_Outptr_ ISvcModule **module
        ) PURE;
};

// DEBUG_SVCEVENT_EXECUTIONSTATECHANGE
//
// An event which is fired when the execution state of the debugger changes (the target breaks in, the target resumes,
// etc...
//
// Event Argument:
//
//     ISvcEventArgumentExecutionStateChange
//
// Event Guid:
//
//     466C9324-F601-4cac-9EAA-8A1E89A0C21E
//
DEFINE_GUID(DEBUG_SVCEVENT_EXECUTIONSTATECHANGE, 0x466c9324, 0xf601, 0x4cac, 0x9e, 0xaa, 0x8a, 0x1e, 0x89, 0xa0, 0xc2, 0x1e);

enum SvcExecutionStateChangeKind
{
    // The target has (or is about to) resume execution
    SvcExecutionStateContinue,

    // The target has (or is about to) break into the debugger.
    SvcExecutionStateBreak
};

#undef INTERFACE
#define INTERFACE ISvcEventArgumentExecutionStateChange
DECLARE_INTERFACE_(ISvcEventArgumentExecutionStateChange, IUnknown)
{
    // GetChangeKind():
    //
    // Gets the kind of execution state change which has occurred.
    //
    STDMETHOD_(SvcExecutionStateChangeKind, GetChangeKind)(
        THIS
        ) PURE;

    // GetChangeEffects():
    //
    // Gets the process and/or execution unit which is affected by the state change.  These may be null
    // on output, indicating that the change affected every process/execution unit in the debug target.
    //
    STDMETHOD(GetChangeEffects)(
        THIS_
        _COM_Outptr_result_maybenull_ ISvcProcess **process,
        _COM_Outptr_result_maybenull_ ISvcExecutionUnit **executionUnit
        ) PURE;

};

// DEBUG_SVCEVENT_SYMBOLCACHEINVALIDATE
//
// An event which is fired when something changes that makes any cached symbols from a given symbol set no longer
// valid.  Any caller which caches individual symbols from a symbol set should listen to this change and flush
// their caches upon receipt.
//
// Event Argument:
//
//     ISvcEventArgumentsSymbolCacheInvalidate
//
// Event Guid:
//
//     3B740272-22A7-40d4-A1E6-12E1BCFD232C
//
DEFINE_GUID(DEBUG_SVCEVENT_SYMBOLCACHEINVALIDATE, 0x3b740272, 0x22a7, 0x40d4, 0xa1, 0xe6, 0x12, 0xe1, 0xbc, 0xfd, 0x23, 0x2c);

#undef INTERFACE
#define INTERFACE ISvcEventArgumentsSymbolCacheInvalidate
DECLARE_INTERFACE_(ISvcEventArgumentsSymbolCacheInvalidate, IUnknown)
{
    // GetSymbolsInformation():
    //
    // Gets information about the module and symbol set for which cache invalidation should occur.
    //
    STDMETHOD(GetSymbolsInformation)(
        THIS_
        _COM_Outptr_ ISvcModule **module,
        _COM_Outptr_ ISvcSymbolSet **symbolSet
        ) PURE;
};

// DEBUG_SVCEVENT_PROCESSARRIVAL
//
// An event which is fired when a new process is targeted by a target.  This may be the result of attaching or
// creating a process *OR* it may be the result of a child process being created while the parent is selected
// to debug all children.
//
// Event Argument:
//
//     ISvcEventArgumentsProcessDiscovery
//
// Event Guid:
//
//     C1AAFD0B-044B-4e2a-A4B0-4B2BF900EDFA
//
DEFINE_GUID(DEBUG_SVCEVENT_PROCESSARRIVAL, 0xc1aafd0b, 0x44b, 0x4e2a, 0xa4, 0xb0, 0x4b, 0x2b, 0xf9, 0x0, 0xed, 0xfa);

// DEBUG_SVCEVENT_PROCESSEXIT
//
// An event which is fired when a process which is targeted exits.
//
// Event Argument:
//
//     ISvcEventArgumentsProcessDiscovery
//
// Event Guid:
//
//     FC9AA8EF-BA7A-4823-9D2F-9F5B3DE9693C
//
DEFINE_GUID(DEBUG_SVCEVENT_PROCESSEXIT, 0xfc9aa8ef, 0xba7a, 0x4823, 0x9d, 0x2f, 0x9f, 0x5b, 0x3d, 0xe9, 0x69, 0x3c);

// DEBUG_SVCEVENT_PROCESSEXEC
//
// An event which is fired when a process does a Unix style exec (effectively replacing the process
// with a new one).
//
// Event Argument:
//
//     ISvcEventArgumentsProcessDiscovery
//
// Event Guid:
//
//     BBD69DE9-331D-48bc-8C2A-D8A8C3CD2E87
//
DEFINE_GUID(DEBUG_SVCEVENT_PROCESSEXEC, 0xbbd69de9, 0x331d, 0x48bc, 0x8c, 0x2a, 0xd8, 0xa8, 0xc3, 0xcd, 0x2e, 0x87);

#undef INTERFACE
#define INTERFACE ISvcEventArgumentsProcessDiscovery
DECLARE_INTERFACE_(ISvcEventArgumentsProcessDiscovery, IUnknown)
{
    // GetProcess():
    //
    // Gets the process which is (dis)appearing.
    //
    // For a process arrival event, the returned process must already be in the enumerator as of the firing
    // of this event and must be fully valid.
    //
    // For a process disappearance event, the interfaces on the returned module *MUST* continue to operate
    // as if the process were targeted until the event notification has completed.  After the event notification
    // is complete, the process may be considered detached/orphaned for anyone continuing to hold the
    // ISvcProcess interface.
    //
    STDMETHOD(GetProcess)(
        THIS_
        _COM_Outptr_ ISvcProcess **process
        ) PURE;

    // GetExitCode():
    //
    // Gets the exit code of the process.  This may only be called for a process exit event.
    // It returns E_ILLEGAL_METHOD_CALL for a process arrival event.
    //
    STDMETHOD(GetExitCode)(
        THIS_
        _Out_ ULONG64 *exitCode
        ) PURE;
};

// DEBUG_SVCEVENT_THREADARRIVAL:
//
// An event which is fired when a new thread is created by a target.
//
// Event Argument:
//
//     ISvcEventArgumentsThreadDiscovery
//
// Event Guid:
//
//     4DC31DD9-43A0-4c12-ADAF-E5DDB68E00C7
//
DEFINE_GUID(DEBUG_SVCEVENT_THREADARRIVAL, 0x4dc31dd9, 0x43a0, 0x4c12, 0xad, 0xaf, 0xe5, 0xdd, 0xb6, 0x8e, 0x0, 0xc7);

// DEBUG_SVCEVENT_THREADEXIT:
//
// An event which is fired when an existing thread exits.
//
// Event Argument:
//
//     ISvcEventArgumentsThreadDiscovery
//
// Event Guid:
//
//     89DD0121-CCEF-4d60-9E2F-53CC8D638608
//
DEFINE_GUID(DEBUG_SVCEVENT_THREADEXIT, 0x89dd0121, 0xccef, 0x4d60, 0x9e, 0x2f, 0x53, 0xcc, 0x8d, 0x63, 0x86, 0x8);

#undef INTERFACE
#define INTERFACE ISvcEventArgumentsThreadDiscovery
DECLARE_INTERFACE_(ISvcEventArgumentsThreadDiscovery, IUnknown)
{
    // GetThread():
    //
    // Gets the thread which is (dis)appearing.
    //
    // For a thread arrival event, the returned thread must already be in the enumerator as of the firing
    // of this event and must be fully valid.
    //
    // For a thread disappearance event, the interfaces on the returned thread *MUST* continue to operate
    // as if the thread were targeted until the event notification has completed.  After the event notification
    // is complete, the thread may be considered detached/orphaned for anyone continuing to hold the
    // ISvcThread interface.
    //
    STDMETHOD(GetThread)(
        THIS_
        _COM_Outptr_ ISvcThread **thread
        ) PURE;

    // GetExitCode():
    //
    // Gets the exit code of the thread.  This may only be called for a thread exit event.
    // It returns E_ILLEGAL_METHOD_CALL for a thread arrival event.
    //
    STDMETHOD(GetExitCode)(
        THIS_
        _Out_ ULONG64 *exitCode
        ) PURE;
};

// DEBUG_SVCEVENT_STATECHANGE_CACHEINVALIDATE
//
// An event which targets can fire to indicate that state changed for some external reason and caches
// related to a given process (or overall kernel target) need to be flushed.
//
// Event Argument:
//
//     ISvcEventArgumentsStateChangeCacheInvalidate
//
// Event Guid:
//
//     33F56B14-0A0D-4a31-896F-1229ACAC0ADB
//
DEFINE_GUID(DEBUG_SVCEVENT_STATECHANGE_CACHEINVALIDATE, 0x33f56b14, 0xa0d, 0x4a31, 0x89, 0x6f, 0x12, 0x29, 0xac, 0xac, 0xa, 0xdb);

#undef INTERFACE
#define INTERFACE ISvcEventArgumentsStateChangeCacheInvalidate
DECLARE_INTERFACE_(ISvcEventArgumentsStateChangeCacheInvalidate, IUnknown)
{
    // GetProcess():
    //
    // Gets the process for which state has changed.  If more than one process is involved or the change is system wide
    // (e.g.: for a kernel target), the process may be null.
    //
    STDMETHOD(GetProcess)(
        THIS_
        _COM_Outptr_result_maybenull_ ISvcProcess **process
        ) PURE;
};

// SvcChecksumKind:
//
// Indicates the kind of checksum
//
enum SvcChecksumKind
{
    ChecksumKind_None,        // indicates no checksum is available
    ChecksumKind_MD5,
    ChecksumKind_SHA1,
    ChecksumKind_SHA256,
};

// ISvcSymbolSetSourceFileChecksums:
//
// Private bridge interface to symbol providers which return the checksum for a source file.
//
#undef INTERFACE
#define INTERFACE ISvcSymbolSetSourceFileChecksums
DECLARE_INTERFACE_(ISvcSymbolSetSourceFileChecksums, IUnknown)
{
    //*************************************************
    // ISvcSymbolSetSourceFileChecksums:
    //

    // GetLegacySourceFileChecksumInformation():
    //
    // Returns the source file checksum kind and the buffer length needed for it
    //
    STDMETHOD(GetLegacySourceFileChecksumInformation)(
        THIS_
        _In_ PCWSTR fileName,
        _Out_ SvcChecksumKind *pChecksumKind,
        _Out_ ULONG *pChecksumSize
        ) PURE;

    // GetLegacySourceFileChecksum():
    //
    // Reads the source file checksum
    //
    STDMETHOD(GetLegacySourceFileChecksum)(
        THIS_
        _In_ PCWSTR fileName,
        _Out_ SvcChecksumKind *pChecksumKind,
        _Out_writes_(checksumSize) BYTE * const pChecksum,
        _In_ DWORD const checksumSize,
        _Out_ DWORD * const pActualBytesWritten
        ) PURE;
};
#ifdef __cplusplus
}; // extern "C"

namespace Debugger
{
namespace TargetComposition
{
namespace Client
{

#ifdef _WRL_IMPLEMENTS_H_

// ServiceBase:
//
// A base class which implements all of the required IDebugServiceLayer methods as if the service is empty and does nothing.
// The user of this class should derive from it and override methods.
//
class ServiceBase :
    public Microsoft::WRL::Implements<
        Microsoft::WRL::RuntimeClassFlags<Microsoft::WRL::RuntimeClassType::ClassicCom>,
        IDebugServiceLayer
        >
{
public:

    // RegisterServices():
    //
    // Registers the services provided by this object (derived class MUST override)
    //
    IFACEMETHOD(RegisterServices)(_In_ IDebugServiceManager * /*pServiceManager*/)
    {
        return S_OK;
    }

    // GetServiceDependencies():
    //
    // Returns the set of services which this service layer / component depends on.  Having sizeHardDependencies or
    // sizeSoftDependencies set to 0 will pass back the number of dependencies and do nothing else.
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
        UNREFERENCED_PARAMETER(sizeHardDependencies);
        UNREFERENCED_PARAMETER(sizeSoftDependencies);

        *pNumHardDependencies = 0;
        *pNumSoftDependencies = 0;
        return S_OK;
    }

    // InitializeServices():
    //
    // Performs initialization of the services in a service layer / component.  Services which aggregate, encapsulate, or
    // stack on top of other services must pass down the initialization notification in an appropriate manner (with
    // notificationKind set to LayeredNotification.
    //
    IFACEMETHOD(InitializeServices)(_In_ ServiceNotificationKind /*notificationKind*/,
                                    _In_ IDebugServiceManager * /*pServiceManager*/,
                                    _In_ REFGUID /*serviceGuid*/)
    {
        return S_OK;
    }

    // NotifyService():
    //
    // Called to notify this component that a service in the target composition stack has changed.
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
    // Called to notify this component that an event of interest occurred.
    //
    IFACEMETHOD(NotifyEvent)(_In_ IDebugServiceManager * /*pServiceManager*/,
                             _In_ REFGUID /*eventGuid*/,
                             _In_opt_ IUnknown * /*pEventArgument*/)
    {
        return S_OK;
    }
};

#endif // _WRL_IMPLEMENTS_H_

// DataReader:
//
// A helper class which assists in the reading and writing of values within a particular address space.
// This works on top of ISvcMemoryAccess and ISvcMachineArchitecture to translate reads and writes of specific
// types into appropriate byte level reads and writes on the ISvcMemoryAccess interface.
//
class DataReader
{
public:

    // DataReader():
    //
    // Construct a data reader from a given memory access interface and a given machine architecture.
    //
    DataReader(_In_ ISvcMemoryAccess *pMemoryAccess, _In_ ISvcMachineArchitecture *pMachineArch, _In_ bool holdRef = true) :
        m_pMemoryAccess(pMemoryAccess),
        m_pMachineArch(pMachineArch),
        m_holdRef(holdRef)
    {
        if (holdRef)
        {
            m_pMemoryAccess->AddRef();
            m_pMachineArch->AddRef();
        }
    }

    ~DataReader()
    {
        if (m_holdRef)
        {
            m_pMemoryAccess->Release();
            m_pMachineArch->Release();
        }
    }

    // ReadData():
    //
    // Reads an ordinal value of type T from the given memory space (correcting for endianness)
    //
    template<typename T>
    HRESULT ReadData(_In_ ISvcAddressContext *pAddressContext, _In_ ULONG64 byteOffset, _Out_ T *pItem)
    {
        static_assert(std::is_arithmetic<T>::value, "T must be a simple type");

        //
        // @TODO: Endianness flip.
        //
        ULONG64 bytesRead;
        HRESULT hr = m_pMemoryAccess->ReadMemory(pAddressContext,
                                                 byteOffset,
                                                 static_cast<void *>(pItem),
                                                 static_cast<ULONG64>(sizeof(T)),
                                                 &bytesRead);
        if (hr == S_FALSE || bytesRead != sizeof(T))
        {
            hr = E_FAIL;
        }

        return hr;
    }

    // WriteData():
    //
    // Writes an ordinal value of type T to the given memory space (correcting for endianness)
    //
    template<typename T>
    HRESULT WriteData(_In_ ISvcAddressContext *pAddressContext, _In_ ULONG64 byteOffset, _In_ T item)
    {
        static_assert(std::is_arithmetic<T>::value, "T must be a simple type");

        //
        // @TODO: Endianness flip.
        //
        ULONG64 bytesWritten;
        HRESULT hr = m_pMemoryAccess->ReadMemory(pAddressContext,
                                                 byteOffset,
                                                 static_cast<void *>(&item),
                                                 static_cast<ULONG64>(sizeof(T)),
                                                 &bytesWritten);
        if (hr == S_FALSE || bytesWritten != sizeof(T))
        {
            hr = E_FAIL;
        }

        return hr;
    }

    // ReadPointer():
    //
    // Reads a pointer from the given memory space and zero extends it to 64-bits.
    //
    HRESULT ReadPointer(_In_ ISvcAddressContext *pAddressContext, _In_ ULONG64 byteOffset, _Out_ ULONG64 *pPointerValue)
    {
        //
        // @TODO: Endianness flip.
        //
        ULONG ptr32;
        ULONG64 ptr64 = 0;
        bool is64Bit = (m_pMachineArch->GetBitness() == 64);
        HRESULT hr;
        ULONG64 bytesRead;

        if (is64Bit)
        {
            hr = m_pMemoryAccess->ReadMemory(pAddressContext,
                                             byteOffset,
                                             static_cast<void *>(&ptr64),
                                             static_cast<ULONG64>(sizeof(ULONG64)),
                                             &bytesRead);

            if (hr == S_FALSE || bytesRead != sizeof(ULONG64))
            {
                hr = E_FAIL;
            }
        }
        else
        {
            hr = m_pMemoryAccess->ReadMemory(pAddressContext,
                                             byteOffset,
                                             static_cast<void *>(&ptr32),
                                             static_cast<ULONG64>(sizeof(ULONG)),
                                             &bytesRead);

            if (hr == S_FALSE || bytesRead != sizeof(ULONG))
            {
                hr = E_FAIL;
            }
            else
            {
                //
                // Zero extend the pointer to 64-bits.
                //
                ptr64 = static_cast<ULONG64>(ptr32);
            }
        }

        if (SUCCEEDED(hr))
        {
            *pPointerValue = ptr64;
        }

        return hr;
    }

    // WritePointer():
    //
    // Writes a pointer from the given memory space.
    //
    HRESULT WritePointer(_In_ ISvcAddressContext *pAddressContext, _In_ ULONG64 byteOffset, _In_ ULONG64 pointerValue)
    {
        //
        // @TODO: Endianness flip.
        //
        ULONG ptr32;
        ULONG64 ptr64;
        bool is64Bit = (m_pMachineArch->GetBitness() == 64);
        HRESULT hr;
        ULONG64 bytesWritten;

        if (is64Bit)
        {
            ptr64 = pointerValue;
            hr = m_pMemoryAccess->WriteMemory(pAddressContext,
                                              byteOffset,
                                              static_cast<void *>(&ptr64),
                                              static_cast<ULONG64>(sizeof(ULONG64)),
                                              &bytesWritten);

            if (hr == S_FALSE || bytesWritten != sizeof(ULONG64))
            {
                hr = E_FAIL;
            }
        }
        else
        {
            //
            // Our pointers are zero extended.  If someone asks us to write a 32-bit pointer that's larger than the
            // size of a 32-bit pointer, fail.
            //
            if (pointerValue > 0xFFFFFFFFull)
            {
                return E_INVALIDARG;
            }
            ptr32 = static_cast<ULONG>(pointerValue);

            hr = m_pMemoryAccess->WriteMemory(pAddressContext,
                                              byteOffset,
                                              static_cast<void *>(&ptr32),
                                              static_cast<ULONG64>(sizeof(ULONG)),
                                              &bytesWritten);

            if (hr == S_FALSE || bytesWritten != sizeof(ULONG))
            {
                hr = E_FAIL;
            }
        }

        return hr;
    }

    // ReadDataArray():
    //
    // Reads an array of ordinal values of type T from the given memory space (correcting for endianness).
    // Partial reads of the array will return S_FALSE and an indication of how many values are actually read.
    // Partial elements will never be read.
    //
    template<typename T>
    HRESULT ReadDataArray(_In_ ISvcAddressContext *pAddressContext,
                          _In_ ULONG64 byteOffset,
                          _In_ ULONG64 arrayCount,
                          _Out_writes_(arrayCount) T *pArray,
                          _Out_ ULONG64 *pValuesRead)
    {
        HRESULT hr = S_OK;
        ULONG64 valuesRead = 0;

        for (ULONG64 i = 0; i < arrayCount; ++i)
        {
            hr = ReadData(pAddressContext, byteOffset, pArray);
            if (FAILED(hr))
            {
                break;
            }

            ++valuesRead;
            ++pArray;
            byteOffset += sizeof(T);
        }

        if (valuesRead == 0)
        {
            hr = E_FAIL;
        }
        else if (valuesRead == arrayCount)
        {
            hr = S_OK;
        }
        else
        {
            hr = S_FALSE;
        }

        *pValuesRead = valuesRead;
        return hr;
    }

    // WriteDataArray();
    //
    // Writes an array of ordinal values of type T to the given memory space (correcting for endianness).
    // Partial writes of the array will return S_FALSE and an indication of how many values were actually written.
    // Partial writes of individual elements will not occur.
    //
    template<typename T>
    HRESULT WriteDataArray(_In_ ISvcAddressContext *pAddressContext,
                           _In_ ULONG64 byteOffset,
                           _In_ ULONG64 arrayCount,
                           _In_reads_(arrayCount) T *pArray,
                           _Out_ ULONG64 *pValuesWritten)
    {
        HRESULT hr = S_OK;
        ULONG64 valuesWritten = 0;

        for (ULONG64 i = 0; i < arrayCount; ++i)
        {
            hr = WriteData(pAddressContext, byteOffset, pArray);
            if (FAILED(hr))
            {
                break;
            }

            ++valuesWritten;
            ++pArray;
            byteOffset += sizeof(T);
        }

        if (valuesWritten == 0)
        {
            hr = E_FAIL;
        }
        else if (valuesWritten == arrayCount)
        {
            hr = S_OK;
        }
        else
        {
            hr = S_FALSE;
        }

        *pValuesWritten = valuesWritten;
        return hr;
    }

    // ReadPointerArray():
    //
    // Reads an array of pointer values from the given memory space (and zero extends them).
    // Partial reads of the array will return S_FALSE an an indication of how many values were actually written.
    // Partial reads of individual entries will not occur.
    //
    template<typename T>
    HRESULT ReadPointerArray(_In_ ISvcAddressContext *pAddressContext,
                             _In_ ULONG64 byteOffset,
                             _In_ ULONG64 arrayCount,
                             _Out_writes_(arrayCount) ULONG64 *pArray,
                             _Out_ ULONG64 *pPointersRead)
    {
        ULONG64 pointerSize = m_pMachineArch->GetBitness() >> 3;

        HRESULT hr = S_OK;
        ULONG64 pointersRead = 0;

        for (ULONG64 i = 0; i < arrayCount; ++i)
        {
            hr = ReadPointer(pAddressContext, byteOffset, pArray);
            if (FAILED(hr))
            {
                break;
            }

            ++pointersRead;
            ++pArray;
            byteOffset += pointerSize;
        }

        if (pointersRead == 0)
        {
            hr = E_FAIL;
        }
        else if (pointersRead == arrayCount)
        {
            hr = S_OK;
        }
        else
        {
            hr = S_FALSE;
        }

        *pPointersRead = pointersRead;
        return hr;
    }

    // WritePointerArray():
    //
    // Reads an array of pointer values from the given memory space (and zero extends them).
    // Partial reads of the array will return S_FALSE an an indication of how many values were actually written.
    // Partial reads of individual entries will not occur.
    //
    template<typename T>
    HRESULT WritePointerArray(_In_ ISvcAddressContext *pAddressContext,
                              _In_ ULONG64 byteOffset,
                              _In_ ULONG64 arrayCount,
                              _Out_writes_(arrayCount) ULONG64 *pArray,
                              _Out_ ULONG64 *pPointersWritten)
    {
        ULONG64 pointerSize = m_pMachineArch->GetBitness() >> 3;

        HRESULT hr = S_OK;
        ULONG64 pointersWritten = 0;

        for (ULONG64 i = 0; i < arrayCount; ++i)
        {
            hr = WritePointer(pAddressContext, byteOffset, pArray);
            if (FAILED(hr))
            {
                break;
            }

            ++pointersWritten;
            ++pArray;
            byteOffset += pointerSize;
        }

        if (pointersWritten == 0)
        {
            hr = E_FAIL;
        }
        else if (pointersWritten == arrayCount)
        {
            hr = S_OK;
        }
        else
        {
            hr = S_FALSE;
        }

        *pPointersWritten = pointersWritten;
        return hr;
    }

private:

    ISvcMemoryAccess *m_pMemoryAccess;
    ISvcMachineArchitecture *m_pMachineArch;
    bool m_holdRef;
};

// GetArchitectureComponentFromConstant():
//
// Returns the component GUID for an aggregate architecture component.  That component serves the architecture
// given by machineArch (an IMAGE_FILE_MACHINE_* constant)
//
inline GUID GetArchitectureComponentFromConstant(_In_ ULONG machineArch)
{
    GUID guidNull = {0};
    switch (machineArch)
    {
        case IMAGE_FILE_MACHINE_AMD64:
            return DEBUG_COMPONENTAGGREGATE_MACHINEARCH_AMD64;

        case IMAGE_FILE_MACHINE_I386:
            return DEBUG_COMPONENTAGGREGATE_MACHINEARCH_X86;

        case IMAGE_FILE_MACHINE_ARM64:
            return DEBUG_COMPONENTAGGREGATE_MACHINEARCH_ARM64;

        case IMAGE_FILE_MACHINE_ARMNT:
        case IMAGE_FILE_MACHINE_ARM:
            return DEBUG_COMPONENTAGGREGATE_MACHINEARCH_ARM32;

        default:
            return guidNull;
    }
}

// GetPlatformGuidFromConstant():
//
// Returns the platform GUID for a given platform identifier.
//
inline GUID GetPlatformGuidFromConstant(_In_ SvcOSPlatform platform)
{
    GUID guidNull = {0};
    switch(platform)
    {
        case SvcOSPlatWindows:
            return DEBUG_PLATDEF_WINDOWS;

        case SvcOSPlatLinux:
            return DEBUG_PLATDEF_LINUX;

        case SvcOSPlatUNIX:
            return DEBUG_PLATDEF_UNIX;

        case SvcOSPlatMacOS:
            return DEBUG_PLATDEF_MACOS;

        case SvcOSPlatiOS:
            return DEBUG_PLATDEF_IOS;

        case SvcOSPlatChromeOS:
            return DEBUG_PLATDEF_CHROMEOS;

        case SvcOSPlatAndroid:
            return DEBUG_PLATDEF_ANDROID;

        default:
            return guidNull;
    }
}

} // Client
} // TargetComposition
} // Debugger

#endif // __cplusplus

#endif // __DBGSERVICES_H_
