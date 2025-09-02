# UEFI Debug Tools

This repository contains tools to support debugging UEFI firmware. The tools are
intended to support many implementations, tool chains, and operating systems. As
such, this repo is not strictly associated with any specific UEFI project or work
environment and may contain specifics for many different projects.

## UEFI Windbg Extension

The UEFI Windbg Extension is a plugin to add support for the UEFI firmware context.
See the [UEFI Extension Readme](UefiDbgExt/readme.md) for more details.

## Scripts

This repo also includes some scripts that can be useful in UEFI firmware debugging.

[ComToTcpServer](Scripts/ComToTcpServer.py) - Allows forwarding between a serial
port (COM) and a TCP port on Windows. This is useful for connection Windbg to a serial
based GDB remote.

## Issues

For bugs or feature requests, please [file a github issue](https://github.com/microsoft/uefi_debug_tools/issues/new/choose)
with a detailed summary of the problem or requested functionality.

For security issues, please see [the security file](SECURITY.md).

## Contributing

Contributions and suggestions are welcome. Most contributions will require you to
agree to the Contributor License Agreement (CLA) declaring you have the right to,
and actually do, grant us the rights to use your contribution. For details, visit
[Microsoft CLA](https://cla.microsoft.com).

All interactions must comply with the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).

## Copyright & License

Copyright (c) Microsoft Corporation.

SPDX-License-Identifier: BSD-2-Clause-Patent
