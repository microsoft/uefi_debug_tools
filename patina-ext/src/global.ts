// A file for global declarations used across the extension.
//
// This file defines all global variables, but does not set their values. The actual values of these variables are set
// in the extension's initialization code, which runs before any visualizers or commands are used.
//
// Copyright (c) Microsoft Corporation.
// SPDX-License-Identifier: BSD-2-Clause-Patent

// Global variable representing the current version of the extension.
declare var APP_VERSION: string;

// Global variable representing the name of the module containing the Patina Core (`patina_dxe_core`).
declare var PATINA_MODULE: string | null;
