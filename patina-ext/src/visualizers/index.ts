// A namespace for all type visualizers provided by the extension.
//
// Each visualizer is implemented as a class and registered as a type signature registration via
// `host.typeSignatureRegistration` The `getRegistrations` function is the only externally visible part of this
// namespace and is consumed by the extension's initialization code to register all visualizers at once.
//
// For better organization, visualizers may be grouped into sub-namespaces within the `Visualizers` namespace, but this
// is not required.
//
// Copyright (c) Microsoft Corporation.
// SPDX-License-Identifier: BSD-2-Clause-Patent

/// <reference path="collections.ts" />
/// <reference path="gcd.ts" />

namespace Visualizers {
  /// Returns all type signature registrations for visualizers in this namespace, including those in sub-namespaces.
  export function getRegistrations(): any[] {
    return [
      ...Visualizers.Collections.getRegistrations(),
      ...Visualizers.Gcd.getRegistrations(),
    ];
  }
}
