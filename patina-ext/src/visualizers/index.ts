/// <reference path="collections.ts" />
/// <reference path="memory.ts" />

namespace Visualizers {
    export function getRegistrations(): any[] {
        return [
            ...Visualizers.Collections.getRegistrations(),
            ...Visualizers.Memory.getRegistrations(),
        ];
    }
}