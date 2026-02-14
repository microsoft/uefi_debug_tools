/// <reference path="util.ts" />
/// <reference path="visualizers/index.ts" />
/// <reference path="commands/index.ts" />

declare const host: any;

function initializeScript(): any[] {
    return [
        ...Visualizers.getRegistrations(),
        ...Commands.getCommands(),
    ];
}
