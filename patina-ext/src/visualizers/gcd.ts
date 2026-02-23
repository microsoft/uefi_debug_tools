// A namespace for all type visualizers related to `patina_dxe_core::gcd` module.
//
// Copyright (c) Microsoft Corporation.
// SPDX-License-Identifier: BSD-2-Clause-Patent
namespace Visualizers.Gcd {
    export function getRegistrations(): any[] {
        // Returns all type signature registrations for visualizers in this namespace.
        return [
            new host.typeSignatureExtension(
                MemoryBlock,
                "enum2$<patina_dxe_core::gcd::memory_block::MemoryBlock>",
            ),
            new host.typeSignatureExtension(
                IoBlock,
                "enum2$<patina_dxe_core::gcd::io_block::IoBlock>",
            ),
        ];
    }

    // A visualizer for the `patina_dxe_core::gcd::memory_block::MemoryBlock` enum type.
    class MemoryBlock {
        // The underlying enum value, which contains the actual fields of the `MemoryBlock` enum.
        __0: any;
        // The tag indicating whether the block is allocated (0x1) or unallocated (0x0).
        tag: any;

        // Exposes the `memory_type` field of the underlying enum as a property of the `MemoryBlock` enum.
        get memory_type(): string {
            const memType = parseInt(this.__0.memory_type);
            switch (memType) {
                case 0: return "NonExistent";
                case 1: return "Reserved";
                case 2: return "SystemMemory";
                case 3: return "MemoryMappedIo";
                case 4: return "Persistent";
                case 5: return "MoreReliable";
                case 6: return "Unaccepted";
                default: return `Unknown(${memType})`;
            }
        }

        // Exposes the `base_address` field of the underlying enum as a property of the `MemoryBlock` enum.
        get base_address(): number {
            return this.__0.base_address;
        }

        // Exposes the `length` field of the underlying enum as a property of the `MemoryBlock` enum.
        get length(): number {
            return this.__0.length;
        }

        // Exposes the `attributes` field of the underlying enum as a property of the `MemoryBlock` enum.
        get attributes(): number {
            return this.__0.attributes;
        }

        // Exposes the `capabilities` field of the underlying enum as a property of the `MemoryBlock` enum.
        get capabilities(): number {
            return this.__0.capabilities;
        }

        // Convert the tag (0x0 or 0x1) to the corresponding string ("Unallocated" or "Allocated")
        tag_str(): string {
            const tagStr = `${this.tag}`;
            return tagStr === "0x0" ? "Unallocated" : "Allocated";
        }
    }

    // A visualizer for the `patina_dxe_core::gcd::io_block::IoBlock` enum type.
    class IoBlock {
        // The underlying enum value, which contains the actual fields of the `IoBlock` enum.
        __0: any;
        // The tag indicating whether the block is allocated (0x1) or unallocated (0x0).
        tag: any;

        // Exposes the `io_type` field of the underlying enum as a property of the `IoBlock` enum.
        get io_type(): string {
            const ioType = parseInt(this.__0.io_type);
            switch (ioType) {
                case 0: return "NonExistent";
                case 1: return "Reserved";
                case 2: return "Io";
                case 3: return "Maximum";
                default: return `Unknown(${ioType})`;
            }
        }

        // Exposes the `base_address` field of the underlying enum as a property of the `IoBlock` enum.
        get base_address(): number {
            return this.__0.base_address;
        }

        // Exposes the `length` field of the underlying enum as a property of the `IoBlock` enum.
        get length(): number {
            return this.__0.length;
        }

        // Convert the tag (0x0 or 0x1) to the corresponding string ("Unallocated" or "Allocated")
        tag_str(): string {
            const tagStr = `${this.tag}`;
            return tagStr === "0x0" ? "Unallocated" : "Allocated";
        }
    }
}
