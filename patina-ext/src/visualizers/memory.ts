namespace Visualizers.Memory {
    export function getRegistrations(): any[] {
        return [
            new host.typeSignatureExtension(
                MemoryBlock,
                "enum2$<patina_dxe_core::gcd::memory_block::MemoryBlock>",
            ),
        ];
    }

    class MemoryBlock {
        __0: any;
        tag: any;

        get memory_type(): number {
            return this.__0.memory_type;
        }

        get base_address(): number {
            return this.__0.base_address;
        }

        get length(): number {
            return this.__0.length;
        }

        get attributes(): number {
            return this.__0.attributes;
        }

        get capabilities(): number {
            return this.__0.capabilities;
        }

        // Convert the tag (0x0 or 0x1) to the corresponding string ("Unallocated" or "Allocated")
        tag_str(): string {
            const tagStr = `${this.tag}`;
            return tagStr === "0x0" ? "Unallocated" : "Allocated";
        }
    }
}
