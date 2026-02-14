namespace Visualizers.Collections {
    export function getRegistrations() {       
        return [
            new host.typeSignatureRegistration(
                Tree,
                "patina_internal_collections::rbt::Rbt<*>",
            ),
            new host.typeSignatureRegistration(
                Node,
                "patina_internal_collections::node::Node<*>",
            ),

        ];
    }

    class Tree {
        root: any;
        storage: any;

        toString(): string {
            return `{ length: ${this.length}, capacity: ${this.capacity} }`;
        }

        get length(): number {
            return this.storage.length;
        }

        get capacity(): number {
            return this.storage.data.length;
        }

        get nodes(): __NodeList {
            return new __NodeList(this);
        }
        
        get root_node(): Node | null {
            return this.root.value.value.dereference();
        }
    }

    class __NodeList {
        __tree: Tree;

        toString(): string {
            return `[${this.inner_type()}; ${this.__tree.length}]`;
        }

        inner_type(): string {
            if (!this.__tree.root_node) {
                return "Unknown";
            }
            return this.__tree.root_node.data.targetType.name;
        }

        constructor(tree: Tree) {
            this.__tree = tree;
        }

        *[Symbol.iterator]() {
            const root = this.__tree.root_node;
            if (!root) {
                return; // Empty tree
            }

            // Use a recursive generator for in-order traversal
            function* traverse(node: Node | null): Generator<Node> {
                if (!node) {
                    return;
                }

                yield* traverse(node.left_node);
                yield node.data;
                yield* traverse(node.right_node);
            }

            yield* traverse(root);
        }
    }

    class Node {
        data: any;
        parent: any;
        left: any;
        right: any;
        color: any;

        toString(): string {
            return `${this.data}`;
        }

        get parent_node(): Node | null {
            var ptr = this.parent.value.value;
            if (ptr.isNull) {
                return null;
            }
            return this.parent.value.value.dereference();
        }

        get left_node(): Node | null {

            var ptr = this.left.value.value;
            if (ptr.isNull) {
                return null;
            }
            return this.left.value.value.dereference();
        }

        get right_node(): Node | null {
            var ptr = this.right.value.value;
            
            if (ptr.isNull) {
                return null;
            }
            return this.right.value.value.dereference();
        }
    }
}
