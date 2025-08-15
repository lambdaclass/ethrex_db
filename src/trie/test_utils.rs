#[macro_export]
/// Creates a trie node
/// All partial paths are expressed in nibbles and values in bytes
macro_rules! pmt_node {
    (
        @( $trie:expr )
        branch { $( $choice:expr => $child_type:ident { $( $child_tokens:tt )* } ),+ $(,)? }
        $( offset $offset:expr )?
    ) => {
        $crate::trie::branch::BranchNode::new({
            #[allow(unused_variables)]
            let offset = true $( ^ $offset )?;
            let mut choices = $crate::trie::branch::BranchNode::EMPTY_CHOICES;
            $(
                let child_node: $crate::trie::node::Node = pmt_node! { @($trie)
                    $child_type { $( $child_tokens )* }
                    offset offset
                }.into();
                choices[$choice as usize] = child_node.into();
            )*
            choices
        })
    };
    (
        @( $trie:expr )
        branch { $( $choice:expr => $child_type:ident { $( $child_tokens:tt )* } ),+ $(,)? }
        with_leaf { $path:expr => $value:expr }
        $( offset $offset:expr )?
    ) => {{
        $crate::trie::branch::BranchNode::new_with_value({
            #[allow(unused_variables)]
            let offset = true $( ^ $offset )?;
            let mut choices = $crate::trie::branch::BranchNode::EMPTY_CHOICES;
            $(
                choices[$choice as usize] = $crate::trie::node::Node::from(
                    pmt_node! { @($trie)
                        $child_type { $( $child_tokens )* }
                        offset offset
                    }).into();
            )*
            choices
        }, $value)
    }};

    (
        @( $trie:expr )
        extension { $prefix:expr , $child_type:ident { $( $child_tokens:tt )* } }
        $( offset $offset:expr )?
    ) => {{
        #[allow(unused_variables)]
        let prefix = $crate::trie::nibbles::Nibbles::from_hex($prefix.to_vec());

        $crate::trie::extension::ExtensionNode::new(
            prefix.clone(),
            {
                let child_node = $crate::trie::node::Node::from(pmt_node! { @($trie)
                    $child_type { $( $child_tokens )* }
                });
                child_node.into()
            }
        )
    }};

    (
        @( $trie:expr)
        leaf { $path:expr => $value:expr }
        $( offset $offset:expr )?
    ) => {
        {
            $crate::trie::leaf::LeafNode::new($crate::trie::nibbles::Nibbles::from_hex($path), $value)
        }
    };
}
