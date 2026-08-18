use typesec_core::{CanRead, Capability, GenericResource};

fn main() {
    let _forged = Capability::<CanRead, GenericResource> {};
}

