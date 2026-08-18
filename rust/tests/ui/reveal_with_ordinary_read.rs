use typesec_core::{CanRead, Capability, GenericResource, SecureValue, Sensitive};

fn misuse(
    value: SecureValue<Sensitive, String, GenericResource>,
    read: &Capability<CanRead, GenericResource>,
) {
    let _ = value.reveal(read);
}

fn main() {}
