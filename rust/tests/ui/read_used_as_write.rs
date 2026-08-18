use typesec_core::{CanRead, CanWrite, Capability, GenericResource};

fn needs_write(_capability: Capability<CanWrite, GenericResource>) {}

fn misuse(read: Capability<CanRead, GenericResource>) {
    needs_write(read);
}

fn main() {}

