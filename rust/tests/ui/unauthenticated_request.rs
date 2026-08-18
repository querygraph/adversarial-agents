use typesec_core::{Agent, CanRead, GenericResource, Unauthenticated};

fn misuse(agent: Agent<Unauthenticated>, resource: &GenericResource) {
    let _ = agent.request_capability::<CanRead, _>(resource);
}

fn main() {}

