use optee_teec::{Context, Uuid};
use proto::{UUID,self};
use sae_core::dragonfly;

fn main() -> optee_teec::Result<()> {
    let mut ctx = Context::new()?;
    let uuid = Uuid::parse_str(UUID).unwrap();
    let mut session = ctx.open_session(uuid)?;

    let mut ctx = Context::new()?;
    let uuid = Uuid::parse_str(UUID).unwrap();
    let mut peer_session = ctx.open_session(uuid)?;

    dragonfly(&mut session,&mut peer_session)?;

    println!("Success");
    Ok(())
}
