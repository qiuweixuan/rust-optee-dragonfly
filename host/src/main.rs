use sae_core::{session_example};

fn main() -> optee_teec::Result<()> {
    println!("Success Example:");
    session_example::sae_success_example()?;

    println!("Fail Example:");
    session_example::sae_fail_example()?;

    
    Ok(())
}
