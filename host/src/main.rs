use sae_core::{session_example};
use structopt::StructOpt;


#[derive(StructOpt, Debug)]
struct Args {
    /// Account Name
    #[structopt(name = "account", long = "--account")]
    account: String,

    /// Client Password
    #[structopt(name = "client_pwd", long = "--clipwd")]
    client_pwd: String,

    /// Server Password
    #[structopt(name = "server_pwd", long = "--serpwd")]
    server_pwd: String,
}

fn main() -> optee_teec::Result<()> {
    // println!("Success Example:");
    // session_example::sae_success_example()?;

    // println!("Fail Example:");
    // session_example::sae_fail_example()?;

     // Parse command line arguments
    let args = Args::from_args();
    let account = &args.account.as_bytes();
    let client_pwd = &args.client_pwd.as_bytes();
    let server_pwd = &args.server_pwd.as_bytes();
    let assert_is_success = client_pwd.to_vec() == server_pwd.to_vec();
    session_example::sae_test(account, client_pwd, server_pwd ,6, assert_is_success)?;
    Ok(())
}
