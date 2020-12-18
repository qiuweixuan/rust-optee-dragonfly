#![no_main]

use optee_utee::{
    ta_close_session, ta_create, ta_destroy, ta_invoke_command, ta_open_session, trace_println,
};
use optee_utee::{Error, ErrorKind, Parameters, Result};
use proto::{Command,self};


mod modular;
use modular::DragonflyOp;
use modular::password;




#[ta_create]
fn create() -> Result<()> {
    // 初始化根账号密码
    password::init_root_password()?;

    trace_println!("[+] TA create");
    Ok(())
}

#[ta_open_session]
fn open_session(_params: &mut Parameters,_sess_ctx: &mut DragonflyOp) -> Result<()> {
    trace_println!("[+] TA open session");
    Ok(())
}

#[ta_close_session]
fn close_session(_sess_ctx: &mut DragonflyOp) {
    trace_println!("[+] TA close session");
}

#[ta_destroy]
fn destroy() {
    trace_println!("[+] TA destroy");
}



#[ta_invoke_command]
fn invoke_command( sess_ctx: &mut DragonflyOp,cmd_id: u32, params: &mut Parameters) -> Result<()> {
    trace_println!("[+] TA invoke command");
    match Command::from(cmd_id) {
        Command::InitMemUserPassword => modular::init_mem_user_password(sess_ctx,params),
        Command::ComputeCommitElement => modular::compute_commit_element(sess_ctx,params),
        Command::ComputeConfirmElement => modular::compute_shared_secret(sess_ctx,params),
        Command::ConfirmExchange => modular::confirm_exchange(sess_ctx,params),
        Command::GeneRandom => modular::gene_random(sess_ctx,params),
        Command::LoadDevUserPassword => modular::load_dev_user_password(sess_ctx,params),
        Command::InitNamedGroup => modular::init_named_group(sess_ctx,params),
        _ => Err(Error::new(ErrorKind::BadParameters)),
    }
    
}

// TA configurations
const TA_FLAGS: u32 = 0;
const TA_DATA_SIZE: u32 = 32 * 1024 * 4;
const TA_STACK_SIZE: u32 = 2 * 1024 * 4;
const TA_VERSION: &[u8] = b"0.1\0";
const TA_DESCRIPTION: &[u8] = b"SAE Core Lib using RUST-OPTEE APIs.\0";
const EXT_PROP_VALUE_1: &[u8] = b"SAE Core Lib TA\0";
const EXT_PROP_VALUE_2: u32 = 0x0010;
const TRACE_LEVEL: i32 = 4;
const TRACE_EXT_PREFIX: &[u8] = b"TA\0";
const TA_FRAMEWORK_STACK_SIZE: u32 = 2048;

include!(concat!(env!("OUT_DIR"), "/user_ta_header.rs"));
