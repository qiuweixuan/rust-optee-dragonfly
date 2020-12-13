// use optee_utee::BigInt;
use optee_utee::{
     trace_println,
};
use optee_utee::{Error, ErrorKind, Parameters, Result};
use proto;

use super::dragonfly_op;
use super::dragonfly_op::DragonflyOp;
use super::gp_bigint;
use std::io::Write;
// use std::mem;

pub fn set_password(op: &mut DragonflyOp,params: &mut Parameters)-> Result<()> {
    let mut p0 = unsafe { params.0.as_memref().unwrap()};

    let password: proto::Password =  match proto::serde_json::from_slice(p0.buffer()){
        Ok(res) =>res,
        Err(_e) => return Err(Error::new(ErrorKind::BadParameters))
    };

    op.password = Some(password.pw);
    match &op.password{
        Some(res) => trace_println!("Set password : {:?}",res),
        None => {}
    };
    
    Ok(())
}

pub fn init_pwe(op: &mut DragonflyOp,params: &mut Parameters)-> Result<()> {
    let mut p0 = unsafe { params.0.as_memref().unwrap()};
    let mut p1 = unsafe { params.1.as_memref().unwrap()};

    let macs: proto::Randoms = match proto::serde_json::from_slice(p0.buffer()){
        Ok(res) => res,
        Err(_e) => return Err(Error::new(ErrorKind::BadParameters))
    };

    op.macs = Some(macs);
    
    op.initiate()?;

    op.commit_exchange()?;

    let commit_element = match &op.commit_element{
        Some(res) => res,
        None => return Err(Error::new(ErrorKind::BadParameters))
    };


    let output = proto::CommitElement{
        scalar:gp_bigint::bigint_to_hexstr(&commit_element.scalar)?,
        element:gp_bigint::bigint_to_hexstr(&commit_element.element)?
    };

   
    let output_vec = proto::serde_json::to_vec(&output).unwrap();
    trace_println!("sizeof out: {:?} ", output_vec.len());
    
    p1.buffer().write(&output_vec).unwrap();
    p1.set_updated_size(output_vec.len());

    Ok(())
}

pub fn compute_shared_secret(op: &mut DragonflyOp,params: &mut Parameters)-> Result<()> {
    let mut p0 = unsafe { params.0.as_memref().unwrap()};
    let mut p1 = unsafe { params.1.as_memref().unwrap()};

    let proto_commit_element: proto::CommitElement = match proto::serde_json::from_slice(p0.buffer()){
        Ok(res) => res,
        Err(_e) => return Err(Error::new(ErrorKind::BadParameters))
    };

    let peer_commit_element = dragonfly_op::CommitElement{
        scalar: gp_bigint::bigint_construct_from_hexstr(&proto_commit_element.scalar)?,
        element: gp_bigint::bigint_construct_from_hexstr(&proto_commit_element.element)?,
    };

    op.peer_commit_element = Some(peer_commit_element);

    op.compute_shared_secret()?;


    let serect = match &op.secret{
        Some(res) => res,
        None => return Err(Error::new(ErrorKind::BadParameters))
    };


    let output = proto::Token{
        token: serect.token.clone()
    };
    let output_vec = proto::serde_json::to_vec(&output).unwrap();
    // trace_println!("sizeof out: {:?} ", output_vec.len());
    p1.buffer().write(&output_vec).unwrap();
    p1.set_updated_size(output_vec.len());

    Ok(())
}

pub fn confirm_exchange(op: &mut DragonflyOp,params: &mut Parameters)-> Result<()> {
    let mut p0 = unsafe { params.0.as_memref().unwrap()};
    // let mut p1 = unsafe { params.1.as_memref().unwrap()};

    let proto_token: proto::Token = match proto::serde_json::from_slice(p0.buffer()){
        Ok(res) => res,
        Err(_e) => return Err(Error::new(ErrorKind::BadParameters))
    };

    let peer_token = &proto_token.token;

    op.confirm_exchange(peer_token)?;


    // let serect = match &op.secret{
    //     Some(res) => res,
    //     None => return Err(Error::new(ErrorKind::BadParameters))
    // };


    // let output = proto::Token{
    //     token: serect.token.clone()
    // };
    // let output_vec = proto::serde_json::to_vec(&output).unwrap();
    // // trace_println!("sizeof out: {:?} ", output_vec.len());
    // p1.buffer().write(&output_vec).unwrap();
    // p1.set_updated_size(output_vec.len());

    Ok(())
}