// use optee_utee::BigInt;
use optee_utee::{
     trace_println,Random
};
use optee_utee::{Error, ErrorKind, Parameters, Result};
use proto;


use super::dragonfly_op::{self,DragonflyOp};
use super::gp_bigint;
use super::password;
use std::io::Write;
// use std::mem;


pub fn init_mem_user_password(op: &mut DragonflyOp,params: &mut Parameters)-> Result<()> {
    let mut p0 = unsafe { params.0.as_memref().unwrap()};

    let req: proto::InitMemUserPasswordReq =  match proto::serde_json::from_slice(p0.buffer()){
        Ok(res) =>res,
        Err(_e) => return Err(Error::new(ErrorKind::BadParameters))
    };
    trace_println!("InitMemUserPasswordReq: {:02x?}",req);

    op.pwd_name = Some(req.pwd_name);
    op.password = Some(req.pw);
    
    Ok(())
}


pub fn load_dev_user_password(op: &mut DragonflyOp,params: &mut Parameters)-> Result<()> {
    let mut p0 = unsafe { params.0.as_memref().unwrap()};

    let mut req: proto::LoadDevUserPasswordReq =  match proto::serde_json::from_slice(p0.buffer()){
        Ok(res) =>res,
        Err(_e) => return Err(Error::new(ErrorKind::BadParameters))
    };
    trace_println!("LoadDevUserPasswordReq: {:02x?}",req);

    let pw = password::read_password(&mut req.pwd_name)?;

    op.pwd_name = Some(req.pwd_name);
    op.password = Some(pw);

    Ok(())
}


pub fn init_named_group(op: &mut DragonflyOp,params: &mut Parameters)-> Result<()> {
    let mut p0 = unsafe { params.0.as_memref().unwrap()};

    let req: proto::InitNamedGroupReq =  match proto::serde_json::from_slice(p0.buffer()){
        Ok(res) =>res,
        Err(_e) => return Err(Error::new(ErrorKind::BadParameters))
    };
    trace_println!("InitNamedGroupReq: {:02x?}",req);

    op.ffc_elemnt.set_group(req.group_code)?;

    Ok(())
}




pub fn init_pwe(op: &mut DragonflyOp,params: &mut Parameters)-> Result<()> {
    let mut p0 = unsafe { params.0.as_memref().unwrap()};
    let mut p1 = unsafe { params.1.as_memref().unwrap()};

    let randoms: proto::SessionRandoms = match proto::serde_json::from_slice(p0.buffer()){
        Ok(res) => res,
        Err(_e) => return Err(Error::new(ErrorKind::BadParameters))
    };

    op.randoms = Some(randoms);
    
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
    // trace_println!("sizeof out: {:?} ", output_vec.len());
    
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
    let mut p1 = unsafe { params.1.as_memref().unwrap()};

    let proto_token: proto::Token = match proto::serde_json::from_slice(p0.buffer()){
        Ok(res) => res,
        Err(_e) => return Err(Error::new(ErrorKind::BadParameters))
    };

    let peer_token = &proto_token.token;
    // 确认握手过程是否成功
    let is_confirm = op.confirm_exchange(peer_token)?;

    let serect = match &op.secret{
        Some(res) => res,
        None => return Err(Error::new(ErrorKind::BadParameters))
    };
    let pmk = match is_confirm{
        true => serect.pmk.clone(),
        false => Vec::<u8>::new()
    };

    let output = proto::HandshakePMK{
        is_confirm,
        pmk,
    };
    let output_vec = proto::serde_json::to_vec(&output).unwrap();
    p1.buffer().write(&output_vec).unwrap();
    p1.set_updated_size(output_vec.len());

    Ok(())
}


pub fn gene_random(_op: &mut DragonflyOp,params: &mut Parameters)-> Result<()> {
    let mut p0 = unsafe { params.0.as_memref().unwrap()};
    let mut p1 = unsafe { params.1.as_memref().unwrap()};

    let random_req: proto::GeneRandomReq = match proto::serde_json::from_slice(p0.buffer()){
        Ok(res) => res,
        Err(_e) => return Err(Error::new(ErrorKind::BadParameters))
    };


    let mut rand_op: Vec<u8> = vec![0u8; random_req.rand_bytes];
    Random::generate(&mut rand_op);
    trace_println!("Generate Random : {:02x?}",rand_op);

    let output = proto::GeneRandomRes{
        rand: rand_op
    };
    let output_vec = proto::serde_json::to_vec(&output).unwrap();
    p1.buffer().write(&output_vec).unwrap();
    p1.set_updated_size(output_vec.len());

    Ok(())
}