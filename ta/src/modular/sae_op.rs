// use optee_utee::BigInt;
use optee_utee::{
     trace_println,Random
};
use optee_utee::{Error, ErrorKind, Parameters, Result};
use proto;


use super::dragonfly_op::{self,DragonflyOp};
use super::gp_bigint;
use super::password;
use super::crypt_op;
use std::io::Write;



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

    let pw = password::read_password(&req.pwd_name)?;

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




pub fn compute_commit_element(op: &mut DragonflyOp,params: &mut Parameters)-> Result<()> {
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

    // 进行测试
    op.aes_ctr_256()?;

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

pub fn client_remote_pwd_manage(_op: &mut DragonflyOp,params: &mut Parameters)-> Result<()> {
    let mut p0 = unsafe { params.0.as_memref().unwrap()};
    let mut p1 = unsafe { params.1.as_memref().unwrap()};   

    let req: proto::RemotePwdManageReq = match proto::serde_json::from_slice(p0.buffer()){
        Ok(res) => res,
        Err(_e) => return Err(Error::new(ErrorKind::BadParameters))
    };

    
    let output : proto::RemotePwdManageRes  = match req{
        proto::RemotePwdManageReq::Get{ key } => {
            let mut value = Vec::<u8>::new();
            let mut is_success = true;
            let result = password::read_password(&key);
            match result {
                Err(_) => is_success = false,
                Ok(pwd) => value = pwd,
            };
            proto::RemotePwdManageRes::Get{
                value,
                is_success,
            }
        },
        proto::RemotePwdManageReq::Set{key,value} => {
            let is_success = password::write_password(&key,&value).is_ok();
            proto::RemotePwdManageRes::Set{
                is_success,
            }
        },
        proto::RemotePwdManageReq::Del{key} => {
            let is_success = password::del_password(&key).is_ok();
            proto::RemotePwdManageRes::Del{
                is_success,
            }
        },
    };
    

   /*  let output : proto::RemotePwdManageRes  = proto::RemotePwdManageRes::Get{
        value: "abcdefg".to_owned(),
        is_success: true,
    }; */
    let output_vec = proto::serde_json::to_vec(&output).unwrap();
    p1.buffer().write(&output_vec).unwrap();
    p1.set_updated_size(output_vec.len());

    Ok(())
}

/* EncReq */
pub fn enc_req(op: &mut DragonflyOp,params: &mut Parameters)-> Result<()> {

    
    let mut p0 = unsafe { params.0.as_memref().unwrap()};
    let mut p1 = unsafe { params.1.as_memref().unwrap()};   

    // 检查权限
    let account  =  DragonflyOp::handle_option(&op.pwd_name)?;
    if account.to_vec() != Vec::<u8>::from("root"){
        return Err(Error::new(ErrorKind::AccessDenied));
    };

    // 获取key
    let secret  =  DragonflyOp::handle_option(&op.secret)?;
    let key: &[u8] =  &secret.kck;
    // let key = &vec![0xa5u8; 32];  
    

    // 获取iv
    // let iv = vec![0x00u8; 16];
    let mut iv: Vec<u8> = vec![0u8; 16];
    Random::generate(&mut iv);


    // 获取密文
    let cipher = crypt_op::aes_ctr_256_enc(key, &iv, p0.buffer())?;

    // 获取哈希值
    let mut hash = vec![0u8;32];
    crypt_op::hmac_sha256(&key,&cipher,&mut hash)?;

    // 组装成加密对象
    let output = proto::CipherTaLoad{
        cipher,
        hash,
        iv,
    };

    let output_vec = proto::serde_json::to_vec(&output).unwrap();
    p1.buffer().write(&output_vec).unwrap();
    p1.set_updated_size(output_vec.len());

    Ok(())
}


/* DecRes */
pub fn dec_res(op: &mut DragonflyOp,params: &mut Parameters)-> Result<()> {
    let mut p0 = unsafe { params.0.as_memref().unwrap()};
    let mut p1 = unsafe { params.1.as_memref().unwrap()};   

    let req: proto::CipherTaLoad = match proto::serde_json::from_slice(p0.buffer()){
        Ok(res) => res,
        Err(_) => return Err(Error::new(ErrorKind::BadParameters))
    };

    // 检查权限
    let account  =  DragonflyOp::handle_option(&op.pwd_name)?;
    if account.to_vec() != Vec::<u8>::from("root"){
        return Err(Error::new(ErrorKind::AccessDenied));
    };

    // 获取key
    let secret =  DragonflyOp::handle_option(&op.secret)?;
    let key: &[u8] =  &secret.kck;
    // let key = &vec![0xa5u8; 32];  

    // 获取iv
    let iv = req.iv;

    // 计算哈希值
    let mut compute_hash = vec![0u8;32];
    crypt_op::hmac_sha256(&key,&req.cipher,&mut compute_hash)?;
    // 哈希值不同，出现错误
    if compute_hash != req.hash {
        return Err(Error::new(ErrorKind::BadParameters));
    }

    // 获取明文
    let plain = crypt_op::aes_ctr_256_dec(key, &iv, &req.cipher)?;

    // 获取响应
    let output_vec = plain;
    p1.buffer().write(&output_vec).unwrap();
    p1.set_updated_size(output_vec.len());

    Ok(())
}

/* TermialPwdManage */
pub fn termial_pwd_manage(op: &mut DragonflyOp,params: &mut Parameters)-> Result<()> {
    let mut p0 = unsafe { params.0.as_memref().unwrap()};
    let mut p1 = unsafe { params.1.as_memref().unwrap()};   

    let req: proto::CipherTaLoad = match proto::serde_json::from_slice(p0.buffer()){
        Ok(res) => res,
        Err(_) => return Err(Error::new(ErrorKind::BadParameters))
    };

    // 检查权限
    let account  =  DragonflyOp::handle_option(&op.pwd_name)?;
    if account.to_vec() != Vec::<u8>::from("root"){
        return Err(Error::new(ErrorKind::AccessDenied));
    };

    // 获取key
    let secret =  DragonflyOp::handle_option(&op.secret)?;
    let key: &[u8] =  &secret.kck;
    // let key = &vec![0xa5u8; 32];  

    // 获取iv
    let iv = req.iv;

    // 计算哈希值
    let mut compute_hash = vec![0u8;32];
    crypt_op::hmac_sha256(&key,&req.cipher,&mut compute_hash)?;
    // 哈希值不同，出现错误
    if compute_hash != req.hash {
        return Err(Error::new(ErrorKind::BadParameters));
    }

    // 获取明文
    let plain = crypt_op::aes_ctr_256_dec(key, &iv, &req.cipher)?;

    // 获取解密后的请求
    let req: proto::RemotePwdManageReq = match proto::serde_json::from_slice(&plain){
        Ok(res) => res,
        Err(_e) => return Err(Error::new(ErrorKind::BadParameters))
    };

    // 处理明文请求, 获取明文响应
    let res : proto::RemotePwdManageRes  = match req{
        proto::RemotePwdManageReq::Get{ key } => {
            let mut value = Vec::<u8>::new();
            let mut is_success = true;
            let result = password::read_password(&key);
            match result {
                Err(_) => is_success = false,
                Ok(pwd) => value = pwd,
            };
            proto::RemotePwdManageRes::Get{
                value,
                is_success,
            }
        },
        proto::RemotePwdManageReq::Set{key,value} => {
            let is_success = password::write_password(&key,&value).is_ok();
            proto::RemotePwdManageRes::Set{
                is_success,
            }
        },
        proto::RemotePwdManageReq::Del{key} => {
            let is_success = password::del_password(&key).is_ok();
            proto::RemotePwdManageRes::Del{
                is_success,
            }
        },
    };

    // 获取明文响应序列化向量
    let res_vec = proto::serde_json::to_vec(&res).unwrap();

    // 获取iv
    // let iv = vec![0x00u8; 16];
    let mut iv: Vec<u8> = vec![0u8; 16];
    Random::generate(&mut iv);


    // 获取密文
    let cipher = crypt_op::aes_ctr_256_enc(key, &iv, &res_vec)?;

    // 获取哈希值
    let mut hash = vec![0u8;32];
    crypt_op::hmac_sha256(&key,&cipher,&mut hash)?;

    // 组装加密对象
    let output = proto::CipherTaLoad{
        cipher,
        hash,
        iv,
    };

    let output_vec = proto::serde_json::to_vec(&output).unwrap();
    p1.buffer().write(&output_vec).unwrap();
    p1.set_updated_size(output_vec.len());
    Ok(())
}










