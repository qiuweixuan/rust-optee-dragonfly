use optee_teec::{Context, Result, Uuid,Error,ErrorKind};
use optee_teec::{Operation, Session};
use optee_teec::{ParamNone, ParamTmpRef};

use proto::{self, Command, UUID};
use serde::{Deserialize, Serialize};


pub struct SaeCaContext<'a> {
    session: Session<'a>,
    pub output_buffer: Vec<u8>,
}

// unsafe impl Send for  SaeCaContext<'static> {}
// unsafe impl Sync for  SaeCaContext<'static> {}

fn convert_error_fn<T>(kind: ErrorKind) ->  impl FnOnce(T) ->  Error{
    let parse_error = move |_| { optee_teec::Error::new(kind) };
    return parse_error;
}


impl<'a> SaeCaContext<'a> {
    pub fn new_session(ctx: &'a mut Context) -> Result<Self> {
        let uuid = Uuid::parse_str(UUID).map_err(convert_error_fn(ErrorKind::BadParameters))?;
        let session = ctx.open_session(uuid)?;
        let output_buffer = vec![0u8; 16384];
        println!("Create SaeCaContext");
        Ok(Self {
            session,
            output_buffer,
        })
    }
    pub fn new_ctx() -> Result<Context> {
        Context::new()
    }

    
}

impl<'a> SaeCaContext<'a> {
    pub fn test(self: &mut Self) {
        let input = proto::GeneRandomReq { rand_bytes: 6 };
        let random_res: proto::GeneRandomRes = serde_invoke_command_req_res(
            &mut self.session,
            &mut self.output_buffer,
            Command::GeneRandom,
            &input,
        )
        .unwrap();
        println!("random is {:?}", random_res);
    }

    /* GeneRandom */
    pub fn gene_random(self: &mut Self, rand_bytes: usize) -> Result<proto::GeneRandomRes> {
        let input = proto::GeneRandomReq { rand_bytes };
        serde_invoke_command_req_res(
            &mut self.session,
            &mut self.output_buffer,
            Command::GeneRandom,
            &input,
        )
    }

    /* InitMemUserPassword */
    pub fn init_mem_user_password(self: &mut Self, pwd_name: &[u8],pw:  &[u8]) -> Result<()> {
        let input = proto::InitMemUserPasswordReq{
            pwd_name: pwd_name.to_vec(),
            pw: pw.to_vec(),
        };
        serde_invoke_command_only_req(
            &mut self.session,
            Command::InitMemUserPassword,
            &input,
        )?;
        return Ok(());
    }

    /* LoadDevUserPassword */
    pub fn load_dev_user_password(self: &mut Self, pwd_name: &[u8]) -> Result<()> {
        let input = proto::LoadDevUserPasswordReq {
            pwd_name: pwd_name.to_vec(),
        };
        serde_invoke_command_only_req(&mut self.session, Command::LoadDevUserPassword, &input)
    }

    /* InitNamedGroup */
    pub fn init_named_group(self: &mut Self, group_code: u16) -> Result<()> {
        let input = proto::InitNamedGroupReq{
            group_code
        };
        serde_invoke_command_only_req(&mut self.session, Command::InitNamedGroup, &input)
    }

    /* ComputeCommitElement */
    pub fn compute_commit_element(self: &mut Self, client_random:&[u8],server_random: &[u8]) -> Result<proto::CommitElement> {
        let input = proto::SessionRandoms {
            client_random: client_random.to_vec(),
            server_random: server_random.to_vec(),
        };
        serde_invoke_command_req_res(&mut self.session, &mut self.output_buffer, Command::ComputeCommitElement, &input)
    }

    /* ComputeConfirmElement */
    pub fn compute_confirm_element(self: &mut Self, peer_scalar :&[u8],peer_element: &[u8]) -> Result<proto::Token> {
        let input = proto::CommitElement {
            scalar: peer_scalar.to_owned(),
            element: peer_element.to_owned(),
        };
        serde_invoke_command_req_res(&mut self.session, &mut self.output_buffer, Command::ComputeConfirmElement, &input)
    }

    /* ConfirmExchange */
    pub fn confirm_exchange(self: &mut Self, peer_token :&[u8]) -> Result<proto::HandshakePMK> {
        let input = proto::Token {
            token: peer_token.to_owned(),
        };
        serde_invoke_command_req_res(&mut self.session, &mut self.output_buffer, Command::ConfirmExchange, &input)
    }

    /* GetRemotePwd */
    pub fn get_remote_pwd_req(self: &mut Self, key :&[u8]) -> Result<proto::CipherTaLoad> {
        let input : proto::RemotePwdManageReq = proto::RemotePwdManageReq::Get {
            key: key.to_owned(),
        };
        serde_invoke_command_req_res(&mut self.session, &mut self.output_buffer, Command::EncReq, &input)
    }

    /* SetRemotePwd */
    pub fn set_remote_pwd_req(self: &mut Self, key :&[u8],value :&[u8]) -> Result<proto::CipherTaLoad> {
        let input : proto::RemotePwdManageReq = proto::RemotePwdManageReq::Set {
            key: key.to_owned(),
            value: value.to_owned(),
        };
        serde_invoke_command_req_res(&mut self.session, &mut self.output_buffer, Command::EncReq, &input)
    }

     /* DelRemotePwd */
     pub fn del_remote_pwd_req(self: &mut Self, key :&[u8]) -> Result<proto::CipherTaLoad> {
        let input : proto::RemotePwdManageReq = proto::RemotePwdManageReq::Del {
            key: key.to_owned(),
        };
        serde_invoke_command_req_res(&mut self.session, &mut self.output_buffer, Command::EncReq, &input)
    }

    /* TermialPwdManage */
    pub fn termial_pwd_manage(self: &mut Self, cipher_req: &proto::CipherTaLoad) -> Result<proto::CipherTaLoad> {
        serde_invoke_command_req_res(&mut self.session, &mut self.output_buffer, Command::TermialPwdManage, cipher_req)
    }

    /* DecRemotePwdRes */
    pub fn remote_pwd_res(self: &mut Self, cipher_res: &proto::CipherTaLoad) -> Result<proto::RemotePwdManageRes> {
        serde_invoke_command_req_res(&mut self.session, &mut self.output_buffer, Command::DecRes, cipher_res)
    }



    /* GetRemotePwd */
    /* pub fn get_remote_pwd_encdec(self: &mut Self, key :&[u8]) -> Result<proto::RemotePwdManageRes> {
        let input : proto::RemotePwdManageReq = proto::RemotePwdManageReq::Get {
            key: key.to_owned(),
        };
        let middle_result : proto::CipherTaLoad  = 
            serde_invoke_command_req_res(&mut self.session, &mut self.output_buffer, Command::EncReq, &input)?;
        let middle_result : proto::CipherTaLoad = 
            serde_invoke_command_req_res(&mut self.session, &mut self.output_buffer, Command::TermialPwdManage, &middle_result)?;
        let result : proto::RemotePwdManageRes = 
            serde_invoke_command_req_res(&mut self.session, &mut self.output_buffer, Command::DecRes, &middle_result)?;
        return Ok(result);
    } */

}

fn serde_invoke_command_req_res<'a, T: Serialize, U: Deserialize<'a>>(
    session: &mut Session,
    output_vec: &'a mut Vec<u8>,
    command_id: Command,
    input: T,
) -> optee_teec::Result<U> {
    let mut serialized_input = proto::serde_json::to_vec(&input).map_err(convert_error_fn(ErrorKind::BadParameters))?;
    let p0 = ParamTmpRef::new_input(serialized_input.as_mut_slice());
    let p1 = ParamTmpRef::new_output(output_vec.as_mut_slice());
    let mut operation = Operation::new(0, p0, p1, ParamNone, ParamNone);
    session.invoke_command(command_id as u32, &mut operation)?;
    let updated_size = operation.parameters().1.updated_size();
    let result: U = proto::serde_json::from_slice(&output_vec[..updated_size]).map_err(convert_error_fn(ErrorKind::BadParameters))?;
    Ok(result)
}

fn serde_invoke_command_only_req<'a, T: Serialize>(
    session: &mut Session,
    command_id: Command,
    input: T,
) -> optee_teec::Result<()> {
    let mut serialized_input = proto::serde_json::to_vec(&input).unwrap();
    let p0 = ParamTmpRef::new_input(serialized_input.as_mut_slice());
    let mut operation = Operation::new(0, p0, ParamNone, ParamNone, ParamNone);
    session.invoke_command(command_id as u32, &mut operation)?;
    Ok(())
}

pub fn dragonfly(session: &mut Session, peer_session: &mut Session) -> optee_teec::Result<()> {
    let mut output_vec = vec![0u8; 16384];
    let pwd_name = b"root";
    // let pw: &[u8] = b"abcdefgh";
    let _pw: &[u8] = b"dragonflysae";

    /* GeneRandom */
    let input = proto::GeneRandomReq { rand_bytes: 6 };
    // sta get random request
    let sta_random_res: proto::GeneRandomRes =
        serde_invoke_command_req_res(session, &mut output_vec, Command::GeneRandom, &input)?;
    // ap get random request
    let ap_random_res: proto::GeneRandomRes =
        serde_invoke_command_req_res(peer_session, &mut output_vec, Command::GeneRandom, &input)?;

    /* InitMemUserPassword */
    /* let input = proto::InitMemUserPasswordReq{
        pwd_name: pwd_name.to_vec(),
        pw: pw.to_vec(),
    };
    // sta set password element
    serde_invoke_command_only_req(session, Command::InitMemUserPassword, &input)?;
    // ap set password element
    serde_invoke_command_only_req(peer_session, Command::InitMemUserPassword, &input)?; */

    /* LoadDevUserPassword */
    let input = proto::LoadDevUserPasswordReq {
        pwd_name: pwd_name.to_vec(),
    };
    // sta load password element
    serde_invoke_command_only_req(session, Command::LoadDevUserPassword, &input)?;
    // ap load password element
    serde_invoke_command_only_req(peer_session, Command::LoadDevUserPassword, &input)?;

    /* InitNamedGroupReq */
    /* let input = proto::InitNamedGroupReq{
        group_code: 0x0101
    };
    // sta init named group
    serde_invoke_command_only_req(session, Command::InitNamedGroup, &input)?;
    // ap init named group
    serde_invoke_command_only_req(peer_session, Command::InitNamedGroup, &input)?; */

    /* ComputeCommitElement */
    let input = proto::SessionRandoms {
        client_random: sta_random_res.rand,
        server_random: ap_random_res.rand,
    };
    // sta commit element
    let sta_commit_element: proto::CommitElement =
        serde_invoke_command_req_res(session, &mut output_vec, Command::ComputeCommitElement, &input)?;
    // ap commit element
    let ap_commit_element: proto::CommitElement =
        serde_invoke_command_req_res(peer_session, &mut output_vec, Command::ComputeCommitElement, &input)?;

    /* ComputeConfirmElement */
    // sta confirm element
    let sta_token: proto::Token = serde_invoke_command_req_res(
        session,
        &mut output_vec,
        Command::ComputeConfirmElement,
        &ap_commit_element,
    )?;
    // ap confirm element
    let ap_token: proto::Token = serde_invoke_command_req_res(
        peer_session,
        &mut output_vec,
        Command::ComputeConfirmElement,
        &sta_commit_element,
    )?;

    /* ConfirmExchange */
    let sta_pmk: proto::HandshakePMK = serde_invoke_command_req_res(
        session,
        &mut output_vec,
        Command::ConfirmExchange,
        &ap_token,
    )?;
    println!("sta_pmk is {:?}", sta_pmk);

    // ap accept pmk element
    let ap_pmk: proto::HandshakePMK = serde_invoke_command_req_res(
        peer_session,
        &mut output_vec,
        Command::ConfirmExchange,
        &sta_token,
    )?;
    println!("ap_pmk is {:?}", ap_pmk);

    Ok(())
}
