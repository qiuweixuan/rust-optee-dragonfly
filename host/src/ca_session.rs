use optee_teec::{Operation, Session};
use optee_teec::{ParamNone, ParamTmpRef};

use proto::{self, Command};
use serde::{Deserialize, Serialize};

fn serde_invoke_command_req_res<'a, T: Serialize, U: Deserialize<'a>>(
    session: &mut Session,
    output_vec: &'a mut Vec<u8>,
    command_id: Command,
    input: T,
) -> optee_teec::Result<U> {
    let mut serialized_input = proto::serde_json::to_vec(&input).unwrap();
    let p0 = ParamTmpRef::new_input(serialized_input.as_mut_slice());
    let p1 = ParamTmpRef::new_output(output_vec.as_mut_slice());
    let mut operation = Operation::new(0, p0, p1, ParamNone, ParamNone);
    session.invoke_command(command_id as u32, &mut operation)?;
    let updated_size = operation.parameters().1.updated_size();
    let result: U = proto::serde_json::from_slice(&output_vec[..updated_size]).unwrap();
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
    let mut output_vec = vec![0u8; 5000];
    let pwd_name = b"root";
    // let pw: &[u8] = b"abcdefgh";
    let pw: &[u8] = b"dragonflysae";


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



    /* InitPWE */
    let input = proto::SessionRandoms {
        client_random: sta_random_res.rand,
        server_random: ap_random_res.rand,
    };
    // sta commit element
    let sta_commit_element: proto::CommitElement =
        serde_invoke_command_req_res(session, &mut output_vec, Command::InitPWE, &input)?;
    // ap commit element
    let ap_commit_element: proto::CommitElement =
        serde_invoke_command_req_res(peer_session, &mut output_vec, Command::InitPWE, &input)?;

    /* ComputeSharedSecret */
    // sta confirm element
    let sta_token: proto::Token = serde_invoke_command_req_res(
        session,
        &mut output_vec,
        Command::ComputeSharedSecret,
        &ap_commit_element,
    )?;
    // ap confirm element
    let ap_token: proto::Token = serde_invoke_command_req_res(
        peer_session,
        &mut output_vec,
        Command::ComputeSharedSecret,
        &sta_commit_element,
    )?;

    /* ConfirmExchange */
    let sta_pmk: proto::HandshakePMK = serde_invoke_command_req_res(
        session,
        &mut output_vec,
        Command::ConfirmExchange,
        &ap_token,
    )?;
    println!("sta_pmk is {:?}",sta_pmk);

    // ap accept pmk element
    let ap_pmk: proto::HandshakePMK = serde_invoke_command_req_res(
        peer_session,
        &mut output_vec,
        Command::ConfirmExchange,
        &sta_token,
    )?;
    println!("ap_pmk is {:?}",ap_pmk);

    Ok(())
}
