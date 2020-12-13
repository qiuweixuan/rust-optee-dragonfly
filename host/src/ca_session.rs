use optee_teec::{Operation, Session};
use optee_teec::{ParamNone, ParamTmpRef};
use proto::{Command,self};
use serde::{Serialize, Deserialize};

fn serde_invoke_command<'a, T:Serialize,U: Deserialize<'a> >(session: &mut Session, output_vec: &'a mut Vec::<u8>,command_id: Command,input: T) ->  optee_teec::Result<U>
{
    let mut serialized_input = proto::serde_json::to_vec(&input).unwrap();
    let p0 = ParamTmpRef::new_input(serialized_input.as_mut_slice());
    let p1 = ParamTmpRef::new_output(output_vec.as_mut_slice());
    let mut operation = Operation::new(0, p0, p1, ParamNone, ParamNone);
    session.invoke_command(command_id as u32, &mut operation)?;
    let updated_size = operation.parameters().1.updated_size();
    let result: U = proto::serde_json::from_slice(&output_vec[..updated_size]).unwrap();
    Ok(result)
}


pub fn dragonfly(session: &mut Session,peer_session: &mut Session) -> optee_teec::Result<()> {
    let pw: &[u8] = b"abcdefgh";
    let input = proto::Password{
        pw: pw.to_vec()
    };
    let mut serialized_input = proto::serde_json::to_vec(&input).unwrap();
    let p0 = ParamTmpRef::new_input(serialized_input.as_mut_slice());
    let mut operation = Operation::new(0, p0, ParamNone, ParamNone, ParamNone);

    // sta set password element
    session.invoke_command(Command::SetPassword as u32, &mut operation)?;
    // ap set password element
    peer_session.invoke_command(Command::SetPassword as u32, &mut operation)?;

    // let sta_random: &[u8] = b"02:00:00:00:01:00";
    // let ap_random: &[u8] = b"02:00:00:00:00:00";

    let sta_random: &[u8] = b"\x02\x00\x00\x00\x01\x00";
    let ap_random: &[u8] = b"\x02\x00\x00\x00\x00\x00";

    let mut output_vec = vec![0u8;5000];

    // sta commit element
    let input = proto::Randoms{
        client_random: sta_random.to_vec(),
        server_random: ap_random.to_vec(),
    };
    let sta_commit_element : proto::CommitElement = serde_invoke_command(session,&mut output_vec,Command::InitPWE,&input)?;
    // println!("sta commit element : scalar: {:?} \n  element: {:?}",&sta_commit_element.scalar,&sta_commit_element.element);
    
    // ap commit element
    let input = proto::Randoms{
        client_random: sta_random.to_vec(),
        server_random: ap_random.to_vec(),
    };
    let ap_commit_element : proto::CommitElement = serde_invoke_command(peer_session,&mut output_vec,Command::InitPWE,&input)?;
    // println!("ap commit element : scalar: {:?} \n  element: {:?}",&ap_commit_element.scalar,&ap_commit_element.element);


    // sta confirm element
    let sta_token: proto::Token = serde_invoke_command(session,&mut output_vec,Command::ComputeSharedSecret,&ap_commit_element)?;
    // println!("sta_token : {:?}",&sta_token);

    // ap confirm element
    let ap_token: proto::Token = serde_invoke_command(peer_session,&mut output_vec,Command::ComputeSharedSecret,&sta_commit_element)?;
    // println!("ap_token : {:?}",&ap_token);

    // sta accept element
    let mut serialized_input = proto::serde_json::to_vec(&ap_token).unwrap();
    let p0 = ParamTmpRef::new_input(serialized_input.as_mut_slice());
    let p1 = ParamTmpRef::new_output(output_vec.as_mut_slice());
    let mut operation = Operation::new(0, p0, p1, ParamNone, ParamNone);
    session.invoke_command(Command::ConfirmExchange as u32, &mut operation)?;

    // ap accept element
    let mut serialized_input = proto::serde_json::to_vec(&sta_token).unwrap();
    let p0 = ParamTmpRef::new_input(serialized_input.as_mut_slice());
    let p1 = ParamTmpRef::new_output(output_vec.as_mut_slice());
    let mut operation = Operation::new(0, p0, p1, ParamNone, ParamNone);
    peer_session.invoke_command(Command::ConfirmExchange as u32, &mut operation)?;


    Ok(())
}

