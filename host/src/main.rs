use optee_teec::{Context, Operation, ParamType, Session, Uuid};
use optee_teec::{ParamNone, ParamTmpRef, ParamValue};
use proto::{Command, UUID,self};



fn dragonfly(session: &mut Session,peer_session: &mut Session) -> optee_teec::Result<()> {
    let pw: &[u8] = b"abcdefgh";
    let input = proto::Password{
        pw: pw.to_vec()
    };
    let mut serialized_input = proto::serde_json::to_vec(&input).unwrap();
    let p0 = ParamTmpRef::new_input(serialized_input.as_mut_slice());
    let mut operation = Operation::new(0, p0, ParamNone, ParamNone, ParamNone);

    session.invoke_command(Command::SetPassword as u32, &mut operation)?;
    peer_session.invoke_command(Command::SetPassword as u32, &mut operation)?;

    let sta_mac: &[u8] = b"02:00:00:00:01:00";
    let ap_mac: &[u8] = b"02:00:00:00:00:00";

    let mut output_vec = vec![0u8;5000];
    let input = proto::Macs{
        local_mac: ap_mac.to_vec(),
        peer_mac: sta_mac.to_vec(),
    };
    

    let mut serialized_input = proto::serde_json::to_vec(&input).unwrap();
    let p0 = ParamTmpRef::new_input(serialized_input.as_mut_slice());
    let p1 = ParamTmpRef::new_output(output_vec.as_mut_slice());
    let mut operation = Operation::new(0, p0, p1, ParamNone, ParamNone);
    session.invoke_command(Command::InitPWE as u32, &mut operation)?;
    let updated_size = operation.parameters().1.updated_size();
    let sta_commit_element: proto::CommitElement = proto::serde_json::from_slice(&output_vec[..updated_size]).unwrap();
     //println!("sta commit element : scalar: {:?} \n  element: {:?}",&sta_commit_element.scalar,&sta_commit_element.element);
    

    let input = proto::Macs{
        local_mac: ap_mac.to_vec(),
        peer_mac: sta_mac.to_vec(),
    };
    let mut serialized_input = proto::serde_json::to_vec(&input).unwrap();
    let p0 = ParamTmpRef::new_input(serialized_input.as_mut_slice());
    let p1 = ParamTmpRef::new_output(output_vec.as_mut_slice());
    let mut operation = Operation::new(0, p0, p1, ParamNone, ParamNone);
    peer_session.invoke_command(Command::InitPWE as u32, &mut operation)?;
    let updated_size = operation.parameters().1.updated_size();
    let ap_commit_element: proto::CommitElement = proto::serde_json::from_slice(&output_vec[..updated_size]).unwrap();
    //println!("ap commit element : scalar: {:?} \n  element: {:?}",&ap_commit_element.scalar,&ap_commit_element.element);


    let mut serialized_input = proto::serde_json::to_vec(&ap_commit_element).unwrap();
    let p0 = ParamTmpRef::new_input(serialized_input.as_mut_slice());
    let p1 = ParamTmpRef::new_output(output_vec.as_mut_slice());
    let mut operation = Operation::new(0, p0, p1, ParamNone, ParamNone);
    session.invoke_command(Command::ComputeSharedSecret as u32, &mut operation)?;
    let updated_size = operation.parameters().1.updated_size();
    let sta_token: proto::Token = proto::serde_json::from_slice(&output_vec[..updated_size]).unwrap();
    // println!("sta_token : {:?}",&sta_token);


    let mut serialized_input = proto::serde_json::to_vec(&sta_commit_element).unwrap();
    let p0 = ParamTmpRef::new_input(serialized_input.as_mut_slice());
    let p1 = ParamTmpRef::new_output(output_vec.as_mut_slice());
    let mut operation = Operation::new(0, p0, p1, ParamNone, ParamNone);
    peer_session.invoke_command(Command::ComputeSharedSecret as u32, &mut operation)?;
    let updated_size = operation.parameters().1.updated_size();
    let ap_token: proto::Token = proto::serde_json::from_slice(&output_vec[..updated_size]).unwrap();
    // println!("ap_token : {:?}",&ap_token);


    let mut serialized_input = proto::serde_json::to_vec(&ap_token).unwrap();
    let p0 = ParamTmpRef::new_input(serialized_input.as_mut_slice());
    let p1 = ParamTmpRef::new_output(output_vec.as_mut_slice());
    let mut operation = Operation::new(0, p0, p1, ParamNone, ParamNone);
    session.invoke_command(Command::ConfirmExchange as u32, &mut operation)?;

    // let updated_size = operation.parameters().1.updated_size();
    // let sta_token: proto::Token = proto::serde_json::from_slice(&output_vec[..updated_size]).unwrap();


    let mut serialized_input = proto::serde_json::to_vec(&sta_token).unwrap();
    let p0 = ParamTmpRef::new_input(serialized_input.as_mut_slice());
    let p1 = ParamTmpRef::new_output(output_vec.as_mut_slice());
    let mut operation = Operation::new(0, p0, p1, ParamNone, ParamNone);
    peer_session.invoke_command(Command::ConfirmExchange as u32, &mut operation)?;


    Ok(())
}

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
