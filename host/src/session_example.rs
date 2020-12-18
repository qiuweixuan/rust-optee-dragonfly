use super::ca_session::SaeCaContext;
use optee_teec;

pub fn sae_success_example() -> optee_teec::Result<()>{
    // 初始化参数
    let pwd_name: &[u8] = b"root";
    let pw: &[u8] = b"dragonflysae";
    let rand_bytes : usize = 6;
    let assert_is_success = true;
    sae_test(pwd_name,pw,pw,rand_bytes,assert_is_success)?;
    Ok(())
}

pub fn sae_fail_example() -> optee_teec::Result<()>{
    // 初始化参数
    let pwd_name: &[u8] = b"root";
    let pw1: &[u8] = b"dragonflysae";
    let pw2: &[u8] = b"saedragonfly";
    let rand_bytes : usize = 6;
    let assert_is_success = false;
    sae_test(pwd_name,pw1,pw2,rand_bytes,assert_is_success)?;
    Ok(())
}


fn sae_test(pwd_name: &[u8], sta_pw: &[u8] , ap_pw : &[u8], rand_bytes: usize,assert_is_success: bool) -> optee_teec::Result<()> {
    // 创建会话
    let mut sta_ctx = SaeCaContext::new_ctx()?;
    let mut ap_ctx = SaeCaContext::new_ctx()?;
    let mut session = SaeCaContext::new_session(&mut sta_ctx)?;
    let mut peer_session = SaeCaContext::new_session(&mut ap_ctx)?;
    
    /* GeneRandom */
    // sta get random request
    let sta_random_res = session.gene_random(rand_bytes)?;
    // ap get random request
    let ap_random_res = peer_session.gene_random(rand_bytes)?;

    /* InitMemUserPassword */
    // sta set password element
    session.init_mem_user_password(pwd_name, sta_pw)?;
    // ap set password element
    peer_session.init_mem_user_password(pwd_name, ap_pw)?; 

    /* LoadDevUserPassword */
    /* // sta load password element
    session.load_dev_user_password(pwd_name)?;
    // ap load password element
    peer_session.load_dev_user_password(pwd_name)?; */

    /* InitNamedGroupReq */
    let group_code: u16 = 0x0101;
    // sta init named group
    session.init_named_group(group_code)?;
    // ap init named group
    peer_session.init_named_group(group_code)?;

    /* ComputeCommitElement */
    let client_random = &sta_random_res.rand;
    let server_random =  &ap_random_res.rand;
    // sta commit element
    let sta_commit_element = session.compute_commit_element(client_random, server_random)?;
    // ap commit element
    let ap_commit_element = peer_session.compute_commit_element(client_random, server_random)?;

    /* ComputeConfirmElement */
    // sta confirm element
    let sta_token = session.compute_confirm_element(&ap_commit_element.scalar, &ap_commit_element.element)?;
    // ap confirm element
    let ap_token = peer_session.compute_confirm_element(&sta_commit_element.scalar, &sta_commit_element.element)?;


    /* ConfirmExchange */
    // sta accept pmk element
    let sta_pmk = session.confirm_exchange(&ap_token.token)?;
    println!("sta_pmk is {:?}", sta_pmk);
    assert_eq!(sta_pmk.is_confirm, assert_is_success);
    // ap accept pmk element
    let ap_pmk = peer_session.confirm_exchange(&sta_token.token)?;
    println!("ap_pmk is {:?}", ap_pmk);
    assert_eq!(ap_pmk.is_confirm, assert_is_success);

    Ok(())
}