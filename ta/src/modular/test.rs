// use optee_utee::{BigInt,BigIntFMMContext,BigIntFMM};
// use optee_utee::{
//      trace_println
// };
use optee_utee::{Result};
use optee_utee::{AlgorithmId, Digest,Mac};
use optee_utee::{AttributeId, AttributeMemref, TransientObject, TransientObjectType};
use optee_utee::{Random};


struct DigestOp {
    op: Digest,
}


use  super::gp_bigint;
use  super::dragonfly_ffc;

use dragonfly_ffc::{FFCElement,Peer};

#[test]
pub fn test_bigint() -> Result<()> {

    test_div_rem()?;
    test_div_rem_core()?;
    test_bigint_expmod()?;
    test_fmm()?;
    Ok(())
}

#[test]
pub fn test_peer() -> Result<()> {
    test_dragonfly_key_exchange()?;
    Ok(())
}


#[test]
pub fn test_dragonfly_key_exchange() -> Result<()> {

    trace_println!("\n[+] TA invoke test_dragonfly_key_exchange\n");

    let group15_elemnt: FFCElement = Default::default(); 

    // let password: &[u8] = b"abc1238";
    // let sta_mac: &[u8] = b"44:67:2D:2C:91:A6";
    // let ap_mac: &[u8] = b"44:37:2C:2F:91:36";

    let password: &[u8] = b"abcdefgh";
    let sta_mac: &[u8] = b"02:00:00:00:01:00";
    let ap_mac: &[u8] = b"02:00:00:00:00:00";

    let sta_name:&[u8] = b"STA";
    let ap_name:&[u8] = b"AP";

    let peer_sta = Peer::new(&password,&sta_mac,&sta_name,&group15_elemnt);
    let sta_password_element = peer_sta.initiate(ap_mac)?;
    trace_println!("peer_sta.initiate password_element : {}",sta_password_element);

    trace_println!("--------------------------");
    let peer_ap = Peer::new(&password,&ap_mac,&ap_name,&group15_elemnt);
    let ap_password_element = peer_ap.initiate(sta_mac)?;
    trace_println!("peer_ap.initiate password_element : {}",ap_password_element);
    trace_println!("--------------------------");

    let sta_private_str = b"369de1458282fb76548b6b88d25eb1b39b85202e58780004c500d9e2d448cee023a41e01e4a3857be297ca9b0aeb710fac965a192ca450f2b1d045919e1540096e144f31b08aa5567585509b5af417cc3aeca5d5d1e7b4d9bd08a23b21e10eda59a30ef9417227f26f19b2314e20edc31e237e4151737f479aa7f2af1374d9919ba95afe819a522f33ec746714a7965792b93ebd3e3b23b3dcf5b6c033fe6e71a73d0727e49b294bb104c6dfb3d0fa6c3033f6283b1e84527ddb3e851cd3e86ee3bdd4198166905d628ac18556944861a190faeac7a4b5a39d0090533db26e24aea4785b1924a8a2b72e774d96506a6769e29a29525463406a8da99e57700409266ed3d3224e69721c02776df21a831f5278b0e8a0589e9c57506224f675483b9c1a10e29842bb3601de3e4b495a67860dfa67ced8e006818cff92609e03444737a63eedf7eff4712e8954085d696de733aeca74b829c0a498ccb17edf4d33f727aecbd5313b1530154a5950a0db811e09ac5301ca4404e12e39d010dcb57a4d";
    let sta_private = gp_bigint::bigint_construct_from_hexstr(sta_private_str)?;
    let sta_mask_str =  b"6aca2ccb867cc9b18827a0ccebf976c52d8eef21b526f8149a5623890f91620201a25e44a62a3bd54a580ab866f1305e8ac080fb0cea31912ecab35ff40c11dacd7601d0247f3a615ebb117f9bafd7e888c8625686392f926fa8c30922f1d399752efe97e97b7de09b0b68dabbe15f53127fe8049160e9ff5c3baaf48de0c6c93f6e36139c7e29d12027e75750003a8da96d3c173399116c94229add40f124f90fdb8f4087713ff748762f0b210632ac9b186218e0dfb7be00bc2038f387ea2395926cca22db6b21501c48242df8cac78ac0c50a6499556867dd86c9225a6b67ef914e6b117b19435371d86010740527be3aa5c258ac707a764d632887fcf096c4c1ee2037edcf038a00e9a8446bb54d93dec995797252fb897065d36302257713128a87dfb056606814e3b8ddc6db19097bffdcc9f9113d47f11ca0e6f72339af8c0b1030ff9117b8629dffa2171ddf6f3004f1eb4beaae6bab20146e7f06b4987abe2cb42585014ab203544e82f47f4421711dd7fa8c43dd3124159cf1e065";
    let sta_mask = gp_bigint::bigint_construct_from_hexstr(sta_mask_str)?;

    let ap_private_str = b"7ecc5a3d7f9cfee156b0ada0eb2d2a2ab2bca037f1f4d5f98563d8f89f835ce6c45eb3af305db1d3d706cce8259c790c06a2ef5e1e0371bf6be0804f2efd07aaf81d2dac36fc06a221e595d340820db5a059d62bb335aeebcd5d08faea379a1a45b3ba1589d26b2122e7e793f2c26dd396197531ed3f4c8dc7aba17ed697c7182a009ebe694208f040ebca0e49ddb63bac809006fec29310236f6ccae190dcc85ac307dccdc29e7f1a0ea612532b3e19e61cff3b8d87398e72ba753cb29e7b91df040ded44c4934e002e3679bf3194a13cb7806019acfd7eb2f4a198fbe8ae0f35ab01b63c5fa5f60dbcc21783ea2b642b6e8dadf14d3a3fd47201864fb1d8c56c9cc48396b03d4b05599bfc4a6a6047d5fb27fb31c406e67e1d173ec675e5ae4730aae202d65ba53c8e76bad1ecbac8341fad8ec2bc13e7c2d03e0c2e8f516c99c56b5e717a22cccea967ef061c059cdcf6039322fd2a84626325737f67a057cba8f0dd670c6a28c107ef3fbe254e7e9d2816fb1ec8b00ea037489da46f21c1";
    let ap_private = gp_bigint::bigint_construct_from_hexstr(ap_private_str)?;
    let ap_mask_str = b"676651fd3ce6efb55c743bcf0d9100acfe506fd3b551ca0280ae90975bedcc4faef9b63cd2f80b2c31fe296b4bcb0db5f118b47c09f61a22313b58a2a735ac5b9715487dc2e875819753243e73ee5ab4eeb99e4e0d75c5004a4c0f9174e990234d848b733d602be395c3da1e32ba6a5bd321f5e2e49086eeb3ac43266d305b18cc20b0c83679cb0db163ea0337cabd1224de298ce1c19cedeef8773efd43bf900b3ef22cf937d440ee82743c41ac3147f6edcd56d23ed18a231de5264194d10e52b918a0f215f669554e0e023f071c8f194cda9b502f6e35ee3ed7a166f4607f86be0e1654f24c5abe48c55dc0a3b2c3b67024928cea0ff84209959b040c649eb2a9eca4c6a5f0c5208e74057a685e4eb215b48ef548860a2682f9aabbd000b52a8a587d97b79b89addf0af94d015c943bf3b5e902a02c09a2b4c4ef1f69887e5511d4e3bbb8a122c2ab9367cbb6086d155f1de342ad9e74c82598cada4fafe18ef585c45cf2ffc1e363924dc2ac1cf0ce04eeaa252391a59d088cbb622d2f67";
    let ap_mask = gp_bigint::bigint_construct_from_hexstr(ap_mask_str)?;

    // let (sta_private,sta_mask,sta_scalar,sta_element) = peer_sta.commit_exchange(&sta_password_element)?;
    // trace_println!("--------------------------");
    // let (ap_private,ap_mask,ap_scalar,ap_element) = peer_ap.commit_exchange(&ap_password_element)?;

    
    let (sta_scalar,sta_element) = peer_sta.commit_exchange_with_priv_mask(&sta_password_element,&sta_private,&sta_mask)?;
    trace_println!("--------------------------");
    let (ap_scalar,ap_element) = peer_ap.commit_exchange_with_priv_mask(&ap_password_element,&ap_private,&ap_mask)?;
    trace_println!("--------------------------");


    let (sta_kck,sta_ss_hex,sta_token) = peer_sta.compute_shared_secret(&ap_scalar,&ap_element,&sta_password_element,&sta_private,&sta_scalar,&sta_element)?;
    trace_println!("--------------------------");
    let (ap_kck,ap_ss_hex,ap_token) = peer_ap.compute_shared_secret(&sta_scalar,&sta_element,&ap_password_element,&ap_private,&ap_scalar,&ap_element)?;
    
    trace_println!("--------------------------");
    peer_sta.confirm_exchange(&ap_scalar,&ap_element,&sta_scalar,&sta_element,&sta_kck,&sta_ss_hex,&ap_token)?;
    trace_println!("--------------------------");
    peer_ap.confirm_exchange(&sta_scalar,&sta_element,&ap_scalar,&ap_element,&ap_kck,&ap_ss_hex,&sta_token)?;
    


    Ok(())
}


#[test]
pub fn test_password_element_derivation() -> Result<()> {

    let group5_elemnt: FFCElement = Default::default(); 
    trace_println!("prime get_bit_count:{} , order get_bit_count {} .", group5_elemnt.prime.get_bit_count() + 64, 
    group5_elemnt.order.get_bit_count() + 64);
    trace_println!("group5_elemnt:\n{}.", group5_elemnt);
    let num_bits = group5_elemnt.prime.get_bit_count() + 64;


    let password: &[u8] = b"abc1238";
    let sta_mac: &[u8] = b"44:67:2D:2C:91:A6";
    let ap_mac: &[u8] = b"44:37:2C:2F:91:36";
    let sta_name:&[u8] = b"STA";
    let _ap_name:&[u8] = b"AP";
    let peer_sta = Peer::new(&password,&sta_mac,&sta_name,&group5_elemnt);

    let k: u8 = 40;
    let mut found = true;
    let label_str: &[u8] = b"Dragonfly Hunting And Pecking";
    let mut count: u8 = 1;


    let mut password_element = BigInt::new(0);
    while count <= k || found == false{
        
        let password_base = peer_sta.compute_hashed_password(&ap_mac, &count)?;
        //trace_println!("password_base:{:02x?}",password_base);

        let temp = peer_sta.compute_password_key(&password_base,label_str,num_bits)?;
        trace_println!("temp:{}",&temp);

        //seed = (temp mod(p - 1)) + 1
        let mut one = BigInt::new(1);
        one.convert_from_s32(1);
        let p_1 = BigInt::sub(&group5_elemnt.prime,&one);
        let seed = BigInt::module(&temp,&p_1);
        let mut seed = BigInt::add(&seed,&one);
        gp_bigint::bigint_normalize(&mut seed);
        trace_println!("seed:{}",&seed);

        // temp = seed ^ ((prime - 1) / order) mod prime

        let exp = match group5_elemnt.is_safe_prime {
            true =>{
                /*
                * exp = (prime - 1) / 2 for the group used here, so this becomes:
                * password_element (temp) = seed ^ 2 modulo prime
                */
                let mut two = BigInt::new(2);
                two.convert_from_s32(2);
                two
            },
            false =>{
                let (quot, _rem) = BigInt::divide(&p_1,&group5_elemnt.order);
                quot
            }
        };
        let seed = gp_bigint::bigint_expmod(&seed,&exp,&group5_elemnt.prime)?;
        trace_println!("seed:{}",&seed);
        
        if BigInt::compare_big_int(&seed,&one) > 0{
            password_element = seed;
            found = true;
        }
        
        count = count + 1;
    }
    trace_println!("password_element:{}",&password_element);


    Ok(())
}


#[test]
pub fn test_ffc_element_construct() -> Result<()> {

    static  DH_GROUP5_PRIME: [u8;192] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
        0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
        0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
        0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22,
        0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
        0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B,
        0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
        0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
        0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
        0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B,
        0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
        0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5,
        0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
        0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
        0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05,
        0x98, 0xDA, 0x48, 0x36, 0x1C, 0x55, 0xD3, 0x9A,
        0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
        0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96,
        0x1C, 0x62, 0xF3, 0x56, 0x20, 0x85, 0x52, 0xBB,
        0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
        0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04,
        0xF1, 0x74, 0x6C, 0x08, 0xCA, 0x23, 0x73, 0x27,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    ];
    static DH_GROUP5_ORDER: [u8;192] = [
        0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xE4, 0x87, 0xED, 0x51, 0x10, 0xB4, 0x61, 0x1A,
        0x62, 0x63, 0x31, 0x45, 0xC0, 0x6E, 0x0E, 0x68,
        0x94, 0x81, 0x27, 0x04, 0x45, 0x33, 0xE6, 0x3A,
        0x01, 0x05, 0xDF, 0x53, 0x1D, 0x89, 0xCD, 0x91,
        0x28, 0xA5, 0x04, 0x3C, 0xC7, 0x1A, 0x02, 0x6E,
        0xF7, 0xCA, 0x8C, 0xD9, 0xE6, 0x9D, 0x21, 0x8D,
        0x98, 0x15, 0x85, 0x36, 0xF9, 0x2F, 0x8A, 0x1B,
        0xA7, 0xF0, 0x9A, 0xB6, 0xB6, 0xA8, 0xE1, 0x22,
        0xF2, 0x42, 0xDA, 0xBB, 0x31, 0x2F, 0x3F, 0x63,
        0x7A, 0x26, 0x21, 0x74, 0xD3, 0x1B, 0xF6, 0xB5,
        0x85, 0xFF, 0xAE, 0x5B, 0x7A, 0x03, 0x5B, 0xF6,
        0xF7, 0x1C, 0x35, 0xFD, 0xAD, 0x44, 0xCF, 0xD2,
        0xD7, 0x4F, 0x92, 0x08, 0xBE, 0x25, 0x8F, 0xF3,
        0x24, 0x94, 0x33, 0x28, 0xF6, 0x72, 0x2D, 0x9E,
        0xE1, 0x00, 0x3E, 0x5C, 0x50, 0xB1, 0xDF, 0x82,
        0xCC, 0x6D, 0x24, 0x1B, 0x0E, 0x2A, 0xE9, 0xCD,
        0x34, 0x8B, 0x1F, 0xD4, 0x7E, 0x92, 0x67, 0xAF,
        0xC1, 0xB2, 0xAE, 0x91, 0xEE, 0x51, 0xD6, 0xCB,
        0x0E, 0x31, 0x79, 0xAB, 0x10, 0x42, 0xA9, 0x5D,
        0xCF, 0x6A, 0x94, 0x83, 0xB8, 0x4B, 0x4B, 0x36,
        0xB3, 0x86, 0x1A, 0xA7, 0x25, 0x5E, 0x4C, 0x02,
        0x78, 0xBA, 0x36, 0x04, 0x65, 0x11, 0xB9, 0x93,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    ];


    // let prime = b"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff";
    // let order = b"7fffffffffffffffe487ed5110b4611a62633145c06e0e68948127044533e63a0105df531d89cd9128a5043cc71a026ef7ca8cd9e69d218d98158536f92f8a1ba7f09ab6b6a8e122f242dabb312f3f637a262174d31bf6b585ffae5b7a035bf6f71c35fdad44cfd2d74f9208be258ff324943328f6722d9ee1003e5c50b1df82cc6d241b0e2ae9cd348b1fd47e9267afc1b2ae91ee51d6cb0e3179ab1042a95dcf6a9483b84b4b36b3861aa7255e4c0278ba36046511b993ffffffffffffffff";
    // let group5_elemnt: FFCElement = FFCElement::new_from_hexstr(prime,order,true)?;
    // trace_println!("prime get_bit_count:{} , order get_bit_count {} .", group5_elemnt.prime.get_bit_count() + 64, 
    // group5_elemnt.order.get_bit_count() + 64);

    let group5_elemnt: FFCElement = FFCElement::new_from_gpstr(&DH_GROUP5_PRIME,&DH_GROUP5_ORDER,true)?;
    trace_println!("prime get_bit_count:{} , order get_bit_count {} .", group5_elemnt.prime.get_bit_count() + 64, 
    group5_elemnt.order.get_bit_count() + 64);

    let group5_elemnt: FFCElement = FFCElement::new()?;
    trace_println!("prime get_bit_count:{} , order get_bit_count {} .", group5_elemnt.prime.get_bit_count() + 64, 
    group5_elemnt.order.get_bit_count() + 64);

    let group5_elemnt: FFCElement = Default::default();
    trace_println!("prime get_bit_count:{} , order get_bit_count {} .", group5_elemnt.prime.get_bit_count() + 64, 
    group5_elemnt.order.get_bit_count() + 64);
    trace_println!("group5_elemnt:\n{}.", group5_elemnt);

    Ok(())
}








#[test]
pub fn test_div_rem() -> Result<()> {

    let a0: BigInt = gp_bigint::bigint_construct_from_hexstr(b"a9fb57dba1eeb")?;
    let bn: u32 = 0xb57dba1e;
    let (q,r) = gp_bigint::div_rem_digit(&a0,bn);
    trace_println!("q:{},r:{:x}",q,r);

    let result = BigInt::multiply(&q,&q);
    trace_println!("result:{}",result);
    Ok(())
}

#[test]
pub fn test_div_rem_core() -> Result<()> {


    let s1 = b"A9FB57DBA1EEB57DBA1EE";
    let s2 = b"B57DBA1EEABC1238";
    
    let a: BigInt = gp_bigint::bigint_construct_from_hexstr(s1)?;
    let b: BigInt = gp_bigint::bigint_construct_from_hexstr(s2)?;
    
    let (q,r) = gp_bigint::div_rem_core(&a,&b)?;
    trace_println!("q:{},r:{}",q,r);

    let prime = b"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff";
    let order = b"7fffffffffffffffe487ed5110b4611a62633145c06e0e68948127044533e63a0105df531d89cd9128a5043cc71a026ef7ca8cd9e69d218d98158536f92f8a1ba7f09ab6b6a8e122f242dabb312f3f637a262174d31bf6b585ffae5b7a035bf6f71c35fdad44cfd2d74f9208be258ff324943328f6722d9ee1003e5c50b1df82cc6d241b0e2ae9cd348b1fd47e9267afc1b2ae91ee51d6cb0e3179ab1042a95dcf6a9483b84b4b36b3861aa7255e4c0278ba36046511b993ffffffffffffffff";


    let a: BigInt = gp_bigint::bigint_construct_from_hexstr(prime)?;
    let b: BigInt = gp_bigint::bigint_construct_from_hexstr(order)?;
    let a = BigInt::multiply(&a,&a);

    let shift_bit = b.data.last().unwrap().leading_zeros() as usize;
    let shift_a = gp_bigint::bigint_shl(&a, shift_bit);
    let shift_b = gp_bigint::bigint_shl(&b, shift_bit);
    trace_println!("shift_a:{},\n shift_b:{}",shift_a,shift_b);
    let (q,r) = gp_bigint::div_rem_core(&shift_a,&shift_b)?;
    trace_println!("q:{},r:{}",q,r);

    Ok(())
}

#[test]
pub fn test_fmm() -> Result<()> {
    let op1 = b"03e8";
    let op2 = b"0640";
    let op_mod = b"45";
    let op1 = gp_bigint::bigint_construct_from_hexstr(op1)?;
    let op2 = gp_bigint::bigint_construct_from_hexstr(op2)?;
    let op_mod = gp_bigint::bigint_construct_from_hexstr(op_mod)?;
    let result = BigInt::mul_mod(&op1,&op2,&op_mod);
    trace_println!("op1:{}",op1);
    trace_println!("op2:{}",op2);
    trace_println!("op_mod:{}",op_mod);
    trace_println!("mul_mod_result:{}",result);

    let op_mod_fmm_context = BigIntFMMContext::new(op_mod.get_bit_count(),&op_mod)?;
    

    let mut op1_fmm = BigIntFMM::new(op1.get_bit_count());
    op1_fmm.convert_from_big_int(&op1,&op_mod,&op_mod_fmm_context);

    let mut op2_fmm = BigIntFMM::new(op2.get_bit_count());
    op2_fmm.convert_from_big_int(&op2,&op_mod,&op_mod_fmm_context);

    let mut result_fmm = BigIntFMM::new(op_mod.get_bit_count());
    result_fmm.compute_fmm(&op1_fmm,&op2_fmm,&op_mod,&op_mod_fmm_context);

    let mut result_bigint = BigInt::new(op_mod.get_bit_count());
    result_bigint.convert_from_big_int_fmm(&result_fmm,&op_mod,&op_mod_fmm_context);
    trace_println!("fmm_result:{}",result_bigint);

    Ok(())
}









#[test]
pub fn test_compute_password_base() -> Result<()> {

    let sha256_op = DigestOp{op:Digest::allocate(AlgorithmId::Sha256).unwrap()};

    let mac1: &[u8] = b"44:67:2D:2C:91:A6";
    let mac2: &[u8] = b"44:37:2C:2F:91:36";
    let min_mac = std::cmp::min(&mac1, &mac2);
    let max_mac = std::cmp::max(&mac1, &mac2);
    trace_println!("min_mac:{:?}", min_mac);
    trace_println!("max_mac:{:?}", max_mac);
    let mut mix_message: Vec<u8> = max_mac.to_vec();
    mix_message.extend(min_mac.into_iter());
    let password: &[u8] = b"abc1238";
    mix_message.extend(password.into_iter());
    mix_message.push(1);
    trace_println!("mix_message:{:02x?}", mix_message);
    

    let mut password_base: [u8; 32] = [0u8; 32];
    sha256_op.op.do_final(&mix_message,&mut password_base).unwrap();
    trace_println!("password_base:{:02x?}",password_base);

    Ok(())
}







#[test]
pub fn hmac_sha256(key: &[u8], data: &[u8],out: &mut [u8]) -> Result<usize> {
    // const MAX_KEY_SIZE: usize = 64;
    // const MIN_KEY_SIZE: usize = 10;
    // if key.len() < MIN_KEY_SIZE || key.len() > MAX_KEY_SIZE {
    //     return Err(Error::new(ErrorKind::BadParameters));
    // }

    match Mac::allocate(AlgorithmId::HmacSha256, key.len() * 8) {
        Err(e) => return Err(e),
        Ok(mac) => {
            match TransientObject::allocate(TransientObjectType::HmacSha256, key.len() * 8) {
                Err(e) => return Err(e),
                Ok(mut key_object) => {
                    //KEY size can be larger than hotp.key_len
                    let mut tmp_key = key.to_vec();
                    tmp_key.truncate(key.len());
                    let attr = AttributeMemref::from_ref(AttributeId::SecretValue, &tmp_key);
                    key_object.populate(&[attr.into()])?;
                    mac.set_key(&key_object)?;
                }
            }
            mac.init(&[0u8; 0]);
            mac.update(&data);
            let out_len = mac.compute_final(&[0u8; 0], out).unwrap();
            Ok(out_len)
        }
    }
}

#[test]
pub fn test_compute_password_key() -> Result<()> {

    let sha256_op = DigestOp{op:Digest::allocate(AlgorithmId::Sha256).unwrap()};

    let pwd_base_str: &[u8] = b"e64ff0945aef2ec8d6252acb8bce091f5e013e073c49607ed20bb1a35921c47d";
    let mut password_base = gp_bigint::gpstr_from_hexstr(pwd_base_str)?;

    
    trace_println!("password_base:{:02x?}",password_base);
    
    let label_str: &[u8] = b"Dragonfly Hunting And Pecking";
    password_base.extend(label_str.into_iter());
    trace_println!("password_base:{:02x?}",password_base);

    let mut kdf_hmac_key: [u8; 32] = [0u8; 32];
    sha256_op.op.do_final(&password_base,&mut kdf_hmac_key).unwrap();
    trace_println!("kdf_hmac_key:{:02x?}",kdf_hmac_key);

    let key_bits: usize = 320;
    let key_bytes: usize = (key_bits + 7) / 8;
    let mut rand_op: Vec<u8> = vec![0u8; key_bytes];
    Random::generate(&mut rand_op);
    trace_println!("rand_op:{:02x?},len:{}", rand_op,rand_op.len());


    //let message_bytes : &[u8] = b"1eff7e89bf7678636580d17dd84a873b14b9c0e1680bbdc87647f3c382902d2f";
    let message_bytes : &[u8] = b"1eff7e89bf7678636580d17dd84a873b14b9c0e1680bbdc87647f3c382902d2f58d2754b39bca874";
    let message = gp_bigint::gpstr_from_hexstr(message_bytes)?;
    
    
    let mut password_key_out = [0u8;32];
    hmac_sha256(&kdf_hmac_key,&message,&mut password_key_out)?;
    trace_println!("password_key_out:{:02x?}", password_key_out);

    let mac_len: usize = 32;
    let mut pos: usize = 0;
    let mut result_key: Vec<u8> = Vec::new();
    while pos < key_bytes{
        let mut message_len = mac_len;
        if key_bytes - pos < mac_len{
            message_len = key_bytes - pos;
        }
        let mut out_digest = [0u8;32];
        hmac_sha256(&kdf_hmac_key,&message[pos..pos+message_len],&mut out_digest)?;
        result_key.extend(&out_digest[0..message_len]);
        pos += message_len;
        trace_println!("out_digest:{:02x?}", &out_digest[0..message_len]);
    }
    trace_println!("result_key:{:02x?}",result_key);

    let mut bigint_result = BigInt::new(result_key.len() as u32 * 8);
    bigint_result.convert_from_octet_string(&result_key, 0)?;
    trace_println!("bigint_result:{}",bigint_result);


    Ok(())
}

#[test]
pub fn test_bigint_expmod() -> Result<()> {
    let prime = b"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff";
    let order = b"7fffffffffffffffe487ed5110b4611a62633145c06e0e68948127044533e63a0105df531d89cd9128a5043cc71a026ef7ca8cd9e69d218d98158536f92f8a1ba7f09ab6b6a8e122f242dabb312f3f637a262174d31bf6b585ffae5b7a035bf6f71c35fdad44cfd2d74f9208be258ff324943328f6722d9ee1003e5c50b1df82cc6d241b0e2ae9cd348b1fd47e9267afc1b2ae91ee51d6cb0e3179ab1042a95dcf6a9483b84b4b36b3861aa7255e4c0278ba36046511b993ffffffffffffffff";

    let op1 = &gp_bigint::bigint_construct_from_hexstr(prime)?;
    let op2 = &gp_bigint::bigint_construct_from_hexstr(order)?;
    let cal_result = &BigInt::multiply(op1,op1);
    let (_,cal_result) = &gp_bigint::bigint_div_rem(cal_result,op2)?;
    trace_println!("cal_result:{}",cal_result);
    Ok(())
}



