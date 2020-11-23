use std::{u8};

use optee_utee::BigInt;

use optee_utee::{
     trace_println
};

use optee_utee::{Result};
use optee_utee::{AlgorithmId, Digest,Mac};
use optee_utee::{AttributeId, AttributeMemref, TransientObject, TransientObjectType};
use optee_utee::{Random};

use optee_utee::{Error, ErrorKind};

use super::gp_bigint;
use super::ffc_op::{FFCElement};
use proto::{Macs};

// use std::{cmp};


struct DigestOp {
    op: Digest,
}



pub struct CommitElement {
    pub scalar: BigInt,
    pub element: BigInt
}


pub struct PrivateMask {
    pub private: BigInt,
    pub mask: BigInt
}

pub struct Secret {
    pub kck: Vec::<u8>,
    pub pmk: Vec::<u8>,
    pub pmkid: Vec::<u8>,
    pub ss_hex: Vec::<u8>,
    pub token: Vec::<u8>
}



pub struct DragonflyOp<'a> {
    pub ffc_elemnt:  FFCElement<'a>,
    //password =》 通信对象:Password,计算对象:Vec::<u8>
    pub password: Option<Vec::<u8>>,
    //Macs是否引入了耦合？
    pub macs:  Option<Macs>,

    pub password_element: Option<BigInt>,
    pub private_mask: Option<PrivateMask>,
    pub commit_element: Option<CommitElement>,
    pub peer_commit_element: Option<CommitElement>,
    pub secret: Option<Secret>
}




impl Default for DragonflyOp<'static> {
    fn default() -> Self {
        Self {
           password: None,
           ffc_elemnt: FFCElement::default(),
           macs: None,
           password_element: None,
           private_mask: None,
           commit_element: None,
           peer_commit_element: None,
           secret: None
        }
    }
}




impl<'a>  DragonflyOp<'a> {
    // pub fn initiate(self: &Self,local_password: &[u8],local_mac: &[u8],peer_mac: &[u8]) -> Result<BigInt> {
    pub fn initiate(self: &mut Self) -> Result<()> {
        let input_macs: &proto::Macs =   Self::handle_option(&self.macs)?;
        let local_mac: &[u8] = input_macs.local_mac.as_ref();
        let peer_mac: &[u8] =  input_macs.peer_mac.as_ref();
        let local_password =  Self::handle_option(&self.password)?;

        let num_bits = self.ffc_elemnt.prime.get_bit_count();
        let  k: u8 = 1;
        let mut found = true;
        let label_str: &[u8] = b"SAE Hunting and Pecking";
        let mut count: u8 = 1;


        let mut password_element = BigInt::new(0);
        while count <= k || found == false{
            
            let password_base = Self::compute_hashed_password(&local_password,&local_mac, &peer_mac, &count)?;
            // trace_println!("password_base:{:02x?}",password_base);

            let temp = self.compute_password_key(&password_base,label_str,num_bits)?;
            // trace_println!("temp:{}",&temp);

            //seed = (temp mod(p - 1)) + 1
            let mut one = BigInt::new(1);
            one.convert_from_s32(1);
            let p_1 = BigInt::sub(&self.ffc_elemnt.prime,&one);

            // let seed = BigInt::module(&temp,&p_1);
            // let mut seed = BigInt::add(&seed,&one);
            // gp_bigint::bigint_normalize(&mut seed);

            let mut seed = BigInt::module(&temp,&self.ffc_elemnt.prime);
            gp_bigint::bigint_normalize(&mut seed);

            // trace_println!("seed:{}",&seed);

            // temp = seed ^ ((prime - 1) / order) mod prime

            let exp = match self.ffc_elemnt.is_safe_prime {
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
                    let (quot, _rem) = BigInt::divide(&p_1,&self.ffc_elemnt.order);
                    quot
                }
            };
            let seed = gp_bigint::bigint_expmod(&seed,&exp,&self.ffc_elemnt.prime)?;
            // trace_println!("seed:{}",&seed);
            
            if BigInt::compare_big_int(&seed,&one) > 0{
                password_element = seed;
                found = true;
            }
            
            count = count + 1;
        }
        trace_println!("password_element:{}",&password_element);

        self.password_element = Some(password_element);
        Ok(())
    }

    pub fn commit_exchange(self: &mut Self) -> Result<()> {
        let password_element = Self::handle_option(&self.password_element)?; 
        
        let rand_bits: usize = self.ffc_elemnt.order.get_bit_count() as usize;
        let rand_bytes: usize = (rand_bits + 7) / 8;
        let two = gp_bigint::bigint_construct_from_s32(2);

        let mut rand_op: Vec<u8> = vec![0u8; rand_bytes];

        Random::generate(&mut rand_op);
        let rand_bigint = gp_bigint::bigint_construct_from_gpstr(&rand_op)?;
        let  (_, mut private) = gp_bigint::bigint_div_rem(&rand_bigint, &self.ffc_elemnt.order)?;
        if BigInt::compare_big_int(&private,&two) < 0{
            private = gp_bigint::bigint_assign(&two);
        }

        Random::generate(&mut rand_op);
        let rand_bigint = gp_bigint::bigint_construct_from_gpstr(&rand_op)?;
        let (_, mut mask) = gp_bigint::bigint_div_rem(&rand_bigint, &self.ffc_elemnt.order)?;
        if BigInt::compare_big_int(&mask,&two) < 0{
            mask = gp_bigint::bigint_assign(&two);
        }

        trace_println!("private:{}",&private);
        trace_println!("mask:{}",&mask);


        // scalar = (private + mask) modulo q
        let scalar = BigInt::add(&private,&mask);
        let (_, scalar) = gp_bigint::bigint_div_rem(&scalar, &self.ffc_elemnt.order)?;

        //Element = inverse(scalar-op(mask, PE))
        let element = self.ffc_elemnt.scalar_op(&mask,&password_element)?;
        let element = self.ffc_elemnt.inverse_op(&element)?;

        
        trace_println!("scalar:{}",&scalar);
        trace_println!("element:{}",&element);

        self.commit_element = Some( CommitElement{
            scalar,
            element
        });

        self.private_mask = Some( PrivateMask{
            private,
            mask
        });


        Ok(())
    }


    pub fn compute_shared_secret(self: &mut Self) -> Result<()> {
        let password_element = Self::handle_option(&self.password_element)?;

        let commit_element: &CommitElement =  Self::handle_option(&self.commit_element)?;
        let scalar: &BigInt =  &commit_element.scalar;
        let element: &BigInt =  &commit_element.element;

        let peer_commit_element: &CommitElement =  Self::handle_option(&self.peer_commit_element)?;
        let peer_scalar: &BigInt =  &peer_commit_element.scalar;
        let peer_element: &BigInt =  &peer_commit_element.element;

        let private_mask: &PrivateMask =  Self::handle_option(&self.private_mask)?;
        let private: &BigInt =  &private_mask.private;



        // ss = scalar-op(peer-commit-scalar, PWE)
        let ss = self.ffc_elemnt.scalar_op(&peer_scalar, &password_element)?;
        trace_println!("ss:\n{}",&ss);

        // ss = elem-op(ss,PEER-COMMIT-ELEMENT)
        let ss = self.ffc_elemnt.element_op(&ss, &peer_element)?;
        trace_println!("ss:\n{}",&ss);


        // ss = scalar-op(private, ss)
        let ss = self.ffc_elemnt.scalar_op(&private, &ss)?;
        trace_println!("ss:\n{}",&ss);

       /* keyseed = H(<0>32, k)
        * KCK || PMK = KDF-512(keyseed, "SAE KCK and PMK",
        *                      (commit-scalar + peer-commit-scalar) modulo r)
        * PMKID = L((commit-scalar + peer-commit-scalar) modulo r, 0, 128)
        */
        
        let nullkey: &[u8] = &[0u8;32];
        let ss_hex = ss.convert_to_octet_string()?;
        trace_println!("ss_hex:\n {:02x?}", &ss_hex);

        let mut keyseed = [0u8;32];
        Self::hmac_sha256(&nullkey,&ss_hex,&mut keyseed)?;
        trace_println!("keyseed:\n {:02x?}", &keyseed);


        let scalar_result = BigInt::add_mod(&scalar,&peer_scalar,&self.ffc_elemnt.order);
        let data = scalar_result.convert_to_octet_string()?;
        trace_println!("data:\n {:02x?}", &data);

        let label_str: &[u8] = b"SAE KCK and PMK";
        

        let key_buf = Self::sha256_prf_bits(&keyseed,label_str,&data,64 * 8)?;
        
        let mut kck: Vec<u8> = Vec::new();
        kck.extend(key_buf[0..32].iter());
        trace_println!("kck:\n {:x?}", &kck);
        
        let mut pmk: Vec<u8> = Vec::new();
        pmk.extend(key_buf[32..64].iter());
        trace_println!("pmk:\n {:x?}", &pmk);

        let len = std::cmp::min(data.len(),16);
        let mut  pmkid = vec![0u8;16];
        for i in 0..len{
            pmkid[i] = data[i];
        }
        trace_println!("pmkid:\n {:02x?}", &pmkid);

        let mut token_message = Vec::new();
        token_message.extend(&ss_hex);
        token_message.extend(&scalar.convert_to_octet_string()?);
        token_message.extend(&peer_scalar.convert_to_octet_string()?);
        token_message.extend(&element.convert_to_octet_string()?);
        token_message.extend(&peer_element.convert_to_octet_string()?);
        
        let mut token = vec![0u8;32];
        Self::hmac_sha256(&kck,&token_message,&mut token)?;
        trace_println!("token:\n {:02x?}", &token);
        
        self.secret = Some(Secret{
            kck,
            pmk,
            pmkid,
            ss_hex,
            token
        });


        Ok(())
    }


    pub fn confirm_exchange(self: &Self,peer_token: &[u8]) -> Result<()> {
        let commit_element: &CommitElement =  Self::handle_option(&self.commit_element)?;
        let scalar: &BigInt =  &commit_element.scalar;
        let element: &BigInt =  &commit_element.element;

        let peer_commit_element: &CommitElement =  Self::handle_option(&self.peer_commit_element)?;
        let peer_scalar: &BigInt =  &peer_commit_element.scalar;
        let peer_element: &BigInt =  &peer_commit_element.element;

        let secret: &Secret =  Self::handle_option(&self.secret)?;
        let kck: &[u8] =  &secret.kck;
        let ss_hex: &[u8] =  &secret.ss_hex;                            

        let mut peer_message = Vec::new();
        peer_message.extend(ss_hex);
        peer_message.extend(&peer_scalar.convert_to_octet_string()?);
        peer_message.extend(&scalar.convert_to_octet_string()?);
        peer_message.extend(&peer_element.convert_to_octet_string()?);
        peer_message.extend(&element.convert_to_octet_string()?);
    
        let mut peer_token_computed = vec![0u8;32];
        Self::hmac_sha256(&kck,&peer_message,&mut peer_token_computed)?;

        trace_println!(" Computed Token from Peer = {:02x?} \n", &peer_token_computed);
        trace_println!(" Received Token from Peer = {:02x?} \n", &peer_token);

        Ok(())
     }  


}

impl<'a>  DragonflyOp<'a> {

    fn mac2vec(mac: &[u8]) -> Vec<u8>{
        // use atoi::atoi;
        use atoi::FromRadix16;
        let split_mac = mac.split(|c| *c == b':');
        let mut ret: Vec<u8>= Vec::new();
        for it in split_mac{
            // let num = atoi::<u8>(it).unwrap();  
            let (num,_) = u8::from_radix_16(it);
            ret.push(num);
        }
        ret
    }

    fn compute_hashed_password(local_password: &[u8],local_mac: &[u8], peer_mac: &[u8],count : &u8) -> Result<([u8; 32])> {
        let max_mac = std::cmp::max(&local_mac, &peer_mac);
        let min_mac = std::cmp::min(&local_mac, &peer_mac);
        
        let max_mac = &Self::mac2vec(max_mac);
        let min_mac = &Self::mac2vec(min_mac);
        
        let mut key: Vec<u8> = Vec::new();
        key.extend(max_mac);
        key.extend(min_mac);
        // key.extend(vec![0u8;24-key.len()]);
        trace_println!("key:{:02x?}",&key);

        let mut message:Vec<u8> = Vec::new();
        message.extend(local_password);
        message.push(*count);
        trace_println!("message:{:02x?}",&message);
        
    
        let mut hashed_password: [u8; 32] = [0u8; 32];
        Self::hmac_sha256(&key,&message,&mut hashed_password)?;

        trace_println!("digest:{:02x?}",hashed_password);
        Ok(hashed_password)
    }


    fn compute_password_key(self: &Self,password_base: &[u8],label_str: &[u8],key_bits: u32) -> Result<(BigInt)> {
        let result_key = Self::sha256_prf_bits(password_base,label_str,self.ffc_elemnt.prime_gp_array,key_bits)?;
        trace_println!("len:{},result_key:{:02x?}",result_key.len(),result_key);
        
        let bigint_result = gp_bigint::bigint_construct_from_gpstr(&result_key)?;

        // trace_println!("bigint_result:{}",bigint_result);
        Ok(bigint_result)
    }



    fn sha256_prf_bits(key: &[u8],label_str: &[u8], data: &[u8], buf_len_bits : u32) -> Result<Vec<u8>> {
        // use std::mem;

        let buf_len: usize = (buf_len_bits as usize + 7) / 8;
        let mut message = Vec::new();
        
        let bits_u8_array = gp_bigint::transmute_u16_to_u8array(buf_len_bits,gp_bigint::U32Kind::LE);
        message.extend(label_str);
        message.extend(data);
        message.extend(&bits_u8_array);
        // trace_println!("message:{:x?}",message);
        
        let mac_len: usize = 32;
        let mut pos: usize = 0;
        let mut count:u32 = 1;
        let mut result_buf: Vec<u8> = Vec::new();
        while pos < buf_len{
            let mut message_len = mac_len;
            if buf_len - pos < mac_len{
                message_len = buf_len - pos;
            }

            let mut out_digest = [0u8;32];
            let count_u8_array = gp_bigint::transmute_u16_to_u8array(count,gp_bigint::U32Kind::LE);
            // trace_println!("count_u8_array:{:x?}",&count_u8_array);
            let mut handle_message = Vec::new();
            handle_message.extend(&count_u8_array);
            handle_message.extend(&message);

            Self::hmac_sha256(&key,&handle_message,&mut out_digest)?;
            result_buf.extend(&out_digest[0..message_len]);
        
            pos += message_len;
            count += 1;
        }

        Ok(result_buf)
    }


    fn hmac_sha256(input_key: &[u8], data: &[u8],out: &mut [u8]) -> Result<usize> {
        const MAX_KEY_SIZE: usize = 128;
        const MIN_KEY_SIZE: usize = 24;

        let mut key :Vec<u8> = Vec::new();
        key.extend(input_key);

        if key.len() < MIN_KEY_SIZE {
            key.extend(vec![0u8;MIN_KEY_SIZE - key.len()]);
        }
        if key.len() > MAX_KEY_SIZE {
            let sha256_op = DigestOp{op:Digest::allocate(AlgorithmId::Sha256).unwrap()};
            sha256_op.op.do_final(&input_key,&mut key).unwrap();
        }

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

    fn handle_option<'b,T>(v: &'b Option<T>) -> Result<&'b T>{
        match v{
            Some(res) => Ok(res),
            None => return Err(Error::new(ErrorKind::BadParameters))
        }
    }

}
