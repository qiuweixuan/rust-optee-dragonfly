use optee_utee::{BigInt};
use optee_utee::{Error,ErrorKind,Result};
use std::{u8,u32};



// 使用num_bigint所需要的库
use num_bigint::BigUint;


pub fn gpstr_from_hexstr(bytes_str: &[u8]) -> Result<Vec<u8>> {
    let radix: u8 = 16;
    let bytes_str_len: usize = bytes_str.len();
    let mut chars_to_u8s: Vec<u8> = Vec::with_capacity(bytes_str_len);
    for byte in bytes_str {
        #[allow(unknown_lints, ellipsis_inclusive_range_patterns)]
        let digest = match byte {
            b'0'...b'9' => byte - b'0',
            b'a'...b'z' => byte - b'a' + 10,
            b'A'...b'Z' => byte - b'A' + 10,
            b'_' => continue,
            _ => u8::MAX,
        };
        if digest < radix as u8 {
            chars_to_u8s.push(digest);
        } else {
            return Err( Error::new(ErrorKind::BadParameters));
        }
    }

    let mut hex_vec: Vec<u8> = Vec::with_capacity((bytes_str_len + 1) / 2);
    let mut start = 0;
    if bytes_str_len % 2 == 1 {
        let c: u8 = chars_to_u8s[start].clone();
        hex_vec.push(c);
        start = start + 1;
    }
    for i in (start..bytes_str_len).step_by(2) {
        let c: u8 = (chars_to_u8s[i] * 16) + (chars_to_u8s[i + 1]);
        hex_vec.push(c);
    }

    Ok(hex_vec)
}


pub fn gpstr_to_hexstr(gpstr: &[u8]) -> Result<Vec<u8>> {
    const CHARS: &[u8] = b"0123456789ABCDEF";
    let mut hexstr = Vec::with_capacity(gpstr.len() * 2);
    for byte in gpstr {
        hexstr.push(CHARS[(byte >> 4) as usize]);
        hexstr.push(CHARS[(byte & 0xf) as usize]);
    }
    Ok(hexstr)
}

#[allow(dead_code)]
pub enum U32Kind {
    BE,
    LE,
}

pub fn transmute_u16_to_u8array(n: u32, mode: U32Kind)->[u8;2]{
    let mut u8array = [0u8;2];
    match mode{
        U32Kind::BE => {
            u8array[0] = ((n >> 8) & 0xff) as u8;
            u8array[1] = (n & 0xff) as u8;
            u8array
        },
        U32Kind::LE => {
            u8array[1] = ((n >> 8) & 0xff) as u8;
            u8array[0] = (n & 0xff) as u8;
            u8array
        },
    }
}


pub fn bigint_to_hexstr(src :&BigInt) -> Result<Vec<u8>>{
    let gpstr = src.convert_to_octet_string()?;
    let hexstr = gpstr_to_hexstr(&gpstr)?;
    Ok(hexstr)
}



pub fn bigint_construct_from_hexstr(hex_bytes:&[u8]) -> Result<BigInt>{
        let hex_u8_vec = gpstr_from_hexstr(hex_bytes)?;
        let mut bigint = BigInt::new(hex_u8_vec.len() as u32 * 8);
        bigint.convert_from_octet_string(&hex_u8_vec, 0)?;
        Ok(bigint)
}
pub fn bigint_construct_from_gpstr(gp_bytes:&[u8]) -> Result<BigInt>{

        let mut bigint = BigInt::new(gp_bytes.len() as u32 * 8);
        bigint.convert_from_octet_string(&gp_bytes, 0)?;
        Ok(bigint)
}


pub fn bigint_construct_from_s32(src: i32)-> BigInt {
    let mut s32 = BigInt::new(32);
    s32.convert_from_s32(src);
    s32
}

pub fn bigint_assign(src: &BigInt) -> BigInt {
    BigInt{data: src.data.clone()}
}


pub fn numbiguint_to_gpbigint(src: &BigUint) -> BigInt {
    // 获取十六进制字符串src_hex_str
    let src_hex_str = src.to_str_radix(16);
    bigint_construct_from_hexstr(&src_hex_str.as_bytes()).unwrap()
}

pub fn gpbigint_to_numbiguint(src: &BigInt) ->  BigUint {
    // 获取十六进制字符串src_hex_str
    let src_hex_str =  bigint_to_hexstr(&src).unwrap(); 
    BigUint::parse_bytes(&src_hex_str,16).unwrap()
}



/* 
int mod(int a,int b,int m){
    int result = 1;
    int base = a;
    while(b>0){
         if(b & 1==1){
            result = (result*base) % m;
         }
         base = (base*base) %m;
         b>>>=1;
    }
    return result;
}
*/   
//https://blog.csdn.net/chen77716/article/details/7093600
pub fn bigint_expmod(base: &BigInt,exp: &BigInt,modular: &BigInt) -> Result<BigInt> {
    let biguint_base = gpbigint_to_numbiguint(&base);
    let biguint_exp = gpbigint_to_numbiguint(&exp);
    let biguint_modular = gpbigint_to_numbiguint(&modular);

    let biguint_result = biguint_base.modpow(&biguint_exp,&biguint_modular);
    let result = numbiguint_to_gpbigint(&biguint_result);
    
    Ok(result)
}

pub fn bigint_div_rem(u: &BigInt, d: &BigInt) -> Result<(BigInt, BigInt)> {
    use num_integer::Integer;
    let biguint_u = gpbigint_to_numbiguint(&u);
    let biguint_d = gpbigint_to_numbiguint(&d);

    let (biguint_q, biguint_r) = biguint_u.div_rem(&biguint_d);
    let q = numbiguint_to_gpbigint(&biguint_q);
    let r = numbiguint_to_gpbigint(&biguint_r);
    
    Ok((q,r))
}

