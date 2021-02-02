use optee_utee::BigInt;

use optee_utee::{
     trace_println
};

use optee_utee::{Result};
use optee_utee::{AlgorithmId, Digest,Mac,Cipher,OperationMode};
use optee_utee::{AttributeId, AttributeMemref, TransientObject, TransientObjectType};
use optee_utee::{Random};

struct DigestOp {
    op: Digest,
}

struct AesCipher {
    pub key_size: usize,
    pub cipher: Cipher,
    pub key_object: TransientObject,
}

impl Default for AesCipher {
    fn default() -> Self {
        Self {
            key_size: 0,
            cipher: Cipher::null(),
            key_object: TransientObject::null_object(),
        }
    }
}


pub fn hmac_sha256(input_key: &[u8], data: &[u8],out: &mut [u8]) -> Result<usize> {
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

pub fn aes_cipher_op(algo: AlgorithmId,op_mode: OperationMode, key_size: usize, key: &[u8],iv: &[u8], input_buf: &[u8]) -> Result<Vec::<u8>> {
    // 需要返回的结果对象
    let mut output_buf = vec![0u8;input_buf.len()];

    // 分配加密对象
    let mut aes = AesCipher::default();
    aes.key_size = key_size;
    aes.cipher = Cipher::allocate(
        algo,
        op_mode,
        aes.key_size * 8,
    )?;

    // 设置密钥
    aes.key_object = TransientObject::allocate(TransientObjectType::Aes, aes.key_size * 8)?;
    let attr = AttributeMemref::from_ref(AttributeId::SecretValue, &key);
    aes.key_object.populate(&[attr.into()])?;
    aes.cipher.set_key(&aes.key_object)?;

    // 设置IV
    aes.cipher.init(&iv);

    // 加解密操作
    aes.cipher.update(&input_buf, &mut output_buf)?;

    Ok(output_buf)  
}

// 加密操作
pub fn aes_ctr_256_enc(key: &[u8],iv: &[u8], input_buf: &[u8]) -> Result<Vec::<u8>> {
    let key_size: usize = 32;
    aes_cipher_op(AlgorithmId::AesCtr,OperationMode::Encrypt,key_size,key,iv,input_buf)
}

// 解密操作
pub fn aes_ctr_256_dec(key: &[u8],iv: &[u8], input_buf: &[u8]) -> Result<Vec::<u8>> {
    let key_size: usize = 32;
    aes_cipher_op(AlgorithmId::AesCtr,OperationMode::Decrypt,key_size,key,iv,input_buf)
}