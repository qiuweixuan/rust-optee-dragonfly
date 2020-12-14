use super::object;
use optee_utee::{Result};

// 初始化根密码
pub fn init_root_password() -> Result<()>{
    let mut root_key_obj_id = "root".as_bytes().to_vec();
    let mut root_key_obj_buf = "abcdefgh".as_bytes().to_vec();
    // 如果对象不存在，则尝试创建对象
    if object::exist_raw_object(&mut root_key_obj_id).is_err(){
        object::create_raw_object(&mut root_key_obj_id,&mut root_key_obj_buf)?;
    }
    return Ok(());
}

// 读密码
pub fn read_password(obj_id: &mut [u8]) -> Result<Vec::<u8>>{
    let mut obj_buf :  Vec::<u8> = vec![0;5000];
    let size = object::read_raw_object(obj_id, &mut obj_buf)?;
    obj_buf.truncate(size as usize); 
    return Ok(obj_buf);
}