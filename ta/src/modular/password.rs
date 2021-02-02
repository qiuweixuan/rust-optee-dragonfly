use super::object;
use optee_utee::{Result};

// 初始化根密码
pub fn init_root_password() -> Result<()>{
    let root_key_obj_id = "root".as_bytes().to_vec();
    let root_key_obj_buf = "abcdefgh".as_bytes().to_vec();
    // 如果对象不存在，则尝试创建对象
    if object::exist_raw_object(&root_key_obj_id).is_err(){
        object::create_raw_object(&root_key_obj_id,&root_key_obj_buf)?;
    }
    return Ok(());
}

// 读密码(get_pwd)
pub fn read_password(obj_id: &[u8]) -> Result<Vec::<u8>>{
    let mut obj_buf :  Vec::<u8> = vec![0;5000];
    let size = object::read_raw_object(obj_id, &mut obj_buf)?;
    obj_buf.truncate(size as usize); 
    return Ok(obj_buf);
}

// 写密码(set_pwd)
pub fn write_password(obj_id: &[u8],obj_buf: &[u8]) -> Result<()>{
    // 如果对象不存在，则尝试创建对象
    if object::exist_raw_object(&obj_id).is_err(){
        object::create_raw_object(&obj_id,&obj_buf)?;
    }
    else{ //对象存在，则写入相应内容
        object::write_raw_object(obj_id, obj_buf)?;
    }

    return Ok(());
}

// 删除密码(del_pwd)
pub fn del_password(obj_id: &[u8]) -> Result<()>{
    object::delete_object(obj_id)
}