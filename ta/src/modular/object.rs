use optee_utee::{DataFlag, ObjectStorageConstants, PersistentObject};
use optee_utee::{Error, ErrorKind, Result};

pub fn delete_object(obj_id: &mut [u8]) -> Result<()> {

    match PersistentObject::open(
        ObjectStorageConstants::Private,
        obj_id,
        DataFlag::ACCESS_READ | DataFlag::ACCESS_WRITE_META,
    ) {
        Err(e) => {
            return Err(e);
        }

        Ok(mut object) => {
            object.close_and_delete()?;
            std::mem::forget(object);
            return Ok(());
        }
    }
}

pub fn create_raw_object(obj_id: &mut [u8],obj_buf: &mut [u8]) -> Result<()> {

    let obj_data_flag = DataFlag::ACCESS_READ
        | DataFlag::ACCESS_WRITE
        | DataFlag::ACCESS_WRITE_META
        | DataFlag::OVERWRITE;

    let mut init_data: [u8; 0] = [0; 0];
    match PersistentObject::create(
        ObjectStorageConstants::Private,
        obj_id,
        obj_data_flag,
        None,
        &mut init_data,
    ) {
        Err(e) => {
            return Err(e);
        }

        Ok(mut object) => match object.write(obj_buf) {
            Ok(()) => {
                return Ok(());
            }
            Err(e_write) => {
                object.close_and_delete()?;
                std::mem::forget(object);
                return Err(e_write);
            }
        },
    }
}

pub fn read_raw_object(obj_id: &mut [u8],obj_buf: &mut [u8]) -> Result<u32> {
    
    match PersistentObject::open(
        ObjectStorageConstants::Private,
        obj_id,
        DataFlag::ACCESS_READ | DataFlag::SHARE_READ,
    ) {
        Err(e) => return Err(e),

        Ok(object) => {
            let obj_info = object.info()?;

            if obj_info.data_size() > obj_buf.len() {
                return Err(Error::new(ErrorKind::ShortBuffer));
            }

            let read_bytes = object.read(obj_buf).unwrap();

            if read_bytes != obj_info.data_size() as u32 {
                return Err(Error::new(ErrorKind::ExcessData));
            }

            Ok(read_bytes)
        }
    }
}

pub fn exist_raw_object(obj_id: &mut [u8]) -> Result<()> {
    
    match PersistentObject::open(
        ObjectStorageConstants::Private,
        obj_id,
        DataFlag::ACCESS_READ | DataFlag::SHARE_READ,
    ) {
        Ok(_) => Ok(()),
        Err(e) => Err(e),
    }
}