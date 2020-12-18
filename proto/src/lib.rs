pub enum Command {
    InitMemUserPassword,
    ComputeCommitElement,
    ComputeConfirmElement,
    ConfirmExchange,
    GeneRandom,
    LoadDevUserPassword,
    InitNamedGroup,
    Unknown,
}

impl From<u32> for Command {
    #[inline]
    fn from(value: u32) -> Command {
        match value {
            0 => Command::InitMemUserPassword,
            1 => Command::ComputeCommitElement,
            2 => Command::ComputeConfirmElement,
            3 => Command::ConfirmExchange,
            4 => Command::GeneRandom,
            5 => Command::LoadDevUserPassword,
            6 => Command::InitNamedGroup,
            _ => Command::Unknown,
        }
    }
}

pub const UUID: &str = &include_str!(concat!(env!("OUT_DIR"), "/uuid.txt"));

use serde::{Serialize, Deserialize};
pub use serde_json;

#[derive(Serialize, Deserialize, Debug)]
pub struct InitMemUserPasswordReq {
    pub pwd_name: Vec::<u8>,
    pub pw: Vec::<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LoadDevUserPasswordReq {
    pub pwd_name: Vec::<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct InitNamedGroupReq {
    pub group_code: u16,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SessionRandoms {
    pub client_random: Vec::<u8>,
    pub server_random: Vec::<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CommitElement {
    pub scalar: Vec::<u8>,
    pub element: Vec::<u8>,
}


#[derive(Serialize, Deserialize, Debug)]
pub struct Token {
    pub token: Vec::<u8>
}

#[derive(Serialize, Deserialize, Debug)]
pub struct HandshakePMK {
    pub pmk: Vec::<u8>,
    pub is_confirm: bool,
}



#[derive(Serialize, Deserialize, Debug)]
pub struct GeneRandomReq {
    pub rand_bytes: usize
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GeneRandomRes {
    pub rand: Vec::<u8>
}

