pub enum Command {
    SetPassword,
    InitPWE,
    ComputeSharedSecret,
    ConfirmExchange,
    GeneRandom,
    Unknown,
}

impl From<u32> for Command {
    #[inline]
    fn from(value: u32) -> Command {
        match value {
            0 => Command::SetPassword,
            1 => Command::InitPWE,
            2 => Command::ComputeSharedSecret,
            3 => Command::ConfirmExchange,
            4 => Command::GeneRandom,
            _ => Command::Unknown,
        }
    }
}

pub const UUID: &str = &include_str!(concat!(env!("OUT_DIR"), "/uuid.txt"));

use serde::{Serialize, Deserialize};
pub use serde_json;

#[derive(Serialize, Deserialize, Debug)]
pub struct Password {
    pub pw: Vec::<u8>
}


#[derive(Serialize, Deserialize, Debug)]
pub struct Randoms {
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
pub struct GeneRandomReq {
    pub rand_bytes: usize
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GeneRandomRes {
    pub rand: Vec::<u8>
}

