use std::{u8, fmt};

use optee_utee::BigInt;

use optee_utee::{
     trace_println
};

use optee_utee::{Error, ErrorKind, Result};

use  super::gp_bigint;
use  super::dh_groups::DHGroupElement;

pub struct FFCElement<'a>{
    pub prime: BigInt,
    pub order: BigInt,
	group: DHGroupElement<'a>,
}   


//构造函数
impl<'a> FFCElement<'a>{
    pub fn new() -> Result< Self >{
		let group = DHGroupElement::default();
		let instance: FFCElement = FFCElement::new_from_group(group)?;
        Ok(instance)
	}
	
	pub fn new_from_group(group: DHGroupElement<'a>) -> Result< Self >{
        let prime = gp_bigint::bigint_construct_from_gpstr(group.prime_gp_array)?;
        let order = gp_bigint::bigint_construct_from_gpstr(group.order_gp_array)?;
        Ok(Self{prime,order,group})
    }

	pub fn set_group(self: &mut Self,value: u16) -> Result<()>{
		let new_group = match DHGroupElement::from(value){
			Some(group) => group,
			None => return Err(Error::new(ErrorKind::BadParameters)),
		};
		if new_group.code != self.group.code {
			let new_element = FFCElement::new_from_group(new_group.clone())?;
			trace_println!("Set group is {:?}" ,new_element.group.code);
			self.group = new_element.group;
			self.prime = new_element.prime;
			self.order = new_element.order;
		}
        Ok(())
    }


	pub fn is_safe_prime(self: &Self) -> bool{
        self.group.is_safe_prime
	}
	
	pub fn prime_gp_array(self: &Self) -> &[u8]{
        self.group.prime_gp_array
	}
	
	// pub fn order_gp_array(self: &Self) -> &[u8]{
    //     self.group.order_gp_array
    // }

    pub fn scalar_op(self: &Self,op_exp: &BigInt, op_base: &BigInt) -> Result<BigInt>{
        let rop = gp_bigint::bigint_expmod(&op_base, &op_exp, &self.prime)?;
        Ok(rop)
    }

    pub fn element_op(self: &Self,op1: &BigInt,op2: &BigInt) -> Result<BigInt>{
        let mul = BigInt::multiply(&op1,&op2);
        let (_,rop) = gp_bigint::bigint_div_rem(&mul,&self.prime)?;
        //let rop = BigInt::mul_mod(&op1,&op2,&self.prime);
        Ok(rop)
    }

    pub fn inverse_op(self: &Self,op: &BigInt) -> Result<BigInt>{
        let rop = BigInt::inv_mod(&op,&self.prime);
        Ok(rop)
    }
}

//显示函数
impl fmt::Display for FFCElement<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "prime : {} \n order : {}", self.prime,self.order)
    }
}

impl Default for FFCElement<'static> {
    fn default() -> FFCElement<'static> { 
        match FFCElement::new(){
            Ok(instance) => instance,
            Err(_) => {panic!("FFCElement default error");}
        }
    }
}

