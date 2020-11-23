use optee_utee::{BigInt,BigIntFMMContext,BigIntFMM};
use optee_utee::{Error,ErrorKind,Result};
use std::{u8,u32};
use std::cmp::Ordering::{self, Equal, Greater, Less};
use std::iter::repeat;


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
    

    // bigint_normalize(&mut result);

    // let mut result : BigInt = bigint_construct_from_s32(1);
    // let mut base_pow_i = bigint_assign(base);
    
    // for i in 0..exp.get_bit_count(){
    //     if exp.get_bit(i) {
            
    //         let mut mul = BigInt::multiply(&result,&base_pow_i);
    //         bigint_normalize(&mut mul);
    //         // let ( _ , rem) = bigint_div_rem(&mul,&modular)?;
    //         let rem = BigInt::module(&mul,&modular);
    //         result = rem;
    //         //result = bigint_assign(&rem);
    //         bigint_normalize(&mut result);
           
    //         // result = BigInt::mul_mod(&result,&base_pow_i,&modular);
    //         // bigint_normalize(&mut result);
    //     }
        
    //     let mut mul = BigInt::multiply(&base_pow_i,&base_pow_i);
    //     bigint_normalize(&mut mul);
    //     // let ( _ , rem) = bigint_div_rem(&mul,&modular)?;
    //     let rem = BigInt::module(&mul,&modular);
    //     base_pow_i = rem;
    //     bigint_normalize(&mut base_pow_i);
        

    //     // result = BigInt::mul_mod(&base_pow_i,&base_pow_i,&modular);
    //     // bigint_normalize(&mut result);
        
    // }
    Ok(result)
}



pub type  BigDigit = u32;
pub type  DoubleBigDigit = u64;
// pub type  BigIntData = Vec<BigDigit>;
pub const BITS: usize = 32;
pub type SignedDoubleBigDigit = i64;

/// Returns a normalized `BigInt.data` .

pub fn bigint_normalize(op :&mut BigInt) {
    
    if op.data.len() <= 2{
        return;
    }
    
    while let Some(&0) = op.data.last(){
        op.data.pop();
        if op.data.len() == 2{
            break;
        }
       
    }
    
    if op.data.len() == 2{
       op.data.push(0);
    }
    

    let len:u32 = op.data.len() as u32 - 2;
    let gp_int_len : u32 =  (len<< 16) + len;
    op.data[1] = gp_int_len;
}




pub fn bigint_div_rem(u: &BigInt, d: &BigInt) -> Result<(BigInt, BigInt)> {

    let zero = &bigint_construct_from_s32(0);
    if BigInt::compare_big_int(d,zero) == 0{
        return Err( Error::new(ErrorKind::BadParameters));
    }
    if BigInt::compare_big_int(u,zero) == 0{
        return Ok( (bigint_assign(zero), bigint_assign(zero)) );
    }

    

    //被除数与除数之间比较
    // Required or the q_len calculation below can underflow:
    let v = BigInt::compare_big_int(u,d);
     if v < 0 {
        return Ok( (bigint_assign(zero), bigint_assign(u)) );
    }
    else if v == 0 {
        return Ok( (bigint_construct_from_s32(1), bigint_assign(zero)) );
    }
    else{} // Do nothing

    // This algorithm is from Knuth, TAOCP vol 2 section 4.3, algorithm D:
    //
    // First, normalize the arguments so the highest bit in the highest digit of the divisor is
    // set: the main loop uses the highest digit of the divisor for generating guesses, so we
    // want it to be the largest number we can efficiently divide by.
    //
    //获取大整数的前导零
    let shift_bit = d.data.last().unwrap().leading_zeros() as usize;
    
    let (q, r) = if shift_bit == 0 {
        // no need to clone d
        div_rem_core(u, d)?
    } else {
        let shift_u = bigint_shl(u, shift_bit);
        let shift_d = bigint_shl(d, shift_bit);
        let (q,r) = div_rem_core(&shift_u,&shift_d)?;
        let mut shift_r = bigint_assign(&r);
        BigInt::shift_right(&mut shift_r,&r,shift_bit);
        bigint_normalize(&mut shift_r);
        (q,shift_r)
    };
    // renormalize the remainder
    Ok((q, r))
}





pub fn div_rem_core(a: &BigInt, b: &BigInt) -> Result<(BigInt, BigInt)> {
    // The algorithm works by incrementally calculating "guesses", q0, for part of the
    // remainder. Once we have any number q0 such that q0 * b <= a, we can set
    //
    //     q += q0
    //     a -= q0 * b
    //
    // and then iterate until a < b. Then, (q, a) will be our desired quotient and remainder.
    //
    // q0, our guess, is calculated by dividing the last few digits of a by the last digit of b
    // - this should give us a guess that is "close" to the actual quotient, but is possibly
    // greater than the actual quotient. If q0 * b > a, we simply use iterated subtraction
    // until we have a guess such that q0 * b <= a.
    //

    // 除数最高位数据为bn
    let bn = *b.data.last().unwrap();
    // 商的位数
    let q_len = a.data.len() - b.data.len() + 1;
    // 商初始化
    //let mut q = bigint_construct_from_s32(0);
    let mut q = BigInt {
        data: vec![0; q_len + 2],
    };
    q.data[0] = 1;

    // 余数初始化
    let mut r = bigint_assign(&a);
    

    // We reuse the same temporary to avoid hitting the allocator in our inner loop - this is
    // sized to hold a0 (in the common case; if a particular digit of the quotient is zero a0
    // can be bigger).
    //

    let mut tmp = BigInt {
        data: vec![0; 2],
    };
    tmp.data[0] = 1;
    

    for j in (0..q_len).rev() {
        /*
         * When calculating our next guess q0, we don't need to consider the digits below j
         * + b.data.len() - 1: we're guessing digit j of the quotient (i.e. q0 << j) from
         * digit bn of the divisor (i.e. bn << (b.data.len() - 1) - so the product of those
         * two numbers will be zero in all digits up to (j + b.data.len() - 1).
         */

        //获取偏移量
        
        let offset = j + b.data.len() - 1;
        if offset >= r.data.len() {
            continue;
        }
    
        
        /* just avoiding a heap allocation: */
        // 拷贝部分数据
        let mut r0 = tmp;
        r0.data.truncate(2);
        r0.data.extend(r.data[offset..].iter().cloned());
        bigint_normalize(&mut r0);
        
        /*
         * q0 << j * big_digit::BITS is our actual quotient estimate - we do the shifts
         * implicitly at the end, when adding and subtracting to a and q. Not only do we
         * save the cost of the shifts, the rest of the arithmetic gets to work with
         * smaller numbers.
         */
        //trace_println!("r0:{},bn:{:x}", r0, bn);

        //q0 = r0 / bn
        let (mut q0, _ ) = div_rem_digit(&r0, bn);
        //prod= q0 * b 
        let mut prod = BigInt::multiply(&b,&q0);
        bigint_normalize(&mut q0);
        bigint_normalize(&mut prod);

        //不断迭代，直至prod < r
        while cmp_slice(&prod.data[2..], &r.data[2 + j..]) == Greater {
            let one = bigint_construct_from_s32(1);
            //q0 = q0 - 1
            q0 = BigInt::sub(&q0,&one);
            //prod = prod - b
            prod =  BigInt::sub(&prod,&b);
            
            bigint_normalize(&mut q0);
            bigint_normalize(&mut prod);
            // trace_println!("q0: {:x?}", q0.data);
            // trace_println!("prod: {:x?}", prod.data); 
        }
        
        //q = q + q0
        //q =  BigInt::add(&q,&q0);
        add2(&mut q.data[2 + j..], &q0.data[2..]);

        //r = r - (q0 * b)
        //r = BigInt::sub(&r,&prod);
        sub2(&mut r.data[2 + j..], &prod.data[2..]);
        
        bigint_normalize(&mut r);
        tmp = q0;      
    }
   
   // debug_assert!(&r.compare_big_int(&b));
    bigint_normalize(&mut q);
    Ok((q, r))
}

// Add with carry:
#[inline]
fn adc(a: BigDigit, b: BigDigit, acc: &mut DoubleBigDigit) -> BigDigit {
    *acc += DoubleBigDigit::from(a);
    *acc += DoubleBigDigit::from(b);
    let lo = *acc as BigDigit;
    *acc >>= BITS;
    lo
}

// Subtract with borrow:
#[inline]
fn sbb(a: BigDigit, b: BigDigit, acc: &mut SignedDoubleBigDigit) -> BigDigit {
    *acc += SignedDoubleBigDigit::from(a);
    *acc -= SignedDoubleBigDigit::from(b);
    let lo = *acc as BigDigit;
    *acc >>= BITS;
    lo
}


pub fn __add2(a: &mut [BigDigit], b: &[BigDigit]) -> BigDigit {
    debug_assert!(a.len() >= b.len());

    let mut carry = 0;
    let (a_lo, a_hi) = a.split_at_mut(b.len());

    for (a, b) in a_lo.iter_mut().zip(b) {
        *a = adc(*a, *b, &mut carry);
    }

    if carry != 0 {
        for a in a_hi {
            *a = adc(*a, 0, &mut carry);
            if carry == 0 {
                break;
            }
        }
    }

    carry as BigDigit
}

/// Two argument addition of raw slices:
/// a += b
///
/// The caller _must_ ensure that a is big enough to store the result - typically this means
/// resizing a to max(a.len(), b.len()) + 1, to fit a possible carry.
pub fn add2(a: &mut [BigDigit], b: &[BigDigit]) {
    let carry = __add2(a, b);

    debug_assert!(carry == 0);
}

pub fn sub2(a: &mut [BigDigit], b: &[BigDigit]) {
    let mut borrow = 0;

    let len = std::cmp::min(a.len(), b.len());
    let (a_lo, a_hi) = a.split_at_mut(len);
    let (b_lo, b_hi) = b.split_at(len);

    for (a, b) in a_lo.iter_mut().zip(b_lo) {
        *a = sbb(*a, *b, &mut borrow);
    }

    if borrow != 0 {
        for a in a_hi {
            *a = sbb(*a, 0, &mut borrow);
            if borrow == 0 {
                break;
            }
        }
    }

    // note: we're _required_ to fail on underflow
    assert!(
        borrow == 0 && b_hi.iter().all(|x| *x == 0),
        "Cannot subtract b from a because b is larger than a."
    );
}


pub fn bigint_shl(src: &BigInt, bits: usize) -> BigInt {
    
    let n_unit = bits / BITS;
    let mut data = match n_unit {
        0 => src.data.clone(),
        _ => {
            let len = n_unit + src.data.len() + 1;
            let mut data = Vec::with_capacity(len);
            
            data.extend(src.data[0..2].iter().cloned());
            data.extend(repeat(0).take(n_unit));
            data.extend(src.data[2..].iter().cloned());
            data
        }
    };

    let n_bits = bits % BITS;
    if n_bits > 0 {
        let mut carry = 0;
        for elem in data[2 + n_unit..].iter_mut() {
            let new_carry = *elem>>(BITS - n_bits);
            *elem = (*elem<<n_bits) | carry;
            carry = new_carry;
        }
        if carry != 0 {
            data.push(carry);
        }
    }

    BigInt{data}
}




pub fn div_rem_digit(a: &BigInt, b: BigDigit) -> (BigInt, BigDigit) {
    let mut quot = BigInt{data:a.data.clone()};
    let mut rem = 0;

    for d in quot.data[2..].iter_mut().rev() {
        let (q, r) = div_wide(rem, *d, b);
        *d = q;
        rem = r;
        // trace_println!("d = {:x} , b = {:x}, q = {:x}, r = {:x}", *d, b, q, r);
    }
    bigint_normalize(&mut quot);
    (quot , rem)
}


fn div_wide(hi: BigDigit, lo: BigDigit, divisor: BigDigit) -> (BigDigit, BigDigit) {
    debug_assert!(hi < divisor);

    let lhs = bigdigit_to_doublebigdigit(hi, lo);
    let rhs = DoubleBigDigit::from(divisor);
    ((lhs / rhs) as BigDigit, (lhs % rhs) as BigDigit)
}

fn bigdigit_to_doublebigdigit(hi: BigDigit, lo: BigDigit) -> DoubleBigDigit {
        DoubleBigDigit::from(lo) | (DoubleBigDigit::from(hi)<<32)
}



pub fn cmp_slice(a: &[BigDigit], b: &[BigDigit]) -> Ordering {
    debug_assert!(a.last() != Some(&0));
    debug_assert!(b.last() != Some(&0));

    let (a_len, b_len) = (a.len(), b.len());
    if a_len < b_len {
        return Less;
    }
    if a_len > b_len {
        return Greater;
    }

    for (&ai, &bi) in a.iter().rev().zip(b.iter().rev()) {
        if ai < bi {
            return Less;
        }
        if ai > bi {
            return Greater;
        }
    }
    return Equal;
}