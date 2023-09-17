use std::io::Write;

use base64::Engine;
use ethers::abi::{Token, Tokenizable};
use prover::utils::to_0x_hex;

pub fn openid_args(id_token_path: String, output_path: String) {
    let id_token = std::fs::read_to_string(&id_token_path).unwrap();
    let id_toeken_split: Vec<_> = id_token.split(".").collect();
    if id_toeken_split.len() != 3 {
        panic!("invalid id_token")
    }
    let base64url_engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let header = base64url_engine
        .decode(id_toeken_split[0].as_bytes())
        .unwrap();
    let payload = base64url_engine
        .decode(id_toeken_split[1].as_bytes())
        .unwrap();
    let signature = base64url_engine
        .decode(id_toeken_split[2].as_bytes())
        .unwrap();

    let field_end_value = r#"","#.as_bytes();
    let obj_end_value = r#""}"#.as_bytes();

    let iss_left_index = index_of_sub_array(&payload, r#""iss":""#.as_bytes(), 0).unwrap() + 7;
    let iss_right_index = match index_of_sub_array(&payload, field_end_value, iss_left_index) {
        Some(iss_right_index) => iss_right_index,
        None => index_of_sub_array(&payload, obj_end_value, iss_left_index).unwrap(),
    };

    let kid_left_index = index_of_sub_array(&header, r#""kid":""#.as_bytes(), 0).unwrap() + 7;
    let kid_right_index = match index_of_sub_array(&header, field_end_value, kid_left_index) {
        Some(kid_right_index) => kid_right_index,
        None => index_of_sub_array(&header, obj_end_value, kid_left_index).unwrap(),
    };

    let iat_left_index = index_of_sub_array(&payload, r#""iat":"#.as_bytes(), 0).unwrap() + 6;
    let exp_left_index = index_of_sub_array(&payload, r#""exp":"#.as_bytes(), 0).unwrap() + 6;

    let sub_left_index = index_of_sub_array(&payload, r#""sub":""#.as_bytes(), 0).unwrap() + 7;
    let sub_right_index = match index_of_sub_array(&payload, field_end_value, sub_left_index) {
        Some(sub_right_index) => sub_right_index,
        None => index_of_sub_array(&payload, obj_end_value, sub_left_index).unwrap(),
    };

    let aud_left_index = index_of_sub_array(&payload, r#""aud":""#.as_bytes(), 0).unwrap() + 7;
    let aud_right_index = match index_of_sub_array(&payload, field_end_value, aud_left_index) {
        Some(aud_right_index) => aud_right_index,
        None => index_of_sub_array(&payload, obj_end_value, aud_left_index).unwrap(),
    };

    let nonce_left_index = index_of_sub_array(&payload, r#""nonce":""#.as_bytes(), 0).unwrap() + 9;

    let data = ethers::abi::encode_packed(&[
        (iss_left_index as u32).to_be_bytes().into_token(),
        (iss_right_index as u32).to_be_bytes().into_token(),
        (kid_left_index as u32).to_be_bytes().into_token(),
        (kid_right_index as u32).to_be_bytes().into_token(),
        (sub_left_index as u32).to_be_bytes().into_token(),
        (sub_right_index as u32).to_be_bytes().into_token(),
        (aud_left_index as u32).to_be_bytes().into_token(),
        (aud_right_index as u32).to_be_bytes().into_token(),
        (nonce_left_index as u32).to_be_bytes().into_token(),
        (iat_left_index as u32).to_be_bytes().into_token(),
        (exp_left_index as u32).to_be_bytes().into_token(),
        (header.len() as u32).to_be_bytes().into_token(),
        Token::Bytes(header),
        (payload.len() as u32).to_be_bytes().into_token(),
        Token::Bytes(payload),
        (signature.len() as u32).to_be_bytes().into_token(),
        Token::Bytes(signature),
    ])
    .unwrap();

    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&output_path)
        .unwrap();
    file.write(to_0x_hex(data).as_bytes()).unwrap();
    file.flush().unwrap();
}

fn index_of_sub_array(array: &[u8], sub_array: &[u8], start: usize) -> Option<usize> {
    if sub_array.is_empty() {
        return None;
    }
    array[start..]
        .windows(sub_array.len())
        .position(|window| window == sub_array)
        .map(|v| v + start)
}

#[test]
fn test_pk() {
    let base64url_engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let a = base64url_engine.decode("lWXY0XOj_ikSIDIvGOhfuRhQJAAj6BWsbbZ6P-PXRclzV32-QLB4GZHPPcH37Lou5pQsTQPvTETAfCLnglIRSbP8x1zA5tUakRlm5RiGF4kcWh5k60x8u0Uslx-d6EueKuY-KLHUVDuMULlHkYAScIdYnXz-Cnr6PFZj8RQezzdPVPH53Q8a_Z9b-vpGzsMS5gszITb-72OQNokojXdPVctl5WzSx-JnWbJxPiwHx_dSWgmTnyiYrZLqrqfampGdroaamtIXy0W8CAe0uCqcD1LunpfX-Q-RD1IycxnEaXSuUKhNhCcxtHWrozEyeD23Zja2WlcvHdYuTzyrvrvS9Q").unwrap();
    println!("{}", to_0x_hex(a));
}
