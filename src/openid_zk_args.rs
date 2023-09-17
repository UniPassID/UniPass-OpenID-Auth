use std::io::Write;

use base64::Engine;
use ethers::abi::{Token, Tokenizable, Tokenize};
use plonk::{
    ark_bn254::{Bn254, Fr},
    prover::Prover,
    GeneralEvaluationDomain,
};
use prover::{
    circuit::openid::OpenIdCircuit,
    parameters::{load_params, load_prover_key, load_verifier_comms},
    utils::{convert_proof_array, convert_public_inputs_array, convert_vk_data_array, to_0x_hex},
};
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use sha2::Digest;

#[derive(Debug, Serialize, Deserialize)]
pub struct ZkConfigs {
    srs_hash: String,
    num_inputs: u64,
    domain_size: u128,
    vkdata: String,
}

pub fn openid_zk_args(
    params_path: String,
    pk_path: String,
    vc_path: String,
    pepper: String,
    id_token_path: String,
    output_path: String,
    zk_configs_path: String,
) {
    let mut rng = thread_rng();
    let from_pepper = hex::decode(pepper).unwrap();
    let id_token = std::fs::read_to_string(&id_token_path).unwrap();
    let circuit = OpenIdCircuit::new(&id_token, &from_pepper);

    let id_token_hash: [u8; 32] = sha2::Sha256::digest(&circuit.id_token_bytes)
        .try_into()
        .unwrap();
    let sub_peper_hash: [u8; 32] = sha2::Sha256::digest(&circuit.sub_pepper_bytes)
        .try_into()
        .unwrap();

    let mut cs = circuit.synthesize();
    let public_input = cs.compute_public_input();

    let pckey = load_params(&params_path).unwrap();
    let sha256_of_srs = pckey.sha256_of_srs();
    let pk = load_prover_key(&pk_path).unwrap();
    let vc = load_verifier_comms(&vc_path).unwrap();
    let mut prover = Prover::<Fr, GeneralEvaluationDomain<Fr>, Bn254>::new(pk);
    prover.insert_verifier_comms(&vc);

    let proof = prover.prove(&mut cs, &pckey, &mut rng).unwrap();

    let vk_data = convert_vk_data_array(prover.domain, &vc, pckey.vk.beta_h);
    let proof_data = convert_proof_array(&proof);
    let public_inputs = convert_public_inputs_array(&public_input);

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
        (circuit.header_base64_len as u32)
            .to_be_bytes()
            .into_token(),
        (circuit.payload_left_index as u32)
            .to_be_bytes()
            .into_token(),
        (circuit.payload_base64_len as u32)
            .to_be_bytes()
            .into_token(),
        (id_token_hash).into_token(),
        (sub_peper_hash).into_token(),
        (prover.domain_size() as u128).to_be_bytes().into_token(),
        (header.len() as u32).to_be_bytes().into_token(),
        Token::Bytes(header),
        (circuit.payload_pub_match.len() as u32)
            .to_be_bytes()
            .into_token(),
        Token::Bytes(circuit.payload_pub_match),
        (signature.len() as u32).to_be_bytes().into_token(),
        Token::Bytes(signature),
        (vk_data.len() as u32).to_be_bytes().into_token(),
        vk_data.clone().into_token(),
        (public_inputs.len() as u32).to_be_bytes().into_token(),
        public_inputs.into_token(),
        (proof_data.len() as u32).to_be_bytes().into_token(),
        proof_data.into_token(),
    ])
    .unwrap();

    let mut vk_data_bytes = (vk_data.len() as u32).to_be_bytes().to_vec();
    vk_data_bytes.extend_from_slice(
        &ethers::abi::encode_packed(vk_data.clone().into_tokens().as_ref()).unwrap(),
    );
    let zk_configs = ZkConfigs {
        srs_hash: to_0x_hex(sha256_of_srs),
        num_inputs: public_input.len() as u64,
        domain_size: prover.domain_size() as u128,
        vkdata: to_0x_hex(vk_data_bytes),
    };

    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&zk_configs_path)
        .unwrap();
    file.write(
        serde_json::to_string_pretty(&zk_configs)
            .unwrap()
            .as_bytes(),
    )
    .unwrap();
    file.flush().unwrap();

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
