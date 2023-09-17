use std::io::Write;

use plonk::{
    ark_bn254::{Bn254, Fr},
    ark_serialize::{CanonicalSerialize, SerializationError},
    prover::Prover,
    GeneralEvaluationDomain,
};
use prover::{
    circuit::openid::OpenIdCircuit,
    parameters::{load_params, load_prover_key, load_verifier_comms},
    types::ContractOpenIdInput,
    utils::to_0x_hex,
};
use rand::thread_rng;
use sha2::Digest;

pub fn prove(
    params_path: String,
    pk_path: String,
    vc_path: String,
    pepper: String,
    id_token_path: String,
    proof_path: String,
    public_input_path: String,
    contract_input_path: String,
) {
    let mut rng = thread_rng();
    let pckey = load_params(&params_path).unwrap();
    let sha256_of_srs = pckey.sha256_of_srs();

    let from_pepper = hex::decode(pepper).unwrap();
    let id_token = std::fs::read_to_string(&id_token_path).unwrap();
    let circuit = OpenIdCircuit::new(&id_token, &from_pepper);
    let mut cs = circuit.synthesize();

    let public_input = cs.compute_public_input();

    let id_token_hash = sha2::Sha256::digest(id_token).to_vec();
    let sub_peper_hash = sha2::Sha256::digest(&circuit.sub_pepper_bytes).to_vec();

    let pk = load_prover_key(&pk_path).unwrap();
    let vc = load_verifier_comms(&vc_path).unwrap();
    let mut prover = Prover::<Fr, GeneralEvaluationDomain<Fr>, Bn254>::new(pk);
    prover.insert_verifier_comms(&vc);

    let proof = prover.prove(&mut cs, &pckey, &mut rng).unwrap();

    // gen contract inputs data for test
    let contract_inputs = ContractOpenIdInput::new(
        circuit.header_raw_bytes,
        circuit.payload_pub_match,
        id_token_hash.clone(),
        sub_peper_hash,
        circuit.header_left_index,
        circuit.header_base64_len,
        circuit.payload_left_index,
        circuit.payload_base64_len,
        circuit.sub_left_index,
        circuit.sub_len,
        &public_input,
        prover.domain,
        &vc,
        pckey.vk.beta_h,
        &proof,
        &sha256_of_srs,
    );

    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&contract_input_path)
        .unwrap();
    file.write(&serde_json::to_vec_pretty(&contract_inputs).unwrap())
        .unwrap();
    file.flush().unwrap();

    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&proof_path)
        .unwrap();
    proof.serialize(&mut file).unwrap();
    file.flush().unwrap();

    let public_input: Vec<_> = public_input
        .into_iter()
        .map(|v| {
            let mut tmp = [0u8; 32];
            v.serialize(&mut tmp[..])?;
            Ok::<String, SerializationError>(to_0x_hex(tmp))
        })
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&public_input_path)
        .unwrap();
    file.write(&serde_json::to_vec_pretty(&public_input).unwrap())
        .unwrap();
    file.flush().unwrap();
}
