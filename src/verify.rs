use plonk::{
    ark_bn254::{Bn254, Fr},
    ark_serialize::CanonicalDeserialize,
    proof::Proof,
    prover::Prover,
    verifier::Verifier,
    GeneralEvaluationDomain,
};
use prover::{
    parameters::{load_params, load_prover_key, load_verifier_comms},
    utils::from_0x_hex,
};

pub fn verify_proof(
    params_path: String,
    pk_path: String,
    vc_path: String,
    proof_path: String,
    public_input_path: String,
) -> bool {
    let pckey = load_params(&params_path).unwrap();
    let sha256_of_srs = pckey.sha256_of_srs();

    let pk = load_prover_key(&pk_path).unwrap();
    let vc = load_verifier_comms(&vc_path).unwrap();
    let mut prover = Prover::<Fr, GeneralEvaluationDomain<Fr>, Bn254>::new(pk);
    prover.insert_verifier_comms(&vc);

    let public_input: Vec<_> = {
        let tmp = std::fs::read(&public_input_path).unwrap();
        let str_vec: Vec<String> = serde_json::from_slice(&tmp).unwrap();
        str_vec
            .into_iter()
            .map(|str| {
                let tmp = from_0x_hex(&str).unwrap();
                Fr::deserialize(&*tmp)
            })
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    };

    let proof = {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .open(&proof_path)
            .unwrap();
        Proof::<Fr, Bn254>::deserialize(file).unwrap()
    };

    let mut verifier = Verifier::new(&prover, &public_input, &vc);

    verifier.verify(&pckey.vk, &proof, &sha256_of_srs)
}
