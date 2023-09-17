use plonk::{
    ark_bn254::{Bn254, Fr},
    prover::Prover,
    GeneralEvaluationDomain,
};
use prover::{
    circuit::openid::OpenIdCircuit,
    parameters::{load_params, store_prover_key, store_verifier_comms},
};

pub fn gen_keys(params_path: String, id_token_path: String, pk_path: String, vc_path: String) {
    let pckey = load_params(&params_path).unwrap();
    let pepper = "03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4";
    let from_pepper = hex::decode(pepper).unwrap();
    let id_token = std::fs::read_to_string(&id_token_path).unwrap();
    let circuit = OpenIdCircuit::new(&id_token, &from_pepper);
    let mut cs = circuit.synthesize();

    let pk = cs
        .compute_prover_key::<GeneralEvaluationDomain<Fr>>()
        .unwrap();

    store_prover_key(&pk, &pk_path).unwrap();

    let mut prover = Prover::<Fr, GeneralEvaluationDomain<Fr>, Bn254>::new(pk);
    let verifier_comms = prover.init_comms(&pckey);
    store_verifier_comms(&verifier_comms, &vc_path).unwrap();
}
