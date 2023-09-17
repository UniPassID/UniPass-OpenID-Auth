use plonk::ark_bn254::Bn254;
use prover::parameters::{prepare_generic_params, store_params};
use rand::thread_rng;

pub fn gen_params(k: u32, params_path: String) {
    let mut rng = thread_rng();
    let n: usize = 1 << k;
    // prepare SRS
    let pckey = prepare_generic_params::<Bn254>(n, &mut rng);
    store_params(&pckey, &params_path).unwrap();
}
