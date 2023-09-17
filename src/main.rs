use clap::{Parser, Subcommand};

use gen_keys::gen_keys;
use gen_params::gen_params;
use openid_args::openid_args;
use openid_zk_args::openid_zk_args;
use prove::prove;
use verify::verify_proof;

mod gen_keys;
mod gen_params;
mod openid_args;
mod openid_zk_args;
mod prove;
mod verify;

#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand, Clone)]
enum Commands {
    /// Generate a setup parameter (not for production).
    GenParams {
        /// k parameter for the one email verification circuit.
        #[arg(long, default_value = "21")]
        k: u32,
        /// setup parameters path
        #[arg(short, long, default_value = "./build/params.bin")]
        params_path: String,
    },
    /// Generate proving keys and verifying keys.
    GenKeys {
        /// setup parameters path
        #[arg(short, long, default_value = "./build/params.bin")]
        params_path: String,

        /// emails path
        #[arg(short, long, default_value = "./build/id_token.txt")]
        id_token_path: String,
        /// proving key path
        #[arg(long, default_value = "./build/app.pk")]
        pk_path: String,
        /// verifying key file
        #[arg(long, default_value = "./build/app.vc")]
        vc_path: String,
    },
    Prove {
        /// setup parameters path
        #[arg(short, long, default_value = "./build/params.bin")]
        params_path: String,
        /// proving key path
        #[arg(long, default_value = "./build/app.pk")]
        pk_path: String,
        #[arg(long, default_value = "./build/app.vc")]
        vc_path: String,
        #[arg(
            long,
            default_value = "03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4"
        )]
        pepper: String,
        /// emails path
        #[arg(short, long, default_value = "./build/id_token.txt")]
        id_token_path: String,
        /// output proof file
        #[arg(long, default_value = "./build/app.proof")]
        proof_path: String,
        /// output proof file
        #[arg(long, default_value = "./build/public_input.json")]
        public_input_path: String,
        /// output proof file
        #[arg(long, default_value = "./build/contract_input.json")]
        contract_input_path: String,
    },
    Verify {
        /// setup parameters path
        #[arg(short, long, default_value = "./build/params.bin")]
        params_path: String,
        /// proving key path
        #[arg(long, default_value = "./build/app.pk")]
        pk_path: String,
        /// verifying key file
        #[arg(long, default_value = "./build/app.vc")]
        vc_path: String,
        /// output proof file
        #[arg(long, default_value = "./build/app.proof")]
        proof_path: String,
        /// output proof file
        #[arg(long, default_value = "./build/public_input.json")]
        public_input_path: String,
    },
    OpenIdArgs {
        /// emails path
        #[arg(short, long, default_value = "./build/id_token.txt")]
        id_token_path: String,
        /// emails path
        #[arg(short, long, default_value = "./build/id_token.output")]
        output_path: String,
    },
    OpenIdZKArgs {
        /// setup parameters path
        #[arg(short, long, default_value = "./build/params.bin")]
        params_path: String,
        /// proving key path
        #[arg(long, default_value = "./build/app.pk")]
        pk_path: String,
        #[arg(long, default_value = "./build/app.vc")]
        vc_path: String,
        #[arg(
            long,
            default_value = "03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4"
        )]
        pepper: String,
        /// emails path
        #[arg(short, long, default_value = "./build/id_token.txt")]
        id_token_path: String,
        /// emails path
        #[arg(short, long, default_value = "./build/id_token_zk.output")]
        output_path: String,
        #[arg(short, long, default_value = "./build/zkConfigs.json")]
        zk_configs_path: String,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::GenParams { k, params_path } => gen_params(k, params_path),
        Commands::GenKeys {
            params_path,
            id_token_path,
            pk_path,
            vc_path,
        } => gen_keys(params_path, id_token_path, pk_path, vc_path),
        Commands::Prove {
            params_path,
            pk_path,
            vc_path,
            pepper,
            id_token_path,
            proof_path,
            public_input_path,
            contract_input_path,
        } => prove(
            params_path,
            pk_path,
            vc_path,
            pepper,
            id_token_path,
            proof_path,
            public_input_path,
            contract_input_path,
        ),
        Commands::Verify {
            params_path,
            pk_path,
            vc_path,
            proof_path,
            public_input_path,
        } => {
            let ok = verify_proof(params_path, pk_path, vc_path, proof_path, public_input_path);
            if ok {
                println!("Verify success");
            } else {
                println!("Verify failed");
            }
        }
        Commands::OpenIdArgs {
            id_token_path,
            output_path,
        } => openid_args(id_token_path, output_path),
        Commands::OpenIdZKArgs {
            params_path,
            pk_path,
            vc_path,
            pepper,
            id_token_path,
            output_path,
            zk_configs_path,
        } => openid_zk_args(
            params_path,
            pk_path,
            vc_path,
            pepper,
            id_token_path,
            output_path,
            zk_configs_path,
        ),
    }
}
