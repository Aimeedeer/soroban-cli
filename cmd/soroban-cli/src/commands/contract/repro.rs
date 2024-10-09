use crate::{
    commands::{global, NetworkRunnable},
    config::{self, locator},
    repro_utils,
    rpc::{self, Client},
    utils, wasm,
};
use clap::{Parser, Subcommand};
use colored::*;
use soroban_env_host::xdr::{Hash, ScMetaEntry};
use std::{
    fmt::Debug,
    fs, io,
    path::{Path, PathBuf},
    process::{Command, ExitStatus},
};

const CONTRACT_REPRO_PATH: &str = "contract-repro";

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    CargoCmd(io::Error),
    #[error(transparent)]
    RustupCmd(io::Error),
    #[error(transparent)]
    GitCmd(io::Error),
    #[error(transparent)]
    CreatingDirectory(io::Error),
    #[error("Exit status {0}")]
    Exit(ExitStatus),
    #[error("Package {package} not found")]
    PackageNotFound { package: String },
    #[error("Reading WASM file: {0}")]
    ReadingWasmFile(io::Error),
    #[error("Writing WASM file: {0}")]
    WritingWasmFile(io::Error),
    #[error(transparent)]
    Wasm(#[from] wasm::Error),
    #[error(transparent)]
    CurrentDir(io::Error),
    #[error(transparent)]
    Utf8(std::str::Utf8Error),
    #[error(transparent)]
    Repro(#[from] repro_utils::Error),
    #[error("Git URL doesn't exist. Please provide corresponding source code path using `--repo <source_code_path>`")]
    GitUrlNotFound,
    #[error("Invalid git URL. Please provide the corresponding source code using `--repo <source_code_path>`")]
    InvalidGitUrl,
    #[error(transparent)]
    Rpc(#[from] rpc::Error),
    #[error(transparent)]
    Config(#[from] config::Error),
    #[error("Cannot parse contract ID {contract_id}: {error}")]
    CannotParseContractId {
        contract_id: String,
        error: locator::Error,
    },
    #[error("Cannot parse WASM hash {wasm_hash}: {error}")]
    CannotParseWasmHash {
        wasm_hash: String,
        error: stellar_strkey::DecodeError,
    },
    #[error("WASM build with unsupported nightly WASM toolchain. Not reproducible.")]
    Nightly,
}

#[derive(Parser, Debug, Clone)]
pub struct Cmd {
    #[command(subcommand)]
    wasm_src: CmdWasmSrc,
    /// Path to the source code
    #[arg(long)]
    repo: Option<String>,
}

#[derive(Subcommand, Debug, Clone)]
pub enum CmdWasmSrc {
    Contract(CmdContract),
    WasmHash(CmdWasmHash),
    WasmPath(CmdWasmPath),
}

#[derive(Parser, Debug, Clone)]
pub struct CmdContract {
    /// Contract ID to fetch
    #[arg(long = "id", env = "STELLAR_CONTRACT_ID")]
    contract_id: String,
    #[command(flatten)]
    config: config::Args,
}

#[derive(Parser, Debug, Clone)]
pub struct CmdWasmHash {
    /// Hash of the already deployed WASM file
    #[arg(long = "hash")]
    wasm_hash: String,
    #[command(flatten)]
    config: config::Args,
}

#[derive(Parser, Debug, Clone)]
pub struct CmdWasmPath {
    /// Path to the local WASM file
    #[arg(long = "path")]
    wasm_path: PathBuf,
}

#[derive(Debug, Default)]
struct ContractMetadata {
    rustc: Option<String>,
    target_dir: String,
    workspace_root: String,
    package_manifest_path: String,
    package_name: String,
    project_name: String,
    git_url: String,
    commit_hash: String,
    is_optimized: bool,
}

impl Cmd {
    pub async fn run(&self) -> Result<(), Error> {
        let current_dir = std::env::current_dir().map_err(Error::CurrentDir)?;
        let repro_dir = current_dir.join(CONTRACT_REPRO_PATH);

        fs::create_dir_all(&repro_dir).map_err(Error::CreatingDirectory)?;

        let wasm_path: PathBuf = match &self.wasm_src {
            CmdWasmSrc::Contract(wasm) => {
                let wasm_bytes = self.run_against_rpc_server(None, None).await?;
                let wasm_path =
                    repro_dir.join(format!("soroban-contract-{}.wasm", wasm.contract_id));
                fs::write(&wasm_path, wasm_bytes).map_err(Error::WritingWasmFile)?;
                wasm_path
            }
            CmdWasmSrc::WasmHash(wasm) => {
                let wasm_bytes = self.run_against_rpc_server(None, None).await?;
                let wasm_path = repro_dir.join(format!("soroban-contract-{}.wasm", wasm.wasm_hash));
                fs::write(&wasm_path, wasm_bytes).map_err(Error::WritingWasmFile)?;
                wasm_path
            }
            CmdWasmSrc::WasmPath(wasm) => wasm.wasm_path.to_path_buf(),
        };

        let metadata = load_contract_metadata(&wasm_path)?;

        // fixme error if no metadata.rustc

        if let Some(ref rustc) = metadata.rustc {
            if rustc.contains("nightly") {
                return Err(Error::Nightly);
            }
        }

        let wasm = wasm::Args { wasm: wasm_path };

        let work_dir_name = format!("{}-{}", &metadata.project_name, wasm.hash()?);

        let work_dir = repro_dir.join(work_dir_name);
        let mut git_dir = work_dir.join(&metadata.project_name);

        if let Some(repo_dir) = &self.repo {
            // fixme reexamine this logic
            if !repo_dir.contains(&metadata.project_name) {
                // fixme return error
                eprintln!(
                    "Can't find the project {} in path: {}. Please input the right repo path.",
                    metadata.project_name, repo_dir
                );
                return Ok(());
            }
            if let Some(dir) = repo_dir.split(&metadata.project_name).next() {
                git_dir = Path::new(&dir).join(&metadata.project_name);
            }
        } else {
            if metadata.git_url.is_empty() {
                // fixme embed git url
                return Err(Error::GitUrlNotFound);
            }

            if !is_git_url_valid(&metadata.git_url) {
                // fixme embed git url
                return Err(Error::InvalidGitUrl);
            }

            let mut git_cmd = Command::new("git");
            git_cmd.args(["clone", &metadata.git_url, &git_dir.to_string_lossy()]);
            git_cmd.status().map_err(Error::GitCmd)?;
            // fixme check exit code
        }

        let package_manifest_path = git_dir.join(&metadata.package_manifest_path);

        let mut git_cmd = Command::new("git");
        git_cmd.current_dir(&git_dir);
        git_cmd.args(["checkout", &metadata.commit_hash]);
        git_cmd.status().map_err(Error::GitCmd)?;
        // fixme check exit code

        if let Some(rustc) = &metadata.rustc {
            let mut rustup_cmd = Command::new("rustup");
            rustup_cmd.args(["toolchain", "install", rustc]);
            let status = rustup_cmd.status().map_err(Error::RustupCmd)?;
            if !status.success() {
                return Err(Error::Exit(status));
            }

            let mut rustup_cmd = Command::new("rustup");
            rustup_cmd.args(["target", "add", "wasm32-unknown-unknown"]);
            rustup_cmd.args(["--toolchain", rustc]);

            let status = rustup_cmd.status().map_err(Error::RustupCmd)?;
            if !status.success() {
                return Err(Error::Exit(status));
            }
        }

        let soroban_path = std::env::current_exe().unwrap();
        let mut soroban_cmd = Command::new(&soroban_path);
        soroban_cmd.args([
            "contract",
            "build",
            "--manifest-path",
            &package_manifest_path.to_string_lossy(),
            "--package",
            &metadata.package_name,
            "--out-dir",
            &repro_dir.to_string_lossy(),
        ]);

        if let Some(rustc) = &metadata.rustc {
            soroban_cmd.env("RUSTUP_TOOLCHAIN", rustc);
        }

        let status = soroban_cmd.status().map_err(Error::CargoCmd)?;
        if !status.success() {
            return Err(Error::Exit(status));
        }

        let file_name = format!("{}.wasm", metadata.package_name.replace('-', "_"));
        let mut new_wasm = repro_dir.join(&file_name);

        if metadata.is_optimized {
            let mut wasm_out = repro_dir.join(&file_name);
            wasm_out.set_extension("optimized.wasm");

            let mut soroban_cmd = Command::new(&soroban_path);
            soroban_cmd.args([
                "contract",
                "optimize",
                "--wasm",
                &new_wasm.to_string_lossy(),
                "--wasm-out",
                &wasm_out.to_string_lossy(),
            ]);

            let status = soroban_cmd.status().map_err(Error::CargoCmd)?;
            if !status.success() {
                return Err(Error::Exit(status));
            }

            new_wasm = wasm_out;
        }

        let pre_buf = wasm.read()?;
        let new_buf = fs::read(new_wasm).map_err(Error::ReadingWasmFile)?;

        let pre_buf_len = pre_buf.len();
        let new_buf_len = new_buf.len();
        if pre_buf_len != new_buf_len {
            eprintln!(
                "{}",
                format!(
                    "They are different! Size diff: {}",
                    pre_buf_len.abs_diff(new_buf_len)
                )
                .red()
                .bold()
            );
            // fixme return error
            return Ok(());
        }

        let num = pre_buf
            .iter()
            .zip(new_buf.iter())
            .filter(|(a, b)| a != b)
            .count();
        if num > 0 {
            eprintln!(
                "{}",
                format!("They are different! Bytes diff: {}", num)
                    .red()
                    .bold()
            );
            // fixme return error
        } else {
            eprintln!("{}", "They are the same!".green().bold());
        }

        Ok(())
    }
}

// fixme move to repro_utils
fn load_contract_metadata(wasm: &PathBuf) -> Result<ContractMetadata, Error> {
    let metadata = repro_utils::read_wasm_contractmeta_file(wasm)?;

    let mut contract_metadata = ContractMetadata::default();
    metadata.iter().for_each(
        |ScMetaEntry::ScMetaV0(data)| match data.key.to_string().as_str() {
            "target_dir" => contract_metadata.target_dir = data.val.to_string(),
            "workspace_root" => contract_metadata.workspace_root = data.val.to_string(),
            "package_manifest_path" => {
                contract_metadata.package_manifest_path = data.val.to_string()
            }
            "package_name" => contract_metadata.package_name = data.val.to_string(),
            "project_name" => contract_metadata.project_name = data.val.to_string(),
            "git_url" => contract_metadata.git_url = data.val.to_string(),
            "commit_hash" => contract_metadata.commit_hash = data.val.to_string(),
            "rsver" => contract_metadata.rustc = Some(data.val.to_string()),
            "wasm_opt" => {
                contract_metadata.is_optimized = match data.val.to_string().as_str() {
                    "true" => true,
                    _ => false,
                }
            }
            _ => {}
        },
    );

    Ok(contract_metadata)
}

// fixme return error with error message, rename `validate_git_url`
fn is_git_url_valid(git_url: &str) -> bool {
    let mut git_cmd = Command::new("git");
    git_cmd.args(["ls-remote", git_url]);
    git_cmd.env("GIT_TERMINAL_PROMPT", "0");

    let mut is_valid = false;

    let output = git_cmd.output();
    match output {
        Ok(output) => {
            if output.status.success() {
                is_valid = true;
            } else {
                let stderr = std::str::from_utf8(&output.stderr).unwrap_or("");
                eprintln!("Failed to access the repository: {}", stderr);
            }
        }
        Err(e) => {
            eprintln!("Failed to execute git command: {}", e);
        }
    }

    is_valid
}

#[async_trait::async_trait]
impl NetworkRunnable for Cmd {
    type Error = Error;
    type Result = Vec<u8>;

    async fn run_against_rpc_server(
        &self,
        _global_args: Option<&global::Args>,
        config: Option<&config::Args>,
    ) -> Result<Vec<u8>, Error> {
        match &self.wasm_src {
            CmdWasmSrc::Contract(wasm) => {
                let config = config.unwrap_or(&wasm.config);
                let network = config.get_network().map_err(Error::Config)?;
                let client = Client::new(&network.rpc_url).map_err(Error::Rpc)?;
                client
                    .verify_network_passphrase(Some(&network.network_passphrase))
                    .await?;

                let contract_id = config
                    .locator
                    .resolve_contract_id(&wasm.contract_id, &network.network_passphrase)
                    .map_err(|e| Error::CannotParseContractId {
                        contract_id: wasm.contract_id.clone(),
                        error: e,
                    })?
                    .0;

                Ok(client.get_remote_wasm(&contract_id).await?)
            }
            CmdWasmSrc::WasmHash(wasm) => {
                let config = config.unwrap_or(&wasm.config);
                let network = config.get_network().map_err(Error::Config)?;
                let client = Client::new(&network.rpc_url).map_err(Error::Rpc)?;
                client
                    .verify_network_passphrase(Some(&network.network_passphrase))
                    .await?;

                let wasm_hash = Hash(
                    utils::contract_id_from_str(&wasm.wasm_hash)
                        .map_err(|e| Error::CannotParseWasmHash {
                            wasm_hash: wasm.wasm_hash.clone(),
                            error: e,
                        })?
                        .0,
                );

                Ok(client.get_remote_wasm_from_hash(wasm_hash).await?)
            }
            _ => unreachable!(),
        }
    }
}
