use crate::{
    commands::{global, NetworkRunnable},
    config::{self, locator},
    repro_utils,
    rpc::{self, Client},
    utils, wasm,
};
use clap::{Parser, Subcommand};
use colored::*;
use itertools::Itertools;
use regex::Regex;
use soroban_env_host::xdr::Hash;
use std::{
    ffi::OsStr,
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
    #[error("Exited with status code: {code}")]
    GitCmdStatus { code: i32 },
    #[error("Process terminated by signal: {git_cmd}.")]
    GitCmdTerminated { git_cmd: String },
    #[error(transparent)]
    CreatingDirectory(io::Error),
    #[error("Exit status {0}.")]
    Exit(ExitStatus),
    #[error("Reading WASM file: {0}.")]
    ReadingWasmFile(io::Error),
    #[error("Writing WASM file: {0}.")]
    WritingWasmFile(io::Error),
    #[error(transparent)]
    Wasm(#[from] wasm::Error),
    #[error(transparent)]
    CurrentDir(io::Error),
    #[error(transparent)]
    Utf8(std::str::Utf8Error),
    #[error(transparent)]
    Repro(#[from] repro_utils::Error),
    #[error("Git URL is not provided.")]
    GitUrlNotProvided,
    #[error("Invalid git URL {url}.")]
    InvalidGitUrl { url: String },
    #[error("Project {name} not found in path {path}.")]
    ProjectNotFound { name: String, path: String },
    #[error(transparent)]
    Rpc(#[from] rpc::Error),
    #[error(transparent)]
    Config(#[from] config::Error),
    #[error("Cannot parse contract ID {contract_id}: {error}.")]
    CannotParseContractId {
        contract_id: String,
        error: locator::Error,
    },
    #[error("Cannot parse WASM hash {wasm_hash}: {error}.")]
    CannotParseWasmHash {
        wasm_hash: String,
        error: stellar_strkey::DecodeError,
    },
    #[error("WASM build with unsupported nightly WASM toolchain. Not reproducible.")]
    Nightly,
    #[error("Rustc not found in the contract's metadata.")]
    RustcNotFound,
    #[error("Reproduced WASM file is different from the original! Size diff: {size_diff}.")]
    SizeDiff { size_diff: u32 },
    #[error("Reproduced WASM file is different from the original! Bytes diff: {bytes_diff}.")]
    BytesDiff { bytes_diff: u32 },
    #[error(transparent)]
    ReadingUserInput(io::Error),
}

#[derive(Parser, Debug, Clone)]
pub struct Cmd {
    #[command(subcommand)]
    wasm_src: CmdWasmSrc,
    /// Building without `--locked`
    #[arg(long, default_value_t = false)]
    build_w_o_locked: bool,
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

impl Cmd {
    pub async fn run(&self) -> Result<(), Error> {
        if self.build_w_o_locked {
            eprintln!(
                "{}",
                "Warning: Building without `--locked`. Build will not be reproducible."
                    .red()
                    .bold()
            );

            let mut input = String::new();
            io::stdin()
                .read_line(&mut input)
                .map_err(Error::ReadingUserInput)?;
        }

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

        let repro_meta = repro_utils::read_wasm_reprometa(&wasm_path)?;

        if let Some(ref rustc) = repro_meta.rustc {
            if rustc.contains("nightly") {
                return Err(Error::Nightly);
            }
        } else {
            return Err(Error::RustcNotFound);
        }

        let wasm = wasm::Args { wasm: wasm_path };

        let work_dir_name = format!("{}-{}", &repro_meta.project_name, wasm.hash()?);

        let work_dir = repro_dir.join(work_dir_name);
        let mut git_dir = work_dir.join(&repro_meta.project_name);

        if let Some(repo_dir) = &self.repo {
            // fixme reexamine this logic
            if !repo_dir.contains(&repro_meta.project_name) {
                return Err(Error::ProjectNotFound {
                    name: repro_meta.project_name,
                    path: repo_dir.to_string(),
                });
            }
            if let Some(dir) = repo_dir.split(&repro_meta.project_name).next() {
                git_dir = Path::new(&dir).join(&repro_meta.project_name);
            }
        } else {
            if repro_meta.git_url.is_empty() {
                return Err(Error::GitUrlNotProvided);
            }

            if !validate_git_url(&repro_meta.git_url) {
                return Err(Error::InvalidGitUrl {
                    url: repro_meta.git_url.to_string(),
                });
            }

            let mut git_cmd = Command::new("git");
            git_cmd.args(["clone", &repro_meta.git_url, &git_dir.to_string_lossy()]);
            let git_cmd_str = format!(
                "{}",
                &git_cmd.get_args().map(OsStr::to_string_lossy).join(" ")
            );

            let status = git_cmd.status().map_err(Error::GitCmd)?;
            if !status.success() {
                match status.code() {
                    Some(code) => {
                        if code != 128 {
                            return Err(Error::GitCmdStatus { code });
                        }
                    }
                    None => {
                        return Err(Error::GitCmdTerminated {
                            git_cmd: git_cmd_str.to_string(),
                        })
                    }
                }
            }
        }

        let package_manifest_path = git_dir.join(&repro_meta.package_manifest_path);

        let mut git_cmd = Command::new("git");
        git_cmd.current_dir(&git_dir);
        git_cmd.args(["checkout", &repro_meta.commit_hash]);
        let git_cmd_str = format!(
            "{}",
            &git_cmd.get_args().map(OsStr::to_string_lossy).join(" ")
        );

        let status = git_cmd.status().map_err(Error::GitCmd)?;
        if !status.success() {
            match status.code() {
                Some(code) => return Err(Error::GitCmdStatus { code }),
                None => {
                    return Err(Error::GitCmdTerminated {
                        git_cmd: git_cmd_str.to_string(),
                    })
                }
            }
        }

        if let Some(rustc) = &repro_meta.rustc {
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
            &repro_meta.package_name,
            "--out-dir",
            &repro_dir.to_string_lossy(),
        ]);
        if !self.build_w_o_locked {
            soroban_cmd.arg("--locked");
        }

        if let Some(rustc) = &repro_meta.rustc {
            soroban_cmd.env("RUSTUP_TOOLCHAIN", rustc);
        }

        let status = soroban_cmd.status().map_err(Error::CargoCmd)?;
        if !status.success() {
            return Err(Error::Exit(status));
        }

        let file_name = format!("{}.wasm", repro_meta.package_name.replace('-', "_"));
        let mut new_wasm = repro_dir.join(&file_name);

        if repro_meta.is_optimized {
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
            let size_diff = pre_buf_len.abs_diff(new_buf_len) as u32;
            return Err(Error::SizeDiff { size_diff });
        }

        let bytes_diff = pre_buf
            .iter()
            .zip(new_buf.iter())
            .filter(|(a, b)| a != b)
            .count() as u32;
        if bytes_diff > 0 {
            return Err(Error::BytesDiff { bytes_diff });
        }

        eprintln!(
            "{}",
            "Reproduced WASM file is the same as the original!"
                .green()
                .bold()
        );

        Ok(())
    }
}

fn validate_git_url(git_url: &str) -> bool {
    let re = Regex::new(
        r"^(https:\/\/(\w+@)?|git@)[\w.-]+(\.[\w.-]+)+(\/|:)[\w._-]+\/[\w._-]+(\.git)?$",
    )
    .unwrap();
    re.is_match(git_url)
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
