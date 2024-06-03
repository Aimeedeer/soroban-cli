use crate::wasm;
use clap::Parser;
use std::{
    fmt::Debug,
    fs, io,
    process::{Command, ExitStatus},
};
use stellar_xdr::curr::ScMetaEntry;
use crate::repro_utils;

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
    #[error("exit status {0}")]
    Exit(ExitStatus),
    #[error("package {package} not found")]
    PackageNotFound { package: String },
    #[error("reading wasm file: {0}")]
    ReadingWasmFile(io::Error),
    #[error("writing wasm file: {0}")]
    WritingWasmFile(io::Error),
    #[error(transparent)]
    Wasm(#[from] wasm::Error),
    #[error(transparent)]
    CurrentDir(io::Error),
    #[error(transparent)]
    Utf8(std::str::Utf8Error),
    #[error(transparent)]
    Repro(#[from] repro_utils::Error),
}

#[derive(Parser, Debug, Clone)]
pub struct Cmd {
    /// Contract wasm file
    #[command(flatten)]
    wasm: wasm::Args,
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
    pub fn run(&self) -> Result<(), Error> {
        let current_dir = std::env::current_dir().map_err(Error::CurrentDir)?;
        let repro_dir = current_dir.join(CONTRACT_REPRO_PATH);

        let metadata = self.load_contract_metadata()?;

        if let Some(ref rustc) = metadata.rustc {
            if rustc.contains("nightly") {
                println!("Wasm not reproducible with nightly toolchains");
                return Ok(());
            }
        }

        let work_dir = repro_dir.join(&metadata.project_name);
        let git_dir = work_dir.join(&metadata.project_name);

        let package_manifest_path = work_dir.join(&metadata.package_manifest_path);

        std::fs::create_dir_all(&git_dir).map_err(Error::CreatingDirectory)?;

        let mut git_cmd = Command::new("git");
        git_cmd.args([
            "clone",
            &metadata.git_url,
            &git_dir.to_string_lossy(),
        ]);
        git_cmd.status().map_err(Error::GitCmd)?;

        let mut git_cmd = Command::new("git");
        git_cmd.current_dir(&git_dir);
        git_cmd.args(["checkout", &metadata.commit_hash]);
        git_cmd.status().map_err(Error::GitCmd)?;
        
        /*
        let mut git_cmd = Command::new("git");
        git_cmd.current_dir(&git_dir);
        git_cmd.args(["branch", "-r", "--contains", &metadata.commit_hash]);
        let output = git_cmd.output().map_err(Error::GitCmd)?;
        let mut remote_branch = std::str::from_utf8(&output.stdout)
            .map_err(Error::Utf8)?
            .trim();

        // choose the first branch
        remote_branch = remote_branch
            .lines()
            .next()
            .expect("Git remote name")
            .trim();

        let mut git_cmd = Command::new("git");
        git_cmd.current_dir(&git_dir);
        git_cmd.args(["checkout", "-b", "repro", remote_branch]);
        git_cmd.status().map_err(Error::GitCmd)?;

        let mut git_cmd = Command::new("git");
        git_cmd.current_dir(&git_dir);
        git_cmd.args(["reset", "--hard", &metadata.commit_hash]);
        git_cmd.status().map_err(Error::GitCmd)?;
        */

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

        if let Some(rustc) = metadata.rustc {
            soroban_cmd.env("RUSTUP_TOOLCHAIN", &rustc);

            let mut rustup_cmd = Command::new("rustup");
            rustup_cmd.args(["toolchain", "install", &rustc]);
            let status = rustup_cmd.status().map_err(Error::RustupCmd)?;
            if !status.success() {
                return Err(Error::Exit(status));
            }

            let mut rustup_cmd = Command::new("rustup");
            rustup_cmd.args(["target", "add", "wasm32-unknown-unknown"]);
            rustup_cmd.args(["--toolchain", &rustc]);

            let status = rustup_cmd.status().map_err(Error::RustupCmd)?;
            if !status.success() {
                return Err(Error::Exit(status));
            }
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

        let pre_buf = self.wasm.read()?;
        let new_buf = fs::read(new_wasm).map_err(Error::ReadingWasmFile)?;

        if pre_buf.len() != new_buf.len() {
            println!("There are different!");
            return Ok(());
        }

        let num = pre_buf
            .iter()
            .zip(new_buf.iter())
            .filter(|(a, b)| a != b)
            .count();
        if num > 0 {
            println!("They are different! num : {num}");
        } else {
            println!("They are the same!");
        }

        Ok(())
    }

    fn load_contract_metadata(&self) -> Result<ContractMetadata, Error> {
        let metadata = repro_utils::read_wasm_contractmeta_file(&self.wasm.wasm)?;

        let mut contract_metadata = ContractMetadata::default();
        metadata.iter().for_each(|ScMetaEntry::ScMetaV0(data)| {
            match data.key.to_string().as_str() {
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
            }
        });

        Ok(contract_metadata)
    }
}
