use crate::repro_utils;
use crate::wasm;
use clap::Parser;
use colored::*;
use std::{
    fmt::Debug,
    fs, io,
    path::Path,
    process::{Command, ExitStatus},
};
use stellar_xdr::curr::ScMetaEntry;

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
    #[error("Git url doesn't exist. Please provide corrolated source code path using `--repo <source_code_path>`")]
    GitUrlNotFound,
    #[error("Invalid git url. Please provide the corrolated source code using `--repo <source_code_path>`")]
    InvalidGitUrl,
}

#[derive(Parser, Debug, Clone)]
pub struct Cmd {
    /// Contract wasm file
    #[command(flatten)]
    wasm: wasm::Args,
    /// Path to the source code
    #[arg(long)]
    repo: Option<String>,
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

        std::fs::create_dir_all(&repro_dir).map_err(Error::CreatingDirectory)?;

        let work_dir_name = format!("{}-{}", &metadata.project_name, self.wasm.hash()?);

        let work_dir = repro_dir.join(work_dir_name);
        let mut git_dir = work_dir.join(&metadata.project_name);

        if let Some(repo_dir) = &self.repo {
            if !repo_dir.contains(&metadata.project_name) {
                println!(
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
                return Err(Error::GitUrlNotFound);
            }

            if !is_git_url_valid(&metadata.git_url) {
                return Err(Error::InvalidGitUrl);
            }

            let mut git_cmd = Command::new("git");
            git_cmd.args(["clone", &metadata.git_url, &git_dir.to_string_lossy()]);
            git_cmd.status().map_err(Error::GitCmd)?;
        }

        let package_manifest_path = git_dir.join(&metadata.package_manifest_path);

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
            println!("{}", "They are different!".red().bold());
            return Ok(());
        }

        let num = pre_buf
            .iter()
            .zip(new_buf.iter())
            .filter(|(a, b)| a != b)
            .count();
        if num > 0 {
            println!("{}", format!("They are different! Size diff: {}", num).red().bold());
        } else {
            println!("{}", "They are the same!".green().bold());
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
                println!("Failed to access the repository: {}", stderr);
            }
        }
        Err(e) => {
            println!("Failed to execute git command: {}", e);
        }
    }

    is_valid
}
