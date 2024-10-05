use crate::xdr::{self, ReadXdr};
use cargo_metadata::Package;
use colored::*;
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Cursor};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str;
use std::str::FromStr;
use stellar_xdr::curr::{Limited, Limits, ScMetaEntry, ScMetaV0, StringM, WriteXdr};
use wasm_encoder::{CustomSection, Section};
use wasmparser::{Parser as WasmParser, Payload};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Reading file {filepath}: {error}")]
    CannotReadContractFile {
        filepath: std::path::PathBuf,
        error: io::Error,
    },
    #[error("Xdr processing error: {0}")]
    Xdr(#[from] xdr::Error),
    #[error(transparent)]
    Parser(#[from] wasmparser::BinaryReaderError),
    #[error(transparent)]
    GitCmd(io::Error),
    #[error(transparent)]
    Utf8(std::str::Utf8Error),
    #[error("Writing wasm file: {0}")]
    WritingWasmFile(io::Error),
    #[error("Copying wasm file: {0}")]
    CopyingWasmFile(io::Error),
    #[error("Failed fetching Git repository. Exited with status code: {code}.")]
    FetchingGitRepo { code: u16 },
    #[error("Failed fetching Git information. Exited with status code: {code}.")]
    FetchingGitInfo { code: i32 },
    #[error(transparent)]
    ParsingGitRepo(#[from] serde_json::Error),
}

#[derive(Debug, Default)]
pub struct ReproMeta {
    pub package_name: String,
    pub relative_manifest_path: String,
    pub git_url: String,
    pub commit_hash: String,
    pub rustc: Option<String>,
    pub is_optimized: bool,
}

pub fn read_wasm(wasm_path: &PathBuf) -> Result<Vec<u8>, Error> {
    let buf = fs::read(wasm_path).map_err(|e| Error::CannotReadContractFile {
        filepath: wasm_path.to_owned(),
        error: e,
    })?;

    Ok(buf)
}

pub fn read_wasm_contractmeta(buf: &[u8]) -> Result<Vec<ScMetaEntry>, Error> {
    let mut meta = vec![];
    for payload in WasmParser::new(0).parse_all(buf) {
        match payload? {
            Payload::CustomSection(s) => match s.name() {
                "contractmetav0" => {
                    if !s.data().is_empty() {
                        let cursor = Cursor::new(s.data());
                        let data =
                            ScMetaEntry::read_xdr_iter(&mut Limited::new(cursor, Limits::none()))
                                .collect::<Result<Vec<_>, _>>()
                                .map_err(Error::Xdr)?;
                        meta = data;
                    }
                }
                _ => {}
            },
            _other => {}
        }
    }
    Ok(meta)
}

pub fn read_wasm_without_contractmeta(buf: &[u8]) -> Result<Vec<u8>, Error> {
    let buf_len = buf.len();
    let mut module = Vec::with_capacity(buf_len);

    for payload in WasmParser::new(0).parse_all(buf) {
        match payload? {
            Payload::CustomSection(s) => match s.name() {
                "contractmetav0" => {
                    let range = s.range();
                    let section_header_size = calc_section_header_size(&range);

                    assert!(range.start >= section_header_size);
                    if range.start > 0 {
                        module.extend_from_slice(&buf[0..(range.start - section_header_size)]);
                    }
                    if range.end < buf_len {
                        module.extend_from_slice(&buf[range.end..buf_len]);
                    }
                }
                _ => {}
            },
            _other => {}
        }
    }
    module.shrink_to_fit();
    Ok(module)
}

pub fn read_wasm_reprometa(wasm: &PathBuf) -> Result<ReproMeta, Error> {
    let wasm_buf = read_wasm(wasm)?;
    let contract_meta = read_wasm_contractmeta(&wasm_buf)?;

    let mut repro_meta = ReproMeta::default();
    contract_meta
        .iter()
        .for_each(
            |ScMetaEntry::ScMetaV0(data)| match data.key.to_string().as_str() {
                "package_name" => repro_meta.package_name = data.val.to_string(),
                "relative_manifest_path" => {
                    repro_meta.relative_manifest_path = data.val.to_string()
                }
                "git_url" => repro_meta.git_url = data.val.to_string(),
                "commit_hash" => repro_meta.commit_hash = data.val.to_string(),
                "rsver" => repro_meta.rustc = Some(data.val.to_string()),
                "wasm_opt" => {
                    repro_meta.is_optimized = match data.val.to_string().as_str() {
                        "true" => true,
                        _ => false,
                    }
                }
                _ => {}
            },
        );

    Ok(repro_meta)
}

pub fn update_wasm_contractmeta(
    contract_path: &PathBuf,
    key: &str,
    val: &str,
) -> Result<Vec<u8>, Error> {
    let metadata = [(key, val)];
    let wasm_buf = read_wasm(&contract_path)?;

    insert_metadata(&metadata, &wasm_buf)
}

pub fn update_wasm_contractmeta_after_build(
    profile: &str,
    p: &Package,
    cargo_metadata: &cargo_metadata::Metadata,
    git_info: &Option<GitInfo>,
) -> Result<(), Error> {
    if git_info.is_none() {
        eprintln!(
            "{}",
            format!(
                "Warning: Package {} doesn't have git information. Build will not be reproducible.",
                &p.name
            )
            .yellow()
            .bold()
        );
    }

    let git_info = if let Some(info) = git_info {
        info
    } else {
        &GitInfo::default()
    };

    let relative_manifest_path = pathdiff::diff_paths(&p.manifest_path, &git_info.root)
        .unwrap_or(p.manifest_path.clone().into());
    let metadata = [
        ("package_name", p.name.as_str()),
        (
            "relative_manifest_path",
            &relative_manifest_path.to_string_lossy(),
        ),
        ("git_url", &git_info.clone_url),
        ("commit_hash", &git_info.commit_hash),
        (
            "soroban_cli_version",
            &format!("{}", env!("CARGO_PKG_VERSION")),
        ),
    ];

    let file_path = Path::new(&cargo_metadata.target_directory)
        .join("wasm32-unknown-unknown")
        .join(profile);
    let target_file = format!("{}.wasm", p.name.replace('-', "_"));
    let target_file_path = file_path.join(&target_file);

    let wasm_buf = read_wasm(&target_file_path)?;
    let wasm = insert_metadata(&metadata, &wasm_buf)?;

    let backup_file_path = target_file_path.with_extension("backup.wasm");
    fs::copy(&target_file_path, backup_file_path).map_err(Error::CopyingWasmFile)?;

    let temp_file = format!("{}.{}.temp", target_file, rand::random::<u32>());
    let temp_file_path = file_path.join(temp_file);

    fs::write(&temp_file_path, wasm).map_err(Error::WritingWasmFile)?;
    fs::rename(&temp_file_path, &target_file_path).map_err(Error::CopyingWasmFile)?;

    let repro_meta = read_wasm_reprometa(&target_file_path)?;
    if let Some(ref rustc) = repro_meta.rustc {
        if rustc.contains("nightly") {
            eprintln!(
                "{}",
                "Warning: Building with rust nightly. Build will not be reproducible."
                    .yellow()
                    .bold()
            );
        }
    }
    Ok(())
}

fn insert_metadata(metadata: &[(&str, &str)], wasm_buf: &[u8]) -> Result<Vec<u8>, Error> {
    let mut metadata_map: BTreeMap<StringM, ScMetaEntry> = read_wasm_contractmeta(&wasm_buf)?
        .into_iter()
        .map(|entry| match entry {
            ScMetaEntry::ScMetaV0(ScMetaV0 { ref key, .. }) => (key.clone(), entry.clone()),
        })
        .collect();

    metadata.iter().for_each(|(key, val)| {
        let key = StringM::from_str(key).expect("StringM");
        let val = StringM::from_str(val).expect("StringM");

        metadata_map.insert(key.clone(), ScMetaEntry::ScMetaV0(ScMetaV0 { key, val }));
    });

    let mut cursor = Limited::new(Cursor::new(vec![]), Limits::none());
    metadata_map
        .iter()
        .for_each(|(_, data)| data.write_xdr(&mut cursor).unwrap());
    let metadata_xdr = cursor.inner.into_inner();

    let custom_section = CustomSection {
        name: Cow::from("contractmetav0"),
        data: Cow::from(metadata_xdr),
    };

    let mut wasm = read_wasm_without_contractmeta(&wasm_buf)?;
    custom_section.append_to(&mut wasm);
    Ok(wasm)
}

fn calc_section_header_size(range: &std::ops::Range<usize>) -> usize {
    let len = range.end - range.start;
    let mut buf = Vec::new();
    let int_enc_size = leb128::write::unsigned(&mut buf, len as u64);
    let int_enc_size = int_enc_size.expect("leb128 write");
    let section_id_byte = 1;
    int_enc_size + section_id_byte
}

#[derive(Debug, Default)]
pub struct GitInfo {
    pub root: String,
    pub clone_url: String,
    pub commit_hash: String,
}

// fixme this is all very fragile
pub fn git_info(cargo_metadata: &cargo_metadata::Metadata) -> Result<Option<GitInfo>, Error> {
    // Git root
    let mut git_cmd = Command::new("git");
    git_cmd.current_dir(&cargo_metadata.workspace_root);
    git_cmd.args(["rev-parse", "--show-toplevel"]);
    let output = git_cmd.output().map_err(Error::GitCmd)?;
    if !output.status.success() {
        if let Some(code) = output.status.code() {
            let err = str::from_utf8(&output.stderr).map_err(Error::Utf8)?;
            // If it's not git repository, return empty GitInfo
            if err.contains("not a git repository") {
                eprintln!("{}", err);
                return Ok(None);
            } else {
                return Err(Error::FetchingGitInfo { code });
            }
        }
    }
    let root = str::from_utf8(&output.stdout)
        .map_err(Error::Utf8)?
        .trim()
        .to_string();

    // Git commit hash
    let mut git_cmd = Command::new("git");
    git_cmd.current_dir(&cargo_metadata.workspace_root);
    git_cmd.args(["rev-parse", "HEAD"]);
    let output = git_cmd.output().map_err(Error::GitCmd)?;
    if !output.status.success() {
        if let Some(code) = output.status.code() {
            return Err(Error::FetchingGitInfo { code });
        }
    }
    let commit_hash = str::from_utf8(&output.stdout)
        .map_err(Error::Utf8)?
        .trim()
        .to_string();

    // Git remote url
    let remote_name = "origin";
    let mut git_cmd = Command::new("git");
    git_cmd.current_dir(&cargo_metadata.workspace_root);
    git_cmd.args(["remote", "get-url", &remote_name]);
    let output = git_cmd.output().map_err(Error::GitCmd)?;
    if !output.status.success() {
        if let Some(code) = output.status.code() {
            return Err(Error::FetchingGitInfo { code });
        }
    }
    let mut clone_url = str::from_utf8(&output.stdout)
        .map_err(Error::Utf8)?
        .trim()
        .to_string();

    if clone_url.starts_with("git@github.com:") {
        clone_url = clone_url.replace("git@github.com:", "https://github.com/");
    }

    Ok(Some(GitInfo {
        root,
        commit_hash,
        clone_url,
    }))
}
