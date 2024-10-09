use cargo_metadata::Package;
use crate::xdr::{self, ReadXdr};
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
    #[error("reading file {filepath}: {error}")]
    CannotReadContractFile {
        filepath: std::path::PathBuf,
        error: io::Error,
    },
    #[error("xdr processing error: {0}")]
    Xdr(#[from] xdr::Error),
    #[error(transparent)]
    Parser(#[from] wasmparser::BinaryReaderError),
    #[error(transparent)]
    GitCmd(io::Error),
    #[error(transparent)]
    Utf8(std::str::Utf8Error),
    #[error("writing wasm file: {0}")]
    WritingWasmFile(io::Error),
    #[error("reading wasm file: {0}")]
    ReadingWasmFile(io::Error),
    #[error("copying wasm file: {0}")]
    CopyingWasmFile(io::Error),
}

#[derive(Debug, Default)]
pub struct ContractMetadata {
    pub rustc: Option<String>,
    pub target_dir: String,
    pub workspace_root: String,
    pub package_manifest_path: String,
    pub package_name: String,
    pub project_name: String,
    pub git_url: String,
    pub commit_hash: String,
    pub is_optimized: bool,
}

pub fn read_wasm_contractmeta(contract_buf: &[u8]) -> Result<Vec<ScMetaEntry>, Error> {
    let mut meta = vec![];
    for payload in WasmParser::new(0).parse_all(contract_buf) {
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

pub fn read_wasm_contractmeta_file(contract_path: &Path) -> Result<Vec<ScMetaEntry>, Error> {
    let buf = fs::read(contract_path).map_err(|e| Error::CannotReadContractFile {
        filepath: contract_path.to_owned(),
        error: e,
    })?;
    read_wasm_contractmeta(&buf)
}

pub fn read_wasm_without_contractmeta(contract_buf: &[u8]) -> Result<Vec<u8>, Error> {
    let buf_len = contract_buf.len();
    let mut module = Vec::with_capacity(buf_len);

    for payload in WasmParser::new(0).parse_all(contract_buf) {
        match payload? {
            Payload::CustomSection(s) => match s.name() {
                "contractmetav0" => {
                    let range = s.range();
                    let section_header_size = calc_section_header_size(&range);

                    assert!(range.start >= section_header_size);
                    if range.start > 0 {
                        module.extend_from_slice(
                            &contract_buf[0..(range.start - section_header_size)],
                        );
                    }
                    if range.end < buf_len {
                        module.extend_from_slice(&contract_buf[range.end..buf_len]);
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

pub fn read_wasm_without_contractmeta_file(contract_path: &Path) -> Result<Vec<u8>, Error> {
    let buf = fs::read(contract_path).map_err(|e| Error::CannotReadContractFile {
        filepath: contract_path.to_owned(),
        error: e,
    })?;
    read_wasm_without_contractmeta(&buf)
}

fn calc_section_header_size(range: &std::ops::Range<usize>) -> usize {
    let len = range.end - range.start;
    let mut buf = Vec::new();
    let int_enc_size = leb128::write::unsigned(&mut buf, len as u64);
    let int_enc_size = int_enc_size.expect("leb128 write");
    let section_id_byte = 1;
    int_enc_size + section_id_byte
}

pub fn update_customsection_metadata(
    contract_path: &Path,
    meta_entry: ScMetaEntry,
) -> Result<Vec<u8>, Error> {
    let mut metadata = read_wasm_contractmeta_file(contract_path)?;

    metadata.push(meta_entry);

    let mut cursor = Limited::new(Cursor::new(vec![]), Limits::none());
    metadata
        .iter()
        .for_each(|data| data.write_xdr(&mut cursor).unwrap());
    let metadata_xdr = cursor.inner.into_inner();

    let custom_section = CustomSection {
        name: Cow::from("contractmetav0"),
        data: Cow::from(metadata_xdr),
    };

    let mut wasm = read_wasm_without_contractmeta_file(contract_path)?;
    custom_section.append_to(&mut wasm);
    Ok(wasm)
}

#[derive(Debug, Default)]
pub struct GitData {
    pub commit_hash: String,
    pub remote_url: String,
    // fixme project_name is probably not the right name for this
    pub project_name: String,
}

// fixme this is all very fragile
pub fn git_data(workspace_root: &str) -> Result<GitData, Error> {
    let mut git_data = GitData::default();

    let mut git_cmd = Command::new("git");
    git_cmd.current_dir(workspace_root);
    git_cmd.args(["rev-parse", "HEAD"]);
    let output = git_cmd.output().map_err(Error::GitCmd)?;
    git_data.commit_hash = str::from_utf8(&output.stdout)
        .map_err(Error::Utf8)?
        .trim()
        .to_string();

    let remote_name = "origin";

    let mut git_cmd = Command::new("git");
    git_cmd.current_dir(workspace_root);
    git_cmd.args(["remote", "get-url", &remote_name]);
    let output = git_cmd.output().map_err(Error::GitCmd)?;
    let mut url = str::from_utf8(&output.stdout)
        .map_err(Error::Utf8)?
        .trim()
        .to_string();

    if url.starts_with("git@github.com:") {
        url = url.replace("git@github.com:", "https://github.com/");
    }
    git_data.remote_url = url;

    let mut tmp_str = git_data
        .remote_url
        .trim_start_matches("https://github.com/");
    tmp_str = tmp_str.trim_end_matches(".git");
    git_data.project_name = tmp_str
        .split("/")
        .skip(1)
        .next()
        .expect("Project name")
        .to_string();

    Ok(git_data)
}

// fixme warn if rustc contains "nightly", like in repro.rs
pub fn update_build_contractmeta_in_contract(
    profile: &str,
    target_dir: &str,
    workspace_root: &str,
    p: &Package,
    git_data: &GitData,
) -> Result<(), Error> {
    // fixme this logic won't work if the directory doesn't have the same name as the github repo
    let mut v: Vec<&str> = target_dir.split(&git_data.project_name).collect();
    v.reverse();
    let relative_target_dir = v[0].trim_start_matches("/");

    let mut v: Vec<&str> = workspace_root.split(&git_data.project_name).collect();
    v.reverse();
    let relative_workspace_root = v[0].trim_start_matches("/");

    let manifest_path_str = p.manifest_path.as_str();
    let mut v: Vec<&str> = manifest_path_str.split(&git_data.project_name).collect();
    v.reverse();
    let relative_package_manifest_path = v[0].trim_start_matches("/");

    let file_path = Path::new(target_dir)
        .join("wasm32-unknown-unknown")
        .join(profile);

    let target_file = format!("{}.wasm", p.name.replace('-', "_"));
    let target_file_path = file_path.join(&target_file);

    let contract_buf = fs::read(&target_file_path).map_err(Error::ReadingWasmFile)?;

    let metadata_map: BTreeMap<StringM, ScMetaEntry> = read_wasm_contractmeta(&contract_buf)?
        .into_iter()
        .map(|entry| match entry {
            ScMetaEntry::ScMetaV0(ScMetaV0 { ref key, .. }) => (key.clone(), entry.clone()),
        })
        .collect();

    let new_metadata = [
        ("target_dir", relative_target_dir),
        ("workspace_root", relative_workspace_root),
        ("package_manifest_path", relative_package_manifest_path),
        ("package_name", &p.name),
        ("project_name", &git_data.project_name),
        ("git_url", &git_data.remote_url),
        ("commit_hash", &git_data.commit_hash),
        ("soroban_cli_version", env!("CARGO_PKG_VERSION")),
    ];
    let metadata_map = insert_new_metadata(&new_metadata, &metadata_map);

    let mut cursor = Limited::new(Cursor::new(vec![]), Limits::none());
    metadata_map
        .iter()
        .for_each(|(_, data)| data.write_xdr(&mut cursor).unwrap());
    let meta_xdr = cursor.inner.into_inner();

    let custom_section = CustomSection {
        name: Cow::from("contractmetav0"),
        data: Cow::from(meta_xdr),
    };

    let mut wasm = read_wasm_without_contractmeta(&contract_buf)?;
    custom_section.append_to(&mut wasm);

    let backup_path = target_file_path.with_extension("back.wasm");
    fs::copy(&target_file_path, backup_path).map_err(Error::CopyingWasmFile)?;

    let temp_file = format!("{}.{}.temp", target_file, rand::random::<u32>());
    let temp_file_path = file_path.join(temp_file);

    fs::write(&temp_file_path, wasm).map_err(Error::WritingWasmFile)?;
    fs::rename(&temp_file_path, target_file_path).map_err(Error::CopyingWasmFile)?;

    Ok(())
}

pub fn load_contract_metadata_from_path(wasm: &PathBuf) -> Result<ContractMetadata, Error> {
    let metadata = read_wasm_contractmeta_file(wasm)?;

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

fn insert_new_metadata(
    data: &[(&str, &str)],
    metadata_map: &BTreeMap<StringM, ScMetaEntry>,
) -> BTreeMap<StringM, ScMetaEntry> {
    let mut metadata_map = metadata_map.clone();

    data.iter().for_each(|(key, val)| {
        let key = StringM::from_str(key).expect("StringM");
        let val = StringM::from_str(val).expect("StringM");

        metadata_map.insert(key.clone(), ScMetaEntry::ScMetaV0(ScMetaV0 { key, val }));
    });

    metadata_map
}
