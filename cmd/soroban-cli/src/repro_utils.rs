use cargo_metadata::Package;
use soroban_env_host::xdr::{self, ReadXdr};
use std::borrow::Cow;
use std::fs;
use std::io::{self, Cursor};
use std::path::Path;
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

fn calc_section_header_size(range: &std::ops::Range<usize>) -> usize {
    let len = range.end - range.start;
    let mut buf = Vec::new();
    let int_enc_size = leb128::write::unsigned(&mut buf, len as u64);
    let int_enc_size = int_enc_size.expect("leb128 write");
    let section_id_byte = 1;
    int_enc_size + section_id_byte
}

#[derive(Debug, Default)]
pub struct GitData {
    pub commit_hash: String,
    pub remote_url: String,
    pub project_name: String,
}

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

    /*let mut git_cmd = Command::new("git");
    git_cmd.current_dir(workspace_root);
    git_cmd.args(["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"]);
    let output = git_cmd.output().map_err(Error::GitCmd)?;
    let mut remote_name = str::from_utf8(&output.stdout)
        .map_err(Error::Utf8)?
        .trim()
        .to_string();
    remote_name = remote_name
        .split('/')
        .next()
        .expect("Git remote name")
        .to_string();*/

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

pub fn update_build_contractmeta_in_contract(
    profile: &str,
    target_dir: &str,
    workspace_root: &str,
    p: &Package,
    git_data: &GitData,
) -> Result<(), Error> {
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
    let mut meta = read_wasm_contractmeta(&contract_buf)?;

    meta.push(ScMetaEntry::ScMetaV0(ScMetaV0 {
        key: StringM::from_str("target_dir").expect("StringM"),
        val: StringM::from_str(&relative_target_dir).expect("StringM"),
    }));

    meta.push(ScMetaEntry::ScMetaV0(ScMetaV0 {
        key: StringM::from_str("workspace_root").expect("StringM"),
        val: StringM::from_str(&relative_workspace_root).expect("StringM"),
    }));

    meta.push(ScMetaEntry::ScMetaV0(ScMetaV0 {
        key: StringM::from_str("package_manifest_path").expect("StringM"),
        val: StringM::from_str(&relative_package_manifest_path).expect("StringM"),
    }));

    meta.push(ScMetaEntry::ScMetaV0(ScMetaV0 {
        key: StringM::from_str("package_name").expect("StringM"),
        val: StringM::from_str(&p.name).expect("StringM"),
    }));

    meta.push(ScMetaEntry::ScMetaV0(ScMetaV0 {
        key: StringM::from_str("project_name").expect("StringM"),
        val: StringM::from_str(&git_data.project_name).expect("StringM"),
    }));

    meta.push(ScMetaEntry::ScMetaV0(ScMetaV0 {
        key: StringM::from_str("git_url").expect("StringM"),
        val: StringM::from_str(&git_data.remote_url).expect("StringM"),
    }));

    meta.push(ScMetaEntry::ScMetaV0(ScMetaV0 {
        key: StringM::from_str("commit_hash").expect("StringM"),
        val: StringM::from_str(&git_data.commit_hash).expect("StringM"),
    }));

    let soroban_cli_version = env!("CARGO_PKG_VERSION");
    meta.push(ScMetaEntry::ScMetaV0(ScMetaV0 {
        key: StringM::from_str("soroban_cli_version").expect("StringM"),
        val: StringM::from_str(soroban_cli_version).expect("StringM"),
    }));

    let mut cursor = Limited::new(Cursor::new(vec![]), Limits::none());
    meta.iter()
        .for_each(|data| data.write_xdr(&mut cursor).unwrap());
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
