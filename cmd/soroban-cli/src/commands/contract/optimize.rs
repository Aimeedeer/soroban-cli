use crate::repro_utils;
use crate::wasm;
use clap::{arg, command, Parser};
use std::fmt::Debug;
#[cfg(feature = "opt")]
use std::str::FromStr;
use std::io;
#[cfg(feature = "opt")]
use std::fs;
#[cfg(feature = "opt")]
use stellar_xdr::curr::{ScMetaEntry, ScMetaV0, StringM};
#[cfg(feature = "opt")]
use wasm_opt::{Feature, OptimizationError, OptimizationOptions};

#[derive(Parser, Debug, Clone)]
#[group(skip)]
pub struct Cmd {
    #[command(flatten)]
    wasm: wasm::Args,
    /// Path to write the optimized WASM file to (defaults to same location as --wasm with .optimized.wasm suffix)
    #[arg(long)]
    wasm_out: Option<std::path::PathBuf>,
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Wasm(#[from] wasm::Error),
    #[cfg(feature = "opt")]
    #[error("optimization error: {0}")]
    OptimizationError(OptimizationError),
    #[cfg(not(feature = "opt"))]
    #[error("Must install with \"opt\" feature, e.g. `cargo install --locked soroban-cli --features opt")]
    Install,
    #[error("writing wasm file: {0}")]
    WritingFile(io::Error),
    #[error("copying wasm file: {0}")]
    CopyingFile(io::Error),
    #[error(transparent)]
    Repro(#[from] repro_utils::Error),
}

impl Cmd {
    #[cfg(not(feature = "opt"))]
    pub fn run(&self) -> Result<(), Error> {
        Err(Error::Install)
    }

    #[cfg(feature = "opt")]
    pub fn run(&self) -> Result<(), Error> {
        if self.is_already_optimized()? {
            println!("The file is already optimized.");
            return Ok(());
        }

        let wasm_size = self.wasm.len()?;

        println!(
            "Reading: {} ({} bytes)",
            self.wasm.wasm.to_string_lossy(),
            wasm_size
        );

        let wasm_out = self.wasm_out.as_ref().cloned().unwrap_or_else(|| {
            let mut wasm_out = self.wasm.wasm.clone();
            wasm_out.set_extension("optimized.wasm");
            wasm_out
        });

        let mut options = OptimizationOptions::new_optimize_for_size_aggressively();
        options.converge = true;

        // Explicitly set to MVP + sign-ext + mutable-globals, which happens to
        // also be the default featureset, but just to be extra clear we set it
        // explicitly.
        //
        // Formerly Soroban supported only the MVP feature set, but Rust 1.70 as
        // well as Clang generate code with sign-ext + mutable-globals enabled,
        // so Soroban has taken a change to support them also.
        options.mvp_features_only();
        options.enable_feature(Feature::MutableGlobals);
        options.enable_feature(Feature::SignExt);

        options
            .run(&self.wasm.wasm, &wasm_out)
            .map_err(Error::OptimizationError)?;

        self.update_metadata(&wasm_out)?;
        let wasm_out_size = wasm::len(&wasm_out)?;
        println!(
            "Optimized: {} ({} bytes)",
            wasm_out.to_string_lossy(),
            wasm_out_size
        );

        Ok(())
    }

    #[cfg(feature = "opt")]
    fn update_metadata(&self, wasm_out: &std::path::PathBuf) -> Result<(), Error> {
        let meta_entry = ScMetaEntry::ScMetaV0(ScMetaV0 {
            key: StringM::from_str("wasm_opt").expect("StringM"),
            val: StringM::from_str("true").expect("StringM"),
        });

        let wasm_buf = repro_utils::update_customsection_metadata(&self.wasm.wasm, meta_entry)?;

        let temp_file = format!(
            "{}.{}.temp",
            wasm_out.to_string_lossy(),
            rand::random::<u32>()
        );

        fs::write(&temp_file, wasm_buf).map_err(Error::WritingFile)?;
        fs::rename(&temp_file, wasm_out).map_err(Error::CopyingFile)?;

        Ok(())
    }

    #[cfg(feature = "opt")]
    fn is_already_optimized(&self) -> Result<bool, Error> {
        let metadata = repro_utils::read_wasm_contractmeta_file(&self.wasm.wasm)?;

        let mut is_optimized = false;
        metadata.iter().for_each(|ScMetaEntry::ScMetaV0(data)| {
            match data.key.to_string().as_str() {
                "wasm_opt" => match data.val.to_string().as_str() {
                    "true" => is_optimized = true,
                    _ => {}
                },
                _ => {}
            }
        });

        Ok(is_optimized)
    }
}
