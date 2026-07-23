// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2025
#![allow(missing_docs)]

mod cli;

use anyhow::Result;
use clap::Parser;
use log::{info, LevelFilter};
use utils::PvLogger;

static LOGGER: PvLogger = PvLogger;

fn main() -> Result<()> {
    LOGGER.start(LevelFilter::Trace)?;
    let opt = cli::CliOptions::parse();
    opt.certificate_args
        .get_verified_hkds("info", opt.hkd_version.map(|v| v.into()))?;
    info!("Host-key documents verified.");
    Ok(())
}
