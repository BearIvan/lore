// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
//! The crate's tests that can share a process, as one integration-test binary.
//!
//! They link the library as an ordinary dependency instead of compiling it a
//! second time in test mode. A test that needs a process of its own goes in a
//! separate `tests/*.rs` file instead.

mod auth;
mod branch;
mod change;
mod commit;
mod dependency;
mod event;
mod file;
mod filter;
mod fs;
mod global;
mod immutable;
mod infer;
mod instance;
mod interface;
mod link;
mod lock;
mod merge;
mod metadata;
mod node;
mod relay;
mod repository;
mod revision;
mod stage;
mod state;
mod util;
