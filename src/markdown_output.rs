//! The only place in the program that may write the file `--output` names.
//!
//! `--output` is a promise of a file at a caller-chosen path: automation runs
//! the command, checks the exit status, then reads that file back. A write
//! failure that is merely printed and then exits 0 makes the caller read a
//! missing or stale file as the answer. The prompt path did exactly that while
//! `open <url>` and `get` exited 1, because the same contract was hand-copied
//! into three command paths and one copy swallowed its error.
//!
//! Collapsing the three copies into one function fixed the three known paths,
//! but a *fourth* hand-rolled write of that path anywhere in `main.rs` would
//! reopen the identical hole, and no amount of grepping for a `fs` write spelt
//! with the variable named `output_path` can stop that — the identifier is the
//! author's choice, and `File::create` + `write_all` is not even a write call.
//!
//! So the guarantee is moved off text and onto the type system. [`MarkdownOutput`]
//! is what clap parses `--output` into, and its path field is private *to this
//! module*. Rust privacy is per-module, not per-crate, so no code in `main.rs`
//! can read that path — not through a field, not through an accessor, not
//! through `Display`, because none is offered. A hand-rolled write of the
//! `--output` destination outside this file therefore does not compile; it is
//! not a test that has to notice, it is a build that cannot succeed.
//!
//! What that does NOT cover, stated plainly:
//!
//! * Code *inside this file* can still write by hand. This module is the
//!   trusted region and is deliberately tiny; the structural test in `main.rs`
//!   pins the number of file writes here at one and forbids re-exporting the
//!   path. That last guard is lexical, and lexical is the ceiling for a region
//!   that is by definition allowed to touch the path.
//! * A path obtained from somewhere other than `--output` (`std::env::args()`,
//!   a config file) is a different contract and not this module's business.
//! * Whether each command path still *calls* this module is a separate
//!   question — nothing here forces `get` to keep honouring `--output` if a
//!   rebase drops the call. `main.rs` keeps a call-site tripwire for that.

use std::convert::Infallible;
use std::str::FromStr;

/// The destination `--output` named, as parsed by clap.
///
/// The field is private on purpose and there is no accessor, no `Deref`, no
/// `Display` and no `Debug`: handing the path back out as a string would undo
/// the whole point of this module, because the caller could then pass it to any
/// file API it liked. Adding one is not a refactor, it is a removal of the
/// guarantee.
#[derive(Clone)]
pub struct MarkdownOutput {
    path: String,
}

impl FromStr for MarkdownOutput {
    type Err = Infallible;

    /// Lets clap build the value, and lets tests build one from a temp path.
    /// Construction is safe to expose — it is the *extraction* of the path that
    /// would reopen the hole.
    fn from_str(path: &str) -> Result<Self, Self::Err> {
        Ok(Self {
            path: path.to_string(),
        })
    }
}

/// Write `markdown` to the `--output` file when the caller asked for one, and
/// return the exit code the command must terminate with (`None` = carry on,
/// which includes the no-`--output` case: a run that promised nothing must not
/// be turned into a failure).
///
/// The exit code is returned rather than taken here so callers can finish
/// producing the other artifacts they already promised before dying.
pub fn write_if_requested(
    output: Option<&MarkdownOutput>,
    markdown: &str,
    verbose: bool,
) -> Option<i32> {
    let output = output?;
    match std::fs::write(&output.path, markdown) {
        Ok(()) => {
            if verbose {
                println!("Successfully wrote Markdown response to {}", output.path);
            }
            None
        }
        Err(e) => {
            eprintln!("Error writing output file: {}", e);
            // 1 is the code every other fatal path in this CLI uses.
            Some(1)
        }
    }
}
