//! The killable pattern-probe child binary.
//!
//! The pattern-safety chain spawns this binary with a hidden subcommand
//! and speaks JSON on stdin/stdout so runaway backtracking loops can be
//! killed on deadline (the reference uses `python -c` children for the
//! same reason).

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match guard_core_engine::redos::child::child_main(&args) {
        Some(code) => std::process::exit(code),
        None => {
            eprintln!("usage: guard-pattern-probe __guard_pattern_probe < payload.json");
            std::process::exit(2);
        }
    }
}
