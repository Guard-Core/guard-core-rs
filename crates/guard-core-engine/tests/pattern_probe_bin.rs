//! The probe child binary's non-probe invocation prints usage and exits
//! with the usage code.

#[test]
fn the_probe_binary_prints_usage_without_its_subcommand() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_guard-pattern-probe"))
        .output()
        .expect("binary runs");
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("usage: guard-pattern-probe"), "{stderr}");
}
