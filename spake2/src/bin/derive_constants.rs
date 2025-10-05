use std::env;
use std::process;

use spake2_conflux::constants::{DERIVATION_LABEL, SUITE_LABEL, derive_constant};

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(s, "{:02x}", b);
    }
    s
}

fn to_rust_array(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 6 + 3);
    s.push('[');
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            s.push_str(", ");
        }
        use std::fmt::Write as _;
        let _ = write!(s, "0x{:02x}", b);
    }
    s.push(']');
    s
}

fn print_provenance(name: &str, bytes: &[u8; 32], counter: u32) {
    println!("--- SPAKE2 Constant: {name} ---");
    println!(
        "suite_label         : {}",
        String::from_utf8_lossy(SUITE_LABEL)
    );
    println!(
        "derivation_label    : {}",
        String::from_utf8_lossy(DERIVATION_LABEL)
    );
    println!("counter             : {}", counter);
    println!("bytes_hex           : {}", to_hex(bytes));
    println!("bytes_rust_literal  : {}", to_rust_array(bytes));
    println!();
}

fn parse_names_from_args() -> Vec<String> {
    // Supports:
    //   --names=M,N,S
    //   --names M,N,S
    // Defaults to M,N,S if not provided.
    let mut args = env::args().skip(1).peekable();
    let mut names_opt: Option<String> = None;

    while let Some(arg) = args.next() {
        if arg == "--names" {
            if let Some(v) = args.peek() {
                names_opt = Some(v.clone());
                let _ = args.next();
            } else {
                eprintln!(
                    "error: --names requires an argument (e.g., --names=M,N,S or --names M,N,S)"
                );
                process::exit(2);
            }
        } else if let Some(rest) = arg.strip_prefix("--names=") {
            names_opt = Some(rest.to_string());
        } else if arg == "--help" || arg == "-h" {
            print_help_and_exit(0);
        } else {
            eprintln!("warning: unrecognized argument: {arg}");
        }
    }

    let default_names = "M,N,S".to_string();
    let names_csv = names_opt.unwrap_or(default_names);
    names_csv
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn print_help_and_exit(code: i32) -> ! {
    eprintln!(
        "Usage: derive_constants [--names M,N,S]\n\
         \n\
         Derives SPAKE2 distinguished constants deterministically and prints their provenance.\n\
         \n\
         Options:\n\
         \n\
           --names M,N,S   Comma-separated list of constants to derive. Defaults to M,N,S.\n\
           -h, --help      Show this help message.\n\
        "
    );
    process::exit(code);
}

fn main() {
    let names = parse_names_from_args();

    if names.is_empty() {
        eprintln!("error: at least one constant name must be provided (e.g., M,N,S).");
        process::exit(2);
    }

    for name in names {
        match name.as_str() {
            "M" | "N" | "S" => match derive_constant(&name) {
                Ok((bytes, counter)) => print_provenance(&name, &bytes, counter),
                Err(e) => {
                    eprintln!("error: failed to derive {name}: {e:?}");
                    process::exit(1);
                }
            },
            other => {
                eprintln!("error: unsupported constant name '{other}'. Supported: M, N, S");
                process::exit(2);
            }
        }
    }
}
