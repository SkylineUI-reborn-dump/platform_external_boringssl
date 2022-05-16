mod conditioner;
mod cutils_socket;
mod drbg;

use std::{
    io::{ErrorKind, Write},
    os::unix::net::UnixListener,
    path::PathBuf,
};

use anyhow::Result;
use clap::Parser;
use nix::sys::signal;

#[derive(Debug, clap::Parser)]
struct Cli {
    #[clap(long, default_value = "/dev/hw_random")]
    source: PathBuf,
    #[clap(long)]
    socket: Option<PathBuf>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    println!("{:?}", cli);
    let hwrng = std::fs::File::open(&cli.source)?;
    let listener = match cli.socket {
        Some(path) => UnixListener::bind(&path)?,
        None => cutils_socket::android_get_control_socket("prng_seeder")?,
    };

    unsafe { signal::signal(signal::Signal::SIGPIPE, signal::SigHandler::SigIgn) }?;

    let mut conditioner = conditioner::Conditioner::new(hwrng)?;

    for mut stream in listener.incoming() {
        match stream {
            Ok(ref mut stream) => {
                stream.write_all(&conditioner.request()?)?;
                conditioner.reseed_if_necessary()?;
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            e => {
                e?;
            }
        }
    }
    Ok(())
}
