mod conditioner;
mod cutils_socket;
mod drbg;

use std::{
    convert::Infallible,
    fs::remove_file,
    io::ErrorKind,
    os::unix::{net::UnixListener, prelude::AsRawFd},
    path::{Path, PathBuf},
};

use anyhow::Result;
use clap::Parser;
use log::{error, info};
use nix::{
    fcntl::{fcntl, FcntlArg::F_SETFL, OFlag},
    sys::signal,
};
use tokio::{io::AsyncWriteExt, net::UnixListener as TokioUnixListener};

use crate::conditioner::Conditioner;

#[derive(Debug, clap::Parser)]
struct Cli {
    #[clap(long, default_value = "/dev/hw_random")]
    source: PathBuf,
    #[clap(long)]
    socket: Option<PathBuf>,
}

fn configure_logging() {
    logger::init(Default::default());
}

fn get_socket(path: &Path) -> Result<UnixListener> {
    if let Err(e) = remove_file(path) {
        if e.kind() != ErrorKind::NotFound {
            return Err(e.into());
        }
    } else {
        info!("Deleted old {}", path.to_string_lossy());
    }
    Ok(UnixListener::bind(path)?)
}

async fn listen_loop(
    mut conditioner: Conditioner,
    listener: TokioUnixListener,
) -> Result<Infallible> {
    loop {
        match listener.accept().await {
            Ok((mut stream, _)) => {
                let new_bytes = conditioner.request()?;
                tokio::spawn(async move {
                    if let Err(e) = stream.write_all(&new_bytes).await {
                        error!("Request failed: {}", e);
                    }
                });
                conditioner.reseed_if_necessary().await?;
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Err(e.into()),
        }
    }
}

fn run(cli: Cli) -> Result<Infallible> {
    let hwrng = std::fs::File::open(&cli.source)?;
    fcntl(hwrng.as_raw_fd(), F_SETFL(OFlag::O_NONBLOCK))?;
    let listener = match cli.socket {
        Some(path) => get_socket(path.as_path())?,
        None => cutils_socket::android_get_control_socket("prng_seeder")?,
    };
    listener.set_nonblocking(true)?;

    unsafe { signal::signal(signal::Signal::SIGPIPE, signal::SigHandler::SigIgn) }?;

    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let conditioner = Conditioner::new(hwrng)?;
            let listener = TokioUnixListener::from_std(listener)?;
            listen_loop(conditioner, listener).await
        })
}

fn main() {
    let cli = Cli::parse();
    configure_logging();
    if let Err(e) = run(cli) {
        error!("Launch failed: {}", e);
    } else {
        error!("Loop terminated without an error")
    }
    std::process::exit(-1);
}
