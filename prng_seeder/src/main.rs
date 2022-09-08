mod conditioner;
mod cutils_socket;
mod drbg;

use std::{convert::Infallible, io::ErrorKind, path::PathBuf, sync::Arc};

use anyhow::Result;
use clap::Parser;
use log::error;
use nix::sys::signal;
use tokio::{
    io::AsyncWriteExt,
    net::{UnixListener, UnixStream},
    sync::Mutex,
};

use crate::conditioner::Conditioner;

#[derive(Debug, clap::Parser)]
struct Cli {
    #[clap(long, default_value = "/dev/hw_random")]
    source: PathBuf,
    #[clap(long)]
    socket: Option<PathBuf>,
}

async fn handle_stream(conditioner: Arc<Mutex<Conditioner>>, mut stream: UnixStream) -> Result<()> {
    let bytes = conditioner.lock().await.request()?;
    stream.write_all(&bytes).await?;
    conditioner.lock().await.reseed_if_necessary().await?;
    Ok(())
}

async fn listen_loop(conditioner: Conditioner, listener: UnixListener) -> Result<Infallible> {
    let conditioner = Arc::new(Mutex::new(conditioner));
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let conditioner = conditioner.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_stream(conditioner, stream).await {
                        error!("Request failed: {}", e);
                    }
                });
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Err(e.into()),
        }
    }
}

fn run(cli: Cli) -> Result<Infallible> {
    let hwrng = std::fs::File::open(&cli.source)?;
    let listener = match cli.socket {
        Some(path) => std::os::unix::net::UnixListener::bind(&path)?,
        None => cutils_socket::android_get_control_socket("prng_seeder")?,
    };

    unsafe { signal::signal(signal::Signal::SIGPIPE, signal::SigHandler::SigIgn) }?;

    let conditioner = Conditioner::new(hwrng)?;
    let listener = UnixListener::from_std(listener)?;

    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async { listen_loop(conditioner, listener).await })
}

fn main() {
    let cli = Cli::parse();
    logger::init(Default::default());    
    if let Err(e) = run(cli) {
        error!("Launch failed: {}", e);
    } else {
        error!("Loop terminated without an error")
    }
    std::process::exit(-1);
}
