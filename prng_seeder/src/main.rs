mod conditioner;
mod cutils_socket;
mod drbg;

use std::{
    convert::Infallible,
    fs::remove_file,
    io::ErrorKind,
    os::unix::net::UnixListener,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::Result;
use clap::Parser;
use log::{error, info};
use nix::sys::signal;
use tokio::{
    io::AsyncWriteExt,
    net::{UnixListener as TokioUnixListener, UnixStream},
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

async fn handle_stream(conditioner: Arc<Mutex<Conditioner>>, mut stream: UnixStream) -> Result<()> {
    let bytes = conditioner.lock().await.request()?;
    stream.write_all(&bytes).await?;
    conditioner.lock().await.reseed_if_necessary().await?;
    Ok(())
}

async fn listen_loop(conditioner: Conditioner, listener: TokioUnixListener) -> Result<Infallible> {
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
        Some(path) => get_socket(path.as_path())?,
        None => cutils_socket::android_get_control_socket("prng_seeder")?,
    };

    unsafe { signal::signal(signal::Signal::SIGPIPE, signal::SigHandler::SigIgn) }?;

    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
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
