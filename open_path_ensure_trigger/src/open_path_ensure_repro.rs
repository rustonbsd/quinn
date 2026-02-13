use anyhow::{Context, Result};
use iroh_quinn::{self as quinn, ClientConfig, ServerConfig};
use iroh_quinn_proto::PathStatus;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

const DEFAULT_PORT: u16 = 63502;
const DEFAULT_SERVER_WORKERS: usize = 4;
const DEFAULT_CLIENT_WORKERS: usize = 4;
const WAVE_INTERVAL_MS: u64 = 5;

#[derive(Clone, Copy, Debug)]
pub enum LaunchMode {
    NoBarrier,
    Barrier,
}

impl LaunchMode {
    fn label(self) -> &'static str {
        match self {
            Self::NoBarrier => "no_barrier",
            Self::Barrier => "barrier",
        }
    }
}

pub fn run(mode: LaunchMode) -> Result<()> {
    let server_workers = configured_server_workers();
    let client_workers = configured_client_workers();
    let port = configured_port();

    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<Vec<u8>>>();

    std::thread::Builder::new()
        .name("onecall-server-runtime".into())
        .spawn(move || {
            if let Err(err) = run_server(ready_tx, server_workers, port) {
                eprintln!("[ONECALL SERVER] runtime failed: {err:#}");
            }
        })
        .context("spawn server thread")?;

    let cert_der = ready_rx
        .recv()
        .context("wait server ready")?
        .context("server startup failed")?;

    run_client(cert_der, client_workers, port, mode)
}

fn run_server(
    ready_tx: std::sync::mpsc::Sender<Result<Vec<u8>>>,
    server_workers: usize,
    port: u16,
) -> Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(server_workers)
        .enable_all()
        .build()?;

    rt.block_on(async {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .context("generate cert")?;
        let cert_der: rustls::pki_types::CertificateDer<'static> = cert.cert.into();
        let cert_bytes = cert_der.as_ref().to_vec();
        let key_der = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());

        let server_config = ServerConfig::with_single_cert(vec![cert_der], key_der.into())
            .context("server config")?;
        let endpoint = quinn::Endpoint::server(
            server_config,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
        )?;

        eprintln!("[ONECALL SERVER] listening on 127.0.0.1:{port}");
        let _ = ready_tx.send(Ok(cert_bytes));

        while let Some(incoming) = endpoint.accept().await {
            tokio::spawn(async move {
                if let Ok(connecting) = incoming.accept() {
                    let _ = connecting.await;
                }
            });
        }
        Ok(())
    })
}

fn run_client(cert_der: Vec<u8>, client_workers: usize, port: u16, mode: LaunchMode) -> Result<()> {
    let tick = Arc::new(AtomicU64::new(now()));
    let tick_watch = tick.clone();
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(Duration::from_secs(2));
            let ago = now().saturating_sub(tick_watch.load(Ordering::Relaxed));
            eprintln!("[WATCHDOG] tokio_tick={}s_ago", ago);
            if ago > 8 {
                eprintln!(
                    "\n[ONECALL REPRO] runtime stalled (mode={}) while driving open_path_ensure waves",
                    mode.label(),
                );
                std::process::exit(99);
            }
        }
    });

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(client_workers)
        .thread_name("onecall-worker")
        .enable_all()
        .build()?;

    rt.block_on(async move {
        tokio::spawn(async move {
            loop {
                tick.store(now(), Ordering::Relaxed);
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });

        let cert = rustls::pki_types::CertificateDer::from(cert_der);
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert).context("add cert")?;

        let endpoint =
            quinn::Endpoint::client(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))?;
        let client_config =
            ClientConfig::with_root_certificates(Arc::new(roots)).context("client config")?;
        endpoint.set_default_client_config(client_config);

        let conn = endpoint
            .connect(
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
                "localhost",
            )?
            .await
            .context("connect")?;

        let remote = conn.remote_address();
        eprintln!(
            "[ONECALL CLIENT] client_workers={client_workers}; launching ensure waves (mode={})",
            mode.label()
        );

        let conn = Arc::new(conn);
        let mut wave: u64 = 0;
        loop {
            match mode {
                LaunchMode::NoBarrier => {
                    for _ in 0..client_workers {
                        let conn = conn.clone();
                        tokio::spawn(async move {
                            let _ = conn.open_path_ensure(remote, PathStatus::Available).await;
                        });
                    }
                }
                LaunchMode::Barrier => {
                    let barrier = Arc::new(tokio::sync::Barrier::new(client_workers + 1));
                    for _ in 0..client_workers {
                        let conn = conn.clone();
                        let barrier = barrier.clone();
                        tokio::spawn(async move {
                            barrier.wait().await;
                            let _ = conn.open_path_ensure(remote, PathStatus::Available).await;
                        });
                    }
                    barrier.wait().await;
                }
            }

            wave += 1;
            if wave.is_multiple_of(100) {
                eprintln!("[ONECALL CLIENT] waves={wave} calls_per_wave={client_workers}");
            }
            tokio::time::sleep(Duration::from_millis(WAVE_INTERVAL_MS)).await;
        }

        #[allow(unreachable_code)]
        Ok(())
    })
}

fn configured_server_workers() -> usize {
    std::env::var("SERVER_WORKERS")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(DEFAULT_SERVER_WORKERS)
}

fn configured_client_workers() -> usize {
    std::env::var("WORKERS")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(DEFAULT_CLIENT_WORKERS)
}

fn configured_port() -> u16 {
    std::env::var("ONECALL_PORT")
        .ok()
        .and_then(|s| s.parse::<u16>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(DEFAULT_PORT)
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
