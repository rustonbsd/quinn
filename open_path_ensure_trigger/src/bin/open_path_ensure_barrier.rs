use anyhow::Result;
use tokio_freeze_bug::open_path_ensure_repro::{self, LaunchMode};

fn main() -> Result<()> {
    open_path_ensure_repro::run(LaunchMode::Barrier)
}
