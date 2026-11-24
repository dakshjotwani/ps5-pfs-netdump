//! ps5-pfs-netdump: stream a running PS5 game over FTP straight into a ShadowMountPlus
//! `.ffpkg`, in one pass.
//!
//! While a game runs on a jailbroken PS5, the kernel serves its decrypted, decompressed inner
//! PFS image at `/mnt/sandbox/pfsmnt/<TITLEID>-app0-nest/pfs_image.dat`. The file list comes
//! from that image's metadata; what ps5-app-dumper adds (package `sce_sys` entries, appmeta,
//! trophy and uds data, decrypted executables) is fetched first and held in memory. PS5 Dump
//! Forge then builds the image from that folder, with file data laid out in the image's own
//! order, so the game data is read in one sequential stream.

mod console;
mod extras;
mod pfs;
mod remote;

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use ps5_dump_forge_core::{ConvertRequest, Event, Jobs};

use console::{Console, DirConsole, FtpConsole};

const PFSMNT: &str = "/mnt/sandbox/pfsmnt";

struct Args {
    host: String,
    title: Option<String>,
    output: Option<PathBuf>,
    port: u16,
    list_only: bool,
    full_verify: bool,
    local_root: Option<PathBuf>,
}

const USAGE: &str = "usage: ps5-pfs-netdump <host> [<TITLEID> [<output.ffpkg>]] [--port N] [--list-only] [--full-verify]

  no TITLEID     list the titles that have a -nest mount (running games)
  --list-only    print the game files with their image offsets; download nothing
  --full-verify  re-read every byte of the image afterwards (default: Forge's fast check)";

fn parse_args() -> Result<Args> {
    let mut a = Args {
        host: String::new(),
        title: None,
        output: None,
        port: 2121,
        list_only: false,
        full_verify: false,
        local_root: None,
    };
    let mut pos = Vec::new();
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--port" => a.port = it.next().context("--port needs a value")?.parse()?,
            "--list-only" => a.list_only = true,
            "--full-verify" => a.full_verify = true,
            // Tests: a folder standing in for the console's root.
            "--local-root" => a.local_root = Some(it.next().context("--local-root needs a value")?.into()),
            "-h" | "--help" => {
                println!("{USAGE}");
                std::process::exit(0);
            }
            s if s.starts_with('-') => bail!("unknown option {s}\n{USAGE}"),
            _ => pos.push(arg),
        }
    }
    let mut pos = pos.into_iter();
    a.host = pos.next().with_context(|| USAGE.to_string())?;
    a.title = pos.next().map(|t| t.to_ascii_uppercase());
    a.output = pos.next().map(PathBuf::from);
    if pos.next().is_some() {
        bail!("too many arguments\n{USAGE}");
    }
    Ok(a)
}

fn log(line: impl AsRef<str>) {
    eprintln!("{}", line.as_ref());
}

fn running_titles(c: &dyn Console) -> Result<Vec<String>> {
    let mut out: Vec<String> = c
        .list(PFSMNT)?
        .unwrap_or_default()
        .into_iter()
        .filter(|(_, d, _)| *d)
        .filter_map(|(n, _, _)| n.strip_suffix("-app0-nest").map(str::to_string))
        .filter(|t| t.len() == 9 && t[..4].bytes().all(|b| b.is_ascii_uppercase()) && t[4..].bytes().all(|b| b.is_ascii_digit()))
        .collect();
    out.sort();
    out.dedup();
    Ok(out)
}

/// `<TITLEID> <Title>.ffpkg`, as `ps5 add` names library images.
fn default_output(title: &str, param_json: Option<&[u8]>) -> PathBuf {
    let name = param_json
        .and_then(|j| serde_json::from_slice::<serde_json::Value>(j).ok())
        .and_then(|v| {
            let l = v.get("localizedParameters")?;
            let lang = l.get("defaultLanguage").and_then(|d| d.as_str()).unwrap_or("en-US").to_string();
            l.get(&lang).or_else(|| l.get("en-US"))?.get("titleName")?.as_str().map(str::to_string)
        })
        .map(|n| n.chars().filter(|c| !"/\\:*?\"<>|".contains(*c)).collect::<String>().trim().to_string())
        .filter(|n| !n.is_empty());
    PathBuf::from(match name {
        Some(n) => format!("{title} {n}.ffpkg"),
        None => format!("{title}.ffpkg"),
    })
}

fn human(n: u64) -> String {
    format!("{:.2} GB", n as f64 / 1e9)
}

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    let a = parse_args()?;
    let console: Arc<dyn Console> = match &a.local_root {
        Some(root) => Arc::new(DirConsole(root.clone())),
        None => Arc::new(FtpConsole::new(&a.host, a.port)?),
    };
    let Some(title) = a.title.clone() else {
        let titles = running_titles(&*console)?;
        if titles.is_empty() {
            bail!("no -nest mounts in {PFSMNT}. Start the game on the PS5 and leave it running.");
        }
        println!("running titles with a -nest mount:");
        for t in titles {
            println!("  {t}");
        }
        return Ok(());
    };

    let nest = format!("{PFSMNT}/{title}-app0-nest/pfs_image.dat");
    let app0 = format!("{PFSMNT}/{title}-app0");
    let img = pfs::Image::open(&*console, &nest, &|l| log(l))?;
    log(format!(
        "pfs_image.dat: {}; superblock {} MB from the end, block size {:#x}, {} inodes",
        human(img.size),
        (img.size - img.sb.offset) >> 20,
        img.sb.block_size,
        img.sb.inode_count
    ));
    let (files, dirs) = img.walk()?;
    let game = pfs::game_files(&files)?;
    let game_dirs: Vec<String> =
        dirs.iter().filter_map(|d| d.strip_prefix("/uroot/").map(str::to_string)).collect();
    log(format!("{} game files, {}", game.len(), human(game.iter().map(|f| f.size).sum())));
    if a.list_only {
        for f in &game {
            println!("{:>14} {:>12} {}", f.offset, f.size, f.path);
        }
        return Ok(());
    }

    // Everything but the game data first, while it's quick: the same steps and order as
    // ps5-app-dumper (a later step's file wins).
    log("fetching package sce_sys entries, appmeta, trophy, uds and decrypted executables ...");
    let mut ex = extras::Extras::default();
    ex.package(&*console, &title, &game)?;
    ex.appmeta_trophy_uds(&*console, &title)?;
    let encrypted = ex.executables(&*console, &nest, &app0, &game)?;
    for l in ex.log.drain(..) {
        log(format!("  {l}"));
    }
    if !encrypted.is_empty() {
        bail!(
            "{} executables could not be fetched decrypted (e.g. {}); not building an image that can't boot",
            encrypted.len(),
            encrypted[0]
        );
    }
    let output = a.output.clone().unwrap_or_else(|| {
        default_output(&title, ex.files.get("sce_sys/param.json").map(Vec::as_slice))
    });
    if output.exists() {
        bail!("{} already exists", output.display());
    }

    // Game files the extras replace are not read from the image.
    let streamed: Vec<&pfs::File> = game.iter().filter(|f| !ex.files.contains_key(&f.path)).collect();
    let order: Vec<String> = streamed.iter().map(|f| f.path.clone()).collect();
    let stream_bytes: u64 = streamed.iter().map(|f| f.size).sum();
    let mem_bytes: u64 = ex.files.values().map(|v| v.len() as u64).sum();
    log(format!(
        "{} files from memory ({}), {} streamed from the image ({})",
        ex.files.len(),
        human(mem_bytes),
        streamed.len(),
        human(stream_bytes)
    ));

    let remote = Arc::new(remote::GameRemote::new(
        console.clone(),
        &nest,
        streamed.iter().map(|f| (f.path.clone(), f.offset, f.size)),
        std::mem::take(&mut ex.files),
        game_dirs,
    ));
    ps5_dump_forge_core::remote::set(remote.clone());

    let request: ConvertRequest = serde_json::from_value(serde_json::json!({
        "source": format!("flink://{}/{}", remote::KEY_ID, remote::ROOT),
        "format": "ffpkg",
        "output": std::path::absolute(&output)?,
        "full_verify": a.full_verify,
        "data_order": order,
    }))
    .context("building the Forge request")?;

    log(format!("building {} ...", output.display()));
    let started = Instant::now();
    let (tx, rx) = mpsc::channel();
    let jobs = Jobs::new(move |event| {
        let _ = tx.send(event);
    });
    let _job = jobs.start(request);
    let mut last = Instant::now() - Duration::from_secs(60);
    let mut stage = String::new();
    let result = loop {
        match rx.recv() {
            Ok(Event::Progress { stage: s, done, total, .. }) => {
                if s != stage || last.elapsed() >= Duration::from_secs(15) {
                    let st = remote.stats();
                    let secs = started.elapsed().as_secs_f64().max(1e-3);
                    log(format!(
                        "  {s}: {}% ({} of {}), streamed {} at {:.0} MB/s",
                        if total > 0 { done * 100 / total } else { 0 },
                        human(done),
                        human(total),
                        human(st.streamed),
                        st.streamed as f64 / 1e6 / secs
                    ));
                    stage = s;
                    last = Instant::now();
                }
            }
            Ok(Event::Log { line, .. }) => log(format!("  forge: {line}")),
            Ok(Event::Done { result, .. }) => break result,
            Ok(Event::Stages { .. }) => {}
            Err(_) => break Err("the Forge job vanished".to_string()),
        }
    };
    jobs.cancel_all_and_wait();
    let st = remote.stats();
    let secs = started.elapsed().as_secs_f64().max(1e-3);
    log(format!(
        "stream: {} read, {} skipped, {} served again from memory, {} reopen(s), {} one-off read(s) ({}), {:.0} s, {:.0} MB/s",
        human(st.streamed),
        human(st.skipped),
        human(st.from_memory),
        st.reopened,
        st.one_off_reads,
        human(st.one_off_bytes),
        secs,
        st.streamed as f64 / 1e6 / secs
    ));
    match result {
        Ok(report) => {
            log(format!("wrote {} ({} files, {} bytes)", report.output.display(), report.files, report.bytes));
            for c in &report.checks {
                log(format!("  ok: {c}"));
            }
            Ok(())
        }
        Err(e) => bail!("Forge: {e}"),
    }
}
