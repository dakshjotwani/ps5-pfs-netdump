//! The console's filesystem: over FTP (the PS5's ftpsrv payload), or a local folder laid
//! out the same way (tests and offline runs).

use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::time::Duration;

/// One directory entry: name, is a directory, size.
pub type Entry = (String, bool, u64);

pub trait Console: Send + Sync {
    /// Entries of `path`, or `None` when it isn't a readable directory.
    fn list(&self, path: &str) -> io::Result<Option<Vec<Entry>>>;
    /// A file's size, or `None` when there is no such file.
    fn size(&self, path: &str) -> io::Result<Option<u64>>;
    /// Up to `len` bytes of `path` from `offset` (fewer only at the end of the file).
    fn read(&self, path: &str, offset: u64, len: usize) -> io::Result<Vec<u8>>;
    /// `path` from `offset` to its end, as one stream.
    fn stream(&self, path: &str, offset: u64) -> io::Result<Box<dyn Read + Send>>;

    fn read_all(&self, path: &str) -> io::Result<Vec<u8>> {
        let n = self
            .size(path)?
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, path.to_string()))?;
        let data = self.read(path, 0, n as usize)?;
        if data.len() as u64 != n {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, format!("{path}: short read")));
        }
        Ok(data)
    }
}

// ---------------------------------------------------------------------------------------
// A local folder standing in for the console's root
// ---------------------------------------------------------------------------------------

pub struct DirConsole(pub PathBuf);

impl DirConsole {
    fn p(&self, path: &str) -> PathBuf {
        self.0.join(path.trim_start_matches('/'))
    }
}

impl Console for DirConsole {
    fn list(&self, path: &str) -> io::Result<Option<Vec<Entry>>> {
        let p = self.p(path);
        if !p.is_dir() {
            return Ok(None);
        }
        let mut out = Vec::new();
        for e in std::fs::read_dir(p)? {
            let e = e?;
            let m = e.metadata()?;
            out.push((e.file_name().to_string_lossy().into_owned(), m.is_dir(), if m.is_dir() { 0 } else { m.len() }));
        }
        out.sort();
        Ok(Some(out))
    }

    fn size(&self, path: &str) -> io::Result<Option<u64>> {
        let p = self.p(path);
        Ok(if p.is_file() { Some(std::fs::metadata(p)?.len()) } else { None })
    }

    fn read(&self, path: &str, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        use std::io::Seek;
        let mut f = std::fs::File::open(self.p(path))?;
        f.seek(io::SeekFrom::Start(offset))?;
        let mut buf = Vec::with_capacity(len);
        f.take(len as u64).read_to_end(&mut buf)?;
        Ok(buf)
    }

    fn stream(&self, path: &str, offset: u64) -> io::Result<Box<dyn Read + Send>> {
        use std::io::Seek;
        let mut f = std::fs::File::open(self.p(path))?;
        f.seek(io::SeekFrom::Start(offset))?;
        Ok(Box::new(f))
    }
}

// ---------------------------------------------------------------------------------------
// FTP: one control connection per operation, as the Python tool does. The PS5 FTP payloads
// answer an early-closed RETR inconsistently, so a transfer cut short just drops the
// connection instead of waiting for a reply.
// ---------------------------------------------------------------------------------------

pub struct FtpConsole {
    addr: SocketAddr,
    timeout: Duration,
}

struct Control {
    w: TcpStream,
    r: BufReader<TcpStream>,
    peer: std::net::IpAddr,
    timeout: Duration,
}

impl FtpConsole {
    pub fn new(host: &str, port: u16) -> io::Result<Self> {
        let addr = (host, port)
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("{host}: no address")))?;
        Ok(Self { addr, timeout: Duration::from_secs(60) })
    }

    fn connect(&self) -> io::Result<Control> {
        let s = TcpStream::connect_timeout(&self.addr, Duration::from_secs(10))?;
        s.set_read_timeout(Some(self.timeout))?;
        s.set_nodelay(true)?;
        let mut c = Control { w: s.try_clone()?, r: BufReader::new(s), peer: self.addr.ip(), timeout: self.timeout };
        c.expect(&[220])?;
        let (code, _) = c.cmd("USER anonymous")?;
        if code == 331 {
            c.cmd_ok("PASS anonymous", &[230, 202])?;
        } else if code != 230 {
            return Err(ftp_err(code, "USER"));
        }
        c.cmd_ok("TYPE I", &[200])?;
        Ok(c)
    }
}

fn ftp_err(code: u32, what: &str) -> io::Error {
    let kind = if code == 550 { io::ErrorKind::NotFound } else { io::ErrorKind::Other };
    io::Error::new(kind, format!("FTP {what}: reply {code}"))
}

impl Control {
    fn reply(&mut self) -> io::Result<(u32, String)> {
        let mut line = String::new();
        if self.r.read_line(&mut line)? == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "FTP connection closed"));
        }
        let code: u32 = line.get(..3).and_then(|c| c.parse().ok()).ok_or_else(|| io::Error::other(format!("bad FTP reply {line:?}")))?;
        let mut text = line.clone();
        if line.as_bytes().get(3) == Some(&b'-') {
            let end = format!("{code} ");
            loop {
                let mut l = String::new();
                if self.r.read_line(&mut l)? == 0 {
                    break;
                }
                text.push_str(&l);
                if l.starts_with(&end) {
                    break;
                }
            }
        }
        Ok((code, text))
    }

    fn expect(&mut self, ok: &[u32]) -> io::Result<String> {
        let (code, text) = self.reply()?;
        if ok.contains(&code) { Ok(text) } else { Err(ftp_err(code, text.trim())) }
    }

    fn cmd(&mut self, c: &str) -> io::Result<(u32, String)> {
        self.w.write_all(format!("{c}\r\n").as_bytes())?;
        self.reply()
    }

    fn cmd_ok(&mut self, c: &str, ok: &[u32]) -> io::Result<String> {
        let (code, text) = self.cmd(c)?;
        if ok.contains(&code) { Ok(text) } else { Err(ftp_err(code, c.split(' ').next().unwrap_or(c))) }
    }

    /// PASV, then `c` (after an optional REST): the data connection once the server says 1xx.
    fn transfer(&mut self, c: &str, rest: Option<u64>) -> io::Result<TcpStream> {
        let text = self.cmd_ok("PASV", &[227])?;
        let nums: Vec<u16> = text
            .split(|ch: char| !ch.is_ascii_digit())
            .filter(|s| !s.is_empty())
            .skip(1) // the reply code
            .filter_map(|s| s.parse().ok())
            .collect();
        if nums.len() < 6 {
            return Err(io::Error::other(format!("bad PASV reply {text:?}")));
        }
        let port = nums[4] * 256 + nums[5];
        // The PS5 may announce 0.0.0.0 or a private address: use the control peer.
        let data = TcpStream::connect_timeout(&SocketAddr::new(self.peer, port), Duration::from_secs(10))?;
        data.set_read_timeout(Some(self.timeout))?;
        if let Some(off) = rest.filter(|&o| o > 0) {
            self.cmd_ok(&format!("REST {off}"), &[350])?;
        }
        self.cmd_ok(c, &[125, 150])?;
        Ok(data)
    }
}

/// A RETR's data connection; the control connection stays open while it is read.
struct FtpStream {
    _control: Control,
    data: TcpStream,
}

impl Read for FtpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.data.read(buf)
    }
}

impl Console for FtpConsole {
    fn list(&self, path: &str) -> io::Result<Option<Vec<Entry>>> {
        let mut c = self.connect()?;
        // ftpsrv has no NLST; LIST works.
        let mut data = match c.transfer(&format!("LIST {path}"), None) {
            Ok(d) => d,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let mut raw = String::new();
        data.read_to_string(&mut raw)?;
        drop(data);
        let _ = c.reply();
        let mut out = Vec::new();
        for line in raw.lines() {
            let p: Vec<&str> = line.splitn(9, char::is_whitespace).filter(|s| !s.is_empty()).collect();
            // `splitn` on single spaces leaves runs; re-split robustly.
            let p: Vec<&str> = if p.len() < 9 { line.split_whitespace().collect() } else { p };
            if p.len() < 9 {
                continue;
            }
            // The name is everything after the 8th field.
            let name = nth_field_rest(line, 8);
            if name == "." || name == ".." || name.is_empty() {
                continue;
            }
            let is_dir = line.starts_with('d');
            out.push((name.to_string(), is_dir, p[4].parse().unwrap_or(0)));
        }
        Ok(Some(out))
    }

    fn size(&self, path: &str) -> io::Result<Option<u64>> {
        let mut c = self.connect()?;
        match c.cmd(&format!("SIZE {path}"))? {
            (213, text) => Ok(text[4..].trim().parse().ok()),
            _ => {
                // Fall back to the parent's listing (and refuse folders).
                let (parent, name) = path.rsplit_once('/').unwrap_or(("/", path));
                Ok(self.list(if parent.is_empty() { "/" } else { parent })?.and_then(|es| {
                    es.into_iter().find(|(n, d, _)| n == name && !d).map(|(_, _, s)| s)
                }))
            }
        }
    }

    fn read(&self, path: &str, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        let mut c = self.connect()?;
        let data = c.transfer(&format!("RETR {path}"), Some(offset))?;
        let mut buf = Vec::with_capacity(len);
        (&data).take(len as u64).read_to_end(&mut buf)?;
        Ok(buf)
    }

    fn stream(&self, path: &str, offset: u64) -> io::Result<Box<dyn Read + Send>> {
        let mut c = self.connect()?;
        let data = c.transfer(&format!("RETR {path}"), Some(offset))?;
        Ok(Box::new(FtpStream { _control: c, data }))
    }
}

/// The text of `line` from its `n`th whitespace-separated field on.
fn nth_field_rest(line: &str, n: usize) -> &str {
    let mut rest = line.trim_start();
    for _ in 0..n {
        match rest.find(char::is_whitespace) {
            Some(i) => rest = rest[i..].trim_start(),
            None => return "",
        }
    }
    rest.trim_end_matches(['\r', '\n'])
}

#[cfg(test)]
mod tests {
    use super::nth_field_rest;

    #[test]
    fn list_names_keep_spaces() {
        let l = "-rw-r--r-- 1 root wheel 12 Jan  1 00:00 a name with spaces.txt";
        assert_eq!(nth_field_rest(l, 8), "a name with spaces.txt");
    }
}
