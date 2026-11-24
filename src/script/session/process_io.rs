use crate::{Result, error};
use nix::{
    fcntl::{FcntlArg, OFlag, fcntl},
    unistd::pipe2,
};
use serde_json::{Value, json};
use std::{
    collections::VecDeque,
    fs::File,
    io::{self, Read, Write},
    os::fd::OwnedFd,
};

const LIMIT: usize = 1024 * 1024;
const TICK_LIMIT: usize = 64 * 1024;

struct Chunk {
    sequence: u64,
    stream: usize,
    text: String,
}

#[derive(Default)]
struct Cursor {
    next: u64,
    truncated: bool,
}

struct Reader {
    file: Option<File>,
    incomplete: Vec<u8>,
}

pub(super) struct ChildIo {
    pub stdin: OwnedFd,
    pub stdout: OwnedFd,
    pub stderr: OwnedFd,
}

pub(super) struct ProcessIo {
    stdin: Option<File>,
    readers: [Reader; 2],
    chunks: VecDeque<Chunk>,
    cursors: [Cursor; 4],
    next: u64,
    size: usize,
}

impl ProcessIo {
    pub fn new() -> Result<(Self, ChildIo)> {
        let (child_stdin, stdin) = pipe2(OFlag::O_CLOEXEC)?;
        let (stdout, child_stdout) = pipe2(OFlag::O_CLOEXEC)?;
        let (stderr, child_stderr) = pipe2(OFlag::O_CLOEXEC)?;
        for fd in [&stdin, &stdout, &stderr] {
            let flags = OFlag::from_bits_truncate(fcntl(fd, FcntlArg::F_GETFL)?);
            fcntl(fd, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK))?;
        }
        let readers = [stdout, stderr].map(|fd| Reader {
            file: Some(fd.into()),
            incomplete: Vec::new(),
        });
        Ok((
            Self {
                stdin: Some(stdin.into()),
                readers,
                chunks: VecDeque::new(),
                cursors: std::array::from_fn(|_| Cursor::default()),
                next: 0,
                size: 0,
            },
            ChildIo {
                stdin: child_stdin,
                stdout: child_stdout,
                stderr: child_stderr,
            },
        ))
    }

    pub fn drain(&mut self) -> Result<()> {
        let mut bytes = [0; 8192];
        // Alternate the pipes so one noisy stream cannot hide the other.
        for _ in 0..TICK_LIMIT / (2 * bytes.len()) {
            let mut progress = false;
            for stream in 0..2 {
                let reader = &mut self.readers[stream];
                let Some(file) = &mut reader.file else {
                    continue;
                };
                let result = file.read(&mut bytes);
                let text = match result {
                    Ok(0) => {
                        reader.file = None;
                        String::from_utf8_lossy(&std::mem::take(&mut reader.incomplete))
                            .into_owned()
                    }
                    Ok(count) => {
                        progress = true;
                        let mut data = std::mem::take(&mut reader.incomplete);
                        data.extend_from_slice(&bytes[..count]);
                        let incomplete = data
                            .utf8_chunks()
                            .last()
                            .map(|chunk| chunk.invalid())
                            .filter(|invalid| {
                                std::str::from_utf8(invalid)
                                    .is_err_and(|err| err.error_len().is_none())
                            })
                            .map_or(0, <[u8]>::len);
                        reader.incomplete = data.split_off(data.len() - incomplete);
                        String::from_utf8_lossy(&data).into_owned()
                    }
                    Err(err)
                        if err.kind() == io::ErrorKind::WouldBlock
                            || err.kind() == io::ErrorKind::Interrupted =>
                    {
                        continue;
                    }
                    Err(err) => return Err(err.into()),
                };
                if !text.is_empty() {
                    self.push(stream, text);
                }
            }
            if !progress {
                break;
            }
        }
        Ok(())
    }

    fn push(&mut self, stream: usize, text: String) {
        while self.size + text.len() > LIMIT {
            let Some(old) = self.chunks.pop_front() else {
                break;
            };
            self.size -= old.text.len();
            for (index, cursor) in self.cursors.iter_mut().enumerate() {
                if cursor.next <= old.sequence {
                    cursor.truncated |= index >= 2 || index == old.stream;
                    cursor.next = old.sequence + 1;
                }
            }
        }
        self.size += text.len();
        self.chunks.push_back(Chunk {
            sequence: self.next,
            stream,
            text,
        });
        self.next += 1;
    }

    pub fn write(&mut self, value: &str) -> Result<usize> {
        if value.len() > TICK_LIMIT {
            return Err(error("stdin write exceeds 64 KiB"));
        }
        let file = self
            .stdin
            .as_mut()
            .ok_or_else(|| error("target stdin is closed"))?;
        match file.write(value.as_bytes()) {
            Ok(count) => Ok(count),
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => Ok(0),
            Err(err) => Err(err.into()),
        }
    }

    pub fn close_input(&mut self) {
        self.stdin = None;
    }

    pub fn read(&mut self, index: usize) -> Value {
        let cursor = &mut self.cursors[index];
        let mut text = String::new();
        for chunk in self
            .chunks
            .iter()
            .filter(|chunk| chunk.sequence >= cursor.next)
        {
            if index >= 2 || index == chunk.stream {
                text.push_str(&chunk.text);
            }
        }
        cursor.next = self.next;
        let eof = if index < 2 {
            self.readers[index].file.is_none()
        } else {
            self.readers.iter().all(|reader| reader.file.is_none())
        };
        json!({"text":text,"eof":eof,"truncated":std::mem::take(&mut cursor.truncated)})
    }

    pub fn mcp_output(&self) -> (Value, u64) {
        let cursor = &self.cursors[3];
        let mut parts = [String::new(), String::new()];
        let mut next = cursor.next;
        let mut size = 0;
        for chunk in self
            .chunks
            .iter()
            .filter(|chunk| chunk.sequence >= cursor.next)
        {
            if size + chunk.text.len() > TICK_LIMIT {
                break;
            }
            parts[chunk.stream].push_str(&chunk.text);
            size += chunk.text.len();
            next = chunk.sequence + 1;
        }
        (
            json!({"stdout":parts[0],"stderr":parts[1],"truncated":cursor.truncated}),
            next,
        )
    }

    pub fn acknowledge(&mut self, next: u64) {
        self.cursors[3] = Cursor {
            next,
            truncated: false,
        };
    }
}
