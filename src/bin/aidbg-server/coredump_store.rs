use aidbg::Result;
use aidbg::coredump::{Dump, hash_reader, valid_dump_id};
use aidbg::rpc::{CoredumpJob, CoredumpJobState};
use nix::libc;
use prost::Message;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tonic::Status;

const MAX_JOBS: usize = 1024;
const MAX_PENDING: usize = 8;

#[derive(Serialize, Deserialize)]
struct Manifest {
    request: Vec<u8>,
    expires_unix_secs: u64,
    state: State,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum State {
    Pending,
    Ready {
        size: u64,
        sha256: [u8; 32],
        summary: serde_json::Value,
    },
    Failed {
        message: String,
    },
}

impl Manifest {
    fn job(&self, id: &str) -> Result<CoredumpJob> {
        let mut job = CoredumpJob {
            dump_id: id.to_owned(),
            expires_unix_secs: self.expires_unix_secs,
            ..Default::default()
        };
        match &self.state {
            State::Pending => job.state = CoredumpJobState::CoredumpPending as i32,
            State::Ready {
                size,
                sha256,
                summary,
            } => {
                job.state = CoredumpJobState::CoredumpReady as i32;
                job.compressed_bytes = *size;
                job.sha256 = sha256.to_vec();
                job.summary_json = serde_json::to_vec(summary)?;
            }
            State::Failed { message } => {
                job.state = CoredumpJobState::CoredumpFailed as i32;
                job.error = message.clone();
            }
        }
        Ok(job)
    }

    fn expired(&self, at: u64) -> bool {
        self.expires_unix_secs != 0 && self.expires_unix_secs <= at
    }
}

pub(super) struct DumpStore {
    root: PathBuf,
    retention_secs: u64,
    max_bytes: u64,
}

pub(super) struct Download {
    pub reader: io::Take<io::Chain<File, File>>,
    _pin: File,
}

fn lock(path: &Path, operation: libc::c_int) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::other("invalid coredump lock file"));
    }
    nix::errno::Errno::result(unsafe { libc::flock(file.as_raw_fd(), operation) })
        .map_err(io::Error::from)?;
    Ok(file)
}

fn load(dir: &Path) -> io::Result<Manifest> {
    let bytes = fs::read(dir.join("job.json"))?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn save(dir: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    let mut file = tempfile::NamedTempFile::new_in(dir)?;
    file.write_all(bytes)?;
    file.as_file().sync_all()?;
    file.persist(dir.join(name))?;
    File::open(dir)?.sync_all()?;
    Ok(())
}

fn save_manifest(dir: &Path, manifest: &Manifest) -> Result<()> {
    save(dir, "job.json", &serde_json::to_vec(manifest)?)
}

fn discard_artifact(dir: &Path) -> io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_name() != "job.json"
            && entry.file_name() != "active.lock"
            && entry.file_type()?.is_file()
        {
            fs::remove_file(entry.path())?;
        }
    }
    Ok(())
}

fn check_id(id: &str) -> std::result::Result<(), Status> {
    if !valid_dump_id(id) {
        return Err(Status::invalid_argument("invalid coredump ID"));
    }
    Ok(())
}

fn missing() -> Status {
    Status::not_found("coredump not found or retention expired")
}

impl DumpStore {
    pub(super) fn retain(
        &self,
        id: &str,
        seconds: u64,
    ) -> std::result::Result<CoredumpJob, Status> {
        if !(1..=30 * 86400).contains(&seconds) {
            return Err(Status::invalid_argument(
                "retention_secs must be in 1..=2592000",
            ));
        }
        let _lock = self.catalog_lock().map_err(super::internal)?;
        let mut artifact = self.manifest(id)?;
        if !matches!(artifact.state, State::Ready { .. }) {
            return Err(Status::failed_precondition("coredump is not ready"));
        }
        artifact.expires_unix_secs = artifact.expires_unix_secs.max(now() + seconds);
        save_manifest(&self.path(id), &artifact).map_err(super::internal)?;
        artifact.job(id).map_err(super::internal)
    }

    pub(super) fn upload_limit(&self, kind: aidbg::rpc::artifact_header::Kind) -> u64 {
        use aidbg::rpc::artifact_header::Kind;
        self.max_bytes.min(match kind {
            Kind::Core => u64::MAX,
            _ => 128 * 1024 * 1024,
        })
    }

    pub(super) fn upload_directory(&self) -> &Path {
        &self.root
    }

    pub(super) fn commit_upload(
        &self,
        mut payload: tempfile::NamedTempFile,
        kind: aidbg::rpc::artifact_header::Kind,
    ) -> Result<serde_json::Value> {
        use aidbg::rpc::artifact_header::Kind;
        use std::os::unix::fs::PermissionsExt;
        let mut ident = [0; 20];
        payload.as_file_mut().read_exact(&mut ident)?;
        let compressed = ident.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]);
        payload.rewind()?;
        if compressed && kind == Kind::Core {
            zstd::stream::read::Decoder::new(payload.as_file_mut())?.read_exact(&mut ident)?;
        }
        let elf_type = u16::from_le_bytes([ident[16], ident[17]]);
        if !ident.starts_with(b"\x7fELF")
            || ident[4..6] != [2, 1]
            || match kind {
                Kind::Core => elf_type != 4,
                Kind::Executable => !matches!(elf_type, 2 | 3),
                Kind::DebugSymbols => elf_type == 4,
            }
        {
            return Err(aidbg::Diagnostic::new(
                "INVALID_ARTIFACT",
                "Expected a matching 64-bit little-endian ELF artifact",
                None,
            )
            .into());
        }
        payload.rewind()?;
        if kind == Kind::Core && !compressed {
            let mut encoder =
                zstd::stream::write::Encoder::new(tempfile::NamedTempFile::new_in(&self.root)?, 1)?;
            io::copy(&mut payload, &mut encoder)?;
            payload = encoder.finish()?;
            payload.rewind()?;
        }
        let token = tempfile::Builder::new()
            .prefix(".upload-")
            .rand_bytes(32)
            .tempfile_in(&self.root)?;
        let name = token
            .path()
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap();
        let id = name.strip_prefix(".upload-").unwrap();
        let (_, guard) = self.reserve(id, vec![])?;
        let _guard = guard.ok_or_else(|| io::Error::other("artifact ID collision"))?;
        let dir = self.path(id);
        let result: Result<_> = (|| {
            let size = payload.as_file().metadata()?.len();
            let mut hash = Sha256::new();
            hash_reader(&mut payload, &mut hash)?;
            let sha256 = hash.finalize().into();
            let artifact = match kind {
                Kind::Core => "core",
                Kind::Executable => "executable",
                Kind::DebugSymbols => "debug_symbols",
            };
            let summary = serde_json::json!({"status": "complete", "artifact": artifact, "compressed_bytes": size, "warnings": []});
            if kind == Kind::Executable {
                payload
                    .as_file()
                    .set_permissions(fs::Permissions::from_mode(0o700))?;
            }
            payload.as_file().sync_all()?;
            let path = dir.join("payload.zst");
            save(&dir, "header.zst", &[])?;
            payload.persist_noclobber(&path)?;
            let path = fs::canonicalize(path)?;
            self.mark_ready(id, size, sha256, summary)?;
            let job = self.get(id)?;
            Ok(
                serde_json::json!({"artifact_id": id, "kind": artifact, "size": size, "expires_unix_secs": job.expires_unix_secs,
                "dump_id": (kind == Kind::Core).then_some(id), "server_path": (kind != Kind::Core).then_some(path)}),
            )
        })();
        if let Err(ref issue) = result {
            self.fail(id, issue.to_string())?;
        }
        result
    }

    pub(super) fn capture_signal(
        &self,
        pid: i32,
        capture: &mut dyn FnMut(&Path) -> Result<Dump>,
    ) -> Result<serde_json::Value> {
        let token = tempfile::Builder::new()
            .prefix(".run-")
            .rand_bytes(32)
            .tempfile_in(&self.root)?;
        let id = token
            .path()
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.strip_prefix(".run-"))
            .filter(|id| valid_dump_id(id))
            .ok_or_else(|| io::Error::other("could not generate coredump ID"))?;
        let request = aidbg::rpc::CoredumpRequest {
            run_id: None,
            pid,
            mode: aidbg::rpc::CoreMode::CoreFull as i32,
            ..Default::default()
        };
        let (_, guard) = self.reserve(id, request.encode_to_vec())?;
        let _guard = guard.ok_or_else(|| io::Error::other("coredump ID collision"))?;
        let result: Result<_> = (|| {
            let dump = capture(&self.path(id))?;
            let summary = serde_json::to_value(&dump.summary)?;
            self.finish(id, dump)?;
            Ok(serde_json::json!({ "dump_id": id, "summary": summary }))
        })();
        if let Err(error) = &result {
            if let Err(store_error) = self.fail(id, error.to_string()) {
                eprintln!("Could not save failed signal coredump status: {store_error}");
            }
        }
        result
    }

    pub(super) fn open(state_dir: &Path, retention_secs: u64, max_bytes: u64) -> Result<Self> {
        let root = state_dir.join("coredumps");
        match DirBuilder::new().mode(0o700).create(&root) {
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            result => result?,
        }
        if !fs::symlink_metadata(&root)?.is_dir() {
            return Err(io::Error::other("coredump state must be a real directory").into());
        }
        super::private_directory(&root)?;
        let store = Self {
            root,
            retention_secs,
            max_bytes,
        };
        store.prune()?;
        Ok(store)
    }

    fn catalog_lock(&self) -> Result<File> {
        Ok(lock(&self.root.join(".lock"), libc::LOCK_EX)?)
    }

    // Called with the catalog locked. A pending worker holds its own lock
    // until completion, and each open download takes a shared lock.
    fn prune_locked(&self, at: u64) -> Result<Vec<(String, Manifest)>> {
        let mut entries = Vec::new();
        for dir in fs::read_dir(&self.root)? {
            let dir = dir?;
            let id = dir.file_name().to_string_lossy().into_owned();
            if !valid_dump_id(&id) || !dir.file_type()?.is_dir() {
                continue;
            }
            let path = dir.path();
            let mut manifest = match load(&path) {
                Ok(manifest) => manifest,
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    fs::remove_dir_all(path)?;
                    continue;
                }
                Err(e) => return Err(e.into()),
            };
            if matches!(manifest.state, State::Pending) || manifest.expired(at) {
                match lock(&path.join("active.lock"), libc::LOCK_EX | libc::LOCK_NB) {
                    Ok(_idle) => {
                        if manifest.expired(at) {
                            fs::remove_dir_all(&path)?;
                            continue;
                        }
                        // There is no worker on any daemon still holding this capture.
                        discard_artifact(&path)?;
                        manifest.state = State::Failed {
                            message: "server stopped before the core was saved".into(),
                        };
                        manifest.expires_unix_secs = at.saturating_add(self.retention_secs);
                        save_manifest(&path, &manifest)?;
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(e) => return Err(e.into()),
                }
            }
            entries.push((id, manifest));
        }
        Ok(entries)
    }

    pub(super) fn prune(&self) -> Result<()> {
        let _catalog = self.catalog_lock()?;
        self.prune_locked(now())?;
        Ok(())
    }

    pub(super) fn path(&self, id: &str) -> PathBuf {
        self.root.join(id)
    }

    pub(super) fn existing_capture(
        &self,
        id: &str,
        request: &[u8],
    ) -> std::result::Result<CoredumpJob, Status> {
        let entry = self.manifest(id)?;
        if entry.request != request {
            return Err(Status::already_exists(
                "coredump ID belongs to a different capture",
            ));
        }
        entry.job(id).map_err(super::internal)
    }

    pub(super) fn reserve(
        &self,
        id: &str,
        request: Vec<u8>,
    ) -> std::result::Result<(CoredumpJob, Option<File>), Status> {
        check_id(id)?;
        let at = now();
        let _catalog = self.catalog_lock().map_err(super::internal)?;
        let entries = self.prune_locked(at).map_err(super::internal)?;
        if let Some((_, entry)) = entries.iter().find(|(key, _)| key == id) {
            if entry.expired(at) {
                return Err(missing());
            }
            if entry.request != request {
                return Err(Status::already_exists(
                    "coredump ID belongs to a different capture",
                ));
            }
            return entry
                .job(id)
                .map(|job| (job, None))
                .map_err(super::internal);
        }
        if entries.len() >= MAX_JOBS
            || entries
                .iter()
                .filter(|(_, entry)| matches!(entry.state, State::Pending))
                .count()
                >= MAX_PENDING
        {
            return Err(Status::resource_exhausted(
                "coredump job capacity exhausted",
            ));
        }
        let dir = self.path(id);
        DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .map_err(super::internal)?;
        let reserved = (|| -> Result<_> {
            let guard = lock(&dir.join("active.lock"), libc::LOCK_EX)?;
            let manifest = Manifest {
                request,
                expires_unix_secs: 0,
                state: State::Pending,
            };
            save_manifest(&dir, &manifest)?;
            File::open(&self.root)?.sync_all()?;
            Ok((manifest.job(id)?, Some(guard)))
        })();
        if reserved.is_err() {
            let _ = fs::remove_dir_all(&dir);
        }
        reserved.map_err(super::internal)
    }

    fn manifest(&self, id: &str) -> std::result::Result<Manifest, Status> {
        check_id(id)?;
        let entry = load(&self.path(id)).map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                missing()
            } else {
                super::internal(e)
            }
        })?;
        if entry.expired(now()) {
            return Err(missing());
        }
        Ok(entry)
    }

    pub(super) fn get(&self, id: &str) -> std::result::Result<CoredumpJob, Status> {
        self.manifest(id)?.job(id).map_err(super::internal)
    }

    pub(super) fn finish(&self, id: &str, mut dump: Dump) -> Result<()> {
        let dir = self.path(id);
        let summary = serde_json::to_value(&dump.summary)?;
        let size = dump.header.len() as u64 + dump.payload.as_file().metadata()?.len();
        if size > self.max_bytes {
            return Err(io::Error::other("coredump exceeds the retained-artifact quota").into());
        }
        let mut hash = Sha256::new();
        hash.update(&dump.header);
        dump.payload.rewind()?;
        let hashed_payload = hash_reader(&mut dump.payload, &mut hash)?;
        if dump.header.len() as u64 + hashed_payload != size {
            return Err(io::Error::other("coredump payload length changed while hashing").into());
        }
        let sha256 = hash.finalize().into();
        dump.payload.as_file().sync_all()?;
        save(&dir, "header.zst", &dump.header)?;
        dump.payload.persist_noclobber(dir.join("payload.zst"))?;

        self.mark_ready(id, size, sha256, summary)
    }

    fn mark_ready(
        &self,
        id: &str,
        size: u64,
        sha256: [u8; 32],
        summary: serde_json::Value,
    ) -> Result<()> {
        let dir = self.path(id);
        let at = now();
        let _catalog = self.catalog_lock()?;
        let used = self
            .prune_locked(at)?
            .iter()
            .fold(0_u64, |total, (_, entry)| match entry.state {
                State::Ready { size, .. } => total.saturating_add(size),
                _ => total,
            });
        if size > self.max_bytes.saturating_sub(used) {
            return Err(io::Error::other("coredump retention quota exhausted").into());
        }
        let mut manifest = load(&dir)?;
        manifest.expires_unix_secs = at.saturating_add(self.retention_secs);
        manifest.state = State::Ready {
            size,
            sha256,
            summary,
        };
        save_manifest(&dir, &manifest)
    }

    pub(super) fn fail(&self, id: &str, message: String) -> Result<()> {
        let dir = self.path(id);
        let mut manifest = load(&dir)?;
        manifest.state = State::Failed { message };
        manifest.expires_unix_secs = now().saturating_add(self.retention_secs);
        let cleaned = discard_artifact(&dir);
        save_manifest(&dir, &manifest)?;
        Ok(cleaned?)
    }

    pub(super) fn download(&self, id: &str, offset: u64) -> std::result::Result<Download, Status> {
        let _catalog = self.catalog_lock().map_err(super::internal)?;
        let entry = self.manifest(id)?;
        let State::Ready { size, .. } = entry.state else {
            return Err(Status::failed_precondition("coredump is not ready"));
        };
        if offset > size {
            return Err(Status::out_of_range(
                "coredump offset exceeds the saved size",
            ));
        }
        let dir = self.path(id);
        let pin = lock(&dir.join("active.lock"), libc::LOCK_SH).map_err(super::internal)?;
        let mut header = File::open(dir.join("header.zst")).map_err(super::internal)?;
        let mut payload = File::open(dir.join("payload.zst")).map_err(super::internal)?;
        let header_len = header.metadata().map_err(super::internal)?.len();
        let payload_len = payload.metadata().map_err(super::internal)?.len();
        if header_len.checked_add(payload_len) != Some(size) {
            return Err(Status::data_loss("saved coredump length changed"));
        }
        header
            .seek(SeekFrom::Start(offset.min(header_len)))
            .map_err(super::internal)?;
        payload
            .seek(SeekFrom::Start(offset.saturating_sub(header_len)))
            .map_err(super::internal)?;
        Ok(Download {
            reader: header.chain(payload).take(size - offset),
            _pin: pin,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "coredumpA0123456789testABCDEFGHI";

    #[test]
    fn repeated_start_keeps_the_job_and_restart_marks_pending_failed() -> Result<()> {
        let root = tempfile::tempdir()?;
        let store = DumpStore::open(root.path(), 60, 1024)?;
        let (job, worker) = store.reserve(ID, vec![1])?;
        assert!(worker.is_some());
        assert_eq!(job.state, CoredumpJobState::CoredumpPending as i32);
        assert!(store.reserve(ID, vec![1])?.1.is_none());
        assert_eq!(
            store.reserve(ID, vec![2]).unwrap_err().code(),
            tonic::Code::AlreadyExists
        );
        assert_eq!(
            store.get("../wrong").unwrap_err().code(),
            tonic::Code::InvalidArgument
        );
        let other = DumpStore::open(root.path(), 60, 1024)?;
        assert_eq!(
            other.get(ID)?.state,
            CoredumpJobState::CoredumpPending as i32
        );
        drop(other);
        drop(worker);
        drop(store);

        let store = DumpStore::open(root.path(), 60, 1024)?;
        let job = store.get(ID)?;
        assert_eq!(job.state, CoredumpJobState::CoredumpFailed as i32);
        assert!(job.error.contains("server stopped"));
        assert!(store.reserve(ID, vec![1])?.1.is_none());
        Ok(())
    }

    #[test]
    fn compressed_offsets_cross_frames_and_downloads_pin_expired_files() -> Result<()> {
        let root = tempfile::tempdir()?;
        let store = DumpStore::open(root.path(), 60, 1024)?;
        let (_, worker) = store.reserve(ID, Vec::new())?;
        let dir = store.path(ID);
        save(&dir, "header.zst", b"head")?;
        save(&dir, "payload.zst", b"body")?;
        let mut manifest = load(&dir)?;
        manifest.state = State::Ready {
            size: 8,
            sha256: [0; 32],
            summary: serde_json::Value::Null,
        };
        save_manifest(&dir, &manifest)?;
        drop(worker);
        for (offset, expected) in [
            (0, "headbody"),
            (3, "dbody"),
            (4, "body"),
            (7, "y"),
            (8, ""),
        ] {
            let mut download = store.download(ID, offset)?;
            let mut body = String::new();
            download.reader.read_to_string(&mut body)?;
            assert_eq!(body, expected);
        }
        assert_eq!(
            store.download(ID, 9).err().unwrap().code(),
            tonic::Code::OutOfRange
        );
        let download = store.download(ID, 0)?;
        manifest.expires_unix_secs = now();
        save_manifest(&dir, &manifest)?;
        store.prune()?;
        assert!(dir.exists());
        assert_eq!(
            store.download(ID, 0).err().unwrap().code(),
            tonic::Code::NotFound
        );
        drop(download);
        store.prune()?;
        assert!(!dir.exists());
        Ok(())
    }
}
