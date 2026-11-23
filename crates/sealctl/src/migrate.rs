//! Changing words (SPEC 16): rewrap every object to the phone's new words (`rewrap`), objects
//! sealed with retired words (`old_words`), re-encryption of sparse bundles and restic
//! repositories under new ids, and `--scan` for objects found by their markers.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use sealctl_core::sealed::Mode;
use sealctl_core::wire::{ObjectFacts, ReplyBody, RequestItem, Subject};
use sealctl_core::ObjectKey;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::approve::{self, Asked};
use crate::backup::{Backup, Repo};
use crate::exit::{self, fail};
use crate::machine::{self, Paired};
use crate::relay::{self, Relay};
use crate::store::Store;
use crate::volume::{self, Kind, Volume};
use crate::{paths, term, util};

/// One object this machine holds a key of.
#[derive(Debug, Clone)]
pub enum Obj {
    /// The secret store.
    Store(Store),
    /// One own-approval secret (its file id, its name).
    Own(String, String),
    /// A volume.
    Volume(Volume),
    /// A restic backup.
    Backup(Backup),
}

impl Obj {
    /// The key item, with the words and check on file.
    pub fn item(&self) -> Result<RequestItem> {
        Ok(match self {
            Obj::Store(s) => s.request_item()?,
            Obj::Own(id, name) => {
                let store = Store::configured()?;
                let h = store.header(name)?;
                let mut it = crate::store::own_item(&store, &h)?;
                it.id = id.clone();
                it
            }
            Obj::Volume(v) => v.request_item(),
            Obj::Backup(b) => b.request_item(),
        })
    }

    /// `secret store`, `volume safe (APFS)`.
    pub fn label(&self) -> String {
        match self {
            Obj::Store(_) => "secret store".into(),
            Obj::Own(_, n) => format!("secret {n} (own approval)"),
            Obj::Volume(v) => format!("volume {} ({})", v.name, v.kind.label()),
            Obj::Backup(b) => format!("backup {}", b.name),
        }
    }
}

/// Every object of this machine.
pub fn objects() -> Result<Vec<Obj>> {
    let mut out = Vec::new();
    for b in Backup::list()? {
        out.push(Obj::Backup(b));
    }
    for v in Volume::list()? {
        out.push(Obj::Volume(v));
    }
    if let Ok(s) = Store::configured() {
        if s.id_file()?.is_some() {
            let own: Vec<(String, String)> = s
                .list()?
                .into_iter()
                .filter(|l| l.own)
                .filter_map(|l| s.header(&l.name).ok().map(|h| (h.file_id, l.name)))
                .collect();
            out.push(Obj::Store(s));
            for (id, n) in own {
                out.push(Obj::Own(id, n));
            }
        }
    }
    Ok(out)
}

/// Re-seals one object from its old key to its new one; checks the new key opens it first
/// where the tool allows, and updates the markers and definitions.
/// `store_old`: the store's old key from the same reply, to read backup credentials with
/// (the session's store key may be of words the phone no longer has).
pub fn rewrap_one(
    obj: &Obj,
    old: &ObjectKey,
    new: &ObjectKey,
    fp: &str,
    store_old: Option<&ObjectKey>,
) -> Result<()> {
    match obj {
        Obj::Store(store) => {
            // no write through a session's old key between the listing and the new `.id`
            let _lock = store.lock_rewrap()?;
            for l in store.list()? {
                let h = store.header(&l.name)?;
                if h.mode != Mode::StoreKey {
                    continue;
                }
                // a file already on the new key (a resumed rewrap) is left as it is
                if store.read(&l.name, new).is_ok() {
                    continue;
                }
                let v = store.read(&l.name, old)?;
                store.write_moved(&l.name, Mode::StoreKey, new, fp, &v, Some(&h.file_id))?;
            }
            let mut f = store.id_file()?.context("store .id")?;
            f.words = fp.into();
            f.check = new.check();
            store.write_id(&f)
        }
        Obj::Own(id, name) => {
            let store = Store::configured()?;
            let _lock = store.lock_rewrap()?;
            if store.read(name, new).is_err() {
                let v = store.read(name, old)?;
                store.write(name, Mode::OwnApproval, new, fp, &v, Some(id))?;
            }
            store.add_own_check(id, &new.check())
        }
        Obj::Volume(v) => {
            let _lock = v.lock()?;
            let (o, n) = (old.hex(), new.hex());
            match v.kind {
                Kind::Sparsebundle => {
                    let p = v.path.as_ref().context("bundle path")?;
                    if !volume::sparsebundle::verify(p, n.as_bytes())? {
                        volume::sparsebundle::change_passphrase(p, o.as_bytes(), n.as_bytes())?;
                    }
                }
                Kind::Apfs => {
                    if !volume::apfs::verify(&v.id, n.as_bytes())? {
                        volume::apfs::change_passphrase(&v.id, o.as_bytes(), n.as_bytes())?;
                    }
                }
                Kind::Luks => {
                    let p = v.path.as_ref().context("LUKS path")?;
                    if !volume::luks::verify(p, n.as_bytes())? {
                        let out = util::run_with_fds(
                            util::system_cmd("cryptsetup")
                                .args(["luksAddKey", "--key-file", "/dev/fd/3"])
                                .arg(p)
                                .arg("/dev/fd/4"),
                            &[(3, o.as_bytes()), (4, n.as_bytes())],
                            None,
                        )?;
                        util::check(out, "cryptsetup luksAddKey")?;
                    }
                    let out = util::run_with_stdin(
                        util::system_cmd("cryptsetup")
                            .args(["luksRemoveKey", "--key-file=-"])
                            .arg(p),
                        o.as_bytes(),
                    )?;
                    // exit 2: no slot opens with the old key any more (an earlier run removed it)
                    if out.status.code() != Some(2) {
                        util::check(out, "cryptsetup luksRemoveKey")?;
                    }
                }
            }
            let mut nv = v.clone();
            nv.words = fp.into();
            nv.check = new.check();
            volume::write_marker(&nv)?;
            if nv.is_open() {
                volume::write_inner_id(&nv);
            }
            nv.save()
        }
        Obj::Backup(b) => {
            let _lock = crate::backup::lock_repo(&b.repo)?;
            let names = b.credential_names();
            let env = match store_old {
                Some(k) if !names.is_empty() => {
                    let store = Store::configured()?;
                    let mut env = BTreeMap::new();
                    for (n, var) in names.iter().zip(&b.credentials) {
                        let v = store.read(n, k)?;
                        env.insert(
                            var.clone(),
                            zeroize::Zeroizing::new(String::from_utf8_lossy(&v).into_owned()),
                        );
                    }
                    env
                }
                _ => credentials(b, &names)?,
            };
            let oldr = Repo::new(&b.repo, old, env.clone());
            let newr = Repo::new(&b.repo, new, env);
            if !newr.opens().unwrap_or(false) {
                let old_id = oldr
                    .keys()?
                    .into_iter()
                    .find(|k| k.3)
                    .map(|k| k.0)
                    .context("restic key")?;
                let new_id = oldr.key_add(new.hex().as_bytes(), "sealctl", &format!("sealctl-{fp}"))?;
                newr.key_remove(&old_id, &new_id)?;
            }
            let mut nb = b.clone();
            nb.words = fp.into();
            nb.check = new.check();
            nb.save()
        }
    }
}

fn credentials(b: &Backup, names: &[String]) -> Result<BTreeMap<String, zeroize::Zeroizing<String>>> {
    let mut env = BTreeMap::new();
    if names.is_empty() {
        return Ok(env);
    }
    for ((_, v), var) in crate::daemon::client::values(names, Some(("backup", &b.name)))?
        .into_iter()
        .zip(&b.credentials)
    {
        env.insert(
            var.clone(),
            zeroize::Zeroizing::new(String::from_utf8_lossy(&v).into_owned()),
        );
    }
    Ok(env)
}

/// What a rewrap did.
#[derive(Debug, Default, Serialize)]
pub struct Outcome {
    /// Objects moved to the new words.
    pub rewrapped: Vec<String>,
    /// Objects already on the new words.
    pub current: Vec<String>,
    /// Objects the phone could not answer, by words fingerprint (retired words).
    pub retired: BTreeMap<String, Vec<String>>,
    /// Objects that failed.
    pub failed: Vec<(String, String)>,
    /// The phone's words.
    pub words: String,
}

fn send(
    paired: &mut Paired,
    body: sealctl_core::wire::RequestBody,
    show: bool,
) -> Result<(ReplyBody, Option<u8>)> {
    let relay = Relay::new(&paired.file.relay)?;
    let rt = relay::runtime()?;
    let mut number = None;
    let asked = rt.block_on(approve::send(&relay, paired, body, &mut |n| {
        number = n;
        if show {
            eprintln!("{}", term::waiting_line(n, false));
        }
    }))?;
    let Asked::Reply { reply, .. } = asked else {
        return Err(fail(exit::ERROR, "The phone delayed a rewrap."));
    };
    if !reply.ok {
        return Err(approve::refusal(&reply, number, Some("sealctl migrate")));
    }
    Ok((reply, number))
}

fn apply(objs: &[Obj], items: &[RequestItem], reply: &ReplyBody, out: &mut Outcome) {
    let fp = reply.w.clone().unwrap_or_default();
    out.words = fp.clone();
    let store_old = objs.iter().zip(items).find_map(|(o, it)| match o {
        Obj::Store(_) => reply
            .keys
            .iter()
            .find(|k| k.p == it.purpose && k.i == it.id)
            .and_then(|k| k.old.as_ref())
            .and_then(|k| ObjectKey::from_b64u(k).ok()),
        _ => None,
    });
    for (obj, it) in objs.iter().zip(items) {
        let label = obj.label();
        if it.words.as_deref() == Some(fp.as_str()) {
            out.current.push(label);
            continue;
        }
        let Some(k) = reply.keys.iter().find(|k| k.p == it.purpose && k.i == it.id) else {
            out.failed.push((label, "no key in the reply".into()));
            continue;
        };
        if k.err.is_some() {
            out.retired
                .entry(it.words.clone().unwrap_or_default())
                .or_default()
                .push(label);
            continue;
        }
        let (Some(new), Some(old)) = (k.k.as_ref(), k.old.as_ref()) else {
            out.failed.push((label, "no keys".into()));
            continue;
        };
        let (Ok(new), Ok(old)) = (ObjectKey::from_b64u(new), ObjectKey::from_b64u(old)) else {
            out.failed.push((label, "malformed keys".into()));
            continue;
        };
        if it.check.as_deref().is_some_and(|c| c != old.check()) {
            out.failed
                .push((label, "the old key does not match the object".into()));
            continue;
        }
        match rewrap_one(obj, &old, &new, &fp, store_old.as_ref()) {
            Ok(()) => out.rewrapped.push(label),
            Err(e) => out.failed.push((label, exit::message_of(&e))),
        }
    }
}

/// Sends `rewrap` for every object not known to be on the phone's words, then `old_words` for
/// objects on retired words (when `old_words` is true; the phone asks for those words).
/// `show`: a person at the terminal sees the number.
pub fn rewrap_all(show: bool, old_words: bool) -> Result<Outcome> {
    let mut paired = machine::load()?;
    let objs = objects()?;
    let mut out = Outcome::default();
    if objs.is_empty() {
        return Ok(out);
    }
    let items: Vec<RequestItem> = objs.iter().map(Obj::item).collect::<Result<_>>()?;
    let mut body = approve::body("rewrap");
    body.lvl = Some(2);
    body.has_match = show;
    body.keys = items.clone();
    let cwd = std::env::current_dir().unwrap_or_default();
    let mut ctx = approve::context(&paired, None, "sealctl migrate", &cwd);
    ctx.subject = Some(Subject {
        kind: "machine".into(),
        name: "rewrap".into(),
    });
    body.ctx = Some(ctx.clone());
    let (reply, _) = send(&mut paired, body, show)?;
    apply(&objs, &items, &reply, &mut out);
    if old_words {
        for (fp, _) in out.retired.clone() {
            let idx: Vec<usize> = items
                .iter()
                .enumerate()
                .filter(|(_, i)| i.words.as_deref() == Some(fp.as_str()))
                .map(|(i, _)| i)
                .collect();
            let sub_objs: Vec<Obj> = idx.iter().map(|i| objs[*i].clone()).collect();
            let sub_items: Vec<RequestItem> = idx.iter().map(|i| items[*i].clone()).collect();
            let mut b = approve::body("old_words");
            b.lvl = Some(2);
            b.old = Some(fp.clone());
            b.keys = sub_items.clone();
            b.ctx = Some(ctx.clone());
            if show {
                eprintln!("Type the words {fp} on your phone.");
            }
            let (reply, _) = match send(&mut paired, b, show) {
                Ok(r) => r,
                Err(e) => {
                    // objects of the first request may be on the new keys already
                    if !out.rewrapped.is_empty() {
                        crate::daemon::client::stop_running();
                    }
                    return Err(e);
                }
            };
            let mut o2 = Outcome::default();
            apply(&sub_objs, &sub_items, &reply, &mut o2);
            out.retired.remove(&fp);
            out.rewrapped.extend(o2.rewrapped);
            out.failed.extend(o2.failed);
            for (k, v) in o2.retired {
                out.retired.entry(k).or_default().extend(v);
            }
        }
    }
    // the phone now has only the new key for this machine; the old one is not needed
    if out.failed.is_empty() && out.retired.is_empty() && paired.file.previous_phone.take().is_some() {
        paired.file.save()?;
    }
    // keys the daemon holds are of the old words
    crate::daemon::client::stop_running();
    Ok(out)
}

// ---------- re-encryption ----------

/// The job state in `migrate.json`.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Job {
    /// Objects, in order.
    pub items: Vec<JobItem>,
    /// `pause` or `cancel` asked for.
    #[serde(default)]
    pub request: Option<String>,
}

/// One object of the job.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobItem {
    /// `volume` or `backup`.
    pub kind: String,
    /// Its name.
    pub name: String,
    /// `waiting`, `running`, `done`, `failed`, `stopped`, `skipped` (nowhere to put a new copy).
    pub state: String,
    /// The new object id (made when the job starts).
    pub new_id: String,
    /// The last note.
    #[serde(default)]
    pub note: String,
    /// The repository the backup had when its new id was made: removed (a folder) only once the
    /// definition names the new one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old: Option<String>,
}

fn job_path() -> Result<PathBuf> {
    Ok(paths::state_dir()?.join("migrate.json"))
}

fn load_job() -> Option<Job> {
    load_job_at(&job_path().ok()?)
}

fn load_job_at(p: &Path) -> Option<Job> {
    std::fs::read(p)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
}

fn save_job(j: &Job) -> Result<()> {
    save_job_at(&job_path()?, j)
}

fn save_job_at(p: &Path, j: &Job) -> Result<()> {
    paths::ensure_private_dir(p.parent().context("state")?)?;
    paths::write_private(p, &serde_json::to_vec_pretty(j)?)
}

/// The runner's save: the item states from `j`, and the `pause` or `cancel` on file (asked for
/// by `sealctl migrate` while an item ran).
fn save_progress(j: &Job) -> Result<()> {
    save_progress_at(&job_path()?, j)
}

fn save_progress_at(p: &Path, j: &Job) -> Result<()> {
    let _held = lock_job_file(p)?;
    let mut j = j.clone();
    j.request = load_job_at(p).and_then(|d| d.request);
    save_job_at(p, &j)
}

/// `sealctl migrate --pause|--cancel|--resume`: the request on file, the runner's item states
/// as they are. Read and written under the job file's lock, as the runner's saves are, so a
/// runner's save in between is never overwritten with the item states read before it.
fn set_request_at(p: &Path, request: Option<String>) -> Result<Job> {
    let _held = lock_job_file(p)?;
    let mut j = load_job_at(p).ok_or_else(|| fail(exit::NOT_FOUND, "No re-encryption job."))?;
    j.request = request;
    save_job_at(p, &j)?;
    Ok(j)
}

/// The lock around a read and write of `migrate.json` (`migrate.json.lock`); waits, briefly.
fn lock_job_file(p: &Path) -> Result<nix::fcntl::Flock<std::fs::File>> {
    let dir = p.parent().context("state")?;
    paths::ensure_private_dir(dir)?;
    let f = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(dir.join("migrate.json.lock"))?;
    nix::fcntl::Flock::lock(f, nix::fcntl::FlockArg::LockExclusive)
        .map_err(|(_, e)| anyhow::anyhow!("locking the re-encryption job: {e}"))
}

/// One runner at a time: an exclusive lock on `migrate.lock`, held until the process exits.
fn lock_runner(state: &Path) -> Result<()> {
    paths::ensure_private_dir(state)?;
    let f = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(state.join("migrate.lock"))?;
    let held = nix::fcntl::Flock::lock(f, nix::fcntl::FlockArg::LockExclusiveNonblock)
        .map_err(|_| fail(exit::USAGE, "The re-encryption job is already running."))?;
    std::mem::forget(held);
    Ok(())
}

fn dir_size(p: &Path) -> u64 {
    let Ok(m) = std::fs::symlink_metadata(p) else {
        return 0;
    };
    if !m.is_dir() {
        return m.len();
    }
    std::fs::read_dir(p)
        .map(|rd| rd.flatten().map(|e| dir_size(&e.path())).sum())
        .unwrap_or(0)
}

/// Disk speed in bytes per second: write and read back a 16 MiB file next to `near`.
pub fn disk_speed(near: &Path) -> u64 {
    use std::io::{Read, Write};
    let dir = if near.is_dir() {
        near.to_path_buf()
    } else {
        near.parent().unwrap_or(Path::new("/tmp")).to_path_buf()
    };
    let f = dir.join(format!(".sealctl-speed-{}", std::process::id()));
    let data = vec![0x5au8; 16 << 20];
    let t = std::time::Instant::now();
    let ok = (|| -> std::io::Result<()> {
        let mut w = std::fs::File::create(&f)?;
        w.write_all(&data)?;
        w.sync_all()?;
        let mut r = std::fs::File::open(&f)?;
        let mut buf = Vec::new();
        r.read_to_end(&mut buf)?;
        Ok(())
    })();
    let _ = std::fs::remove_file(&f);
    let secs = t.elapsed().as_secs_f64().max(0.001);
    if ok.is_err() {
        return 100 << 20;
    }
    ((2.0 * data.len() as f64) / secs) as u64
}

fn human(bytes: u64) -> String {
    match bytes {
        b if b < 1 << 10 => format!("{b} B"),
        b if b < 1 << 20 => format!("{} KB", b >> 10),
        b if b < 1 << 30 => format!("{} MB", b >> 20),
        b => format!("{:.1} GB", b as f64 / (1u64 << 30) as f64),
    }
}

/// The table `sealctl migrate` prints: object, size, rewrap state, re-encrypt estimate.
pub fn table() -> Result<Vec<serde_json::Value>> {
    let mut rows = Vec::new();
    let speed = disk_speed(&paths::state_dir()?);
    for o in objects()? {
        let (size, re) = match &o {
            Obj::Volume(v) if v.kind == Kind::Sparsebundle => {
                let s = v.path.as_ref().map(|p| dir_size(p)).unwrap_or(0);
                let secs = (s * 2) / speed.max(1);
                (s, Some(secs))
            }
            // APFS and LUKS keep their data key: rewrap covers them
            Obj::Volume(_) => (0, None),
            Obj::Backup(b) if !b.repo.contains(':') => {
                let s = dir_size(Path::new(&b.repo));
                (s, Some((s * 2) / speed.max(1)))
            }
            Obj::Backup(_) => (0, None),
            Obj::Store(s) => (dir_size(&s.dir), None),
            Obj::Own(..) => (0, None),
        };
        let item = o.item()?;
        rows.push(json!({
            "object": o.label(),
            "words": item.words,
            "size": size,
            "sizeText": human(size),
            "reencrypt": re.map(|s| [s * 8 / 10, s * 5 / 4]),
        }));
    }
    Ok(rows)
}

fn print_table(rows: &[serde_json::Value], words: Option<&str>) {
    println!("  {:<34} {:>9}  {:<6}  re-encrypt", "object", "size", "words");
    for r in rows {
        let re = match r["reencrypt"].as_array() {
            Some(a) => format!(
                "about {} to {}",
                crate::daemon::session::duration(a[0].as_u64().unwrap_or(0).max(1)),
                crate::daemon::session::duration(a[1].as_u64().unwrap_or(0).max(1))
            ),
            None => "-".into(),
        };
        let w = r["words"].as_str().unwrap_or("");
        let mark = match words {
            Some(cur) if cur != w => " (old)",
            _ => "",
        };
        println!(
            "  {:<34} {:>9}  {w:<6}{mark}  {re}",
            r["object"].as_str().unwrap_or(""),
            r["sizeText"].as_str().unwrap_or("")
        );
    }
}

/// Options of `sealctl migrate`.
pub struct Opts {
    /// `--status`.
    pub status: bool,
    /// `--scan [PATH...]`.
    pub scan: Option<Vec<PathBuf>>,
    /// `--depth`.
    pub depth: String,
    /// `--yes`.
    pub yes: bool,
    /// `--pause`, `--resume`, `--cancel`.
    pub control: Option<String>,
    /// `--json`.
    pub json: bool,
    /// Hidden `--run-job`.
    pub run_job: bool,
    /// Hidden: run the job here instead of in the background.
    pub foreground: bool,
    /// Hidden: the daemon's own rewrap (no terminal, no old words).
    pub auto: bool,
}

/// `sealctl migrate`.
pub fn run(o: Opts) -> Result<()> {
    if o.run_job {
        return run_job();
    }
    if let Some(c) = o.control {
        let j = set_request_at(&job_path()?, if c == "resume" { None } else { Some(c.clone()) })?;
        if c == "resume" && j.items.iter().any(|i| i.state != "done" && i.state != "skipped") {
            start_job(false)?;
        }
        eprintln!("Re-encryption: {c}.");
        return Ok(());
    }
    if o.status {
        let j = load_job().unwrap_or_default();
        if o.json {
            println!("{}", serde_json::to_string(&j)?);
        } else if j.items.is_empty() {
            println!("No re-encryption job.");
        } else {
            for i in &j.items {
                println!("{} {}: {} {}", i.kind, i.name, i.state, i.note);
            }
        }
        return Ok(());
    }
    if let Some(roots) = o.scan {
        return scan(&roots, o.json);
    }
    term::refuse_agent("sealctl migrate")?;
    let paired = machine::load()?;
    let rows = table()?;
    if o.json && !o.yes {
        println!("{}", json!({"objects": rows}));
        return Ok(());
    }
    if o.depth == "rewrap" {
        let show = term::is_person() && !o.auto;
        let out = rewrap_all(show, !o.auto)?;
        if o.json {
            println!("{}", serde_json::to_string(&out)?);
        }
        report_outcome(&out);
        return if out.failed.is_empty() && out.retired.is_empty() {
            Ok(())
        } else {
            Err(fail(exit::WRONG_KEY, "Some objects stay on old words."))
        };
    }
    // re-encrypt: the table, then the job for sparse bundles and restic repositories
    let _ = paired;
    print_table(&rows, None);
    let candidates: Vec<JobItem> = objects()?
        .into_iter()
        .filter_map(|o| match o {
            Obj::Volume(v) if v.kind == Kind::Sparsebundle => Some(("volume", v.name)),
            Obj::Backup(b) if sibling_repo(&b.repo, "id").is_some() => Some(("backup", b.name)),
            Obj::Backup(b) => {
                eprintln!("backup {}: {}", b.name, no_place_note(&b.repo));
                None
            }
            _ => None,
        })
        .map(|(k, n)| JobItem {
            kind: k.into(),
            name: n,
            state: "waiting".into(),
            new_id: String::new(),
            note: String::new(),
            old: None,
        })
        .collect();
    if candidates.is_empty() {
        eprintln!(
            "Nothing to re-encrypt here (APFS and LUKS volumes keep their data key; rewrap covers them)."
        );
        return Ok(());
    }
    let names: Vec<String> = candidates
        .iter()
        .map(|c| format!("{} {}", c.kind, c.name))
        .collect();
    if !o.yes {
        if !term::is_person() {
            return Ok(());
        }
        if !term::confirm(
            &format!(
                "Re-encrypt {} now? It keeps running if you close the terminal.",
                names.join(" and ")
            ),
            false,
        )? {
            return Ok(());
        }
    }
    save_job(&Job {
        items: candidates,
        request: None,
    })?;
    start_job(o.foreground)
}

fn report_outcome(out: &Outcome) {
    if !out.rewrapped.is_empty() {
        eprintln!(
            "Rewrapped {} objects to words {}.",
            out.rewrapped.len(),
            out.words
        );
    }
    if out.rewrapped.is_empty() && out.failed.is_empty() && out.retired.is_empty() {
        eprintln!("Every object is on words {} already.", out.words);
    }
    for (fp, objs) in &out.retired {
        eprintln!(
            "Sealed with words {fp}: {}. Type those words on the phone: sealctl migrate --depth rewrap",
            objs.join(", ")
        );
    }
    for (o, why) in &out.failed {
        eprintln!("sealctl: {o}: {why}");
    }
}

fn start_job(foreground: bool) -> Result<()> {
    if foreground {
        return run_job();
    }
    let exe = std::env::current_exe()?;
    let log = paths::state_dir()?.join("migrate.log");
    let f = std::fs::OpenOptions::new().create(true).append(true).open(&log)?;
    use std::os::unix::process::CommandExt;
    std::process::Command::new(exe)
        .args(["migrate", "--run-job"])
        .stdin(std::process::Stdio::null())
        .stdout(f.try_clone()?)
        .stderr(f)
        .process_group(0)
        .spawn()
        .context("starting the re-encryption job")?;
    eprintln!("Re-encryption started. Progress: sealctl migrate --status");
    Ok(())
}

fn run_job() -> Result<()> {
    lock_runner(&paths::state_dir()?)?;
    let mut job = load_job().ok_or_else(|| fail(exit::NOT_FOUND, "No re-encryption job."))?;
    for i in 0..job.items.len() {
        if let Some(r) = load_job().and_then(|j| j.request) {
            for it in job.items.iter_mut().filter(|it| it.state == "waiting") {
                it.state = "stopped".into();
                it.note = format!("{r} asked");
            }
            save_progress(&job)?;
            return Ok(());
        }
        if job.items[i].state == "done" {
            continue;
        }
        // a definition changed since the job was made: nothing to fix by resuming
        if job.items[i].kind == "backup" {
            if let Ok(b) = Backup::load(&job.items[i].name) {
                if sibling_repo(&b.repo, "id").is_none() {
                    job.items[i].state = "skipped".into();
                    job.items[i].note = no_place_note(&b.repo);
                    save_progress(&job)?;
                    continue;
                }
            }
        }
        job.items[i].state = "running".into();
        save_progress(&job)?;
        let r = match job.items[i].kind.as_str() {
            "volume" => reencrypt_bundle(&mut job, i),
            _ => reencrypt_backup(&mut job, i),
        };
        match r {
            Ok(note) => {
                job.items[i].state = "done".into();
                job.items[i].note = note;
            }
            Err(e) => {
                job.items[i].state = "failed".into();
                job.items[i].note = exit::message_of(&e);
            }
        }
        save_progress(&job)?;
    }
    for it in &job.items {
        eprintln!("{} {}: {} {}", it.kind, it.name, it.state, it.note);
    }
    if job.items.iter().any(|i| i.state == "failed") {
        return Err(fail(
            exit::PARTWAY,
            "Re-encryption stopped. Fix it, then: sealctl migrate --resume",
        ));
    }
    Ok(())
}

fn new_key(kind: &str, id: &str, path: String) -> Result<(ObjectKey, String)> {
    let item = RequestItem {
        purpose: kind.into(),
        id: id.into(),
        words: None,
        check: None,
        object: Some(ObjectFacts {
            kind: kind.into(),
            path,
            size: 0,
        }),
    };
    crate::daemon::client::new_key(&item, (kind, "migrate"))
}

fn reencrypt_bundle(job: &mut Job, i: usize) -> Result<String> {
    let v = Volume::load(&job.items[i].name)?;
    // nothing else changes, opens or backs up from the bundle while it is copied and swapped
    let _lock = v.lock()?;
    let old_path = v.path.clone().context("bundle path")?;
    if job.items[i].new_id.is_empty() {
        job.items[i].new_id = util::new_uuid()?;
        save_progress(job)?;
    }
    let new_id = job.items[i].new_id.clone();
    let new_path = old_path.with_file_name(format!(".{}.migrating.sparsebundle", v.name));
    let aside = old_path.with_file_name(format!(".{}.old.sparsebundle", v.name));
    if v.id == new_id {
        // an earlier run swapped the bundles and saved the definition
        if aside.exists() {
            std::fs::remove_dir_all(&aside)?;
        }
        return Ok(DONE_NOTE.into());
    }
    if aside.exists() {
        // an earlier run stopped during the swap: the bundles go back to where they were
        if old_path.exists() {
            if new_path.exists() {
                anyhow::bail!(
                    "{}, {} and {} all exist; keep the bundle that opens with the current key",
                    paths::tilde(&old_path),
                    paths::tilde(&new_path),
                    paths::tilde(&aside)
                );
            }
            std::fs::rename(&old_path, &new_path)?;
        }
        std::fs::rename(&aside, &old_path)?;
    }
    let (mut keys, _) = crate::daemon::client::keys(&[v.request_item()], Some(("volume", &v.name)))?;
    let old_key = keys.remove(0);
    let (key, fp) = new_key("volume", &new_id, paths::tilde(&old_path))?;
    if v.is_open() {
        volume::close(&v, false)?;
    }
    if !new_path.exists() {
        let out = util::run_with_stdin(
            util::system_cmd("hdiutil")
                .args([
                    "create",
                    "-quiet",
                    "-size",
                    "1t",
                    "-type",
                    "SPARSEBUNDLE",
                    "-fs",
                    "APFS",
                    "-encryption",
                    "AES-256",
                    "-stdinpass",
                    "-volname",
                ])
                .arg(&v.name)
                .arg(&new_path),
            key.hex().as_bytes(),
        )?;
        util::check(out, "hdiutil create")?;
    }
    let tmp = paths::state_dir()?.join(format!("migrate-{}", std::process::id()));
    let (old_mp, new_mp) = (tmp.join("old"), tmp.join("new"));
    std::fs::create_dir_all(&old_mp)?;
    std::fs::create_dir_all(&new_mp)?;
    let attach = |p: &Path, mp: &Path, k: &ObjectKey, ro: bool| -> Result<()> {
        let mut c = util::system_cmd("hdiutil");
        c.args(["attach", "-quiet", "-stdinpass", "-owners", "on", "-mountpoint"])
            .arg(mp);
        if ro {
            c.arg("-readonly");
        }
        c.arg(p);
        util::check(
            util::run_with_stdin(&mut c, k.hex().as_bytes())?,
            "hdiutil attach",
        )?;
        Ok(())
    };
    attach(&old_path, &old_mp, &old_key, true)?;
    let r = (|| -> Result<()> {
        attach(&new_path, &new_mp, &key, false)?;
        // item by item, leaving out the folders macOS keeps on every volume (root-owned
        // `.fseventsd` can't be read by the user, and the new volume makes its own)
        for e in std::fs::read_dir(&old_mp)? {
            let e = e?;
            if is_system_entry(&e.file_name().to_string_lossy()) {
                continue;
            }
            let out = util::system_cmd("ditto")
                .arg(e.path())
                .arg(new_mp.join(e.file_name()))
                .output()?;
            util::check(out, "ditto")?;
        }
        let count = |d: &Path| walk_count(d);
        if count(&old_mp) != count(&new_mp) {
            anyhow::bail!("the copy differs from the original (file count)");
        }
        Ok(())
    })();
    let new_off = detach(&new_mp);
    let old_off = detach(&old_mp);
    if new_off && old_off {
        // empty folders by now: never anything that could still be a mounted volume
        let _ = std::fs::remove_dir(&new_mp);
        let _ = std::fs::remove_dir(&old_mp);
        let _ = std::fs::remove_dir(&tmp);
    }
    if let Err(e) = r {
        if new_off && old_off {
            return Err(e);
        }
        anyhow::bail!(
            "{}; a copy is still attached under {}: detach it (hdiutil detach), then: sealctl migrate --resume",
            exit::message_of(&e),
            paths::tilde(&tmp)
        );
    }
    if !(new_off && old_off) {
        anyhow::bail!(
            "a copy is still attached under {}; detach it (hdiutil detach), then: sealctl migrate --resume",
            paths::tilde(&tmp)
        );
    }
    // the swap: the old bundle is set aside, and deleted only once the definition names the new one
    std::fs::rename(&old_path, &aside)?;
    let swapped = std::fs::rename(&new_path, &old_path)
        .map_err(anyhow::Error::from)
        .and_then(|()| {
            let mut nv = v.clone();
            nv.id = new_id;
            nv.words = fp;
            nv.check = key.check();
            volume::write_marker(&nv)?;
            nv.save()
        });
    if let Err(e) = swapped {
        if old_path.exists() && !new_path.exists() {
            let _ = std::fs::rename(&old_path, &new_path);
        }
        if !old_path.exists() {
            let _ = std::fs::rename(&aside, &old_path);
        }
        return Err(e);
    }
    std::fs::remove_dir_all(&aside)?;
    Ok(DONE_NOTE.into())
}

const DONE_NOTE: &str = "copied to a new bundle under a new key";

/// True when `p` is the root of a different file system from its parent's (a mount point).
/// A path that cannot be read counts as mounted, unless it is gone.
fn is_mount_point(p: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let parent = p.parent().map(std::fs::metadata);
    match (std::fs::metadata(p), parent) {
        (Err(e), _) if e.kind() == std::io::ErrorKind::NotFound => false,
        (Ok(m), Some(Ok(pm))) => m.dev() != pm.dev(),
        _ => true,
    }
}

/// Detaches the image mounted at `mp`, with `-force` after two tries. True once nothing is
/// mounted there.
fn detach(mp: &Path) -> bool {
    for attempt in 0..4 {
        if !is_mount_point(mp) {
            return true;
        }
        if attempt > 0 {
            std::thread::sleep(std::time::Duration::from_secs(2));
        }
        let mut c = util::system_cmd("hdiutil");
        c.args(["detach", "-quiet"]);
        if attempt >= 2 {
            c.arg("-force");
        }
        let _ = c.arg(mp).output();
    }
    !is_mount_point(mp)
}

/// Folders macOS keeps at the top of every volume; not user data.
fn is_system_entry(name: &str) -> bool {
    matches!(
        name,
        ".fseventsd" | ".Spotlight-V100" | ".Trashes" | ".TemporaryItems" | ".DocumentRevisions-V100"
    )
}

fn walk_count(d: &Path) -> (u64, u64) {
    let mut n = 0;
    let mut size = 0;
    if let Ok(rd) = std::fs::read_dir(d) {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if is_system_entry(&name) {
                continue;
            }
            let p = e.path();
            if p.is_dir() && !p.is_symlink() {
                let (a, b) = walk_count(&p);
                n += a;
                size += b;
            } else {
                n += 1;
                size += e.metadata().map(|m| m.len()).unwrap_or(0);
            }
        }
    }
    (n, size)
}

fn reencrypt_backup(job: &mut Job, i: usize) -> Result<String> {
    let b = Backup::load(&job.items[i].name)?;
    if job.items[i].new_id.is_empty() {
        job.items[i].new_id = util::new_uuid()?;
        job.items[i].old = Some(b.repo.clone());
        save_progress(job)?;
    }
    let new_id = job.items[i].new_id.clone();
    if b.repo_id == new_id {
        // an earlier run saved the definition on the new repository and stopped before the job
        // noted it: only the old repository may be left to remove
        let old = job.items[i].old.clone();
        let _lock = old.as_deref().map(crate::backup::lock_repo).transpose()?;
        return remove_old_repo(&b, old.as_deref());
    }
    // no backup run, rewrap or unseal of this repository while it is copied
    let _lock = crate::backup::lock_repo(&b.repo)?;
    let new_url = sibling_repo(&b.repo, &new_id).ok_or_else(|| fail(exit::USAGE, no_place_note(&b.repo)))?;
    let (mut keys, _) = crate::daemon::client::keys(&[b.request_item()], Some(("backup", &b.name)))?;
    let old_key = keys.remove(0);
    let env = credentials(&b, &b.credential_names())?;
    let (key, fp) = new_key("backup", &new_id, new_url.clone())?;
    let newr = Repo::new(&new_url, &key, env.clone());
    let pw_old = old_key.hex();
    let run_two = |args: &[&str]| -> Result<()> {
        let mut c = newr.command();
        c.env("RESTIC_FROM_REPOSITORY", &b.repo)
            .args(args)
            .args(["--from-password-file", "/dev/fd/3"]);
        let out = util::run_with_fds(&mut c, &[(3, pw_old.as_bytes())], Some(key.hex().as_bytes()))?;
        util::check(out, &format!("restic {}", args[0]))?;
        Ok(())
    };
    if !newr.opens().unwrap_or(false) {
        run_two(&["init", "--copy-chunker-params"])?;
        // restic init names the key after this host; the words go into a key of their own
        let init_key = newr
            .keys()?
            .into_iter()
            .next()
            .map(|k| k.0)
            .context("restic key")?;
        let kid = newr.key_add(key.hex().as_bytes(), "sealctl", &format!("sealctl-{fp}"))?;
        newr.key_remove(&init_key, &kid)?;
    }
    run_two(&["copy"])?;
    let out = newr.output(&["check"])?;
    util::check(out, "restic check")?;
    if job.items[i].old.is_none() {
        job.items[i].old = Some(b.repo.clone());
        save_progress(job)?;
    }
    // the definition names the new repository before the old one goes: a stop in between
    // leaves both, and the resumed job only removes the old one
    let mut nb = b.clone();
    nb.repo = new_url;
    nb.repo_id = new_id;
    nb.words = fp;
    nb.check = key.check();
    nb.save()?;
    crate::seal::journal::test_kill("reencrypt-backup", "saved");
    remove_old_repo(&nb, Some(&b.repo))
}

/// Removes the repository a backup had before its re-encryption: a folder is removed, other
/// back ends are named for the person. Never the one the definition names now. The caller
/// holds the old repository's lock.
fn remove_old_repo(b: &Backup, old: Option<&str>) -> Result<String> {
    let Some(old) = old.filter(|o| *o != b.repo) else {
        return Ok("copied to a new repository".into());
    };
    if !old.contains(':') && Path::new(old).is_dir() {
        let same = std::fs::canonicalize(old).ok() == std::fs::canonicalize(&b.repo).ok();
        if same {
            return Ok("copied to a new repository".into());
        }
        std::fs::remove_dir_all(old)?;
        Ok("copied to a new repository; the old one is removed".to_string())
    } else if !old.contains(':') {
        Ok("copied to a new repository; the old one is removed".to_string())
    } else {
        Ok(format!(
            "copied to {}; delete the old repository {old} in its provider's console",
            b.repo
        ))
    }
}

/// Why a backup is left out of re-encryption: no place for a new repository beside it.
fn no_place_note(repo: &str) -> String {
    format!(
        "not re-encrypted: {repo} has no place beside it on its server for a new repository; it stays on its rewrapped key"
    )
}

/// Where the re-encrypted copy of the restic repository `repo` goes: beside it, its last path
/// segment replaced by `id`, on the same server (and, for B2, GCS, Azure and Swift, in the same
/// bucket or container, which those URLs name before a `:`). On S3 and rclone the last segment
/// may be the bucket itself: `backup init` makes `s3:host/<id>` from a base of `s3:host`, and
/// restic creates the new bucket. None when nothing follows the server or the named bucket (a
/// sibling would be another host or container), or for a URL form not known here.
fn sibling_repo(repo: &str, id: &str) -> Option<String> {
    let repo = repo.trim_end_matches('/');
    let (scheme, rest) = match repo.split_once(':') {
        Some((sch, rest)) if !sch.is_empty() && !sch.contains('/') => (sch, rest),
        _ => ("", repo), // a folder
    };
    // `host://` skipped: where the authority starts
    let after_scheme = |s: &str| s.find("://").map(|i| i + 3);
    // up to and including the first `:` (`bucket:`, `user@host:`)
    let colon = |s: &str| s.find(':').map(|i| i + 1);
    // the part of `rest` naming the server, bucket or container: it stays
    let fixed = match scheme {
        "" | "local" => 0,
        "s3" => {
            let a = after_scheme(rest).unwrap_or(0);
            a + segments_end(&rest[a..], 1)? // host
        }
        "rest" => {
            let a = after_scheme(rest)?;
            a + segments_end(&rest[a..], 1)? // host
        }
        "sftp" if rest.starts_with("//") => 2 + segments_end(&rest[2..], 1)?,
        // `remote:` stays; the path after it may start with `/` (`backup init` makes
        // `rclone:remote:/<id>` from a base of `rclone:remote:`)
        "sftp" | "b2" | "gs" | "azure" | "swift" | "rclone" => colon(rest)?,
        _ => return None,
    };
    let (head, path) = rest.split_at(fixed);
    if path.trim_start_matches('/').is_empty() || (scheme.is_empty() && !path.contains('/')) {
        return None;
    }
    let cut = path.rfind('/').map_or(0, |i| i + 1);
    let scheme = if scheme.is_empty() {
        String::new()
    } else {
        format!("{scheme}:")
    };
    Some(format!("{scheme}{head}{}{id}", &path[..cut]))
}

/// The end of the first `n` non-empty `/`-separated segments of `s`.
fn segments_end(s: &str, n: usize) -> Option<usize> {
    let mut end = 0;
    for k in 0..n {
        let start = if k == 0 { 0 } else { end + 1 };
        let tail = s.get(start..)?;
        let len = tail.find('/').unwrap_or(tail.len());
        if len == 0 {
            return None;
        }
        end = start + len;
    }
    Some(end)
}

/// `--scan`: objects found by their markers under `roots` (default: home and /Volumes).
fn scan(roots: &[PathBuf], json_out: bool) -> Result<()> {
    let roots: Vec<PathBuf> = if roots.is_empty() {
        vec![paths::home()?, PathBuf::from("/Volumes")]
    } else {
        roots.to_vec()
    };
    let mut found = Vec::new();
    fn walk(d: &Path, depth: usize, out: &mut Vec<serde_json::Value>) {
        let Ok(rd) = std::fs::read_dir(d) else { return };
        for e in rd.flatten() {
            let p = e.path();
            let n = e.file_name().to_string_lossy().into_owned();
            if matches!(n.as_str(), "node_modules" | ".git" | "Library" | "target") {
                continue;
            }
            let Ok(ft) = e.file_type() else { continue };
            if ft.is_dir() {
                if let Ok(t) = std::fs::read_to_string(p.join("sealctl.id")) {
                    if let Ok(f) = sealctl_core::ids::IdFile::parse(&t) {
                        out.push(json!({"kind": "volume", "volume": "sparsebundle", "id": f.id, "words": f.words, "path": paths::tilde(&p)}));
                        continue;
                    }
                }
                if let Ok(t) = std::fs::read_to_string(p.join(format!("{n}.id"))) {
                    if let Ok(f) = sealctl_core::ids::IdFile::parse(&t) {
                        out.push(
                            json!({"kind": f.kind, "id": f.id, "words": f.words, "path": paths::tilde(&p)}),
                        );
                        continue;
                    }
                }
                if p.join("keys").is_dir() && p.join("config").is_file() {
                    if let Some(w) = crate::recover::restic_words(&p.to_string_lossy()) {
                        out.push(json!({"kind": "backup", "id": n, "words": w, "path": paths::tilde(&p)}));
                        continue;
                    }
                }
                if depth > 0 {
                    walk(&p, depth - 1, out);
                }
            }
        }
    }
    for r in &roots {
        walk(r, 6, &mut found);
    }
    if json_out {
        println!("{}", json!({"objects": found}));
    } else {
        for f in &found {
            println!(
                "{:<7} {}  {}  {}",
                f["kind"].as_str().unwrap_or(""),
                f["words"].as_str().unwrap_or(""),
                f["id"].as_str().unwrap_or(""),
                f["path"].as_str().unwrap_or("")
            );
        }
        if found.is_empty() {
            eprintln!("No sealctl objects found.");
        }
    }
    Ok(())
}

/// The daemon's rewrap after a move to a new phone key: a separate `sealctl migrate --depth
/// rewrap --auto` (no terminal, so no number: the phone relies on `near`), which stops the
/// daemon when done since its keys are of the old words. Objects that fail stay on the old
/// words for `sealctl migrate` at the terminal.
pub fn rewrap_in_background() {
    let Ok(exe) = std::env::current_exe() else { return };
    let log = paths::state_dir().map(|d| d.join("migrate.log"));
    let f = log
        .ok()
        .and_then(|l| std::fs::OpenOptions::new().create(true).append(true).open(l).ok());
    use std::os::unix::process::CommandExt;
    let mut c = std::process::Command::new(exe);
    c.args(["migrate", "--depth", "rewrap", "--auto"])
        .stdin(std::process::Stdio::null())
        .process_group(0);
    // the daemon may have been started from inside an agent's command; this run is the daemon's
    // own, so the agent refusal of `sealctl migrate` does not apply to it
    for var in crate::guard::agent_variables() {
        c.env_remove(var);
    }
    if let Some(f) = f {
        if let Ok(f2) = f.try_clone() {
            c.stdout(f2);
        }
        c.stderr(f);
    }
    let _ = c.spawn();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sibling_repositories() {
        let s = |r: &str| sibling_repo(r, "NEW");
        // made by sealctl: `<base>/<id>`
        assert_eq!(s("/Users/a/repos/abc").as_deref(), Some("/Users/a/repos/NEW"));
        assert_eq!(s("/Users/a/repos/abc/").as_deref(), Some("/Users/a/repos/NEW"));
        assert_eq!(s("local:/srv/abc").as_deref(), Some("local:/srv/NEW"));
        assert_eq!(
            s("s3:s3.amazonaws.com/bucket/abc").as_deref(),
            Some("s3:s3.amazonaws.com/bucket/NEW")
        );
        assert_eq!(
            s("s3:s3.amazonaws.com/bucket/p/abc").as_deref(),
            Some("s3:s3.amazonaws.com/bucket/p/NEW")
        );
        assert_eq!(
            s("s3:http://minio:9000/bucket/abc").as_deref(),
            Some("s3:http://minio:9000/bucket/NEW")
        );
        assert_eq!(
            s("rest:https://host:8000/abc").as_deref(),
            Some("rest:https://host:8000/NEW")
        );
        assert_eq!(s("b2:bucket:/abc").as_deref(), Some("b2:bucket:/NEW"));
        assert_eq!(s("b2:bucket:abc").as_deref(), Some("b2:bucket:NEW"));
        assert_eq!(s("gs:bucket:/p/abc").as_deref(), Some("gs:bucket:/p/NEW"));
        assert_eq!(
            s("sftp:user@host:/srv/abc").as_deref(),
            Some("sftp:user@host:/srv/NEW")
        );
        assert_eq!(
            s("sftp://user@host:22//srv/abc").as_deref(),
            Some("sftp://user@host:22//srv/NEW")
        );
        assert_eq!(
            s("rclone:remote:bucket/abc").as_deref(),
            Some("rclone:remote:bucket/NEW")
        );
        assert_eq!(
            s("rclone:nas:/backups/abc").as_deref(),
            Some("rclone:nas:/backups/NEW")
        );
        assert_eq!(s("rclone:remote:/abc").as_deref(), Some("rclone:remote:/NEW"));
        // a repository that is the whole bucket: a new bucket beside it, as `backup init` made it
        assert_eq!(
            s("s3:s3.amazonaws.com/bucket").as_deref(),
            Some("s3:s3.amazonaws.com/NEW")
        );
        assert_eq!(s("rclone:remote:bucket").as_deref(), Some("rclone:remote:NEW"));
        // nothing after the server or the named bucket: no place beside it
        assert_eq!(s("s3:s3.amazonaws.com"), None);
        assert_eq!(s("s3:https://minio:9000/"), None);
        assert_eq!(s("rest:https://host:8000/"), None);
        assert_eq!(s("rest:https://host:8000"), None);
        assert_eq!(s("b2:bucket:"), None);
        assert_eq!(s("azure:container:/"), None);
        assert_eq!(s("rclone:remote:"), None);
        assert_eq!(s("rclone:remote:/"), None);
        assert_eq!(s("sftp://user@host:22/"), None);
        assert_eq!(s("sftp:user@host:"), None);
        assert_eq!(s("repo"), None);
        assert_eq!(s("/"), None);
        assert_eq!(s("unknown:thing/abc"), None);
    }

    /// Every base `backup init` takes gives `<base>/<id>`, and its sibling is `<base>/NEW`.
    #[test]
    fn siblings_of_repositories_made_by_init() {
        for base in [
            "/Users/a/repos",
            "/",
            "repos",
            "local:/srv/restic",
            "s3:s3.amazonaws.com",
            "s3:s3.amazonaws.com/bucket",
            "s3:s3.amazonaws.com/bucket/p",
            "s3:http://minio:9000",
            "s3:https://minio:9000/bucket/",
            "rest:https://host:8000",
            "rest:https://host:8000/",
            "rest:https://user:pw@host:8000/p",
            "sftp:user@host:",
            "sftp:user@host:/srv",
            "sftp:user@host:srv",
            "sftp://user@host:22",
            "sftp://user@host:22//srv",
            "b2:bucket:",
            "b2:bucket:p",
            "gs:bucket:/",
            "gs:bucket:/p",
            "azure:container:",
            "azure:container:/p",
            "swift:container:/p",
            "rclone:remote:",
            "rclone:remote:bucket",
            "rclone:nas:/backups",
        ] {
            let b = base.trim_end_matches('/');
            let made = format!("{b}/abc");
            assert_eq!(
                sibling_repo(&made, "NEW").as_deref(),
                Some(format!("{b}/NEW").as_str()),
                "{made}"
            );
        }
    }

    #[test]
    fn progress_keeps_the_request_on_file() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("state").join("migrate.json");
        let item = |state: &str| JobItem {
            kind: "volume".into(),
            name: "v".into(),
            state: state.into(),
            new_id: String::new(),
            note: String::new(),
            old: None,
        };
        for asked in ["pause", "cancel"] {
            // `sealctl migrate --pause` while the item runs
            save_job_at(
                &p,
                &Job {
                    items: vec![item("running")],
                    request: Some(asked.into()),
                },
            )
            .unwrap();
            // the runner's copy, read before the request was written
            save_progress_at(
                &p,
                &Job {
                    items: vec![item("done")],
                    request: None,
                },
            )
            .unwrap();
            let on_file = load_job_at(&p).unwrap();
            assert_eq!(on_file.request.as_deref(), Some(asked));
            assert_eq!(on_file.items[0].state, "done");
        }
    }

    /// `--pause` between the runner's read and its save of an item's end: the item's end is
    /// kept, and so is the pause. The control waits for a save under way (the lock held here,
    /// as the runner holds it), and never writes back the item states it read before it.
    #[test]
    fn a_pause_never_writes_back_old_item_states() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("state").join("migrate.json");
        let item = |state: &str| JobItem {
            kind: "backup".into(),
            name: "b".into(),
            state: state.into(),
            new_id: "n".into(),
            note: String::new(),
            old: None,
        };
        save_job_at(
            &p,
            &Job {
                items: vec![item("running")],
                request: None,
            },
        )
        .unwrap();
        let held = lock_job_file(&p).unwrap();
        let p2 = p.clone();
        let control = std::thread::spawn(move || set_request_at(&p2, Some("pause".into())).unwrap());
        std::thread::sleep(std::time::Duration::from_millis(200));
        assert!(!control.is_finished(), "the control waits for the save under way");
        // the runner's save, under its lock
        let mut j = load_job_at(&p).unwrap();
        j.items[0].state = "done".into();
        save_job_at(&p, &j).unwrap();
        drop(held);
        control.join().unwrap();
        let on_file = load_job_at(&p).unwrap();
        assert_eq!(on_file.items[0].state, "done");
        assert_eq!(on_file.request.as_deref(), Some("pause"));
    }

    #[test]
    fn one_runner_at_a_time() {
        let d = tempfile::tempdir().unwrap();
        let st = d.path().join("state");
        // a second process: a separate open file description, as a second runner has
        std::fs::create_dir_all(&st).unwrap();
        let f = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(st.join("migrate.lock"))
            .unwrap();
        let held = nix::fcntl::Flock::lock(f, nix::fcntl::FlockArg::LockExclusiveNonblock).unwrap();
        assert!(lock_runner(&st).is_err());
        drop(held);
        assert!(lock_runner(&st).is_ok());
    }

    #[test]
    fn mount_points() {
        let d = tempfile::tempdir().unwrap();
        assert!(!is_mount_point(d.path()));
        assert!(!is_mount_point(&d.path().join("gone")));
        assert!(is_mount_point(Path::new("/")));
        // a file system of its own everywhere tests run, also in the Nix build sandbox (whose
        // /dev is a plain folder on the sandbox root): devfs on macOS, procfs on Linux
        #[cfg(target_os = "macos")]
        assert!(is_mount_point(Path::new("/dev")));
        #[cfg(target_os = "linux")]
        assert!(is_mount_point(Path::new("/proc")));
    }
}
