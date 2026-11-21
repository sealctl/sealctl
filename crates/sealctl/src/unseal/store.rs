//! Where new passwords and handed-back secrets go: the OS keychain, 1Password (`op`),
//! Bitwarden (`bw`), shown once on the terminal, or (secrets only) a 0600 `.env` file.
//!
//! Values reach every store through stdin or a native API, never an argument or an environment
//! variable, and are read back into memory to compare their SHA-256 before anything that
//! depends on them happens.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::util::{check, sha256_hex};

/// Keychain service name of every item `sealctl unseal` writes.
pub const SERVICE: &str = "sealctl-unsealed";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum StoreKind {
    /// macOS Keychain, or the Linux Secret Service (GNOME Keyring, KeePassXC).
    Keychain,
    /// 1Password CLI (`op`, signed in).
    Op,
    /// Bitwarden CLI (`bw`, unlocked).
    Bw,
    /// Shown once on the terminal for you to write down (new passwords only).
    Show,
    /// A 0600 dotenv file (secrets only).
    Env,
}

impl StoreKind {
    pub fn describe(self) -> &'static str {
        match self {
            StoreKind::Keychain if cfg!(target_os = "macos") => "macOS Keychain",
            StoreKind::Keychain => "the Secret Service keyring",
            StoreKind::Op => "1Password",
            StoreKind::Bw => "Bitwarden",
            StoreKind::Show => "shown once on this terminal",
            StoreKind::Env => "a .env file",
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            StoreKind::Keychain => "keychain",
            StoreKind::Op => "op",
            StoreKind::Bw => "bw",
            StoreKind::Show => "show",
            StoreKind::Env => "env",
        }
    }
}

/// Where one value went. Holds no value; serialised into the journal and `handback.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Location {
    pub store: StoreKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub var: Option<String>,
}

impl Location {
    fn new(store: StoreKind) -> Self {
        Location {
            store,
            service: None,
            account: None,
            vault: None,
            item: None,
            field: None,
            file: None,
            var: None,
        }
    }

    /// One line for people: where to find it.
    pub fn describe(&self) -> String {
        match self.store {
            StoreKind::Keychain => format!(
                "{}, service {}, account {}",
                self.store.describe(),
                self.service.as_deref().unwrap_or(SERVICE),
                self.account.as_deref().unwrap_or("?")
            ),
            StoreKind::Op => format!("1Password item {}", self.item.as_deref().unwrap_or("?")),
            StoreKind::Bw => format!("Bitwarden item {}", self.item.as_deref().unwrap_or("?")),
            StoreKind::Show => "written down by you".into(),
            StoreKind::Env => format!(
                "{} ({})",
                self.file
                    .as_deref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_default(),
                self.var.as_deref().unwrap_or("?")
            ),
        }
    }
}

/// What a value is, for the store's item.
pub struct Item<'a> {
    /// `volume`, `backup`, `ssh`, `secret`.
    pub kind: &'a str,
    /// `safe`, `safe/password`, `shop/openai-api-key`.
    pub name: &'a str,
    /// What it opens and how (notes of the password manager item).
    pub notes: String,
    /// An API key or token rather than a password (1Password category).
    pub credential: bool,
}

impl Item<'_> {
    pub fn account(&self) -> String {
        format!("{}/{}", self.kind, self.name)
    }

    pub fn label(&self) -> String {
        format!("sealctl: {} {}", self.kind, self.name)
    }
}

/// The settings of all stores for one run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// New passwords (volumes, backups, SSH keys).
    pub to: StoreKind,
    /// Secrets and backup storage credentials.
    pub secrets_to: StoreKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env_file: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub op_vault: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bw_folder: Option<String>,
    #[serde(default)]
    pub type_passwords: bool,
}

/// Keychain service: [`SERVICE`] (tests may override it with the `test-hooks` feature).
pub fn keychain_service() -> String {
    #[cfg(feature = "test-hooks")]
    if let Ok(s) = std::env::var("SEALCTL_TEST_KEYCHAIN_SERVICE") {
        if !s.is_empty() {
            return s;
        }
    }
    SERVICE.to_string()
}

/// Default `.env` file for `--secrets-to env`.
pub fn default_env_file() -> Result<PathBuf> {
    Ok(PathBuf::from(std::env::var_os("HOME").context("$HOME is not set")?).join("sealctl-secrets.env"))
}

/// The variable name of a secret in the `.env` store: upper case, `/ - . @ +` as `_`.
pub fn env_var_name(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect()
}

/// A new password: 32 characters of `a-z0-9` in groups of four joined by `-` (about 165
/// bits), from the OS random number generator.
pub fn generate_password() -> Result<Zeroizing<String>> {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut out = Zeroizing::new(String::with_capacity(39));
    let mut n = 0;
    while n < 32 {
        let mut buf = Zeroizing::new([0u8; 64]);
        getrandom::fill(&mut buf[..]).map_err(|e| anyhow::anyhow!("system RNG failed: {e}"))?;
        for b in buf.iter() {
            // rejection sampling: 252 = 7 * 36, no modulo bias
            if *b >= 252 || n >= 32 {
                continue;
            }
            if n > 0 && n % 4 == 0 {
                out.push('-');
            }
            out.push(ALPHABET[(*b % 36) as usize] as char);
            n += 1;
        }
    }
    Ok(out)
}

/// Ask for a password twice on the terminal (`--type-passwords`), at least 12 characters.
pub fn type_password(what: &str) -> Result<Zeroizing<String>> {
    for _ in 0..3 {
        let a = crate::util::read_hidden(&format!("New passphrase for {what}: "))?;
        if a.chars().count() < 12 {
            eprintln!("At least 12 characters, please.");
            continue;
        }
        let b = crate::util::read_hidden("Again: ")?;
        if *a != *b {
            eprintln!("They differ. Once more.");
            continue;
        }
        return Ok(a);
    }
    bail!("no passphrase for {what}")
}

fn which(bin: &str) -> bool {
    crate::util::which(bin)
}

/// The stores present on this machine (for the question and the plan).
pub fn available() -> Vec<StoreKind> {
    let mut v = vec![];
    if keychain_available() {
        v.push(StoreKind::Keychain);
    }
    if op_available() {
        v.push(StoreKind::Op);
    }
    if bw_available() {
        v.push(StoreKind::Bw);
    }
    v.push(StoreKind::Show);
    v
}

pub fn keychain_available() -> bool {
    if cfg!(target_os = "macos") {
        return true;
    }
    match keyring::Entry::new(&keychain_service(), "availability-check") {
        Ok(e) => matches!(e.get_password(), Ok(_) | Err(keyring::Error::NoEntry)),
        Err(_) => false,
    }
}

pub fn op_available() -> bool {
    which("op")
        && Command::new("op")
            .arg("whoami")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
}

pub fn bw_available() -> bool {
    which("bw")
        && Command::new("bw")
            .arg("status")
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .ok()
            .and_then(|o| serde_json::from_slice::<Value>(&o.stdout).ok())
            .is_some_and(|v| v["status"] == "unlocked")
}

/// Is `kind` usable now? `Err` says why not.
pub fn usable(kind: StoreKind, secrets: bool) -> Result<()> {
    match kind {
        StoreKind::Keychain if !keychain_available() => {
            bail!("no keychain here (on Linux a running Secret Service is needed)")
        }
        StoreKind::Op if !op_available() => {
            bail!("1Password CLI `op` is not installed or not signed in (op signin)")
        }
        StoreKind::Bw if !bw_available() => {
            bail!(
                "Bitwarden CLI `bw` is not installed or not unlocked (export BW_SESSION=$(bw unlock --raw))"
            )
        }
        StoreKind::Show if secrets => bail!("secrets can't be shown; choose keychain, op, bw or env"),
        StoreKind::Env if !secrets => bail!("new passwords can't go to a .env file"),
        _ => Ok(()),
    }
}

/// The stores of one run.
pub struct Stores {
    pub cfg: Config,
    /// Folder id of `--bw-folder`, looked up once.
    bw_folder_id: Option<Option<String>>,
    /// Values shown once in this process (the `show` store), for the steps that follow.
    shown: BTreeMap<String, Zeroizing<String>>,
}

impl Stores {
    pub fn new(cfg: Config) -> Self {
        Stores {
            cfg,
            bw_folder_id: None,
            shown: BTreeMap::new(),
        }
    }

    /// Store `value` and read it back: the SHA-256 of what the store returns must match.
    /// `on_edit` is called with a file before the store edits it (the `.env` store).
    pub fn put_checked(
        &mut self,
        kind: StoreKind,
        item: &Item,
        value: &[u8],
        on_edit: &dyn Fn(&Path) -> Result<()>,
    ) -> Result<Location> {
        let loc = self.put(kind, item, value, on_edit)?;
        if kind == StoreKind::Show {
            return Ok(loc); // checked by the typed last four characters
        }
        let back = self
            .read(&loc)
            .with_context(|| format!("reading {} back", item.label()))?;
        if sha256_hex(&back) != sha256_hex(value) {
            bail!(
                "{} read back from {} differs from what was written; stopping before anything depends on it",
                item.label(),
                kind.describe()
            );
        }
        Ok(loc)
    }

    fn put(
        &mut self,
        kind: StoreKind,
        item: &Item,
        value: &[u8],
        on_edit: &dyn Fn(&Path) -> Result<()>,
    ) -> Result<Location> {
        match kind {
            StoreKind::Keychain => {
                let service = keychain_service();
                let account = item.account();
                keyring::Entry::new(&service, &account)
                    .and_then(|e| e.set_secret(value))
                    .with_context(|| format!("writing {} to the keychain", item.label()))?;
                let mut l = Location::new(kind);
                l.service = Some(service);
                l.account = Some(account);
                Ok(l)
            }
            StoreKind::Op => self.op_put(item, value),
            StoreKind::Bw => self.bw_put(item, value),
            StoreKind::Show => self.show_put(item, value),
            StoreKind::Env => {
                let file = match &self.cfg.env_file {
                    Some(f) => f.clone(),
                    None => default_env_file()?,
                };
                on_edit(&file)?;
                let var = env_var_name(item.name);
                env_upsert(&file, &var, value)?;
                let mut l = Location::new(kind);
                l.file = Some(file);
                l.var = Some(var);
                Ok(l)
            }
        }
    }

    /// Read a value back into memory.
    pub fn read(&mut self, loc: &Location) -> Result<Zeroizing<Vec<u8>>> {
        match loc.store {
            StoreKind::Keychain => {
                let e = keyring::Entry::new(
                    loc.service.as_deref().unwrap_or(SERVICE),
                    loc.account.as_deref().context("keychain account")?,
                )?;
                Ok(Zeroizing::new(
                    e.get_secret().context("reading from the keychain")?,
                ))
            }
            StoreKind::Op => {
                let field = loc.field.as_deref().unwrap_or("password");
                let reference = format!(
                    "op://{}/{}/{field}",
                    loc.vault.as_deref().context("1Password vault")?,
                    loc.item.as_deref().context("1Password item")?
                );
                let out = check(
                    Command::new("op")
                        .args(["read", "--no-newline", &reference])
                        .stdin(Stdio::null())
                        .output()
                        .context("running op")?,
                    "op read",
                )?;
                Ok(Zeroizing::new(out.stdout))
            }
            StoreKind::Bw => {
                let out = check(
                    Command::new("bw")
                        .args(["get", "password", loc.item.as_deref().context("Bitwarden item")?])
                        .stdin(Stdio::null())
                        .output()
                        .context("running bw")?,
                    "bw get password",
                )?;
                Ok(Zeroizing::new(out.stdout))
            }
            StoreKind::Show => {
                let key = loc.account.clone().unwrap_or_default();
                if let Some(v) = self.shown.get(&key) {
                    return Ok(Zeroizing::new(v.as_bytes().to_vec()));
                }
                // after a resume: the person wrote it down
                let v = crate::util::read_hidden(&format!(
                    "Type the passphrase you wrote down for {}: ",
                    key.replace('/', " ")
                ))?;
                self.shown.insert(key, v.clone());
                Ok(Zeroizing::new(v.as_bytes().to_vec()))
            }
            StoreKind::Env => {
                let file = loc.file.as_deref().context(".env file")?;
                let text = Zeroizing::new(
                    std::fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?,
                );
                let map = crate::secrets::parse_dotenv(&text)?;
                let v = map
                    .get(loc.var.as_deref().context("variable")?)
                    .context("the variable is missing from the .env file")?;
                Ok(Zeroizing::new(v.as_bytes().to_vec()))
            }
        }
    }

    fn op_put(&mut self, item: &Item, value: &[u8]) -> Result<Location> {
        let value = std::str::from_utf8(value).context("1Password items hold text")?;
        let field = if item.credential { "credential" } else { "password" };
        let mut f = json!({
            "id": field, "type": "CONCEALED", "label": field, "value": value
        });
        if !item.credential {
            f["purpose"] = json!("PASSWORD");
        }
        let template = Zeroizing::new(
            json!({
                "title": item.label(),
                "category": if item.credential { "API_CREDENTIAL" } else { "PASSWORD" },
                "tags": ["sealctl"],
                "fields": [
                    f,
                    {"id": "notesPlain", "type": "STRING", "purpose": "NOTES",
                     "label": "notesPlain", "value": item.notes}
                ]
            })
            .to_string(),
        );
        let mut cmd = Command::new("op");
        cmd.args(["item", "create", "--format", "json"]);
        if let Some(v) = &self.cfg.op_vault {
            cmd.args(["--vault", v]);
        }
        // the item template, value included, arrives on stdin
        let out = check(
            crate::util::run_with_stdin(&mut cmd, template.as_bytes())?,
            "op item create",
        )?;
        let v: Value = serde_json::from_slice(&out.stdout).context("parsing op item create output")?;
        let mut l = Location::new(StoreKind::Op);
        l.item = Some(v["id"].as_str().context("op returned no item id")?.to_string());
        l.vault = v["vault"]["id"]
            .as_str()
            .map(str::to_string)
            .or_else(|| self.cfg.op_vault.clone());
        l.field = Some(field.to_string());
        Ok(l)
    }

    fn bw_folder(&mut self) -> Result<Option<String>> {
        if let Some(id) = &self.bw_folder_id {
            return Ok(id.clone());
        }
        let id = match &self.cfg.bw_folder {
            None => None,
            Some(name) => {
                let out = check(
                    Command::new("bw")
                        .args(["list", "folders", "--search", name])
                        .stdin(Stdio::null())
                        .output()
                        .context("running bw")?,
                    "bw list folders",
                )?;
                let v: Value = serde_json::from_slice(&out.stdout).context("parsing bw folders")?;
                let found = v
                    .as_array()
                    .and_then(|a| a.iter().find(|f| f["name"].as_str() == Some(name.as_str())))
                    .and_then(|f| f["id"].as_str())
                    .map(str::to_string);
                Some(found.with_context(|| format!("no Bitwarden folder named {name}"))?)
            }
        };
        self.bw_folder_id = Some(id.clone());
        Ok(id)
    }

    fn bw_put(&mut self, item: &Item, value: &[u8]) -> Result<Location> {
        let value = std::str::from_utf8(value).context("Bitwarden items hold text")?;
        let folder = self.bw_folder()?;
        let json = Zeroizing::new(
            json!({
                "organizationId": null, "folderId": folder, "type": 1,
                "name": item.label(), "notes": item.notes, "favorite": false,
                "login": {"username": item.account(), "password": value, "uris": []},
                "fields": [], "reprompt": 0
            })
            .to_string(),
        );
        let encoded = check(
            crate::util::run_with_stdin(Command::new("bw").arg("encode"), json.as_bytes())?,
            "bw encode",
        )?;
        let encoded = Zeroizing::new(encoded.stdout);
        let out = check(
            crate::util::run_with_stdin(Command::new("bw").args(["create", "item"]), &encoded)?,
            "bw create item",
        )?;
        let v: Value = serde_json::from_slice(&out.stdout).context("parsing bw create item output")?;
        let mut l = Location::new(StoreKind::Bw);
        l.item = Some(v["id"].as_str().context("bw returned no item id")?.to_string());
        Ok(l)
    }

    fn show_put(&mut self, item: &Item, value: &[u8]) -> Result<Location> {
        let value = Zeroizing::new(String::from_utf8(value.to_vec()).context("passwords are text")?);
        let mut tty = std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/tty")
            .context("the `show` store needs a terminal")?;
        let what = format!("{} {}", item.kind, item.name);
        writeln!(tty, "\nNew passphrase for {what}: {}", value.as_str())?;
        let last4: String = {
            let c: Vec<char> = value.chars().collect();
            c[c.len().saturating_sub(4)..].iter().collect()
        };
        let mut ok = false;
        for _ in 0..3 {
            let typed = crate::util::read_hidden("Write it down. Type its last 4 characters to go on: ")?;
            if typed.trim() == last4 {
                ok = true;
                break;
            }
            writeln!(tty, "That is not it; look again.")?;
        }
        // move the cursor up and clear the shown line from the screen
        let _ = write!(tty, "\x1b[s\x1b[2A\x1b[2K\x1b[u");
        if !ok {
            bail!("the passphrase for {what} was not confirmed");
        }
        let mut l = Location::new(StoreKind::Show);
        l.account = Some(item.account());
        self.shown.insert(item.account(), value);
        Ok(l)
    }
}

/// Quote a value for a dotenv file (double quotes; `\n \r \t \" \\ \$` escaped).
fn dotenv_quote(v: &str) -> Zeroizing<String> {
    let mut s = Zeroizing::new(String::with_capacity(v.len() + 2));
    s.push('"');
    for c in v.chars() {
        match c {
            '\n' => s.push_str("\\n"),
            '\r' => s.push_str("\\r"),
            '\t' => s.push_str("\\t"),
            '"' => s.push_str("\\\""),
            '\\' => s.push_str("\\\\"),
            '$' => s.push_str("\\$"),
            c => s.push(c),
        }
    }
    s.push('"');
    s
}

/// Set `var` in the dotenv `file` (0600), replacing an earlier line of the same variable.
fn env_upsert(file: &Path, var: &str, value: &[u8]) -> Result<()> {
    let value = std::str::from_utf8(value).context("values in a .env file are text")?;
    let old = Zeroizing::new(std::fs::read_to_string(file).unwrap_or_default());
    let existing = crate::secrets::parse_dotenv(&old)
        .with_context(|| format!("{} is not a dotenv file", file.display()))?;
    let mut text = Zeroizing::new(String::new());
    if old.is_empty() {
        text.push_str(
            "# Written by `sealctl unseal`. These are your keys in plain text, where AI agents can\n\
             # read them. Move them to a password manager, then delete this file.\n",
        );
    }
    if existing.contains_key(var) {
        // rewrite the file from its parsed form (comments kept only at the top)
        let header: String = old
            .lines()
            .take_while(|l| l.starts_with('#'))
            .map(|l| format!("{l}\n"))
            .collect();
        text.push_str(&header);
        for (k, v) in existing.iter() {
            let v = if k == var { value } else { v.as_str() };
            text.push_str(&format!("{k}={}\n", dotenv_quote(v).as_str()));
        }
    } else {
        text.push_str(&old);
        if !text.is_empty() && !text.ends_with('\n') {
            text.push('\n');
        }
        text.push_str(&format!("{var}={}\n", dotenv_quote(value).as_str()));
    }
    crate::paths::write_private(file, text.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_alphabet_and_length() {
        for _ in 0..200 {
            let p = generate_password().unwrap();
            assert_eq!(p.len(), 39);
            let groups: Vec<&str> = p.split('-').collect();
            assert_eq!(groups.len(), 8);
            assert!(groups.iter().all(|g| g.len() == 4));
            assert!(p
                .chars()
                .all(|c| c == '-' || c.is_ascii_lowercase() || c.is_ascii_digit()));
        }
        assert_ne!(*generate_password().unwrap(), *generate_password().unwrap());
    }

    #[test]
    fn env_names() {
        assert_eq!(env_var_name("shop/openai-api-key"), "SHOP_OPENAI_API_KEY");
        assert_eq!(env_var_name("a.b@c+d"), "A_B_C_D");
        assert_eq!(
            env_var_name("backup/safe/AWS_ACCESS_KEY_ID"),
            "BACKUP_SAFE_AWS_ACCESS_KEY_ID"
        );
    }

    #[test]
    fn env_store_roundtrip() {
        let t = tempfile::tempdir().unwrap();
        let file = t.path().join("s.env");
        let mut s = Stores::new(Config {
            to: StoreKind::Show,
            secrets_to: StoreKind::Env,
            env_file: Some(file.clone()),
            op_vault: None,
            bw_folder: None,
            type_passwords: false,
        });
        let tricky = "line1\nline2 \"q\" $HOME \\ end";
        for (name, v) in [("a/one", "plain"), ("a/two", tricky), ("a/one", "again")] {
            let item = Item {
                kind: "secret",
                name,
                notes: String::new(),
                credential: true,
            };
            let loc = s
                .put_checked(StoreKind::Env, &item, v.as_bytes(), &|_| Ok(()))
                .unwrap();
            assert_eq!(&*s.read(&loc).unwrap(), v.as_bytes());
        }
        let map = crate::secrets::parse_dotenv(&std::fs::read_to_string(&file).unwrap()).unwrap();
        assert_eq!(map.len(), 2);
        assert_eq!(map["A_ONE"].as_str(), "again");
        assert_eq!(map["A_TWO"].as_str(), tricky);
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
