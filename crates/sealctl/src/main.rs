//! sealctl command-line interface (SPEC 10).

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Result;
use clap::{CommandFactory, Parser, Subcommand};
use sealctl::seal::store::StoreKind;
use sealctl::seal::unseal::{self, Target};
use sealctl::volume::{CreateOpts, Kind};
use sealctl::{cli, exit, git, pair, seal, ssh, status};

#[derive(Parser)]
#[command(
    name = "sealctl",
    version,
    about = "Keys for your developer machine, approved on your phone",
    long_about = "Keeps API keys away from AI agents, signs SSH logins and git commits, opens \
                  encrypted volumes and runs restic backups. Keys come from 24 words held by the \
                  sealctl phone app, which approves their use.",
    propagate_version = true
)]
struct Cli {
    /// More logging on stderr (never values).
    #[arg(long, short, global = true, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Relay origin (also SEALCTL_RELAY); recorded at pairing.
    #[arg(long, global = true, value_name = "ORIGIN")]
    relay: Option<String>,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// The session and this machine; never asks the phone.
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Open the session now (store key, auto volumes, backup keys).
    Open,
    /// Lock now: wipe keys, back up, close volumes.
    Lock {
        /// A volume name (0.5): use `sealctl volume close <name>`.
        #[arg(hide = true)]
        volume: Option<String>,
        /// Unmount even if files are open.
        #[arg(long)]
        force: bool,
        /// Skip the on-lock backups.
        #[arg(long)]
        no_backup: bool,
    },
    /// Removed in 0.7: use `sealctl volume open <name>`.
    #[command(hide = true)]
    Unlock { name: Option<String> },
    /// Pair this machine with the sealctl app on your phone.
    Pair {
        /// Name shown on the phone (default user@full-hostname).
        #[arg(long)]
        name: Option<String>,
        /// Replace an existing pairing without asking.
        #[arg(long)]
        force: bool,
    },
    /// Unpair this machine.
    Unpair {
        #[arg(long)]
        yes: bool,
    },
    /// Cancel a delayed level 3 action approved on the phone.
    Cancel {
        id: Option<String>,
        #[arg(long)]
        yes: bool,
    },
    /// Check the setup.
    Doctor {
        #[arg(long)]
        json: bool,
    },
    /// API keys and tokens in the store.
    #[command(subcommand)]
    Secret(SecretCmd),
    /// Run a command with secrets in its environment (.sealctl.toml and -e).
    Run {
        /// NAME=secret, repeatable.
        #[arg(long = "env", short = 'e')]
        env: Vec<String>,
        /// Ignore .sealctl.toml.
        #[arg(long)]
        no_project: bool,
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },
    /// AI coding agents: skill, hooks and deny rules.
    #[command(subcommand)]
    Ai(AiCmd),
    /// Remembered agent answers on this machine.
    Rules {
        #[arg(long)]
        json: bool,
    },
    /// (internal) Hook entry point called by AI agents.
    #[command(hide = true)]
    Hook { tool: String },
    /// SSH keys from the store, served by the daemon's agent.
    #[command(subcommand)]
    Ssh(SshCmd),
    /// Git commit signing and credentials.
    #[command(subcommand)]
    Git(GitCmd),
    /// (internal) AWS credential_process helper.
    #[command(subcommand, hide = true)]
    Aws(AwsCmd),
    /// Encrypted volumes.
    #[command(subcommand)]
    Volume(VolumeCmd),
    /// Encrypted, versioned backups (restic).
    #[command(subcommand)]
    Backup(BackupCmd),
    /// Find keys in .env files, shell files, histories and ~/.aws, and seal them.
    Scan {
        /// Folders or files (default: the repository root or this folder).
        paths: Vec<PathBuf>,
        /// Also the home folder: .env files, shell rc files, histories, ~/.aws/credentials.
        #[arg(long)]
        home: bool,
        /// List only.
        #[arg(long)]
        dry_run: bool,
        /// Do not ask.
        #[arg(long)]
        yes: bool,
        #[arg(long)]
        json: bool,
    },
    /// Move objects to new words (rewrap, old words) or re-encrypt them under new keys.
    Migrate {
        /// The re-encryption job: per object, state and notes.
        #[arg(long)]
        status: bool,
        /// Find objects by their markers (default: home and /Volumes).
        #[arg(long, num_args = 0..)]
        scan: Option<Vec<PathBuf>>,
        /// rewrap: same data key, new words; re-encrypt: new keys and a copy of the data.
        #[arg(long, default_value = "re-encrypt", value_parser = ["rewrap", "re-encrypt"])]
        depth: String,
        #[arg(long)]
        yes: bool,
        #[arg(long, conflicts_with_all = ["resume", "cancel"])]
        pause: bool,
        #[arg(long, conflicts_with = "cancel")]
        resume: bool,
        #[arg(long)]
        cancel: bool,
        #[arg(long)]
        json: bool,
        #[arg(long, hide = true)]
        run_job: bool,
        #[arg(long, hide = true)]
        foreground: bool,
        #[arg(long, hide = true)]
        auto: bool,
    },
    /// Objects this machine knows.
    Inventory {
        #[arg(long)]
        json: bool,
    },
    /// Take over something you already have: a volume, backup, SSH key, secret or .env file.
    Seal(SealArgs),
    /// Hand objects back in plain, standard form (into ~/sealctl-unsealed-<date>).
    Unseal(UnsealArgs),
    /// Open an object with the 24 words alone (no phone, no relay).
    Recover {
        /// Store folder, .sealed file, sparse bundle or restic repository.
        target: String,
        /// Write every secret into this folder.
        #[arg(long)]
        out: Option<PathBuf>,
        /// One secret to stdout.
        #[arg(long)]
        name: Option<String>,
        /// Print to a terminal.
        #[arg(long)]
        show: bool,
        /// restic arguments (default: snapshots).
        #[arg(last = true)]
        restic: Vec<String>,
    },
    /// $5.99 once keeps the relay running.
    Buy {
        /// Seats for a team (2 to 1,000).
        #[arg(long)]
        seats: Option<u32>,
        /// Claim a seat from a team code.
        #[arg(long)]
        code: Option<String>,
    },
    /// Shell completions.
    Completions { shell: clap_complete::Shell },
    /// (internal) The session daemon.
    #[command(hide = true)]
    Daemon {
        #[arg(long)]
        spawned: bool,
        /// Lock and stop a running daemon.
        #[arg(long)]
        stop: bool,
    },
}

#[derive(Subcommand)]
enum SecretCmd {
    /// Store a value: clipboard, stdin when piped, or a hidden prompt.
    Set {
        name: String,
        #[arg(long)]
        force: bool,
        #[arg(long)]
        from_clipboard: bool,
        /// Ask the phone on every use.
        #[arg(long)]
        own_approval: bool,
    },
    /// Print a value (not inside an AI agent; to a terminal only with --show).
    Get {
        name: String,
        #[arg(long)]
        clip: bool,
        #[arg(long)]
        show: bool,
    },
    /// Names, no key needed.
    #[command(alias = "list")]
    Ls {
        #[arg(long)]
        json: bool,
    },
    /// Remove a secret.
    Rm {
        name: String,
        #[arg(long)]
        yes: bool,
    },
    /// Rename a secret.
    Mv { old: String, new: String },
    /// Alias of `sealctl seal env`.
    ImportEnv {
        #[arg(default_value = ".env")]
        file: PathBuf,
        #[arg(long)]
        prefix: String,
        #[arg(long)]
        delete: bool,
        #[arg(long)]
        force: bool,
    },
    /// Show the store folder, or use another one.
    Store {
        #[arg(long = "use")]
        use_dir: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum AiCmd {
    /// Install for every detected tool (or the named ones).
    Install { tools: Vec<String> },
    /// Remove.
    Uninstall { tools: Vec<String> },
    /// What is installed.
    Status { tools: Vec<String> },
}

#[derive(Subcommand)]
enum SshCmd {
    /// New Ed25519 key stored as ssh/<name>.
    Keygen {
        #[arg(default_value = "ed25519")]
        name: String,
        #[arg(long, default_value = "sealctl")]
        comment: String,
    },
    /// Public key line.
    Pubkey {
        #[arg(default_value = "ed25519")]
        name: String,
    },
    /// The ~/.ssh/config lines.
    Setup,
    /// Alias of `sealctl seal ssh`.
    Import {
        file: PathBuf,
        #[arg(long)]
        name: Option<String>,
    },
}

#[derive(Subcommand)]
enum GitCmd {
    /// Commit signing with ssh/<key> through the daemon's agent.
    Setup {
        #[arg(long)]
        local: bool,
        #[arg(long)]
        key: Option<String>,
        #[arg(long)]
        undo: bool,
    },
    /// git asks sealctl for https://<host> tokens (secret git/<host>).
    Credentials {
        host: String,
        #[arg(long)]
        undo: bool,
    },
    /// (internal) git credential helper.
    #[command(hide = true)]
    Credential { action: String },
    /// (internal) gpg.ssh.program wrapper.
    #[command(hide = true, name = "ssh-keygen")]
    SshKeygen {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
}

#[derive(Subcommand)]
enum AwsCmd {
    /// credential_process output for a profile.
    Credentials {
        #[arg(long)]
        profile: String,
    },
}

#[derive(Subcommand)]
enum VolumeCmd {
    /// Create a volume (mounted right away).
    Create {
        name: String,
        #[arg(long, value_enum)]
        kind: Option<Kind>,
        #[arg(long, default_value = "50g")]
        size: String,
        #[arg(long)]
        container: Option<String>,
        #[arg(long)]
        path: Option<PathBuf>,
        #[arg(long)]
        mountpoint: Option<PathBuf>,
        /// Not mounted when the session opens.
        #[arg(long)]
        manual: bool,
    },
    /// List volumes.
    Ls {
        #[arg(long)]
        json: bool,
    },
    /// Mount one volume.
    Open { name: String },
    /// Unmount one volume.
    Close {
        name: String,
        #[arg(long)]
        force: bool,
    },
    /// Register a sealed volume, or take over one of your own (alias of `seal volume`).
    Import {
        name: String,
        target: String,
        #[arg(long, value_enum)]
        kind: Option<Kind>,
        #[arg(long)]
        mountpoint: Option<PathBuf>,
    },
    /// Forget a volume; --delete-data destroys it.
    Rm {
        name: String,
        #[arg(long)]
        delete_data: bool,
    },
}

#[derive(Subcommand)]
enum BackupCmd {
    /// New restic repository for a volume or folder.
    Init {
        name: String,
        #[arg(long)]
        from: String,
        #[arg(long)]
        repo: String,
        #[arg(short = 'e')]
        env: Vec<String>,
    },
    /// Back up now.
    Run {
        names: Vec<String>,
        #[arg(long)]
        all: bool,
        #[arg(long)]
        if_open: bool,
        #[arg(long)]
        quiet: bool,
    },
    /// List snapshots.
    Snapshots {
        name: String,
        #[arg(long)]
        json: bool,
    },
    /// Restore a snapshot.
    Restore {
        name: String,
        #[arg(long)]
        target: PathBuf,
        #[arg(long, default_value = "latest")]
        snapshot: String,
        #[arg(long)]
        include: Vec<String>,
    },
    /// restic check.
    Check {
        name: String,
        #[arg(long)]
        read_data: Option<u8>,
    },
    /// When backups run and what they keep.
    Policy {
        name: String,
        #[arg(long)]
        on_lock: Option<bool>,
        #[arg(long)]
        scheduled: Option<bool>,
        #[arg(long)]
        keep_daily: Option<u32>,
        #[arg(long)]
        keep_weekly: Option<u32>,
        #[arg(long)]
        keep_monthly: Option<u32>,
    },
    /// The backup schedule.
    #[command(subcommand)]
    Schedule(ScheduleCmd),
}

#[derive(Subcommand)]
enum ScheduleCmd {
    /// Install: sealctl backup run --all --if-open --quiet.
    Install {
        #[arg(long, default_value_t = 60)]
        every: u64,
    },
    /// Remove.
    Uninstall,
}

#[derive(clap::Args)]
struct SealArgs {
    #[command(subcommand)]
    what: Option<SealCmd>,
    /// Take over every object of a hand-back list (handback.json from `unseal`, 0.6.0 or 0.7).
    #[arg(long)]
    from: Option<PathBuf>,
    /// With --from: leave one object out, <kind>/<name>.
    #[arg(long)]
    skip: Vec<String>,
    /// With --from: keys from the 24 words instead of the phone.
    #[arg(long)]
    words: bool,
}

#[derive(Subcommand)]
enum SealCmd {
    /// An APFS volume UUID, sparse bundle or LUKS file with your own passphrase.
    Volume {
        name: String,
        target: String,
        #[arg(long)]
        mountpoint: Option<PathBuf>,
        #[arg(long)]
        manual: bool,
        /// Keys from the 24 words instead of the phone.
        #[arg(long)]
        words: bool,
    },
    /// A restic repository with your own password.
    Backup {
        name: String,
        #[arg(long)]
        repo: String,
        #[arg(long)]
        from: Option<String>,
        #[arg(short = 'e')]
        env: Vec<String>,
        #[arg(long)]
        keep_old_password: bool,
        #[arg(long)]
        words: bool,
    },
    /// An OpenSSH private key file.
    Ssh {
        file: PathBuf,
        #[arg(long)]
        name: Option<String>,
    },
    /// A secret (clipboard, stdin or a hidden prompt).
    Secret {
        name: String,
        #[arg(long)]
        from_clipboard: bool,
        #[arg(long)]
        force: bool,
    },
    /// A .env file.
    Env {
        #[arg(default_value = ".env")]
        file: PathBuf,
        #[arg(long)]
        prefix: String,
        #[arg(long)]
        delete: bool,
        #[arg(long)]
        force: bool,
    },
}

#[derive(clap::Args)]
struct UnsealArgs {
    #[command(subcommand)]
    what: Option<UnsealWhat>,
    /// Everything on this machine, then sealctl's settings, services, hooks and pairing.
    #[arg(long, global = true)]
    all: bool,
    /// Continue the newest unfinished run.
    #[arg(long, global = true)]
    resume: bool,
    /// Keys from the 24 words instead of the phone.
    #[arg(long, global = true)]
    words: bool,
    /// Show the plan only.
    #[arg(long, global = true)]
    dry_run: bool,
    #[arg(long, global = true)]
    json: bool,
    /// Leave the store folder in place.
    #[arg(long, global = true)]
    keep_store: bool,
    /// Leave one object out: <kind>/<name>.
    #[arg(long, global = true)]
    skip: Vec<String>,
    /// Where new passwords go (default: the unsealed folder).
    #[arg(long, global = true, value_enum)]
    to: Option<StoreKind>,
    /// Where secrets and storage credentials go (default: as --to).
    #[arg(long, global = true, value_enum)]
    secrets_to: Option<StoreKind>,
    /// The .env file for --secrets-to env (default ~/sealctl-secrets.env).
    #[arg(long, global = true)]
    env_file: Option<PathBuf>,
    /// 1Password vault for --to op.
    #[arg(long, global = true)]
    op_vault: Option<String>,
    /// Bitwarden folder for --to bw.
    #[arg(long, global = true)]
    bw_folder: Option<String>,
    /// Type each new password (twice, at least 12 characters) instead of generating it.
    #[arg(long, global = true)]
    type_passwords: bool,
    /// SSH keys end without a passphrase (always with the folder store).
    #[arg(long, global = true)]
    no_ssh_passphrase: bool,
}

#[derive(Subcommand)]
enum UnsealWhat {
    /// One secret.
    Secret { name: String },
    /// The whole store.
    Secrets,
    /// One volume.
    Volume { name: String },
    /// One backup.
    Backup { name: String },
    /// One SSH key.
    Ssh { name: String },
    /// Git signing.
    Git,
    /// AI integrations.
    Ai { tools: Vec<String> },
}

fn print_reports(reports: Vec<sealctl::ai::Report>) {
    for r in reports {
        eprintln!("{}{}", r.tool, if r.detected { "" } else { " (not found)" });
        for l in r.lines {
            eprintln!("  {l}");
        }
    }
}

fn run(cli: Cli) -> Result<i32> {
    let relay = cli.relay.clone();
    let r = relay.as_deref();
    match cli.cmd {
        Cmd::Status { json } => status::status(json),
        Cmd::Open => cli::open().map(|_| 0),
        Cmd::Lock { volume: Some(v), .. } => {
            Err(exit::fail(exit::USAGE, format!("Use sealctl volume close {v}")))
        }
        Cmd::Lock { force, no_backup, .. } => cli::lock(force, no_backup),
        Cmd::Unlock { name } => Err(exit::fail(
            exit::USAGE,
            format!(
                "Use sealctl volume open {}",
                name.unwrap_or_else(|| "<name>".into())
            ),
        )),
        Cmd::Pair { name, force } => {
            pair::pair(pair::PairOpts { name, force, relay })?;
            sealctl::licence::maybe_ask();
            Ok(0)
        }
        Cmd::Unpair { yes } => pair::unpair(yes, r).map(|_| 0),
        Cmd::Cancel { id, yes } => status::cancel(id, yes, r).map(|_| 0),
        Cmd::Doctor { json } => status::doctor(json),
        Cmd::Secret(c) => match c {
            SecretCmd::Set {
                name,
                force,
                from_clipboard,
                own_approval,
            } => cli::secret_set(&name, force, from_clipboard, own_approval),
            SecretCmd::Get { name, clip, show } => cli::secret_get(&name, clip, show),
            SecretCmd::Ls { json } => cli::secret_ls(json),
            SecretCmd::Rm { name, yes } => cli::secret_rm(&name, yes),
            SecretCmd::Mv { old, new } => sealctl::daemon::client::store_mv(&old, &new),
            SecretCmd::ImportEnv {
                file,
                prefix,
                delete,
                force,
            } => seal::seal_env(&file, &prefix, delete, force),
            SecretCmd::Store { use_dir, json } => cli::secret_store(use_dir, json),
        }
        .map(|_| 0),
        Cmd::Run {
            env,
            no_project,
            command,
        } => sealctl::project::run(&env, !no_project, &command).map(|_| 0),
        Cmd::Ai(c) => {
            match c {
                AiCmd::Install { tools } => print_reports(sealctl::ai::install(&tools)?),
                AiCmd::Uninstall { tools } => print_reports(sealctl::ai::uninstall(&tools)?),
                AiCmd::Status { tools } => print_reports(sealctl::ai::status(&tools)?),
            }
            Ok(0)
        }
        Cmd::Rules { json } => status::rules(json).map(|_| 0),
        Cmd::Hook { tool } => sealctl::ai::run_hook(&tool).map(|_| 0),
        Cmd::Ssh(c) => match c {
            SshCmd::Keygen { name, comment } => {
                let line = ssh::keygen(&name, &comment)?;
                println!("{line}");
                Ok(0)
            }
            SshCmd::Pubkey { name } => {
                println!("{}", ssh::read_public(&name)?.to_openssh()?);
                Ok(0)
            }
            SshCmd::Setup => {
                print!("{}", ssh::setup_text()?);
                eprintln!("Add these lines to ~/.ssh/config. The sealctl daemon serves the agent.");
                Ok(0)
            }
            SshCmd::Import { file, name } => seal::seal_ssh(&file, name).map(|_| 0),
        },
        Cmd::Git(c) => match c {
            GitCmd::Setup {
                local, undo: true, ..
            } => git::undo(local).map(|_| 0),
            GitCmd::Setup { local, key, .. } => git::setup(local, key.as_deref()).map(|_| 0),
            GitCmd::Credentials { host, undo } => git::credentials(&host, undo).map(|_| 0),
            GitCmd::Credential { action } => git::credential(&action).map(|_| 0),
            GitCmd::SshKeygen { args } => git::ssh_keygen_shim(&args).map(|_| 0),
        },
        Cmd::Aws(AwsCmd::Credentials { profile }) => cli::aws_credentials(&profile).map(|_| 0),
        Cmd::Volume(c) => match c {
            VolumeCmd::Create {
                name,
                kind,
                size,
                container,
                path,
                mountpoint,
                manual,
            } => cli::volume_create(CreateOpts {
                name,
                kind: kind.unwrap_or_else(Kind::default_for_os),
                size,
                path,
                container,
                mountpoint,
                manual,
            }),
            VolumeCmd::Ls { json } => cli::volume_ls(json),
            VolumeCmd::Open { name } => cli::volume_open(&name),
            VolumeCmd::Close { name, force } => cli::volume_close(&name, force),
            VolumeCmd::Import {
                name,
                target,
                kind,
                mountpoint,
            } => cli::volume_import(&name, &target, kind, mountpoint),
            VolumeCmd::Rm { name, delete_data } => cli::volume_rm(&name, delete_data),
        }
        .map(|_| 0),
        Cmd::Backup(c) => match c {
            BackupCmd::Init {
                name,
                from,
                repo,
                env,
            } => cli::backup_init(&name, &from, &repo, &env),
            BackupCmd::Run {
                names,
                all,
                if_open,
                quiet,
            } => cli::backup_run(&names, all, if_open, quiet),
            BackupCmd::Snapshots { name, json } => {
                let mut a = vec!["snapshots"];
                if json {
                    a.push("--json");
                }
                cli::backup_restic(&name, &a)
            }
            BackupCmd::Restore {
                name,
                target,
                snapshot,
                include,
            } => {
                let t = target.to_string_lossy().into_owned();
                let mut a = vec!["restore", snapshot.as_str(), "--target", t.as_str()];
                for i in &include {
                    a.push("--include");
                    a.push(i);
                }
                cli::backup_restic(&name, &a)
            }
            BackupCmd::Check { name, read_data } => {
                let pct = read_data.map(|p| format!("--read-data-subset={p}%"));
                let mut a = vec!["check"];
                if let Some(p) = &pct {
                    a.push(p);
                }
                cli::backup_restic(&name, &a)
            }
            BackupCmd::Policy {
                name,
                on_lock,
                scheduled,
                keep_daily,
                keep_weekly,
                keep_monthly,
            } => cli::backup_policy(&name, on_lock, scheduled, keep_daily, keep_weekly, keep_monthly),
            BackupCmd::Schedule(ScheduleCmd::Install { every }) => sealctl::backup::schedule_install(every),
            BackupCmd::Schedule(ScheduleCmd::Uninstall) => sealctl::backup::schedule_uninstall(),
        }
        .map(|_| 0),
        Cmd::Scan {
            paths,
            home,
            dry_run,
            yes,
            json,
        } => sealctl::scan::run(paths, home, dry_run, yes, json).map(|_| 0),
        Cmd::Migrate {
            status,
            scan,
            depth,
            yes,
            pause,
            resume,
            cancel,
            json,
            run_job,
            foreground,
            auto,
        } => {
            let control = if pause {
                Some("pause".to_string())
            } else if resume {
                Some("resume".into())
            } else if cancel {
                Some("cancel".into())
            } else {
                None
            };
            sealctl::migrate::run(sealctl::migrate::Opts {
                status,
                scan,
                depth,
                yes,
                control,
                json,
                run_job,
                foreground,
                auto,
            })
            .map(|_| 0)
        }
        Cmd::Inventory { json } => status::inventory(json).map(|_| 0),
        Cmd::Seal(SealArgs {
            from: Some(f),
            skip,
            words,
            ..
        }) => seal::seal_from(&f, &skip, words).map(|_| 0),
        Cmd::Seal(SealArgs { what: None, .. }) => Err(exit::fail(
            exit::USAGE,
            "Say what to take over (see sealctl seal --help), or --from <hand-back list>.",
        )),
        Cmd::Seal(SealArgs { what: Some(c), .. }) => match c {
            SealCmd::Volume {
                name,
                target,
                mountpoint,
                manual,
                words,
            } => seal::seal_volume(&name, &target, mountpoint, manual, words),
            SealCmd::Backup {
                name,
                repo,
                from,
                env,
                keep_old_password,
                words,
            } => seal::seal_backup(&name, &repo, from.as_deref(), &env, keep_old_password, words),
            SealCmd::Ssh { file, name } => seal::seal_ssh(&file, name),
            SealCmd::Secret {
                name,
                from_clipboard,
                force,
            } => {
                sealctl::term::refuse_agent("sealctl seal")?;
                cli::secret_set(&name, force, from_clipboard, false)
            }
            SealCmd::Env {
                file,
                prefix,
                delete,
                force,
            } => seal::seal_env(&file, &prefix, delete, force),
        }
        .map(|_| 0),
        Cmd::Unseal(a) => {
            let target = if a.all {
                Some(Target::All)
            } else {
                a.what.map(|w| match w {
                    UnsealWhat::Secret { name } => Target::Secret(name),
                    UnsealWhat::Secrets => Target::Secrets,
                    UnsealWhat::Volume { name } => Target::Volume(name),
                    UnsealWhat::Backup { name } => Target::Backup(name),
                    UnsealWhat::Ssh { name } => Target::Ssh(name),
                    UnsealWhat::Git => Target::Git,
                    UnsealWhat::Ai { tools } => Target::Ai(tools),
                })
            };
            if target.is_none() && !a.resume {
                return Err(exit::fail(
                    exit::USAGE,
                    "Say what to unseal (see sealctl unseal --help), or --all.",
                ));
            }
            unseal::unseal(unseal::Opts {
                target,
                resume: a.resume,
                words: a.words,
                dry_run: a.dry_run,
                json: a.json,
                keep_store: a.keep_store,
                skip: a.skip,
                to: a.to,
                secrets_to: a.secrets_to,
                env_file: a.env_file,
                op_vault: a.op_vault,
                bw_folder: a.bw_folder,
                type_passwords: a.type_passwords,
                no_ssh_passphrase: a.no_ssh_passphrase,
                relay,
            })
            .map(|_| 0)
        }
        Cmd::Recover {
            target,
            out,
            name,
            show,
            restic,
        } => sealctl::recover::recover(&target, out, name, show, restic).map(|_| 0),
        Cmd::Buy { seats, code } => sealctl::licence::buy(seats, code, r).map(|_| 0),
        Cmd::Completions { shell } => {
            clap_complete::generate(shell, &mut Cli::command(), "sealctl", &mut std::io::stdout());
            Ok(0)
        }
        Cmd::Daemon { stop: true, .. } => {
            sealctl::daemon::client::stop_running();
            Ok(0)
        }
        Cmd::Daemon { spawned, .. } => sealctl::daemon::run(spawned).map(|_| 0),
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let level = match (cli.verbose, std::env::var("SEALCTL_LOG").ok().as_deref()) {
        (0, Some("info")) | (1, _) => "info",
        (0, Some("debug")) | (2.., _) => "debug",
        _ => "warn",
    };
    env_logger::Builder::new()
        .parse_filters(level)
        .format_timestamp(None)
        .init();
    // panics print only the location, never a value
    std::panic::set_hook(Box::new(|info| {
        let at = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_default();
        eprintln!("sealctl: internal error at {at}. Please report it.");
    }));
    if let Some(r) = &cli.relay {
        match sealctl::config::validate_origin(r) {
            Ok(_) => {}
            Err(e) => {
                eprintln!("sealctl: {}", exit::message_of(&e));
                return ExitCode::from(exit::USAGE as u8);
            }
        }
        // one place reads the relay: the environment, as SEALCTL_RELAY
        std::env::set_var("SEALCTL_RELAY", r);
    }
    match run(cli) {
        Ok(code) => ExitCode::from(code as u8),
        Err(e) => {
            let code = exit::code_of(&e);
            let msg = exit::message_of(&e);
            if code == 0 {
                eprintln!("{msg}");
            } else {
                eprintln!("sealctl: {msg}");
            }
            ExitCode::from(code as u8)
        }
    }
}
