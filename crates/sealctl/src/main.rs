//! sealctl command-line interface.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use sealctl::volume::{self, Kind};
use sealctl::{
    agent, backup, card, cert, crypto, doctor, git, kit, pin, project, secrets, setup, ssh, util, Ctx,
};
use sealctl_ledger::Select;

#[derive(Parser)]
#[command(
    name = "sealctl",
    version,
    about = "Your hardware wallet as an everyday developer key",
    long_about = "Unlock encrypted volumes, run encrypted backups, keep API keys and sign with SSH — \
                  using the OpenPGP app on a Ledger over USB or Bluetooth.",
    propagate_version = true
)]
struct Cli {
    /// How to reach the Ledger.
    #[arg(long, short = 't', global = true, value_enum, default_value_t = TransportArg::Auto, env = "SEALCTL_TRANSPORT")]
    transport: TransportArg,

    /// Bluetooth scan timeout in seconds.
    #[arg(long, global = true, default_value_t = 30, env = "SEALCTL_BLE_SCAN")]
    ble_scan: u64,

    /// More logging (-v, -vv for raw APDUs).
    #[arg(long, short, global = true, action = clap::ArgAction::Count)]
    verbose: u8,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Copy, Clone, ValueEnum)]
enum TransportArg {
    /// USB first, then Bluetooth.
    Auto,
    Usb,
    #[value(alias = "bluetooth")]
    Ble,
}

#[derive(Subcommand)]
enum Cmd {
    /// Overview: key, volumes (locked/unlocked, last backup), services. No device needed.
    Status,

    /// Unlock a volume (decrypts its key on the Ledger).
    Unlock { name: String },
    /// Lock a volume (backs it up first if configured). Without a name: lock all volumes and
    /// stop the agent.
    Lock {
        name: Option<String>,
        /// Skip the backup before locking.
        #[arg(long)]
        no_backup: bool,
        /// Unmount even if files are open.
        #[arg(long)]
        force: bool,
    },

    /// Encrypted volumes.
    #[command(subcommand)]
    Volume(VolumeCmd),

    /// Encrypted, versioned backups of volumes (restic).
    #[command(subcommand)]
    Backup(BackupCmd),

    /// API keys and tokens (pass-compatible store, local only).
    #[command(subcommand)]
    Secret(SecretCmd),

    /// Run a command with secrets in its environment (from .sealctl.toml and --env).
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

    /// Encrypt a file (or stdin) to yourself and/or other certificates.
    Encrypt {
        input: Option<PathBuf>,
        /// Additional recipient certificate files.
        #[arg(long, short)]
        recipient: Vec<PathBuf>,
        /// Don't encrypt to your own key.
        #[arg(long)]
        no_self: bool,
        #[arg(long, short)]
        output: Option<PathBuf>,
        /// ASCII armor (default when writing to a terminal or .asc).
        #[arg(long, short)]
        armor: bool,
    },
    /// Decrypt a file (or stdin) on the Ledger.
    Decrypt {
        input: Option<PathBuf>,
        #[arg(long, short)]
        output: Option<PathBuf>,
    },

    /// The session agent: remembers Ledger results after one PIN entry, exits when idle.
    #[command(subcommand)]
    Agent(AgentCmd),

    /// SSH agent and public key.
    #[command(subcommand)]
    Ssh(SshCmd),

    /// Git commit signing with the Ledger.
    #[command(subcommand)]
    Git(GitCmd),

    /// One-time: create seed-derived keys on the Ledger OpenPGP app.
    Setup {
        /// OpenPGP User ID, e.g. "Jane Doe <jane@example.org>".
        #[arg(long)]
        uid: Option<String>,
        /// Regenerate keys even if the card already has some.
        #[arg(long)]
        force: bool,
    },
    /// Change the user or admin PIN (entered on the Ledger).
    Pin {
        #[arg(value_enum)]
        which: pin::Which,
    },
    /// Check that the card keys match the certificate and seed-derived keys are reproducible.
    Doctor {
        /// Also do a test decryption on the device.
        #[arg(long)]
        full: bool,
    },
    /// Recovery kit (public / encrypted files needed besides the seed).
    #[command(subcommand)]
    Kit(KitCmd),

    /// Disaster recovery without a Ledger: recompute your decryption key from the 24 words and
    /// serve it through the agent, so unlock / backup restore / secrets work. Verified against
    /// your certificate. Exposes the phrase to this computer — use only to recover, offline.
    Recover {
        /// OpenPGP app key slot (1–3).
        #[arg(long, default_value_t = 1)]
        slot: u32,
        /// Ask for a BIP39 passphrase (only if you set one up on the Ledger).
        #[arg(long)]
        passphrase: bool,
        /// Stop after this many idle minutes.
        #[arg(long, default_value_t = 60)]
        idle: u64,
    },

    /// List Ledger devices on USB and Bluetooth.
    Devices,
    /// Show the OpenPGP card state on the device.
    Card,
    /// Print shell completions.
    Completions { shell: clap_complete::Shell },
}

#[derive(Subcommand)]
enum VolumeCmd {
    /// Create an encrypted volume (mounted right away).
    Create {
        name: String,
        /// Maximum size, e.g. 50g (sparse: uses space only as it fills).
        #[arg(long, default_value = "50g")]
        size: String,
        #[arg(long, value_enum)]
        kind: Option<Kind>,
        /// Image/container file (default ~/Vaults/<name>.sparsebundle or .luks).
        #[arg(long)]
        path: Option<PathBuf>,
        /// APFS container for --kind apfs-volume, e.g. disk3.
        #[arg(long)]
        container: Option<String>,
        #[arg(long)]
        mountpoint: Option<PathBuf>,
    },
    /// List volumes.
    Ls,
    /// Register an existing sealctl volume on this machine (e.g. after recovery):
    /// a .sparsebundle / .luks path, or an APFS volume UUID.
    Import {
        name: String,
        /// Path of the image file, or the APFS volume UUID.
        target: String,
        #[arg(long, value_enum)]
        kind: Kind,
        #[arg(long)]
        mountpoint: Option<PathBuf>,
    },
    /// Convert a volume made by an older sealctl (stored key file) to a seed-derived key.
    Rekey { name: String },
    /// Forget a volume (keeps the encrypted data unless --delete-data).
    Rm {
        name: String,
        #[arg(long)]
        delete_data: bool,
    },
}

#[derive(Subcommand)]
enum BackupCmd {
    /// Configure restic backups for an unlocked volume.
    Init {
        volume: String,
        /// restic repository, e.g. s3:https://<account>.r2.cloudflarestorage.com/<bucket>/<path>
        #[arg(long)]
        repo: String,
        /// Extra environment for restic, KEY=VALUE (credentials are asked for if missing).
        #[arg(long = "env", short = 'e')]
        env: Vec<String>,
        /// Id the repository password is derived from (default: the volume name).
        #[arg(long)]
        key_id: Option<String>,
    },
    /// Switch an existing repository to the password derived from a key id (default: the
    /// volume name) — e.g. repositories created by sealctl 0.2.0, which used the URL.
    Rekey {
        volume: String,
        #[arg(long)]
        key_id: Option<String>,
    },
    /// Back up volumes now.
    Run {
        volumes: Vec<String>,
        #[arg(long)]
        all: bool,
        /// Silently skip locked volumes (for schedules).
        #[arg(long)]
        if_unlocked: bool,
        #[arg(long, short)]
        quiet: bool,
    },
    /// List snapshots (works while locked: uses the Ledger).
    Snapshots { volume: String },
    /// Restore files from a snapshot.
    Restore {
        volume: String,
        #[arg(long, default_value = "latest")]
        snapshot: String,
        #[arg(long)]
        target: PathBuf,
        /// Paths to restore (relative to the volume), repeatable.
        #[arg(long)]
        include: Vec<String>,
    },
    /// Verify repository integrity.
    Check {
        volume: String,
        /// Also read this percentage of the data.
        #[arg(long)]
        read_data: Option<u8>,
    },
    /// Change backup behaviour of a volume.
    Policy {
        volume: String,
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
    /// Periodic backups of unlocked volumes (launchd / systemd).
    #[command(subcommand)]
    Schedule(ScheduleCmd),
}

#[derive(Subcommand)]
enum ScheduleCmd {
    Install {
        /// Interval in minutes.
        #[arg(long, default_value_t = 60)]
        every: u64,
    },
    Uninstall,
}

#[derive(Subcommand)]
enum SecretCmd {
    /// Store a secret (value from stdin, or asked without echo).
    Set {
        name: String,
        #[arg(long)]
        force: bool,
    },
    /// Print a secret (or copy it with -c, cleared after 45 s).
    Get {
        name: String,
        #[arg(long, short)]
        clip: bool,
    },
    /// List secret names.
    Ls,
    /// Delete a secret.
    Rm { name: String },
    /// Move a .env file into the store and write .sealctl.toml for `sealctl run`.
    ImportEnv {
        #[arg(default_value = ".env")]
        file: PathBuf,
        /// Name prefix, e.g. the project name.
        #[arg(long)]
        prefix: String,
        /// Delete the .env file afterwards.
        #[arg(long)]
        delete: bool,
    },
}

#[derive(Subcommand)]
enum AgentCmd {
    /// Run the agent in the foreground (normally started automatically).
    Run {
        /// Exit after this many minutes without requests.
        #[arg(long, default_value_t = 60)]
        idle: u64,
        /// Exit this many hours after starting, even while in use (PIN needed again).
        #[arg(long, default_value_t = 24)]
        max_hours: u64,
    },
    /// Forget everything now and exit.
    Stop,
    /// Is it running, how much is cached, when does it expire.
    Status,
}

#[derive(Subcommand)]
enum SshCmd {
    /// New SSH key: random Ed25519, saved as ~/.ssh/sealctl_<name> (standard OpenSSH format),
    /// encrypted with a passphrase derived on the Ledger from its fingerprint. The agent keeps it
    /// unlocked for the session (1 h idle, 24 h max) — no Ledger round trip per signature.
    Keygen {
        #[arg(default_value = "ed25519")]
        name: String,
        /// Key comment (default: your certificate's user id).
        #[arg(long)]
        comment: Option<String>,
    },
    /// Print a public key: an encrypted key file's by name, or the Ledger key's.
    Pubkey { name: Option<String> },
    /// Print the passphrase of an encrypted key file (for ssh-keygen -p / other agents).
    Passphrase {
        #[arg(default_value = "ed25519")]
        name: String,
    },
    /// Run the agent in the foreground.
    Agent {
        #[arg(long)]
        socket: Option<PathBuf>,
    },
    /// Install the agent as a login service.
    Install,
    /// Remove the login service.
    Uninstall,
}

#[derive(Subcommand)]
enum GitCmd {
    /// Configure git to sign commits and tags (Ledger key, or an encrypted key file).
    Setup {
        /// Only for the current repository.
        #[arg(long)]
        local: bool,
        /// Sign with the encrypted key file ~/.ssh/sealctl_<NAME> instead of the Ledger key.
        #[arg(long)]
        key: Option<String>,
        /// Remove the signing settings sealctl made.
        #[arg(long)]
        undo: bool,
    },
    /// (internal) ssh-keygen wrapper used as gpg.ssh.program.
    #[command(hide = true, name = "ssh-keygen")]
    SshKeygen {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
}

#[derive(Subcommand)]
enum KitCmd {
    Export { dir: PathBuf },
    Import { dir: PathBuf },
}

fn main() {
    let cli = Cli::parse();
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(match cli.verbose {
        // btleplug logs a spurious error on macOS disconnect; hide it unless verbose
        // ssh_agent_lib logs every unsupported optional request (e.g. OpenSSH's extension query)
        0 => "warn,btleplug=off,ssh_agent_lib=off",
        1 => "debug",
        _ => "trace",
    }))
    .format_timestamp(None)
    .init();

    if let Err(e) = real_main(cli) {
        eprintln!("Error: {e:#}");
        std::process::exit(1);
    }
}

fn transport_args(cli: &Cli) -> Vec<String> {
    let t = match cli.transport {
        TransportArg::Auto => "auto",
        TransportArg::Usb => "usb",
        TransportArg::Ble => "ble",
    };
    vec!["--transport".into(), t.into()]
}

fn real_main(cli: Cli) -> Result<()> {
    let ctx = Ctx {
        select: match cli.transport {
            TransportArg::Auto => Select::Auto,
            TransportArg::Usb => Select::Usb,
            TransportArg::Ble => Select::Ble,
        },
        scan: Duration::from_secs(cli.ble_scan),
    };
    let targs = transport_args(&cli);
    match cli.cmd {
        Cmd::Status => card::overview(),
        Cmd::Unlock { name } => {
            if volume::Volume::load(&name)?.is_unlocked()? {
                println!("'{name}' is already unlocked");
                return Ok(());
            }
            volume::unlock(agent::oracle(&ctx)?.as_mut(), &name).map(|_| ())
        }
        Cmd::Lock {
            name: Some(n),
            no_backup,
            force,
        } => volume::lock(&n, no_backup, force),
        Cmd::Lock {
            name: None,
            no_backup,
            force,
        } => {
            volume::lock_all(no_backup, force)?;
            if ssh::forget() {
                println!("🔒 SSH keys forgotten by the agent");
            }
            if agent::stop()? {
                println!("🔒 agent stopped — the Ledger is needed again next time");
            }
            Ok(())
        }
        Cmd::Recover {
            slot,
            passphrase,
            idle,
        } => {
            if !(1..=3).contains(&slot) {
                anyhow::bail!("slot must be 1, 2 or 3");
            }
            let expected = sealctl::recover::expected_public()?;
            let words = sealctl::recover::read_phrase()?;
            let pass = if passphrase {
                sealctl::util::read_hidden("BIP39 passphrase: ")?
            } else {
                zeroize::Zeroizing::new(String::new())
            };
            let key = sealctl::recover::recover_key(&words, &pass, slot - 1, &expected)?;
            drop((words, pass));
            println!("✅ recovered the decryption key — it matches your certificate");
            println!("   Recovery agent running. In another terminal: sealctl unlock <name>,");
            println!("   sealctl backup restore …, sealctl secret get …   (Ctrl-C to stop)");
            agent::run_with(
                ctx,
                agent::Limits {
                    idle: Duration::from_secs(idle.max(1) * 60),
                    max_life: Duration::from_secs(24 * 3600),
                },
                Some(Box::new(sealctl::recover::SeedOracle(key))),
            )
        }
        Cmd::Agent(AgentCmd::Run { idle, max_hours }) => agent::run(
            ctx,
            agent::Limits {
                idle: Duration::from_secs(idle.max(1) * 60),
                max_life: Duration::from_secs(max_hours.max(1) * 3600),
            },
        ),
        Cmd::Agent(AgentCmd::Stop) => {
            println!(
                "{}",
                if agent::stop()? {
                    "agent stopped"
                } else {
                    "agent was not running"
                }
            );
            Ok(())
        }
        Cmd::Agent(AgentCmd::Status) => {
            match agent::AgentClient::connect() {
                Ok(mut c) => {
                    let (n, idle_left, life_left) = c.status()?;
                    println!(
                        "running — {n} cached result(s); exits after {} min idle, at the latest in {}h{:02}m",
                        idle_left / 60,
                        life_left / 3600,
                        (life_left % 3600) / 60
                    );
                }
                Err(_) => println!("not running (starts automatically when needed)"),
            }
            Ok(())
        }

        Cmd::Volume(VolumeCmd::Create {
            name,
            size,
            kind,
            path,
            container,
            mountpoint,
        }) => {
            let v = volume::create(
                agent::oracle(&ctx)?.as_mut(),
                volume::CreateOpts {
                    name,
                    kind: kind.unwrap_or_else(Kind::default_for_os),
                    size,
                    path,
                    container,
                    mountpoint,
                },
            )?;
            println!(
                "✅ volume '{}' created and unlocked at {}",
                v.name,
                v.mountpoint.display()
            );
            println!(
                "   Its key is derived from your Ledger seed and the volume id {} — nothing to back up.",
                v.id
            );
            Ok(())
        }
        Cmd::Volume(VolumeCmd::Ls) => {
            for v in volume::Volume::list()? {
                let (icon, err) = match v.is_unlocked() {
                    Ok(true) => ("🔓", None),
                    Ok(false) => ("🔒", None),
                    Err(e) => ("❓", Some(e)),
                };
                println!(
                    "{:<14} {:<13} {} {}",
                    v.name,
                    format!("{:?}", v.kind).to_lowercase(),
                    icon,
                    v.mountpoint.display()
                );
                if let Some(e) = err {
                    println!("               state unknown: {e:#}");
                }
            }
            Ok(())
        }
        Cmd::Volume(VolumeCmd::Import {
            name,
            target,
            kind,
            mountpoint,
        }) => volume::import(&name, kind, &target, mountpoint).map(|_| ()),
        Cmd::Volume(VolumeCmd::Rekey { name }) => volume::rekey(&ctx, agent::oracle(&ctx)?.as_mut(), &name),
        Cmd::Volume(VolumeCmd::Rm { name, delete_data }) => {
            if delete_data && !util::confirm(&format!("Permanently delete the encrypted data of '{name}'?"))?
            {
                return Ok(());
            }
            volume::remove(&name, delete_data)
        }

        Cmd::Backup(b) => match b {
            BackupCmd::Init {
                volume,
                repo,
                env,
                key_id,
            } => backup::init(
                agent::oracle(&ctx)?.as_mut(),
                &volume,
                &repo,
                key_id.as_deref(),
                &env,
            ),
            BackupCmd::Rekey { volume, key_id } => {
                backup::rekey(agent::oracle(&ctx)?.as_mut(), &volume, key_id.as_deref())
            }
            BackupCmd::Run {
                volumes,
                all,
                if_unlocked,
                quiet,
            } => backup::run(&volumes, all, if_unlocked, quiet),
            BackupCmd::Snapshots { volume } => backup::snapshots(agent::oracle(&ctx)?.as_mut(), &volume),
            BackupCmd::Restore {
                volume,
                snapshot,
                target,
                include,
            } => backup::restore(
                agent::oracle(&ctx)?.as_mut(),
                &volume,
                &snapshot,
                &target,
                &include,
            ),
            BackupCmd::Check { volume, read_data } => {
                backup::check(agent::oracle(&ctx)?.as_mut(), &volume, read_data)
            }
            BackupCmd::Policy {
                volume,
                on_lock,
                scheduled,
                keep_daily,
                keep_weekly,
                keep_monthly,
            } => backup::set_policy(&volume, |p| {
                if let Some(x) = on_lock {
                    p.on_lock = x;
                }
                if let Some(x) = scheduled {
                    p.scheduled = x;
                }
                if let Some(x) = keep_daily {
                    p.keep_daily = x;
                }
                if let Some(x) = keep_weekly {
                    p.keep_weekly = x;
                }
                if let Some(x) = keep_monthly {
                    p.keep_monthly = x;
                }
            }),
            BackupCmd::Schedule(ScheduleCmd::Install { every }) => backup::schedule_install(every),
            BackupCmd::Schedule(ScheduleCmd::Uninstall) => backup::schedule_uninstall(),
        },

        Cmd::Secret(s) => match s {
            SecretCmd::Set { name, force } => {
                let v = secrets::read_value(&name)?;
                secrets::set(agent::oracle(&ctx)?.as_mut(), &name, &v, force)?;
                eprintln!("✅ stored {name}");
                Ok(())
            }
            SecretCmd::Get { name, clip } => {
                let v = secrets::get(agent::oracle(&ctx)?.as_mut(), &name)?;
                if clip {
                    util::copy_to_clipboard_with_clear(&v, 45)?;
                    eprintln!("📋 copied {name} (clears in 45 s)");
                } else {
                    println!("{}", v.as_str());
                }
                Ok(())
            }
            SecretCmd::Ls => {
                for n in secrets::list()? {
                    println!("{n}");
                }
                Ok(())
            }
            SecretCmd::Rm { name } => secrets::remove(&name),
            SecretCmd::ImportEnv { file, prefix, delete } => {
                project::import_dotenv(agent::oracle(&ctx)?.as_mut(), &file, &prefix, delete)
            }
        },
        Cmd::Run {
            env,
            no_project,
            command,
        } => project::run(agent::oracle(&ctx)?.as_mut(), &env, !no_project, &command),

        Cmd::Encrypt {
            input,
            recipient,
            no_self,
            output,
            armor,
        } => {
            let mut certs = recipient
                .iter()
                .map(|p| cert::read(p))
                .collect::<Result<Vec<_>>>()?;
            if !no_self {
                certs.push(cert::own()?);
            }
            let data = read_input(input.as_ref())?;
            let armor = armor
                || output
                    .as_ref()
                    .is_some_and(|p| p.extension().is_some_and(|e| e == "asc"))
                || (output.is_none() && std::io::IsTerminal::is_terminal(&std::io::stdout()));
            let ct = crypto::encrypt(&certs, &data, armor)?;
            write_output(output.as_ref(), &ct, false)
        }
        Cmd::Decrypt { input, output } => {
            let data = read_input(input.as_ref())?;
            let pt = crypto::decrypt(&ctx, &data)?;
            write_output(output.as_ref(), &pt, true)
        }

        Cmd::Ssh(s) => match s {
            SshCmd::Keygen { name, comment } => {
                let comment = match comment {
                    Some(c) => c,
                    None => cert::own()
                        .map(|c| cert::primary_user_id(&c))
                        .unwrap_or_else(|_| format!("sealctl {name}")),
                };
                let path = ssh::keygen(agent::oracle(&ctx)?.as_mut(), &name, &comment)?;
                let public = ssh::read_public(&path)?;
                println!(
                    "✅ {} (encrypted; passphrase derived from your Ledger seed)",
                    path.display()
                );
                println!("   {}", public.fingerprint(ssh_key::HashAlg::Sha256));
                println!("   Back up this file — the 24 words alone cannot recreate a random key.");
                println!(
                    "   Public key ({}.pub) — add it to GitHub / authorized_keys:",
                    path.display()
                );
                println!("   {}", public.to_openssh()?);
                Ok(())
            }
            SshCmd::Pubkey { name: Some(name) } => {
                println!("{}", ssh::read_public(&ssh::key_path(&name)?)?.to_openssh()?);
                Ok(())
            }
            SshCmd::Pubkey { name: None } => {
                println!("{}", ssh::public_key_line(&cert::own()?)?);
                Ok(())
            }
            SshCmd::Passphrase { name } => {
                let public = ssh::read_public(&ssh::key_path(&name)?)?;
                let pass = ssh::passphrase_for(agent::oracle(&ctx)?.as_mut(), &public)?;
                println!("{}", *pass);
                Ok(())
            }
            SshCmd::Agent { socket } => ssh::run_agent(ctx, socket),
            SshCmd::Install => ssh::install(targs),
            SshCmd::Uninstall => sealctl::service::uninstall(ssh::AGENT_LABEL),
        },
        Cmd::Git(GitCmd::Setup { local, key, undo }) => {
            if undo {
                git::undo(local)
            } else {
                git::setup(local, key.as_deref())
            }
        }
        Cmd::Git(GitCmd::SshKeygen { args }) => git::ssh_keygen_shim(&args),

        Cmd::Setup { uid, force } => setup::setup(&ctx, uid, force),
        Cmd::Pin { which } => pin::change(&ctx, which),
        Cmd::Doctor { full } => doctor::run(&ctx, full),
        Cmd::Kit(KitCmd::Export { dir }) => kit::export(&dir),
        Cmd::Kit(KitCmd::Import { dir }) => kit::import(&dir),
        Cmd::Devices => card::devices(ctx.select, ctx.scan),
        Cmd::Card => card::status(&ctx),
        Cmd::Completions { shell } => {
            clap_complete::generate(shell, &mut Cli::command(), "sealctl", &mut std::io::stdout());
            Ok(())
        }
    }
}

fn read_input(p: Option<&PathBuf>) -> Result<Vec<u8>> {
    match p {
        Some(p) if p.as_os_str() != "-" => {
            std::fs::read(p).with_context(|| format!("reading {}", p.display()))
        }
        _ => {
            let mut v = Vec::new();
            std::io::stdin().read_to_end(&mut v)?;
            Ok(v)
        }
    }
}

fn write_output(p: Option<&PathBuf>, data: &[u8], private: bool) -> Result<()> {
    match p {
        Some(p) if p.as_os_str() != "-" => {
            if private {
                sealctl::paths::write_private(p, data)
            } else {
                std::fs::write(p, data).with_context(|| format!("writing {}", p.display()))
            }
        }
        _ => {
            std::io::stdout().write_all(data)?;
            Ok(())
        }
    }
}
