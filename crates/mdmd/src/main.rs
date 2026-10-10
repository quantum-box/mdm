use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use mdm_protocol::CommandPayload;
use mdmd::{
    apns::ApnsClient,
    config::Config,
    gateway::GatewayKey,
    http::{App, router_with_gateway},
    identity::Identity,
    storage::Store,
};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};

#[derive(Parser)]
#[command(version, about = "Independent Apple MDM engine and management CLI")]
struct Cli {
    #[arg(
        long,
        global = true,
        env = "MDM_API_URL",
        default_value = "https://mdm.example.com"
    )]
    api_url: String,
    #[arg(long, global = true, env = "MDM_ADMIN_TOKEN", hide_env_values = true)]
    token: Option<String>,
    #[command(subcommand)]
    action: Action,
}
#[derive(Subcommand)]
enum Action {
    /// Run the HTTPS server, or a loopback backend behind a trusted TLS proxy.
    Serve(Serve),
    /// Create a private local enrollment CA. Existing files are never overwritten.
    InitCa {
        #[arg(long, default_value = "data/ca.pem")]
        cert: PathBuf,
        #[arg(long, default_value = "data/ca-key.pem")]
        key: PathBuf,
    },
    /// Save a one-time enrollment profile; prints only the enrollment ID.
    Enroll {
        #[arg(long)]
        output: PathBuf,
    },
    Devices {
        #[arg(long)]
        after: Option<String>,
    },
    Command {
        enrollment_id: String,
        /// Reuse this key only to retry the exact same management request.
        #[arg(long)]
        idempotency_key: Option<String>,
        #[command(subcommand)]
        command: DeviceCommand,
    },
    Status {
        command_id: String,
    },
    Revoke {
        enrollment_id: String,
    },
    Cancel {
        command_id: String,
    },
    Audit {
        #[arg(long, default_value_t = 0)]
        after: i64,
    },
    Certificates,
    /// Manage declarations and device-channel declarative management.
    Ddm {
        #[command(subcommand)]
        operation: DdmAction,
    },
    /// Manage legacy application commands and Apps & Books assignments.
    Apps {
        #[command(subcommand)]
        operation: AppsAction,
    },
    /// Query and schedule legacy operating-system updates.
    Os {
        #[command(subcommand)]
        operation: OsAction,
    },
    /// Immediately lock an enrolled device.
    Lock {
        enrollment_id: String,
        #[arg(long)]
        message: Option<String>,
        #[arg(long)]
        phone_number: Option<String>,
        #[arg(long)]
        pin: Option<String>,
        #[arg(long)]
        idempotency_key: Option<String>,
    },
    /// Apply or release a supervised-device App Lock kiosk profile.
    Kiosk {
        enrollment_id: String,
        #[command(subcommand)]
        operation: KioskAction,
    },
    /// Manage Automated Device Enrollment state and profiles.
    Ade {
        #[command(subcommand)]
        operation: AdeAction,
    },
    /// Prepare and execute a destructive erase with a two-step confirmation.
    Erase {
        #[command(subcommand)]
        operation: EraseAction,
    },
    /// Read server-side device observations.
    Observations {
        enrollment_id: String,
    },
    /// Read configured Apple integration metadata.
    IntegrationsApple,
    /// Create a consistent SQLite snapshot. Back up CA/APNs keys separately.
    Backup {
        #[arg(long, default_value = "data/mdm.sqlite")]
        database: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Validate and restore a private snapshot into a new database file.
    Restore {
        #[arg(long)]
        backup: PathBuf,
        #[arg(long)]
        database: PathBuf,
    },
}
#[derive(Args)]
struct Serve {
    #[arg(long, default_value = "data/mdm.sqlite", env = "MDM_DATABASE")]
    database: PathBuf,
    #[arg(long, default_value = "127.0.0.1:8080", env = "MDM_BIND")]
    bind: SocketAddr,
    #[arg(long, env = "MDM_PUBLIC_URL")]
    public_url: String,
    #[arg(long, env = "MDM_BOOTSTRAP_URL")]
    bootstrap_url: Option<String>,
    #[arg(long, env = "MDM_TOPIC")]
    topic: String,
    #[arg(long, default_value = "MDM", env = "MDM_ORGANIZATION")]
    organization: String,
    #[arg(long, default_value = "data/ca.pem", env = "MDM_CA_CERT")]
    ca_cert: PathBuf,
    #[arg(long, default_value = "data/ca-key.pem", env = "MDM_CA_KEY")]
    ca_key: PathBuf,
    #[arg(long, env = "MDM_APNS_IDENTITY")]
    apns_identity: Option<PathBuf>,
    #[arg(long, env = "MDM_READ_TOKEN", hide_env_values = true)]
    read_token: Option<String>,
    /// Trust certificate headers overwritten by the local TLS proxy. Read docs/nginx.conf.
    #[arg(long, env = "MDM_TRUST_PROXY")]
    trust_proxy: bool,
    /// HMAC key file used by a public request gateway.
    #[arg(long, env = "MDM_GATEWAY_KEY_FILE", hide_env_values = true)]
    gateway_key_file: Option<PathBuf>,
    /// HTTPS certificate chain for the built-in TLS listener.
    #[arg(long, env = "MDM_TLS_CERT")]
    tls_cert: Option<PathBuf>,
    /// Matching HTTPS private key, stored privately.
    #[arg(long, env = "MDM_TLS_KEY")]
    tls_key: Option<PathBuf>,
}
#[derive(Subcommand)]
enum DeviceCommand {
    Info {
        #[arg(long="query",default_values=["DeviceName","OSVersion","SerialNumber","ModelName","UDID"])]
        queries: Vec<String>,
    },
    Install {
        #[arg(long)]
        profile: PathBuf,
    },
    Remove {
        #[arg(long)]
        identifier: String,
    },
}

#[derive(Subcommand)]
enum AppsAction {
    /// Install or update an App Store device-licensed or HTTPS enterprise app.
    Install {
        enrollment_id: String,
        #[arg(
            long,
            conflicts_with = "manifest_url",
            required_unless_present = "manifest_url"
        )]
        app_store_id: Option<u64>,
        #[arg(
            long,
            conflicts_with = "app_store_id",
            required_unless_present = "app_store_id"
        )]
        manifest_url: Option<String>,
        #[arg(long, default_value_t = 1)]
        purchase_method: u8,
        #[arg(long)]
        idempotency_key: Option<String>,
    },
    /// Remove a managed app by bundle identifier.
    Remove {
        enrollment_id: String,
        identifier: String,
        #[arg(long)]
        idempotency_key: Option<String>,
    },
    /// Query installed applications.
    Installed {
        enrollment_id: String,
        #[arg(long = "identifier")]
        identifiers: Vec<String>,
        #[arg(long)]
        managed_only: bool,
        #[arg(long = "item")]
        items: Vec<String>,
        #[arg(long)]
        idempotency_key: Option<String>,
    },
    /// Query managed application state.
    Managed {
        enrollment_id: String,
        #[arg(long = "identifier")]
        identifiers: Vec<String>,
        #[arg(long)]
        idempotency_key: Option<String>,
    },
    /// Assign or unassign an Apps & Books device license.
    License {
        adam_id: u64,
        serial_number: String,
        #[arg(long, conflicts_with = "unassign")]
        assign: bool,
        #[arg(long, conflicts_with = "assign")]
        unassign: bool,
        #[arg(long)]
        idempotency_key: Option<String>,
    },
    /// Read one Apps & Books license assignment.
    LicenseStatus {
        adam_id: u64,
        #[arg(long)]
        serial_number: String,
    },
}

#[derive(Subcommand)]
enum OsAction {
    /// Query available updates.
    List {
        enrollment_id: String,
        #[arg(long)]
        idempotency_key: Option<String>,
    },
    /// Query update status.
    Status {
        enrollment_id: String,
        #[arg(long)]
        idempotency_key: Option<String>,
    },
    /// Schedule a legacy OS update.
    Schedule {
        enrollment_id: String,
        #[arg(long)]
        product_key: Option<String>,
        #[arg(long)]
        product_version: Option<String>,
        #[arg(long, default_value = "Default")]
        install_action: String,
        #[arg(long)]
        max_user_deferrals: Option<u64>,
        #[arg(long)]
        priority: Option<String>,
        #[arg(long)]
        idempotency_key: Option<String>,
    },
}

#[derive(Subcommand)]
enum KioskAction {
    Apply {
        #[arg(long)]
        bundle_id: String,
        #[arg(long)]
        idempotency_key: Option<String>,
    },
    Release {
        #[arg(long)]
        idempotency_key: Option<String>,
    },
}

#[derive(Subcommand)]
enum AdeAction {
    Devices,
    Sync {
        #[arg(long)]
        cursor: Option<String>,
    },
    Profile {
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        idempotency_key: Option<String>,
    },
    Assign {
        #[arg(long)]
        profile_uuid: String,
        #[arg(long = "device")]
        devices: Vec<String>,
        #[arg(long)]
        idempotency_key: Option<String>,
    },
    Unassign {
        #[arg(long)]
        profile_uuid: String,
        #[arg(long = "device")]
        devices: Vec<String>,
        #[arg(long)]
        idempotency_key: Option<String>,
    },
    /// Release an ADE device from await-configuration via DeviceConfigured.
    Configured {
        enrollment_id: String,
        #[arg(long)]
        idempotency_key: Option<String>,
    },
}

#[derive(Subcommand)]
enum EraseAction {
    Prepare {
        enrollment_id: String,
        #[arg(long)]
        output: PathBuf,
    },
    Execute {
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        confirm_serial: String,
        #[arg(long)]
        idempotency_key: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EraseIntentFile {
    enrollment_id: String,
    id: String,
    token: String,
    serial_number: String,
    expires_at: i64,
}

#[derive(Subcommand)]
enum DdmAction {
    Enable {
        enrollment_id: String,
        #[arg(long)]
        idempotency_key: Option<String>,
    },
    Put {
        #[arg(long)]
        file: PathBuf,
    },
    List {
        #[arg(long)]
        after: Option<String>,
    },
    /// Replace the complete target set. Omit --enrollment to unassign all.
    Targets {
        identifier: String,
        #[arg(long = "enrollment")]
        enrollment_ids: Vec<String>,
    },
    Delete {
        identifier: String,
        #[arg(long)]
        server_token: String,
    },
    Status {
        enrollment_id: String,
        #[arg(long, default_value_t = 0)]
        after: i64,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "mdmd=info".into()),
        )
        .init();
    let cli = Cli::parse();
    match cli.action {
        Action::InitCa { cert, key } => {
            Identity::initialize(&cert, &key)?;
            println!("Enrollment CA created. Protect the key and back it up.");
        }
        Action::Backup { database, output } => {
            if !database.is_file() {
                bail!("backup source database does not exist");
            }
            Store::open(&database)?.backup(&output)?;
            println!("Snapshot saved to {}", output.display());
        }
        Action::Restore { backup, database } => {
            mdmd::recovery::restore_database(&backup, &database)?;
            println!("Validated snapshot restored to {}", database.display());
        }
        Action::Serve(args) => {
            let config = Config {
                database: args.database,
                bind: args.bind,
                public_url: args.public_url,
                bootstrap_url: args.bootstrap_url,
                topic: args.topic,
                organization: args.organization,
                ca_cert: args.ca_cert,
                ca_key: args.ca_key,
                apns_identity: args.apns_identity,
                admin_token: cli
                    .token
                    .context("set MDM_ADMIN_TOKEN (32 or more random characters)")?,
                read_token: args.read_token,
                trust_proxy: args.trust_proxy,
                gateway_key_file: args.gateway_key_file,
                tls_cert: args.tls_cert,
                tls_key: args.tls_key,
            };
            serve(config).await?;
        }
        action => {
            let client = ApiClient::new(
                &cli.api_url,
                cli.token
                    .context("set MDM_ADMIN_TOKEN for the management API")?,
            )?;
            match action {
                Action::Enroll { output } => {
                    let mut file = create_private_file(&output)?;
                    let result: Result<String> = async {
                        let response = client
                            .request(reqwest::Method::POST, "/v1/enrollments", None)
                            .await?;
                        let profile = response["profile"]
                            .as_str()
                            .context("server did not return a profile")?;
                        use std::io::Write;
                        file.write_all(profile.as_bytes())?;
                        file.sync_all()?;
                        Ok(response["id"]
                            .as_str()
                            .context("server did not return an enrollment ID")?
                            .to_owned())
                    }
                    .await;
                    if result.is_err() {
                        // Only this invocation's create_new output is removed.
                        // A failed HTTP request must not leave an empty file
                        // that prevents retrying enrollment at the same path.
                        drop(file);
                        let _ = fs::remove_file(&output);
                    }
                    println!("{}", result?);
                }
                Action::Devices { after } => {
                    let path = match after {
                        Some(id) => format!("/v1/enrollments?after={}", url_component(&id)),
                        None => "/v1/enrollments".to_owned(),
                    };
                    print_json(client.request(reqwest::Method::GET, &path, None).await?)?;
                }
                Action::Command {
                    enrollment_id,
                    idempotency_key,
                    command,
                } => {
                    let command = match command {
                        DeviceCommand::Info { queries } => {
                            CommandPayload::DeviceInformation { queries }
                        }
                        DeviceCommand::Install { profile } => CommandPayload::InstallProfile {
                            payload: fs::read(profile)?,
                        },
                        DeviceCommand::Remove { identifier } => {
                            CommandPayload::RemoveProfile { identifier }
                        }
                    };
                    command.validate()?;
                    let key = idempotency_key.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
                    // Print the key before network I/O so a lost response can be retried safely.
                    eprintln!("Idempotency key: {key}");
                    let body = serde_json::json!({"idempotency_key":key,"command":command});
                    print_json(
                        client
                            .request(
                                reqwest::Method::POST,
                                &format!(
                                    "/v1/enrollments/{}/commands",
                                    url_component(&enrollment_id)
                                ),
                                Some(body),
                            )
                            .await?,
                    )?;
                }
                Action::Status { command_id } => print_json(
                    client
                        .request(
                            reqwest::Method::GET,
                            &format!("/v1/commands/{}", url_component(&command_id)),
                            None,
                        )
                        .await?,
                )?,
                Action::Revoke { enrollment_id } => {
                    client
                        .request(
                            reqwest::Method::POST,
                            &format!("/v1/enrollments/{}/revoke", url_component(&enrollment_id)),
                            None,
                        )
                        .await?;
                    println!("Enrollment revoked: {enrollment_id}");
                }
                Action::Cancel { command_id } => {
                    client
                        .request(
                            reqwest::Method::POST,
                            &format!("/v1/commands/{}/cancel", url_component(&command_id)),
                            None,
                        )
                        .await?;
                    println!("Command cancelled: {command_id}");
                }
                Action::Audit { after } => print_json(
                    client
                        .request(
                            reqwest::Method::GET,
                            &format!("/v1/audit?after={after}"),
                            None,
                        )
                        .await?,
                )?,
                Action::Certificates => print_json(
                    client
                        .request(reqwest::Method::GET, "/v1/certificates", None)
                        .await?,
                )?,
                Action::Ddm { operation } => {
                    let (method, path, body) = match operation {
                        DdmAction::Enable {
                            enrollment_id,
                            idempotency_key,
                        } => {
                            let key =
                                idempotency_key.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
                            eprintln!("Idempotency key: {key}");
                            (
                                reqwest::Method::POST,
                                format!(
                                    "/v1/enrollments/{}/ddm/enable",
                                    url_component(&enrollment_id)
                                ),
                                Some(serde_json::json!({"idempotency_key":key})),
                            )
                        }
                        DdmAction::Put { file } => {
                            if fs::metadata(&file)?.len() > 256 * 1024 {
                                bail!("declaration file is too large");
                            }
                            let declaration: mdm_core::AppleDeclaration =
                                serde_json::from_slice(&fs::read(file)?)?;
                            declaration.validate()?;
                            (
                                reqwest::Method::POST,
                                "/v1/declarations".to_owned(),
                                Some(serde_json::to_value(declaration)?),
                            )
                        }
                        DdmAction::List { after } => {
                            let path = after
                                .map(|id| format!("/v1/declarations?after={}", url_component(&id)))
                                .unwrap_or_else(|| "/v1/declarations".to_owned());
                            (reqwest::Method::GET, path, None)
                        }
                        DdmAction::Targets {
                            identifier,
                            enrollment_ids,
                        } => (
                            reqwest::Method::PUT,
                            format!("/v1/declarations/{}/targets", url_component(&identifier)),
                            Some(serde_json::json!({"enrollment_ids":enrollment_ids})),
                        ),
                        DdmAction::Delete {
                            identifier,
                            server_token,
                        } => (
                            reqwest::Method::DELETE,
                            format!(
                                "/v1/declarations/{}?server_token={}",
                                url_component(&identifier),
                                url_component(&server_token)
                            ),
                            None,
                        ),
                        DdmAction::Status {
                            enrollment_id,
                            after,
                        } => (
                            reqwest::Method::GET,
                            format!(
                                "/v1/enrollments/{}/ddm/status?after={after}",
                                url_component(&enrollment_id)
                            ),
                            None,
                        ),
                    };
                    print_json(client.request(method, &path, body).await?)?;
                }
                Action::Apps { operation } => match operation {
                    AppsAction::Install {
                        enrollment_id,
                        app_store_id,
                        manifest_url,
                        purchase_method,
                        idempotency_key,
                    } => {
                        let source = match (app_store_id, manifest_url) {
                            (Some(itunes_store_id), None) => {
                                mdm_protocol::ApplicationInstallSource::AppStore {
                                    itunes_store_id,
                                    purchase_method,
                                }
                            }
                            (None, Some(manifest_url)) => {
                                mdm_protocol::ApplicationInstallSource::Enterprise { manifest_url }
                            }
                            _ => bail!("specify exactly one of --app-store-id or --manifest-url"),
                        };
                        print_json(
                            enqueue_command(
                                &client,
                                &enrollment_id,
                                idempotency_key,
                                CommandPayload::InstallApplication { source },
                            )
                            .await?,
                        )?;
                    }
                    AppsAction::Remove {
                        enrollment_id,
                        identifier,
                        idempotency_key,
                    } => {
                        print_json(
                            enqueue_command(
                                &client,
                                &enrollment_id,
                                idempotency_key,
                                CommandPayload::RemoveApplication { identifier },
                            )
                            .await?,
                        )?;
                    }
                    AppsAction::Installed {
                        enrollment_id,
                        identifiers,
                        managed_only,
                        items,
                        idempotency_key,
                    } => {
                        let identifiers = (!identifiers.is_empty()).then_some(identifiers);
                        let items = (!items.is_empty()).then_some(items);
                        print_json(
                            enqueue_command(
                                &client,
                                &enrollment_id,
                                idempotency_key,
                                CommandPayload::InstalledApplicationList {
                                    identifiers,
                                    managed_apps_only: managed_only,
                                    items,
                                },
                            )
                            .await?,
                        )?;
                    }
                    AppsAction::Managed {
                        enrollment_id,
                        identifiers,
                        idempotency_key,
                    } => {
                        print_json(
                            enqueue_command(
                                &client,
                                &enrollment_id,
                                idempotency_key,
                                CommandPayload::ManagedApplicationList {
                                    identifiers: (!identifiers.is_empty()).then_some(identifiers),
                                },
                            )
                            .await?,
                        )?;
                    }
                    AppsAction::License {
                        adam_id,
                        serial_number,
                        assign,
                        unassign,
                        idempotency_key,
                    } => {
                        if assign == unassign {
                            bail!("specify exactly one of --assign or --unassign");
                        }
                        let key =
                            idempotency_key.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
                        eprintln!("Idempotency key: {key}");
                        print_json(
                            client
                                .request(
                                    reqwest::Method::POST,
                                    "/v1/apps/licenses",
                                    Some(serde_json::json!({
                                        "adam_id": adam_id,
                                        "serial_number": serial_number,
                                        "assign": assign,
                                        "idempotency_key": key,
                                    })),
                                )
                                .await?,
                        )?;
                    }
                    AppsAction::LicenseStatus {
                        adam_id,
                        serial_number,
                    } => print_json(
                        client
                            .request(
                                reqwest::Method::GET,
                                &format!(
                                    "/v1/apps/licenses/{}?serial={}",
                                    url_component(&adam_id.to_string()),
                                    url_component(&serial_number)
                                ),
                                None,
                            )
                            .await?,
                    )?,
                },
                Action::Os { operation } => match operation {
                    OsAction::List {
                        enrollment_id,
                        idempotency_key,
                    } => {
                        print_json(
                            enqueue_command(
                                &client,
                                &enrollment_id,
                                idempotency_key,
                                CommandPayload::AvailableOSUpdates,
                            )
                            .await?,
                        )?;
                    }
                    OsAction::Status {
                        enrollment_id,
                        idempotency_key,
                    } => {
                        print_json(
                            enqueue_command(
                                &client,
                                &enrollment_id,
                                idempotency_key,
                                CommandPayload::OSUpdateStatus,
                            )
                            .await?,
                        )?;
                    }
                    OsAction::Schedule {
                        enrollment_id,
                        product_key,
                        product_version,
                        install_action,
                        max_user_deferrals,
                        priority,
                        idempotency_key,
                    } => {
                        let install_action = parse_install_action(&install_action)?;
                        let priority =
                            priority.as_deref().map(parse_update_priority).transpose()?;
                        print_json(
                            enqueue_command(
                                &client,
                                &enrollment_id,
                                idempotency_key,
                                CommandPayload::ScheduleOSUpdate {
                                    updates: vec![mdm_protocol::OsUpdate {
                                        product_key,
                                        product_version,
                                        install_action,
                                        max_user_deferrals,
                                        priority,
                                    }],
                                },
                            )
                            .await?,
                        )?;
                    }
                },
                Action::Lock {
                    enrollment_id,
                    message,
                    phone_number,
                    pin,
                    idempotency_key,
                } => {
                    print_json(
                        enqueue_command(
                            &client,
                            &enrollment_id,
                            idempotency_key,
                            CommandPayload::DeviceLock {
                                message,
                                phone_number,
                                pin,
                            },
                        )
                        .await?,
                    )?;
                }
                Action::Kiosk {
                    enrollment_id,
                    operation,
                } => {
                    let (path, body) = match operation {
                        KioskAction::Apply {
                            bundle_id,
                            idempotency_key,
                        } => {
                            let key =
                                idempotency_key.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
                            eprintln!("Idempotency key: {key}");
                            (
                                format!("/v1/enrollments/{}/kiosk", url_component(&enrollment_id)),
                                serde_json::json!({
                                    "bundle_id": bundle_id,
                                    "idempotency_key": key,
                                }),
                            )
                        }
                        KioskAction::Release { idempotency_key } => {
                            let key =
                                idempotency_key.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
                            eprintln!("Idempotency key: {key}");
                            (
                                format!(
                                    "/v1/enrollments/{}/kiosk/release",
                                    url_component(&enrollment_id)
                                ),
                                serde_json::json!({"idempotency_key":key}),
                            )
                        }
                    };
                    print_json(
                        client
                            .request(reqwest::Method::POST, &path, Some(body))
                            .await?,
                    )?;
                }
                Action::Ade { operation } => match operation {
                    AdeAction::Devices => print_json(
                        client
                            .request(reqwest::Method::GET, "/v1/ade/devices", None)
                            .await?,
                    )?,
                    AdeAction::Sync { cursor } => print_json(
                        client
                            .request(
                                reqwest::Method::POST,
                                "/v1/ade/sync",
                                Some(serde_json::json!({"cursor": cursor})),
                            )
                            .await?,
                    )?,
                    AdeAction::Profile {
                        file,
                        idempotency_key,
                    } => {
                        let profile: serde_json::Value = serde_json::from_slice(&fs::read(file)?)?;
                        let key =
                            idempotency_key.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
                        eprintln!("Idempotency key: {key}");
                        print_json(
                            client
                                .request(
                                    reqwest::Method::POST,
                                    "/v1/ade/profiles",
                                    Some(serde_json::json!({
                                        "profile": profile,
                                        "idempotency_key": key,
                                    })),
                                )
                                .await?,
                        )?;
                    }
                    AdeAction::Assign {
                        profile_uuid,
                        devices,
                        idempotency_key,
                    } => {
                        let key =
                            idempotency_key.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
                        eprintln!("Idempotency key: {key}");
                        print_json(
                            client
                                .request(
                                    reqwest::Method::POST,
                                    "/v1/ade/assign",
                                    Some(serde_json::json!({
                                        "profile_uuid": profile_uuid,
                                        "devices": devices,
                                        "idempotency_key": key,
                                    })),
                                )
                                .await?,
                        )?;
                    }
                    AdeAction::Unassign {
                        profile_uuid,
                        devices,
                        idempotency_key,
                    } => {
                        let key =
                            idempotency_key.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
                        eprintln!("Idempotency key: {key}");
                        print_json(
                            client
                                .request(
                                    reqwest::Method::POST,
                                    "/v1/ade/unassign",
                                    Some(serde_json::json!({
                                        "profile_uuid": profile_uuid,
                                        "devices": devices,
                                        "idempotency_key": key,
                                    })),
                                )
                                .await?,
                        )?;
                    }
                    AdeAction::Configured {
                        enrollment_id,
                        idempotency_key,
                    } => {
                        print_json(
                            enqueue_command(
                                &client,
                                &enrollment_id,
                                idempotency_key,
                                CommandPayload::DeviceConfigured,
                            )
                            .await?,
                        )?;
                    }
                },
                Action::Erase { operation } => match operation {
                    EraseAction::Prepare {
                        enrollment_id,
                        output,
                    } => {
                        let mut file = create_private_file(&output)?;
                        let result: Result<String> = async {
                            let response = client
                                .request(
                                    reqwest::Method::POST,
                                    &format!(
                                        "/v1/enrollments/{}/erase-intents",
                                        url_component(&enrollment_id)
                                    ),
                                    None,
                                )
                                .await?;
                            let intent = EraseIntentFile {
                                enrollment_id,
                                id: response["id"]
                                    .as_str()
                                    .context("erase intent response missing id")?
                                    .to_owned(),
                                token: response["token"]
                                    .as_str()
                                    .context("erase intent response missing token")?
                                    .to_owned(),
                                serial_number: response["serial_number"]
                                    .as_str()
                                    .context("erase intent response missing serial_number")?
                                    .to_owned(),
                                expires_at: response["expires_at"]
                                    .as_i64()
                                    .context("erase intent response missing expires_at")?,
                            };
                            use std::io::Write;
                            file.write_all(serde_json::to_string_pretty(&intent)?.as_bytes())?;
                            file.write_all(b"\n")?;
                            file.sync_all()?;
                            Ok(intent.id)
                        }
                        .await;
                        if result.is_err() {
                            drop(file);
                            let _ = fs::remove_file(&output);
                        }
                        println!("{}", result?);
                    }
                    EraseAction::Execute {
                        file,
                        confirm_serial,
                        idempotency_key,
                    } => {
                        let metadata =
                            fs::symlink_metadata(&file).context("inspect erase intent file")?;
                        if !metadata.file_type().is_file() {
                            bail!("erase intent file must be a regular file");
                        }
                        if metadata.len() > 16 * 1024 {
                            bail!("erase intent file is too large");
                        }
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::PermissionsExt;
                            if metadata.permissions().mode() & 0o077 != 0 {
                                bail!("erase intent file must be private (mode 0600)");
                            }
                        }
                        let intent: EraseIntentFile = serde_json::from_slice(&fs::read(&file)?)?;
                        if intent.serial_number != confirm_serial {
                            bail!("--confirm-serial does not match the prepared erase intent");
                        }
                        let key =
                            idempotency_key.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
                        eprintln!("Idempotency key: {key}");
                        print_json(
                            client
                                .request(
                                    reqwest::Method::POST,
                                    &format!(
                                        "/v1/enrollments/{}/erase",
                                        url_component(&intent.enrollment_id)
                                    ),
                                    Some(serde_json::json!({
                                        "intent_id": intent.id,
                                        "token": intent.token,
                                        "confirm_serial": confirm_serial,
                                        "idempotency_key": key,
                                    })),
                                )
                                .await?,
                        )?;
                    }
                },
                Action::Observations { enrollment_id } => print_json(
                    client
                        .request(
                            reqwest::Method::GET,
                            &format!(
                                "/v1/enrollments/{}/observations",
                                url_component(&enrollment_id)
                            ),
                            None,
                        )
                        .await?,
                )?,
                Action::IntegrationsApple => print_json(
                    client
                        .request(reqwest::Method::GET, "/v1/integrations/apple", None)
                        .await?,
                )?,
                _ => unreachable!(),
            }
        }
    }
    Ok(())
}

async fn serve(config: Config) -> Result<()> {
    config.validate()?;
    let gateway_key = config
        .gateway_key_file
        .as_ref()
        .map(|path| GatewayKey::load(path))
        .transpose()?;
    mdmd::apple::validate_configuration()?;
    let identity = Arc::new(Identity::load(&config.ca_cert, &config.ca_key)?);
    let apns = config
        .apns_identity
        .as_ref()
        .map(|path| ApnsClient::new(path, &config.topic).map(Arc::new))
        .transpose()?;
    let store = Store::open(&config.database)?;
    let listener = tokio::net::TcpListener::bind(config.bind).await?;
    let app = App {
        config: config.clone(),
        store: store.clone(),
        identity,
    };
    if apns.is_none() {
        tracing::warn!(
            category = "apns_unconfigured",
            message = "notifications remain pending until an Apple MDM Push identity is configured"
        );
    }
    tracing::info!(bind=%config.bind,version=env!("CARGO_PKG_VERSION"),"mdmd ready");
    let (stop, receiver) = tokio::sync::watch::channel(false);
    let worker = tokio::spawn(mdmd::worker::run(store, apns, receiver));
    let shutdown_sender = stop.clone();
    let shutdown = async move {
        shutdown_signal().await;
        let _ = shutdown_sender.send(true);
    };
    if let (Some(cert), Some(key)) = (&config.tls_cert, &config.tls_key) {
        mdmd::tls::serve_with_gateway(listener, app, cert, key, gateway_key, shutdown).await?;
    } else {
        axum::serve(
            listener,
            router_with_gateway(app, gateway_key, None)
                .into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(shutdown)
        .await?;
    }
    let _ = stop.send(true);
    worker.await?;
    Ok(())
}
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        if let Ok(mut term) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            tokio::select! {_=tokio::signal::ctrl_c()=>{},_=term.recv()=>{}}
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}
fn create_private_file(path: &Path) -> Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .context("create private output file (must not exist)")
}
fn url_component(value: &str) -> String {
    percent_encoding::utf8_percent_encode(value, percent_encoding::NON_ALPHANUMERIC).to_string()
}

async fn enqueue_command(
    client: &ApiClient,
    enrollment_id: &str,
    idempotency_key: Option<String>,
    command: CommandPayload,
) -> Result<serde_json::Value> {
    command.validate()?;
    let key = idempotency_key.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    // Print the key before network I/O so a lost response can be retried safely.
    eprintln!("Idempotency key: {key}");
    client
        .request(
            reqwest::Method::POST,
            &format!("/v1/enrollments/{}/commands", url_component(enrollment_id)),
            Some(serde_json::json!({"idempotency_key":key,"command":command})),
        )
        .await
}

fn parse_install_action(value: &str) -> Result<mdm_protocol::OsInstallAction> {
    match value {
        "Default" => Ok(mdm_protocol::OsInstallAction::Default),
        "DownloadOnly" => Ok(mdm_protocol::OsInstallAction::DownloadOnly),
        "InstallASAP" => Ok(mdm_protocol::OsInstallAction::InstallAsap),
        "NotifyOnly" => Ok(mdm_protocol::OsInstallAction::NotifyOnly),
        "InstallLater" => Ok(mdm_protocol::OsInstallAction::InstallLater),
        "InstallForceRestart" => Ok(mdm_protocol::OsInstallAction::InstallForceRestart),
        _ => bail!(
            "unsupported --install-action {value}; use Default, DownloadOnly, InstallASAP, NotifyOnly, InstallLater, or InstallForceRestart"
        ),
    }
}

fn parse_update_priority(value: &str) -> Result<mdm_protocol::OsUpdatePriority> {
    match value {
        "Low" => Ok(mdm_protocol::OsUpdatePriority::Low),
        "High" => Ok(mdm_protocol::OsUpdatePriority::High),
        _ => bail!("unsupported --priority {value}; use Low or High"),
    }
}

fn print_json(value: serde_json::Value) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}
struct ApiClient {
    client: reqwest::Client,
    base: String,
    token: String,
}
impl ApiClient {
    fn new(base: &str, token: String) -> Result<Self> {
        let url = reqwest::Url::parse(base)?;
        let loopback = url
            .host_str()
            .is_some_and(|h| h == "localhost" || h == "127.0.0.1" || h == "[::1]");
        if (url.scheme() != "https" && !(url.scheme() == "http" && loopback))
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.path() != "/"
        {
            bail!("API URL must be an HTTPS origin (HTTP is allowed only for loopback)");
        }
        if token.len() < 32 || token.chars().any(char::is_whitespace) {
            bail!("management token must have at least 32 characters without whitespace");
        }
        Ok(Self {
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
            base: base.trim_end_matches('/').to_owned(),
            token,
        })
    }
    async fn request(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> Result<serde_json::Value> {
        let mut request = self
            .client
            .request(method, format!("{}{path}", self.base))
            .bearer_auth(&self.token);
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send().await.context("management request failed")?;
        let status = response.status();
        if !status.is_success() {
            bail!("management API returned HTTP {status}");
        }
        if status == reqwest::StatusCode::NO_CONTENT {
            return Ok(serde_json::Value::Null);
        }
        response.json().await.context("invalid management response")
    }
}
