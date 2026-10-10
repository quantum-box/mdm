use anyhow::{Context, Result, bail};
use mdm_core::{CommandKind, CommandState, EnrollmentState, Reply};
use mdm_protocol::{CheckIn, CommandPayload, DeviceResponse, ResponseStatus};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    fmt, fs,
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

mod ddm;
mod operations;
pub use ddm::DeclarationView;
pub use operations::{AppleRequest, EraseIntent, ObservationView};

pub const DEFER_SECONDS: i64 = 30;
pub const RESPONSE_TIMEOUT_SECONDS: i64 = 300;

#[derive(Debug)]
pub enum StoreError {
    NotFound,
    Conflict,
    Unauthorized,
    InvalidInput,
}
impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotFound => "resource not found",
            Self::Conflict => "request conflicts with persisted state",
            Self::Unauthorized => "device identity is not active",
            Self::InvalidInput => "invalid request",
        })
    }
}
impl std::error::Error for StoreError {}

#[derive(Clone)]
pub struct Store(Arc<Mutex<Connection>>);

#[derive(Serialize)]
pub struct EnrollmentView {
    pub id: String,
    pub state: String,
    pub udid: Option<String>,
    pub serial_number: Option<String>,
    pub device_name: Option<String>,
    pub os_version: Option<String>,
    pub certificate_expires_at: Option<String>,
    pub push_ready: bool,
    pub created_at: i64,
    pub awaiting_configuration: bool,
    pub mdm_access_rights: i64,
}

#[derive(Serialize, Debug)]
pub struct CommandView {
    pub id: String,
    pub enrollment_id: String,
    pub kind: String,
    pub state: String,
    pub attempt_count: i64,
    pub created_at: i64,
    pub updated_at: i64,
    pub result: Option<serde_json::Value>,
    pub notification_state: String,
    pub notification_attempts: i64,
    pub notification_reason: Option<String>,
}

pub struct Notification {
    pub id: i64,
    pub enrollment_id: String,
    pub token: Vec<u8>,
    pub push_magic: String,
    pub attempt: i64,
}

pub struct IssuedCertificate {
    pub fingerprint: String,
    pub expires_at: String,
    pub response: Vec<u8>,
}

type IssuanceRecord = (String, String, i64, Option<String>, Option<Vec<u8>>);

pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
pub fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn state<T: serde::de::DeserializeOwned>(value: String) -> Result<T> {
    Ok(serde_json::from_value(serde_json::Value::String(value))?)
}
fn name<T: Serialize>(value: T) -> Result<String> {
    serde_json::to_value(value)?
        .as_str()
        .map(str::to_owned)
        .context("invalid persisted enum")
}
fn kind(payload: &CommandPayload) -> CommandKind {
    match payload {
        CommandPayload::DeviceInformation { .. } => CommandKind::DeviceInformation,
        CommandPayload::InstallProfile { .. } => CommandKind::InstallProfile,
        CommandPayload::RemoveProfile { .. } => CommandKind::RemoveProfile,
        CommandPayload::DeclarativeManagement { .. } => CommandKind::DeclarativeManagement,
        CommandPayload::InstallApplication { .. } => CommandKind::InstallApplication,
        CommandPayload::RemoveApplication { .. } => CommandKind::RemoveApplication,
        CommandPayload::InstalledApplicationList { .. } => CommandKind::InstalledApplicationList,
        CommandPayload::ManagedApplicationList { .. } => CommandKind::ManagedApplicationList,
        CommandPayload::AvailableOSUpdates => CommandKind::AvailableOsUpdates,
        CommandPayload::ScheduleOSUpdate { .. } => CommandKind::ScheduleOsUpdate,
        CommandPayload::OSUpdateStatus => CommandKind::OsUpdateStatus,
        CommandPayload::DeviceLock { .. } => CommandKind::DeviceLock,
        CommandPayload::EraseDevice { .. } => CommandKind::EraseDevice,
        CommandPayload::DeviceConfigured => CommandKind::DeviceConfigured,
    }
}
fn audit(tx: &Transaction<'_>, actor: &str, action: &str, id: &str, time: i64) -> Result<()> {
    tx.execute(
        "INSERT INTO audit(happened_at,actor,action,resource_id) VALUES(?,?,?,?)",
        params![time, actor, action, id],
    )?;
    Ok(())
}

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty())
            && !parent.exists()
        {
            fs::create_dir_all(parent)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
            }
        }
        let mut options = fs::OpenOptions::new();
        options.write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options.open(path).context("open database file")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if fs::metadata(path)?.permissions().mode() & 0o077 != 0 {
                bail!("database must be private: chmod 600 the database file");
            }
        }
        Self::from_connection(Connection::open(path)?)
    }
    pub fn memory() -> Result<Self> {
        Self::from_connection(Connection::open_in_memory()?)
    }
    fn from_connection(mut connection: Connection) -> Result<Self> {
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.execute_batch(
            "PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;",
        )?;
        let version: i64 = connection.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        match version {
            0 => {
                let tx = connection.transaction()?;
                tx.execute_batch(include_str!("../migrations/001_initial.sql"))?;
                tx.commit()?;
            }
            1..=4 => {}
            _ => bail!("database schema is newer than this binary"),
        }
        if version < 2 {
            let tx = connection.transaction()?;
            tx.execute_batch(include_str!("../migrations/002_ddm.sql"))?;
            tx.commit()?;
        }
        if version < 3 {
            let tx = connection.transaction()?;
            tx.execute_batch(include_str!("../migrations/003_operations.sql"))?;
            tx.commit()?;
        }
        if version < 4 {
            let tx = connection.transaction()?;
            tx.execute_batch(include_str!("../migrations/004_gateway.sql"))?;
            tx.commit()?;
        }
        Ok(Self(Arc::new(Mutex::new(connection))))
    }
    fn with_tx<T>(&self, action: impl FnOnce(&Transaction<'_>) -> Result<T>) -> Result<T> {
        let mut connection = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("storage lock poisoned"))?;
        let tx = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let result = action(&tx)?;
        tx.commit()?;
        Ok(result)
    }

    /// Atomically records a gateway nonce after removing expired entries.
    ///
    /// The immediate transaction serializes concurrent gateway requests, so a
    /// nonce can only be accepted once across processes that share the
    /// database.  A duplicate live nonce is returned as a generic conflict so
    /// callers do not need to expose database constraint details.
    pub fn claim_gateway_nonce(&self, nonce: &str, now: i64, expires_at: i64) -> Result<()> {
        if nonce.is_empty() || expires_at <= now {
            return Err(StoreError::InvalidInput.into());
        }
        self.with_tx(|tx| {
            tx.execute("DELETE FROM gateway_nonces WHERE expires_at <= ?", [now])?;
            match tx.execute(
                "INSERT INTO gateway_nonces(nonce,expires_at) VALUES(?,?)",
                params![nonce, expires_at],
            ) {
                Ok(_) => Ok(()),
                Err(rusqlite::Error::SqliteFailure(error, _))
                    if error.code == rusqlite::ErrorCode::ConstraintViolation =>
                {
                    Err(StoreError::Conflict.into())
                }
                Err(error) => Err(error.into()),
            }
        })
    }

    pub fn create_enrollment(&self, challenge: &str, time: i64) -> Result<String> {
        let id = Uuid::new_v4().to_string();
        self.with_tx(|tx| {
            tx.execute("INSERT INTO enrollments(id,state,challenge_hash,challenge_expires_at,created_at,updated_at,mdm_access_rights) VALUES(?,'pending',?,?,?,?,?)",
                params![id,digest(challenge.as_bytes()),time+900,time,time,mdm_protocol::ENROLLMENT_PROFILE_ACCESS_RIGHTS])?;
            audit(tx,"admin","create_enrollment",&id,time)?;
            Ok(id)
        })
    }

    // Issuance and one-time challenge consumption commit together. Exact request replay
    // returns the persisted CertRep, including across a crash after commit before HTTP reply.
    pub fn issue_identity(
        &self,
        challenge: &str,
        request_hash: &str,
        time: i64,
        issue: impl FnOnce(&str) -> Result<IssuedCertificate>,
    ) -> Result<Vec<u8>> {
        self.with_tx(|tx| {
            let record: Option<IssuanceRecord> = tx.query_row(
                "SELECT id,state,challenge_expires_at,scep_request_hash,scep_response FROM enrollments WHERE challenge_hash=?",
                [digest(challenge.as_bytes())], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).optional()?;
            let (id,current,expiry,prior_hash,prior_response) = record.ok_or(StoreError::Unauthorized)?;
            if current == "revoked" { return Err(StoreError::Unauthorized.into()); }
            if let Some(hash) = prior_hash {
                if hash == request_hash { return prior_response.context("missing persisted certificate response"); }
                return Err(StoreError::Conflict.into());
            }
            if expiry <= time || current != "pending" { return Err(StoreError::Unauthorized.into()); }
            let certificate = issue(&id)?;
            tx.execute("UPDATE enrollments SET fingerprint=?,certificate_expires_at=?,scep_request_hash=?,scep_response=?,updated_at=? WHERE id=?",
                params![certificate.fingerprint,certificate.expires_at,request_hash,certificate.response,time,id])?;
            audit(tx,"scep","issue_certificate",&id,time)?;
            Ok(certificate.response)
        })
    }

    fn subject(
        tx: &Transaction<'_>,
        fingerprint: &str,
    ) -> Result<(String, EnrollmentState, Option<String>)> {
        let record: Option<(String, String, Option<String>)> = tx
            .query_row(
                "SELECT id,state,udid FROM enrollments WHERE fingerprint=?",
                [fingerprint],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        let (id, current, udid) = record.ok_or(StoreError::Unauthorized)?;
        let current: EnrollmentState = state(current)?;
        if current == EnrollmentState::Revoked {
            return Err(StoreError::Unauthorized.into());
        }
        Ok((id, current, udid))
    }

    pub fn checkin(&self, fingerprint: &str, message: &CheckIn, time: i64) -> Result<()> {
        self.with_tx(|tx| {
            let (id,current,known_udid) = Self::subject(tx,fingerprint)?;
            let udid = match message {
                CheckIn::Authenticate {udid,..} | CheckIn::TokenUpdate {udid,..} | CheckIn::CheckOut {udid} | CheckIn::DeclarativeManagement {udid,..} => udid,
            };
            if known_udid.as_ref().is_some_and(|v| v != udid) { return Err(StoreError::Unauthorized.into()); }
            match message {
                CheckIn::Authenticate {serial_number,os_version,..} => {
                    let (expected_serial,expected_udid):(Option<String>,Option<String>)=tx.query_row("SELECT expected_serial,expected_udid FROM enrollments WHERE id=?",[&id],|r|Ok((r.get(0)?,r.get(1)?)))?;
                    if (expected_serial.is_some() && expected_serial.as_ref()!=serial_number.as_ref()) || expected_udid.as_ref().is_some_and(|expected|expected!=udid) {return Err(StoreError::Unauthorized.into());}
                    let next = current.authenticate().map_err(|_| StoreError::Conflict)?;
                    // A newly issued admin-authorized identity creates a new generation;
                    // all queued work for the previous generation is isolated/revoked.
                    let prior: Option<String> = tx.query_row("SELECT id FROM enrollments WHERE udid=? AND state!='revoked' AND id!=?",
                        params![udid,id],|r| r.get(0)).optional()?;
                    if let Some(prior) = prior { Self::revoke_tx(tx,&prior,"device",time)?; }
                    tx.execute("UPDATE enrollments SET state=?,udid=?,serial_number=?,os_version=?,updated_at=? WHERE id=?",
                        params![name(next)?,udid,serial_number,os_version,time,id])?;
                    audit(tx,"device","authenticate",&id,time)?;
                }
                CheckIn::TokenUpdate {token,push_magic,awaiting_configuration,..} => {
                    if known_udid.is_none() { return Err(StoreError::Conflict.into()); }
                    let next = current.token_update().map_err(|_| StoreError::Conflict)?;
                    tx.execute("UPDATE enrollments SET state=?,push_token=?,push_magic=?,awaiting_configuration=?,updated_at=? WHERE id=?",
                        params![name(next)?,token,push_magic,awaiting_configuration,time,id])?;
                    tx.execute("UPDATE outbox SET state='pending',available_at=?,lease_until=NULL WHERE enrollment_id=? AND state IN ('pending','rejected','accepted') AND command_id IN (SELECT id FROM commands WHERE state IN ('queued','deferred'))",
                        params![time,id])?;
                    audit(tx,"device","token_update",&id,time)?;
                }
                CheckIn::CheckOut {..} => {
                    if known_udid.is_none() { return Err(StoreError::Conflict.into()); }
                    Self::revoke_tx(tx,&id,"device",time)?;
                }
                CheckIn::DeclarativeManagement {..} => return Err(StoreError::InvalidInput.into()),
            }
            Ok(())
        })
    }

    fn revoke_tx(tx: &Transaction<'_>, id: &str, actor: &str, time: i64) -> Result<()> {
        tx.execute("UPDATE enrollments SET state='revoked',push_token=NULL,push_magic=NULL,scep_response=NULL,updated_at=? WHERE id=?",params![time,id])?;
        tx.execute("UPDATE commands SET state='cancelled',updated_at=? WHERE enrollment_id=? AND state IN ('queued','deferred','awaiting_response','outcome_unknown')",params![time,id])?;
        tx.execute(
            "UPDATE outbox SET state='cancelled',lease_until=NULL WHERE enrollment_id=?",
            [id],
        )?;
        audit(tx, actor, "revoke_enrollment", id, time)
    }
    pub fn revoke(&self, id: &str, time: i64) -> Result<()> {
        self.with_tx(|tx| {
            let exists: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM enrollments WHERE id=?)",
                [id],
                |r| r.get(0),
            )?;
            if !exists {
                return Err(StoreError::NotFound.into());
            }
            Self::revoke_tx(tx, id, "admin", time)
        })
    }

    pub fn enrollments(&self, after: Option<&str>) -> Result<Vec<EnrollmentView>> {
        self.with_tx(|tx| {
            let mut statement = tx.prepare("SELECT id,state,udid,serial_number,os_version,certificate_expires_at,push_token IS NOT NULL,created_at,awaiting_configuration,mdm_access_rights,(SELECT CASE WHEN json_type(body,'$.QueryResponses.DeviceName')='text' THEN substr(json_extract(body,'$.QueryResponses.DeviceName'),1,256) END FROM device_observations WHERE enrollment_id=enrollments.id AND category='device_information') FROM enrollments WHERE id>? ORDER BY id LIMIT 100")?;
            let rows = statement.query_map([after.unwrap_or("")],|r| Ok(EnrollmentView {
                id:r.get(0)?,state:r.get(1)?,udid:r.get(2)?,serial_number:r.get(3)?,os_version:r.get(4)?,certificate_expires_at:r.get(5)?,push_ready:r.get(6)?,created_at:r.get(7)?,awaiting_configuration:r.get(8)?,mdm_access_rights:r.get(9)?,device_name:r.get(10)?,
            }))?;
            Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
        })
    }

    pub fn enqueue(
        &self,
        enrollment_id: &str,
        payload: &CommandPayload,
        key: &str,
        time: i64,
    ) -> Result<String> {
        payload.validate().map_err(|_| StoreError::InvalidInput)?;
        if matches!(payload, CommandPayload::EraseDevice { .. }) {
            return Err(StoreError::InvalidInput.into());
        }
        if let CommandPayload::DeclarativeManagement { data } = payload {
            // Tokens belong to the persisted manifest. Management callers
            // cannot inject a token snapshot unrelated to that manifest.
            if data.is_some() {
                return Err(StoreError::InvalidInput.into());
            }
            return self.enable_ddm(enrollment_id, key, time);
        }
        if key.is_empty() || key.len() > 128 || key.chars().any(char::is_control) {
            return Err(StoreError::InvalidInput.into());
        }
        let serialized = serde_json::to_string(payload)?;
        let request_hash = digest(format!("{enrollment_id}\n{serialized}").as_bytes());
        self.with_tx(|tx| {
            Self::enqueue_tx(
                tx,
                enrollment_id,
                payload,
                key,
                &serialized,
                &request_hash,
                time,
            )
        })
    }

    fn enqueue_tx(
        tx: &Transaction<'_>,
        enrollment_id: &str,
        payload: &CommandPayload,
        key: &str,
        serialized: &str,
        request_hash: &str,
        time: i64,
    ) -> Result<String> {
        let prior: Option<(String, String)> = tx
            .query_row(
                "SELECT id,request_hash FROM commands WHERE idempotency_key=?",
                [key],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        if let Some((id, hash)) = prior {
            return if hash == request_hash {
                Ok(id)
            } else {
                Err(StoreError::Conflict.into())
            };
        }
        let current: Option<String> = tx
            .query_row(
                "SELECT state FROM enrollments WHERE id=?",
                [enrollment_id],
                |r| r.get(0),
            )
            .optional()?;
        if current.ok_or(StoreError::NotFound)? != "active" {
            return Err(StoreError::Conflict.into());
        }
        Self::validate_operation_tx(tx, enrollment_id, payload, time)?;
        let queued:i64=tx.query_row("SELECT count(*) FROM commands WHERE enrollment_id=? AND state IN ('queued','deferred','awaiting_response','outcome_unknown')",[enrollment_id],|r|r.get(0))?;
        if queued >= 256 {
            return Err(StoreError::Conflict.into());
        }
        let id = Uuid::new_v4().to_string();
        tx.execute("INSERT INTO commands(id,enrollment_id,kind,payload,state,idempotency_key,request_hash,next_attempt_at,created_at,updated_at) VALUES(?,?,?,?,'queued',?,?,?,?,?)",
                params![id,enrollment_id,name(kind(payload))?,serialized,key,request_hash,time,time,time])?;
        tx.execute("INSERT INTO outbox(command_id,enrollment_id,state,available_at) VALUES(?,?,'pending',?)",params![id,enrollment_id,time])?;
        audit(tx, "admin", "enqueue_command", &id, time)?;
        Ok(id)
    }

    pub fn command(&self, id: &str) -> Result<CommandView> {
        self.with_tx(|tx| {
            let view:Option<CommandView>=tx.query_row("SELECT c.id,c.enrollment_id,c.kind,c.state,c.attempt_count,c.created_at,c.updated_at,c.result,o.state,o.attempts,o.last_reason FROM commands c JOIN outbox o ON o.command_id=c.id WHERE c.id=?",[id],|r| {
                let result:Option<String>=r.get(7)?;
                Ok(CommandView {id:r.get(0)?,enrollment_id:r.get(1)?,kind:r.get(2)?,state:r.get(3)?,attempt_count:r.get(4)?,created_at:r.get(5)?,updated_at:r.get(6)?,result:result.and_then(|s|serde_json::from_str(&s).ok()),notification_state:r.get(8)?,notification_attempts:r.get(9)?,notification_reason:r.get(10)?})
            }).optional()?;
            view.ok_or_else(||StoreError::NotFound.into())
        })
    }

    pub fn poll(
        &self,
        fingerprint: &str,
        response: &DeviceResponse,
        time: i64,
    ) -> Result<Option<Vec<u8>>> {
        self.with_tx(|tx| {
            let (enrollment_id,current,known_udid)=Self::subject(tx,fingerprint)?;
            if current!=EnrollmentState::Active || known_udid.as_deref()!=Some(&response.udid) {return Err(StoreError::Unauthorized.into());}
            if response.status!=ResponseStatus::Idle { Self::respond_tx(tx,&enrollment_id,response,time)?; }
            let blocked:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM commands WHERE enrollment_id=? AND state IN ('awaiting_response','outcome_unknown'))",[&enrollment_id],|r|r.get(0))?;
            if blocked {return Ok(None);}
            let candidate:Option<(String,String,String,i64,i64)>=tx.query_row("SELECT id,payload,state,attempt_count,next_attempt_at FROM commands WHERE enrollment_id=? AND state IN ('queued','deferred') ORDER BY created_at,rowid LIMIT 1",[&enrollment_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).optional()?;
            let Some((id,payload,current,attempt,available))=candidate else{return Ok(None)};
            if available>time {return Ok(None);}
            let current:CommandState=state(current)?;
            let next=current.dispatch().map_err(|_|StoreError::Conflict)?;
            let payload:CommandPayload=serde_json::from_str(&payload)?;
            // Recheck time-sensitive prerequisites immediately before dispatch.
            if let Err(error)=Self::validate_operation_tx(tx,&enrollment_id,&payload,time) {
                if !matches!(error.downcast_ref::<StoreError>(),Some(StoreError::Conflict|StoreError::InvalidInput)) {return Err(error);}
                tx.execute("UPDATE commands SET state='failed',result=?,updated_at=? WHERE id=?",params!["{\"local_error\":\"operation_prerequisites_changed\"}",time,id])?;
                tx.execute("UPDATE outbox SET state='cancelled',lease_until=NULL WHERE command_id=?",[&id])?;
                audit(tx,"system","operation_prerequisites_changed",&id,time)?;
                return Ok(None);
            }
            // Serialization must succeed before dispatch is durably recorded.
            let bytes=mdm_protocol::encode_command(&id,&payload)?;
            tx.execute("UPDATE commands SET state=?,attempt_count=?,updated_at=? WHERE id=?",params![name(next)?,attempt+1,time,id])?;
            tx.execute("INSERT INTO delivery_attempts(command_id,attempt,dispatched_at) VALUES(?,?,?)",params![id,attempt+1,time])?;
            audit(tx,"device","dispatch_command",&id,time)?;
            Ok(Some(bytes))
        })
    }

    fn respond_tx(
        tx: &Transaction<'_>,
        enrollment_id: &str,
        response: &DeviceResponse,
        time: i64,
    ) -> Result<()> {
        let id = response
            .command_uuid
            .as_deref()
            .ok_or(StoreError::InvalidInput)?;
        let record:Option<(String,i64,Option<String>,String)>=tx.query_row("SELECT state,attempt_count,result,kind FROM commands WHERE id=? AND enrollment_id=?",params![id,enrollment_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()?;
        let (current, attempt, result, command_kind) = record.ok_or(StoreError::Conflict)?;
        if attempt == 0 {
            return Err(StoreError::Conflict.into());
        }
        // Convert through JSON Value to canonicalize dictionary ordering before
        // comparing retransmissions; plist key order carries no semantics.
        let body = serde_json::to_string(&serde_json::to_value(&response.raw)?)?;
        let reply = match response.status {
            ResponseStatus::Acknowledged => Reply::Acknowledged,
            ResponseStatus::Error => Reply::Error,
            ResponseStatus::CommandFormatError => Reply::CommandFormatError,
            ResponseStatus::NotNow => Reply::NotNow,
            ResponseStatus::Idle => return Err(StoreError::InvalidInput.into()),
        };
        let status = match response.status {
            ResponseStatus::Acknowledged => "Acknowledged",
            ResponseStatus::Error => "Error",
            ResponseStatus::CommandFormatError => "CommandFormatError",
            ResponseStatus::NotNow => "NotNow",
            ResponseStatus::Idle => unreachable!(),
        };
        let current: CommandState = state(current)?;
        // An administrator may cancel a command after it was dispatched while
        // the device is still able to return the old response.  The response
        // is authenticated and tied to this enrollment above, so consume it
        // as history without attempting a state transition.  In particular,
        // do not call CommandState::respond: Cancelled is intentionally a
        // terminal core state.  This lets the same poll continue to the next
        // queued command while keeping cancellation durable.
        if current == CommandState::Cancelled {
            let inserted = tx.execute(
                "INSERT OR IGNORE INTO responses(command_id,attempt,status,digest,body,received_at) VALUES(?,?,?,?,?,?)",
                params![id, attempt, status, digest(body.as_bytes()), body, time],
            )?;
            if inserted != 0 {
                audit(tx, "device", "late_cancelled_response_ignored", id, time)?;
            }
            return Ok(());
        }
        if matches!(current, CommandState::Completed | CommandState::Failed) {
            if result.as_deref() == Some(&body) {
                return Ok(());
            }
            return Err(StoreError::Conflict.into());
        }
        // Previously stored identical responses in this dispatch attempt are idempotent.
        let inserted=tx.execute("INSERT OR IGNORE INTO responses(command_id,attempt,status,digest,body,received_at) VALUES(?,?,?,?,?,?)",params![id,attempt,status,digest(body.as_bytes()),body,time])?;
        if inserted == 0 {
            return Ok(());
        }
        // A read-only retry can still be queued when its previous dispatch's
        // response arrives. Persisted attempt_count proves it was dispatched.
        let response_state = if current == CommandState::Queued
            && state::<CommandKind>(command_kind)?.is_read_only()
        {
            CommandState::AwaitingResponse
        } else {
            current
        };
        let next = response_state
            .respond(reply)
            .map_err(|_| StoreError::Conflict)?;
        let final_result = if response.status == ResponseStatus::NotNow {
            None
        } else {
            Some(&body)
        };
        tx.execute(
            "UPDATE commands SET state=?,result=?,next_attempt_at=?,updated_at=? WHERE id=?",
            params![name(next)?, final_result, time + DEFER_SECONDS, time, id],
        )?;
        if response.status == ResponseStatus::NotNow {
            tx.execute("UPDATE outbox SET state='pending',available_at=?,lease_until=NULL WHERE command_id=?",params![time+DEFER_SECONDS,id])?;
        } else {
            tx.execute("UPDATE outbox SET state='cancelled',lease_until=NULL WHERE command_id=? AND state IN ('pending','leased')",[id])?;
        }
        if response.status == ResponseStatus::Acknowledged {
            Self::observe_response_tx(tx, enrollment_id, id, &response.raw, time)?;
        }
        audit(tx, "device", "command_response", id, time)
    }

    pub fn recover_timeouts(&self, time: i64) -> Result<usize> {
        self.with_tx(|tx| {
            let records={
                let mut stmt=tx.prepare("SELECT id,kind FROM commands WHERE state='awaiting_response' AND updated_at<=?")?;
                stmt.query_map([time-RESPONSE_TIMEOUT_SECONDS],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?)))?.collect::<rusqlite::Result<Vec<_>>>()?
            };
            for (id,command_kind) in &records {
                let next=CommandState::AwaitingResponse.timeout(state(command_kind.clone())?);
                tx.execute("UPDATE commands SET state=?,next_attempt_at=?,updated_at=? WHERE id=?",params![name(next)?,time,time,id])?;
                if next==CommandState::Queued {
                    tx.execute("UPDATE outbox SET state='pending',available_at=?,lease_until=NULL WHERE command_id=?",params![time,id])?;
                }
                audit(tx,"system","response_timeout",id,time)?;
            }
            Ok(records.len())
        })
    }

    // Manual cancellation does not claim the device failed to execute the command.
    pub fn cancel_command(&self, id: &str, time: i64) -> Result<()> {
        self.with_tx(|tx| {
            let current: Option<String> = tx
                .query_row("SELECT state FROM commands WHERE id=?", [id], |r| r.get(0))
                .optional()?;
            let current: CommandState = state(current.ok_or(StoreError::NotFound)?)?;
            tx.execute(
                "UPDATE commands SET state=?,updated_at=? WHERE id=?",
                params![name(current.cancel())?, time, id],
            )?;
            tx.execute(
                "UPDATE outbox SET state='cancelled',lease_until=NULL WHERE command_id=?",
                [id],
            )?;
            audit(tx, "admin", "cancel_command", id, time)
        })
    }

    pub fn claim_notification(&self, time: i64) -> Result<Option<Notification>> {
        self.with_tx(|tx| {
            let record:Option<(i64,String,Vec<u8>,String,i64)>=tx.query_row(
                "SELECT o.id,o.enrollment_id,e.push_token,e.push_magic,o.attempts FROM outbox o JOIN enrollments e ON e.id=o.enrollment_id JOIN commands c ON c.id=o.command_id WHERE e.state='active' AND e.push_token IS NOT NULL AND e.push_magic IS NOT NULL AND c.state IN ('queued','deferred','awaiting_response') AND ((o.state='pending' AND o.available_at<=?) OR (o.state='leased' AND o.lease_until<=?) OR (o.state='accepted' AND o.available_at<=? AND c.state IN ('queued','deferred'))) ORDER BY o.id LIMIT 1",
                params![time,time,time],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).optional()?;
            let Some((id,enrollment_id,token,push_magic,attempt))=record else{return Ok(None)};
            tx.execute("UPDATE outbox SET state='leased',lease_until=?,attempts=attempts+1 WHERE id=?",params![time+60,id])?;
            Ok(Some(Notification{id,enrollment_id,token,push_magic,attempt:attempt+1}))
        })
    }
    pub fn finish_notification(
        &self,
        job: &Notification,
        outcome: &str,
        reason: Option<&str>,
        apns_id: Option<&str>,
        time: i64,
    ) -> Result<()> {
        self.with_tx(|tx| {
            // Compare lease attempt so a stale worker cannot overwrite a newer delivery.
            let current:Option<(String,i64)>=tx.query_row("SELECT state,attempts FROM outbox WHERE id=?",[job.id],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
            if current!=Some(("leased".to_owned(),job.attempt)) {return Ok(());}
            let (next,delay)=match outcome {
                // APNs acceptance does not guarantee that a device wakes up.
                // Repush after five minutes while work remains undispatched.
                "accepted"=>("accepted",300),
                "retry"=>("pending",(5_i64*2_i64.pow(job.attempt.min(8) as u32)).min(900)),
                "rejected"=>("rejected",0),
                _=>return Err(StoreError::InvalidInput.into()),
            };
            tx.execute("UPDATE outbox SET state=?,available_at=?,lease_until=NULL,last_reason=?,apns_id=? WHERE id=?",params![next,time+delay,reason,apns_id,job.id])?;
            tx.execute("INSERT INTO notification_attempts(outbox_id,attempted_at,outcome,reason,apns_id) VALUES(?,?,?,?,?)",params![job.id,time,outcome,reason,apns_id])?;
            audit(tx,"system","notification_result",&job.id.to_string(),time)
        })
    }

    pub fn audits(&self, after: i64) -> Result<Vec<serde_json::Value>> {
        self.with_tx(|tx| {
            let mut stmt=tx.prepare("SELECT id,happened_at,actor,action,resource_id FROM audit WHERE id>? ORDER BY id LIMIT 100")?;
            Ok(stmt.query_map([after],|r|Ok(serde_json::json!({"id":r.get::<_,i64>(0)?,"happened_at":r.get::<_,i64>(1)?,"actor":r.get::<_,String>(2)?,"action":r.get::<_,String>(3)?,"resource_id":r.get::<_,String>(4)?})))?.collect::<rusqlite::Result<Vec<_>>>()?)
        })
    }

    pub fn backup(&self, destination: &Path) -> Result<()> {
        if destination.exists() {
            bail!("backup destination already exists");
        }
        let connection = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("storage lock poisoned"))?;
        // Precreate the empty destination privately. SQLite accepts an empty
        // existing file for VACUUM INTO; no public-permission exposure window.
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options.open(destination)?;
        // SQLite creates a consistent standalone snapshot including committed WAL content.
        connection.execute(
            "VACUUM INTO ?",
            [destination.to_str().context("backup path must be UTF-8")?],
        )?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(destination, fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }
}
