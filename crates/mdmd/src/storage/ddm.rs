use super::*;
use mdm_core::{
    AppManagedPayload, AppleDeclaration, AppleDeclarationType, OperationKind, OsVersion,
};
use mdm_protocol::{ACCESS_RIGHT_APPLICATION_MANAGEMENT, DeclarativeEndpoint};
use serde_json::{Value, json};
use std::collections::BTreeSet;

#[derive(Debug, Serialize)]
pub struct DeclarationView {
    pub declaration: AppleDeclaration,
    pub deleted: bool,
    pub targets: Vec<String>,
    pub updated_at: i64,
}

impl Store {
    fn validate_declaration_target_tx(
        tx: &Transaction<'_>,
        id: &str,
        declaration: &AppleDeclaration,
        time: i64,
    ) -> Result<()> {
        let os: String =
            tx.query_row("SELECT os_version FROM enrollments WHERE id=?", [id], |r| {
                r.get(0)
            })?;
        declaration
            .validate_for_ipados(os.as_str())
            .map_err(|_| StoreError::Conflict)?;

        if declaration
            .supported_type()
            .map_err(|_| StoreError::InvalidInput)?
            == AppleDeclarationType::AppManaged
        {
            let rights: i64 = tx.query_row(
                "SELECT mdm_access_rights FROM enrollments WHERE id=?",
                [id],
                |r| r.get(0),
            )?;
            if rights & ACCESS_RIGHT_APPLICATION_MANAGEMENT != ACCESS_RIGHT_APPLICATION_MANAGEMENT {
                return Err(StoreError::Conflict.into());
            }
            let payload: AppManagedPayload = serde_json::from_value(declaration.payload.clone())
                .map_err(|_| StoreError::InvalidInput)?;
            if payload.required_supervision() {
                Self::require_supervised_tx(tx, id, OperationKind::SilentAppInstall, time)?;
            }
        }
        Ok(())
    }

    fn ddm_target(tx: &Transaction<'_>, id: &str) -> Result<()> {
        let row: Option<(String, Option<String>)> = tx
            .query_row(
                "SELECT state,os_version FROM enrollments WHERE id=?",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let (current, os) = row.ok_or(StoreError::NotFound)?;
        if current != "active" {
            return Err(StoreError::Conflict.into());
        }
        let os = OsVersion::parse(os.as_deref().ok_or(StoreError::Conflict)?)
            .map_err(|_| StoreError::Conflict)?;
        // DDM for device enrollment is available starting with iPadOS 16.
        if os < OsVersion::new(16, 0, 0) {
            return Err(StoreError::Conflict.into());
        }
        Ok(())
    }

    fn ddm_command_tx(tx: &Transaction<'_>, id: &str, key: &str, time: i64) -> Result<String> {
        let payload = CommandPayload::DeclarativeManagement { data: None };
        let serialized = serde_json::to_string(&payload)?;
        let hash = digest(format!("{id}\n{serialized}").as_bytes());
        Self::enqueue_tx(tx, id, &payload, key, &serialized, &hash, time)
    }

    fn ddm_changed_tx(tx: &Transaction<'_>, id: &str, time: i64) -> Result<()> {
        let current: String =
            tx.query_row("SELECT state FROM enrollments WHERE id=?", [id], |r| {
                r.get(0)
            })?;
        if current != "active" {
            return Ok(());
        }
        tx.execute(
            "UPDATE ddm_state SET declarations_token=?,updated_at=? WHERE enrollment_id=?",
            params![Uuid::new_v4().to_string(), time, id],
        )?;
        // A pending command with no Data fetches the current tokens, so several
        // edits can share it. An in-flight command never gets rewritten.
        let queued: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM commands WHERE enrollment_id=? AND kind='declarative_management' AND state IN ('queued','deferred'))",[id],|r|r.get(0))?;
        if !queued {
            Self::ddm_command_tx(tx, id, &format!("ddm-sync-{}", Uuid::new_v4()), time)?;
        }
        audit(tx, "admin", "ddm_manifest_changed", id, time)
    }

    pub fn enable_ddm(&self, id: &str, key: &str, time: i64) -> Result<String> {
        if key.is_empty() || key.len() > 128 || key.chars().any(char::is_control) {
            return Err(StoreError::InvalidInput.into());
        }
        self.with_tx(|tx| {
            Self::ddm_target(tx,id)?;
            tx.execute("INSERT OR IGNORE INTO ddm_state(enrollment_id,declarations_token,updated_at) VALUES(?,?,?)",
                params![id,Uuid::new_v4().to_string(),time])?;
            Self::ddm_command_tx(tx,id,key,time)
        })
    }

    pub fn put_declaration(&self, declaration: &AppleDeclaration, time: i64) -> Result<()> {
        declaration
            .validate()
            .map_err(|_| StoreError::InvalidInput)?;
        DeclarativeEndpoint::parse(&format!(
            "declaration/{}/{}",
            declaration.kind(),
            declaration.identifier
        ))
        .map_err(|_| StoreError::InvalidInput)?;
        let body = declaration.canonical_json();
        if body.len() > 256 * 1024 {
            return Err(StoreError::InvalidInput.into());
        }
        self.with_tx(|tx| {
            let prior: Option<(String,String,String,bool)> = tx.query_row(
                "SELECT category,server_token,body,deleted FROM declarations WHERE identifier=?",
                [&declaration.identifier],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()?;
            if let Some((category, token, current, deleted)) = &prior {
                if category != &declaration.kind() { return Err(StoreError::Conflict.into()); }
                if token == &declaration.server_token {
                    return if current==&body && !deleted { Ok(()) } else { Err(StoreError::Conflict.into()) };
                }
            }
            // Never reuse a historical opaque revision, even after deletion.
            let reused: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM declaration_revisions WHERE identifier=? AND server_token=?)",
                params![declaration.identifier,declaration.server_token],|r|r.get(0))?;
            if reused { return Err(StoreError::Conflict.into()); }
            let targets = Self::targets_tx(tx,&declaration.identifier)?;
            for id in &targets {
                Self::validate_declaration_target_tx(tx, id, declaration, time)?;
            }
            tx.execute("INSERT INTO declarations(identifier,category,server_token,body,updated_at) VALUES(?,?,?,?,?) ON CONFLICT(identifier) DO UPDATE SET server_token=excluded.server_token,body=excluded.body,deleted=0,updated_at=excluded.updated_at",
                params![declaration.identifier,declaration.kind(),declaration.server_token,body,time])?;
            tx.execute("INSERT INTO declaration_revisions(identifier,server_token,body,created_at) VALUES(?,?,?,?)",
                params![declaration.identifier,declaration.server_token,body,time])?;
            for id in targets { Self::ddm_changed_tx(tx,&id,time)?; }
            audit(tx,"admin","put_declaration",&declaration.identifier,time)
        })
    }

    fn targets_tx(tx: &Transaction<'_>, identifier: &str) -> Result<Vec<String>> {
        let mut stmt = tx.prepare("SELECT enrollment_id FROM declaration_targets WHERE identifier=? ORDER BY enrollment_id")?;
        Ok(stmt
            .query_map([identifier], |r| r.get(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn replace_declaration_targets(
        &self,
        identifier: &str,
        targets: &[String],
        time: i64,
    ) -> Result<()> {
        let requested: BTreeSet<&String> = targets.iter().collect();
        if targets.len() > 100 || requested.len() != targets.len() {
            return Err(StoreError::InvalidInput.into());
        }
        self.with_tx(|tx| {
            let body: Option<String> = tx.query_row("SELECT body FROM declarations WHERE identifier=? AND deleted=0",
                [identifier],|r|r.get(0)).optional()?;
            let declaration: AppleDeclaration = serde_json::from_str(&body.ok_or(StoreError::NotFound)?)?;
            for id in targets {
                Self::ddm_target(tx,id)?;
                Self::validate_declaration_target_tx(tx, id, &declaration, time)?;
                let enabled: bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM ddm_state WHERE enrollment_id=?)",[id],|r|r.get(0))?;
                if !enabled { return Err(StoreError::Conflict.into()); }
                let count: i64=tx.query_row("SELECT count(*) FROM declaration_targets WHERE enrollment_id=?",[id],|r|r.get(0))?;
                let existing: bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM declaration_targets WHERE enrollment_id=? AND identifier=?)",params![id,identifier],|r|r.get(0))?;
                if count>=256 && !existing { return Err(StoreError::Conflict.into()); }
            }
            let prior = Self::targets_tx(tx,identifier)?;
            let old: BTreeSet<&String> = prior.iter().collect();
            if old==requested { return Ok(()); }
            let changed: Vec<String> = old.symmetric_difference(&requested).map(|id|(*id).clone()).collect();
            tx.execute("DELETE FROM declaration_targets WHERE identifier=?",[identifier])?;
            for id in targets { tx.execute("INSERT INTO declaration_targets(identifier,enrollment_id) VALUES(?,?)",params![identifier,id])?; }
            for id in changed { Self::ddm_changed_tx(tx,&id,time)?; }
            audit(tx,"admin","replace_declaration_targets",identifier,time)
        })
    }

    pub fn delete_declaration(
        &self,
        identifier: &str,
        expected_token: &str,
        time: i64,
    ) -> Result<()> {
        self.with_tx(|tx| {
            let prior: Option<(String, bool)> = tx
                .query_row(
                    "SELECT server_token,deleted FROM declarations WHERE identifier=?",
                    [identifier],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            let (token, deleted) = prior.ok_or(StoreError::NotFound)?;
            if token != expected_token {
                return Err(StoreError::Conflict.into());
            }
            if deleted {
                return Ok(());
            }
            let targets = Self::targets_tx(tx, identifier)?;
            tx.execute(
                "UPDATE declarations SET deleted=1,updated_at=? WHERE identifier=?",
                params![time, identifier],
            )?;
            tx.execute(
                "DELETE FROM declaration_targets WHERE identifier=?",
                [identifier],
            )?;
            for id in targets {
                Self::ddm_changed_tx(tx, &id, time)?;
            }
            audit(tx, "admin", "delete_declaration", identifier, time)
        })
    }

    pub fn declarations(&self, after: Option<&str>) -> Result<Vec<DeclarationView>> {
        self.with_tx(|tx| {
            let mut stmt=tx.prepare("SELECT identifier,body,deleted,updated_at FROM declarations WHERE identifier>? ORDER BY identifier LIMIT 100")?;
            let rows=stmt.query_map([after.unwrap_or("")],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,bool>(2)?,r.get::<_,i64>(3)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
            rows.into_iter().map(|(id,body,deleted,updated_at)|Ok(DeclarationView {
                declaration:serde_json::from_str(&body)?,deleted,updated_at,targets:Self::targets_tx(tx,&id)?
            })).collect()
        })
    }

    pub fn ddm_request(
        &self,
        fingerprint: &str,
        udid: &str,
        endpoint: &str,
        data: Option<&Value>,
        time: i64,
    ) -> Result<Option<Value>> {
        let endpoint =
            DeclarativeEndpoint::parse(endpoint).map_err(|_| StoreError::InvalidInput)?;
        self.with_tx(|tx| {
            let (id,current,known)=Self::subject(tx,fingerprint)?;
            if current!=EnrollmentState::Active || known.as_deref()!=Some(udid) { return Err(StoreError::Unauthorized.into()); }
            Self::ddm_target(tx,&id)?;
            let token: Option<(String,String)> = tx.query_row("SELECT declarations_token,strftime('%Y-%m-%dT%H:%M:%SZ',updated_at,'unixepoch') FROM ddm_state WHERE enrollment_id=?",
                [&id],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
            let (token,timestamp)=token.ok_or(StoreError::Conflict)?;
            if !matches!(endpoint,DeclarativeEndpoint::Status) && data.is_some() { return Err(StoreError::InvalidInput.into()); }
            match endpoint {
                DeclarativeEndpoint::Tokens => Ok(Some(json!({"SyncTokens":{"DeclarationsToken":token,"Timestamp":timestamp}}))),
                DeclarativeEndpoint::DeclarationItems => {
                    let mut manifest=json!({"Activations":[],"Configurations":[],"Assets":[],"Management":[]});
                    let rows: Vec<(String, String, String, String)> = {
                        let mut stmt=tx.prepare("SELECT d.category,d.identifier,d.server_token,d.body FROM declarations d JOIN declaration_targets t ON t.identifier=d.identifier WHERE t.enrollment_id=? AND d.deleted=0 ORDER BY d.identifier")?;
                        stmt.query_map([&id],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,String>(3)?)))?.collect::<rusqlite::Result<Vec<_>>>()?
                    };
                    for (category,identifier,server_token,body) in rows {
                        let declaration: AppleDeclaration = serde_json::from_str(&body)?;
                        Self::validate_declaration_target_tx(tx, &id, &declaration, time)?;
                        let key=match category.as_str(){"activation"=>"Activations","configuration"=>"Configurations","management"=>"Management",_=>"Assets"};
                        manifest[key].as_array_mut().context("invalid manifest category")?.push(json!({"Identifier":identifier,"ServerToken":server_token}));
                    }
                    Ok(Some(json!({"Declarations":manifest,"DeclarationsToken":token})))
                }
                DeclarativeEndpoint::Declaration{kind,identifier} => {
                    let path=DeclarativeEndpoint::Declaration{kind,identifier:identifier.clone()}.as_str();
                    let category=path.split('/').nth(1).context("invalid declaration path")?;
                    let body: Option<String>=tx.query_row("SELECT d.body FROM declarations d JOIN declaration_targets t ON t.identifier=d.identifier WHERE t.enrollment_id=? AND d.identifier=? AND d.category=? AND d.deleted=0",
                        params![id,identifier,category],|r|r.get(0)).optional()?;
                    let declaration:AppleDeclaration=serde_json::from_str(&body.ok_or(StoreError::NotFound)?)?;
                    Self::validate_declaration_target_tx(tx, &id, &declaration, time)?;
                    Ok(Some(serde_json::to_value(declaration)?))
                }
                DeclarativeEndpoint::Status => {
                    let report=data.ok_or(StoreError::InvalidInput)?;
                    mdm_protocol::parse_status_report(&serde_json::to_vec(report)?).map_err(|_|StoreError::InvalidInput)?;
                    let body=serde_json::to_string(report)?;
                    let inserted=tx.execute("INSERT OR IGNORE INTO ddm_reports(enrollment_id,digest,body,received_at) VALUES(?,?,?,?)",
                        params![id,digest(body.as_bytes()),body,time])?;
                    if inserted!=0 {audit(tx,"device","ddm_status_received",&id,time)?;}
                    // Reports have no sequence number; retain observations rather
                    // than claiming receipt order is device execution order.
                    Ok(None)
                }
            }
        })
    }

    pub fn ddm_reports(&self, id: &str, after: i64) -> Result<Vec<Value>> {
        self.with_tx(|tx| {
            let exists:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM enrollments WHERE id=?)",[id],|r|r.get(0))?;
            if !exists {return Err(StoreError::NotFound.into());}
            let mut stmt=tx.prepare("SELECT id,body,received_at FROM ddm_reports WHERE enrollment_id=? AND id>? ORDER BY id LIMIT 100")?;
            let rows=stmt.query_map(params![id,after],|r|Ok((r.get::<_,i64>(0)?,r.get::<_,String>(1)?,r.get::<_,i64>(2)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
            rows.into_iter().map(|(id,body,received_at)|Ok(json!({"id":id,"received_at":received_at,"report":serde_json::from_str::<Value>(&body)?}))).collect()
        })
    }
}
