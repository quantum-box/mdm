use super::*;
use mdm_core::{OperationKind, SupervisionEvidence};
use serde_json::{Value, json};

#[derive(Serialize)]
pub struct ObservationView {
    pub category: String,
    pub command_id: String,
    pub dispatched_at: i64,
    pub received_at: i64,
    pub body: Value,
}
#[derive(Serialize)]
pub struct EraseIntent {
    pub id: String,
    pub token: String,
    pub serial_number: String,
    pub expires_at: i64,
}
#[derive(Serialize)]
pub struct AppleRequest {
    pub idempotency_key: String,
    pub state: String,
    pub result: Option<Value>,
}

impl Store {
    pub(super) fn validate_operation_tx(
        tx: &Transaction<'_>,
        id: &str,
        payload: &CommandPayload,
        time: i64,
    ) -> Result<()> {
        let (rights, awaiting): (i64, bool) = tx.query_row(
            "SELECT mdm_access_rights,awaiting_configuration FROM enrollments WHERE id=?",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let required = match payload {
            CommandPayload::DeviceInformation { .. }
            | CommandPayload::AvailableOSUpdates
            | CommandPayload::OSUpdateStatus => 16,
            CommandPayload::InstallProfile { .. } | CommandPayload::RemoveProfile { .. } => 2,
            CommandPayload::InstalledApplicationList { .. }
            | CommandPayload::ManagedApplicationList { .. } => 256,
            CommandPayload::InstallApplication { .. }
            | CommandPayload::RemoveApplication { .. }
            | CommandPayload::ScheduleOSUpdate { .. } => 4096,
            CommandPayload::DeviceLock { .. } => 4,
            CommandPayload::EraseDevice { .. } => 8,
            _ => 0,
        };
        if rights & required != required {
            return Err(StoreError::Conflict.into());
        }
        let operation = match payload {
            CommandPayload::AvailableOSUpdates => Some(OperationKind::AvailableOsUpdates),
            CommandPayload::OSUpdateStatus => Some(OperationKind::OsUpdateStatus),
            CommandPayload::ScheduleOSUpdate { updates } => {
                // These fields and install actions are macOS-only in Apple's schema.
                if updates.iter().any(|u| {
                    u.max_user_deferrals.is_some()
                        || u.priority.is_some()
                        || matches!(
                            u.install_action,
                            mdm_protocol::OsInstallAction::NotifyOnly
                                | mdm_protocol::OsInstallAction::InstallLater
                                | mdm_protocol::OsInstallAction::InstallForceRestart
                        )
                }) {
                    return Err(StoreError::InvalidInput.into());
                }
                Some(OperationKind::ScheduleOsUpdate)
            }
            CommandPayload::DeviceConfigured => {
                if !awaiting {
                    return Err(StoreError::Conflict.into());
                }
                Some(OperationKind::DeviceConfigured)
            }
            CommandPayload::DeviceLock { pin, .. } => {
                if pin.is_some() {
                    return Err(StoreError::InvalidInput.into());
                }
                None
            }
            CommandPayload::EraseDevice {
                pin,
                obliteration_behavior,
                ..
            } => {
                if pin.is_some() || obliteration_behavior.is_some() {
                    return Err(StoreError::InvalidInput.into());
                }
                None
            }
            _ => None,
        };
        if let Some(operation) = operation {
            Self::require_supervised_tx(tx, id, operation, time)?;
        }
        if let CommandPayload::InstallProfile { payload } = payload {
            let root = plist::Value::from_reader(std::io::Cursor::new(payload))?;
            let contents = root
                .as_dictionary()
                .and_then(|d| d.get("PayloadContent"))
                .and_then(plist::Value::as_array)
                .ok_or(StoreError::InvalidInput)?;
            for item in contents {
                let Some(d) = item.as_dictionary() else {
                    return Err(StoreError::InvalidInput.into());
                };
                if d.get("PayloadType").and_then(plist::Value::as_string)
                    == Some("com.apple.app.lock")
                {
                    Self::require_supervised_tx(tx, id, OperationKind::KioskMode, time)?;
                    let bundle = d
                        .get("App")
                        .and_then(plist::Value::as_dictionary)
                        .and_then(|a| a.get("Identifier"))
                        .and_then(plist::Value::as_string)
                        .ok_or(StoreError::InvalidInput)?;
                    let observation:Option<(String,i64)>=tx.query_row("SELECT body,received_at FROM device_observations WHERE enrollment_id=? AND category='installed_applications'",[id],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
                    let Some((body, received)) = observation else {
                        return Err(StoreError::Conflict.into());
                    };
                    let body: Value = serde_json::from_str(&body)?;
                    let installed =
                        body["InstalledApplicationList"]
                            .as_array()
                            .is_some_and(|apps| {
                                apps.iter().any(|app| {
                                    app["Identifier"].as_str() == Some(bundle)
                                        && app["Installing"].as_bool() != Some(true)
                                })
                            });
                    if !installed || time - received > 86400 {
                        return Err(StoreError::Conflict.into());
                    }
                }
            }
        }
        Ok(())
    }
    pub(in crate::storage) fn require_supervised_tx(
        tx: &Transaction<'_>,
        id: &str,
        operation: OperationKind,
        time: i64,
    ) -> Result<()> {
        let record:Option<(String,i64)>=tx.query_row("SELECT body,received_at FROM device_observations WHERE enrollment_id=? AND category='device_information'",[id],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
        let evidence = if let Some((body, received)) = record {
            let body: Value = serde_json::from_str(&body)?;
            if time - received > 86400 {
                SupervisionEvidence::Unknown
            } else {
                match body["QueryResponses"]["IsSupervised"].as_bool() {
                    Some(true) => SupervisionEvidence::Supervised,
                    Some(false) => SupervisionEvidence::Unsupervised,
                    None => SupervisionEvidence::Unknown,
                }
            }
        } else {
            SupervisionEvidence::Unknown
        };
        operation
            .check_supervision(evidence)
            .map_err(|_| StoreError::Conflict.into())
    }
    pub(super) fn observe_response_tx(
        tx: &Transaction<'_>,
        enrollment_id: &str,
        command_id: &str,
        raw: &plist::Value,
        time: i64,
    ) -> Result<()> {
        let command_kind: String =
            tx.query_row("SELECT kind FROM commands WHERE id=?", [command_id], |r| {
                r.get(0)
            })?;
        let kind: CommandKind = state(command_kind)?;
        if kind == CommandKind::DeviceConfigured {
            tx.execute(
                "UPDATE enrollments SET awaiting_configuration=0 WHERE id=?",
                [enrollment_id],
            )?;
        }
        let category = match kind {
            CommandKind::DeviceInformation => "device_information",
            CommandKind::InstalledApplicationList => "installed_applications",
            CommandKind::ManagedApplicationList => "managed_applications",
            CommandKind::AvailableOsUpdates => "available_os_updates",
            CommandKind::OsUpdateStatus => "os_update_status",
            _ => return Ok(()),
        };
        let (dispatched,dispatch_order):(i64,i64)=tx.query_row("SELECT dispatched_at,rowid FROM delivery_attempts WHERE command_id=? ORDER BY attempt DESC LIMIT 1",[command_id],|r|Ok((r.get(0)?,r.get(1)?)))?;
        let body = serde_json::to_string(&serde_json::to_value(raw)?)?;
        // Arrival order is not execution order. A stale reply cannot overwrite a newer dispatch.
        tx.execute("INSERT INTO device_observations(enrollment_id,category,command_id,dispatched_at,dispatch_order,received_at,body) VALUES(?,?,?,?,?,?,?) ON CONFLICT(enrollment_id,category) DO UPDATE SET command_id=excluded.command_id,dispatched_at=excluded.dispatched_at,dispatch_order=excluded.dispatch_order,received_at=excluded.received_at,body=excluded.body WHERE excluded.dispatch_order>device_observations.dispatch_order",params![enrollment_id,category,command_id,dispatched,dispatch_order,time,body])?;
        Ok(())
    }
    pub fn observations(&self, id: &str) -> Result<Vec<ObservationView>> {
        self.with_tx(|tx|{
            Self::exists_tx(tx,id)?;
            let mut statement=tx.prepare("SELECT category,command_id,dispatched_at,received_at,body FROM device_observations WHERE enrollment_id=? ORDER BY category")?;
            let rows=statement.query_map([id],|r|{let body:String=r.get(4)?;Ok(ObservationView{category:r.get(0)?,command_id:r.get(1)?,dispatched_at:r.get(2)?,received_at:r.get(3)?,body:serde_json::from_str(&body).unwrap_or(Value::Null)})})?;
            Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
        })
    }
    fn exists_tx(tx: &Transaction<'_>, id: &str) -> Result<()> {
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM enrollments WHERE id=?)",
            [id],
            |r| r.get(0),
        )?;
        if exists {
            Ok(())
        } else {
            Err(StoreError::NotFound.into())
        }
    }
    pub fn apply_kiosk(&self, id: &str, bundle_id: &str, key: &str, time: i64) -> Result<String> {
        mdm_core::KioskPolicy::new(bundle_id).map_err(|_| StoreError::InvalidInput)?;
        let identifier = format!("org.quantumbox.mdm.kiosk.{id}");
        let hash = Sha256::digest(identifier.as_bytes());
        let bytes: [u8; 16] = hash[..16].try_into()?;
        let payload = CommandPayload::InstallProfile {
            payload: mdm_protocol::kiosk_profile(
                bundle_id,
                &identifier,
                &Uuid::from_bytes(bytes).to_string(),
            )
            .map_err(|_| StoreError::InvalidInput)?,
        };
        self.enqueue(id, &payload, key, time)
    }
    pub fn release_kiosk(&self, id: &str, key: &str, time: i64) -> Result<String> {
        self.enqueue(
            id,
            &CommandPayload::RemoveProfile {
                identifier: format!("org.quantumbox.mdm.kiosk.{id}"),
            },
            key,
            time,
        )
    }
    pub fn prepare_erase(&self, id: &str, time: i64) -> Result<EraseIntent> {
        self.with_tx(|tx|{
            let serial:Option<String>=tx.query_row("SELECT serial_number FROM enrollments WHERE id=? AND state='active'",[id],|r|r.get(0)).optional()?.flatten();
            let serial=serial.filter(|s|!s.is_empty()).ok_or(StoreError::Conflict)?;
            tx.execute("DELETE FROM erase_intents WHERE expires_at<=? AND command_id IS NULL",[time])?;
            let count:i64=tx.query_row("SELECT count(*) FROM erase_intents WHERE enrollment_id=? AND command_id IS NULL",[id],|r|r.get(0))?;
            if count>=16{return Err(StoreError::Conflict.into());}
            let intent=EraseIntent{id:Uuid::new_v4().to_string(),token:hex::encode(rand::random::<[u8;32]>()),serial_number:serial,expires_at:time+300};
            tx.execute("INSERT INTO erase_intents(id,enrollment_id,token_hash,serial_number,expires_at) VALUES(?,?,?,?,?)",params![intent.id,id,digest(intent.token.as_bytes()),intent.serial_number,intent.expires_at])?;
            audit(tx,"admin","prepare_erase",id,time)?;Ok(intent)
        })
    }
    pub fn confirm_erase(
        &self,
        id: &str,
        intent_id: &str,
        token: &str,
        serial: &str,
        key: &str,
        time: i64,
    ) -> Result<String> {
        if key.is_empty() || key.len() > 128 || key.chars().any(char::is_control) {
            return Err(StoreError::InvalidInput.into());
        }
        self.with_tx(|tx|{
            let record:Option<(String,String,i64,Option<String>)>=tx.query_row("SELECT token_hash,serial_number,expires_at,command_id FROM erase_intents WHERE id=? AND enrollment_id=?",params![intent_id,id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()?;
            let (hash,expected,expiry,prior)=record.ok_or(StoreError::Conflict)?;
            if hash!=digest(token.as_bytes())||serial!=expected{return Err(StoreError::Conflict.into());}
            let payload=CommandPayload::EraseDevice{preserve_data_plan:false,disallow_proximity_setup:true,pin:None,obliteration_behavior:None};
            let serialized=serde_json::to_string(&payload)?;
            let request_hash=digest(format!("{id}\n{serialized}").as_bytes());
            if let Some(prior)=prior {
                let prior_key:String=tx.query_row("SELECT idempotency_key FROM commands WHERE id=?",[&prior],|r|r.get(0))?;
                return if prior_key==key{Ok(prior)}else{Err(StoreError::Conflict.into())};
            }
            if expiry<=time{return Err(StoreError::Conflict.into());}
            let current_serial:Option<String>=tx.query_row("SELECT serial_number FROM enrollments WHERE id=?",[id],|r|r.get(0))?;
            if current_serial.as_deref()!=Some(serial){return Err(StoreError::Conflict.into());}
            let command=Self::enqueue_tx(tx,id,&payload,key,&serialized,&request_hash,time)?;
            tx.execute("UPDATE erase_intents SET command_id=? WHERE id=?",params![command,intent_id])?;
            audit(tx,"admin","confirm_erase",id,time)?;Ok(command)
        })
    }
    /// A pending external mutation is never replayed after an uncertain network result.
    pub fn reserve_apple_request(
        &self,
        key: &str,
        operation: &str,
        body: &Value,
        time: i64,
    ) -> Result<Option<AppleRequest>> {
        if key.is_empty() || key.len() > 128 || key.chars().any(char::is_control) {
            return Err(StoreError::InvalidInput.into());
        }
        let hash = digest(format!("{operation}\n{}", serde_json::to_string(body)?).as_bytes());
        self.with_tx(|tx|{
            let prior:Option<(String,String,Option<String>)>=tx.query_row("SELECT request_hash,state,result FROM apple_requests WHERE idempotency_key=?",[key],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
            if let Some((prior_hash,state,result))=prior {
                if prior_hash!=hash{return Err(StoreError::Conflict.into());}
                return Ok(Some(AppleRequest{idempotency_key:key.into(),state,result:result.map(|s|serde_json::from_str(&s)).transpose()?}));
            }
            tx.execute("INSERT INTO apple_requests(idempotency_key,request_hash,operation,state,created_at,updated_at) VALUES(?,?,?,'outcome_unknown',?,?)",params![key,hash,operation,time,time])?;
            audit(tx,"admin",operation,key,time)?;Ok(None)
        })
    }
    pub fn finish_apple_request(&self, key: &str, result: &Value, time: i64) -> Result<()> {
        self.with_tx(|tx|{tx.execute("UPDATE apple_requests SET state='completed',result=?,updated_at=? WHERE idempotency_key=?",params![serde_json::to_string(result)?,time,key])?;Ok(())})
    }
    pub fn save_ade_devices(&self, devices: &[Value], time: i64) -> Result<()> {
        self.with_tx(|tx|{for device in devices {
            let serial=device["serial_number"].as_str().or_else(||device["serial"].as_str()).filter(|s|!s.is_empty()&&s.len()<=128).ok_or(StoreError::InvalidInput)?;
            tx.execute("INSERT INTO ade_devices(serial_number,profile_uuid,op_type,updated_at,body) VALUES(?,?,?,?,?) ON CONFLICT(serial_number) DO UPDATE SET profile_uuid=excluded.profile_uuid,op_type=excluded.op_type,updated_at=excluded.updated_at,body=excluded.body",params![serial,device["profile_uuid"].as_str(),device["op_type"].as_str().unwrap_or("added"),time,serde_json::to_string(device)?])?;
        }Ok(())})
    }
    pub fn ade_devices(&self) -> Result<Vec<Value>> {
        self.with_tx(|tx|{let mut stmt=tx.prepare("SELECT serial_number,profile_uuid,op_type,updated_at,body FROM ade_devices ORDER BY serial_number LIMIT 1000")?;let rows=stmt.query_map([],|r|{let body:String=r.get(4)?;Ok(json!({"serial_number":r.get::<_,String>(0)?,"profile_uuid":r.get::<_,Option<String>>(1)?,"op_type":r.get::<_,String>(2)?,"updated_at":r.get::<_,i64>(3)?,"details":serde_json::from_str::<Value>(&body).unwrap_or(Value::Null)}))})?;Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)})
    }
    pub fn save_license_event(
        &self,
        adam_id: u64,
        serial: &str,
        event: &Value,
        time: i64,
    ) -> Result<()> {
        self.with_tx(|tx|{tx.execute("INSERT INTO app_license_assignments(adam_id,serial_number,assigned,updated_at,body) VALUES(?,?,0,?,?) ON CONFLICT(adam_id,serial_number) DO UPDATE SET updated_at=excluded.updated_at,body=excluded.body",params![adam_id,serial,time,serde_json::to_string(event)?])?;Ok(())})
    }
    pub fn license_event(&self, adam_id: u64, serial: &str) -> Result<Value> {
        self.with_tx(|tx| {
            let body: Option<String> = tx
                .query_row(
                    "SELECT body FROM app_license_assignments WHERE adam_id=? AND serial_number=?",
                    params![adam_id, serial],
                    |r| r.get(0),
                )
                .optional()?;
            body.map(|s| serde_json::from_str(&s).map_err(Into::into))
                .unwrap_or(Err(StoreError::NotFound.into()))
        })
    }
}

impl Store {
    pub fn save_ade_profile(&self, profile_uuid: &str, profile: &Value) -> Result<()> {
        self.with_tx(|tx|{tx.execute("INSERT INTO ade_profiles(profile_uuid,body) VALUES(?,?) ON CONFLICT(profile_uuid) DO UPDATE SET body=excluded.body",params![profile_uuid,serde_json::to_string(profile)?])?;Ok(())})
    }
    pub fn ade_bootstrap(
        &self,
        serial: &str,
        udid: &str,
        request_hash: &str,
        time: i64,
        make_profile: impl FnOnce(&str, &str) -> Result<Vec<u8>>,
    ) -> Result<Vec<u8>> {
        self.with_tx(|tx|{
            let assigned:Option<(String,String)>=tx.query_row("SELECT p.body,d.body FROM ade_devices d JOIN ade_profiles p ON p.profile_uuid=d.profile_uuid WHERE d.serial_number=? AND d.op_type!='deleted'",[serial],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
            let (_profile,device)=assigned.ok_or(StoreError::Unauthorized)?;
            let device:Value=serde_json::from_str(&device)?;
            if device["profile_status"].as_str()!=Some("assigned")&&device["profile_status"].as_str()!=Some("pushed") {return Err(StoreError::Unauthorized.into());}
            let prior:Option<(String,Vec<u8>,i64)>=tx.query_row("SELECT b.request_hash,b.profile,b.expires_at FROM ade_bootstrap b JOIN enrollments e ON e.id=b.enrollment_id WHERE b.serial_number=? AND e.state='pending' AND e.scep_request_hash IS NULL",[serial],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
            if let Some((hash,profile,expiry))=prior {return if hash==request_hash&&expiry>time{Ok(profile)}else{Err(StoreError::Conflict.into())};}
            let used:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM ade_bootstrap WHERE serial_number=?)",[serial],|r|r.get(0))?;
            if used{return Err(StoreError::Conflict.into());}
            let id=Uuid::new_v4().to_string();
            let challenge=hex::encode(rand::random::<[u8;32]>());
            let profile=make_profile(&id,&challenge)?;
            tx.execute("INSERT INTO enrollments(id,state,challenge_hash,challenge_expires_at,created_at,updated_at,mdm_access_rights,expected_serial,expected_udid) VALUES(?,'pending',?,?,?,?,?,?,?)",params![id,digest(challenge.as_bytes()),time+900,time,time,mdm_protocol::ENROLLMENT_PROFILE_ACCESS_RIGHTS,serial,udid])?;
            tx.execute("INSERT INTO ade_bootstrap(serial_number,enrollment_id,request_hash,profile,expires_at) VALUES(?,?,?,?,?)",params![serial,id,request_hash,profile,time+900])?;
            audit(tx,"apple_device","ade_bootstrap",&id,time)?;Ok(profile)
        })
    }
    pub fn reset_ade_bootstrap(&self, serial: &str, time: i64) -> Result<()> {
        self.with_tx(|tx| {
            let old:Option<(String,String)>=tx.query_row("SELECT e.id,e.state FROM ade_bootstrap b JOIN enrollments e ON e.id=b.enrollment_id WHERE b.serial_number=?",[serial],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
            if let Some((id,current))=old && matches!(current.as_str(),"pending"|"authenticated") {Self::revoke_tx(tx,&id,"admin",time)?;}
            tx.execute("DELETE FROM ade_bootstrap WHERE serial_number=?", [serial])?;
            audit(tx, "admin", "reset_ade_bootstrap", serial, time)
        })
    }
}

impl Store {
    pub fn commands(&self, id: &str, after: Option<&str>) -> Result<Vec<CommandView>> {
        let ids = self.with_tx(|tx| {
            Self::exists_tx(tx, id)?;
            let mut stmt = tx.prepare(
                "SELECT id FROM commands WHERE enrollment_id=? AND id>? ORDER BY id LIMIT 100",
            )?;
            let rows =
                stmt.query_map(params![id, after.unwrap_or("")], |r| r.get::<_, String>(0))?;
            Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
        })?;
        ids.into_iter().map(|id| self.command(&id)).collect()
    }
}
