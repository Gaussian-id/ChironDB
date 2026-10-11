//! Offline fixture preparation followed by TLS requests to the real server
//! executable. This is deliberately not an in-process router/mock test.
use super::*;
use crate::security::*;
use base64::Engine;
use std::collections::{BTreeMap, BTreeSet};
use std::process::Command;
use uuid::Uuid;

fn write_private(path: &Path, bytes: &[u8]) {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path).unwrap().write_all(bytes).unwrap();
}
fn scope(actions: &[Action]) -> ScopeGrant {
    ScopeGrant {
        tenants: BTreeSet::from(["acme".into()]),
        collections: BTreeSet::from(["docs".into()]),
        actions: actions.iter().copied().collect(),
    }
}
fn role(
    id: &str,
    department: &str,
    clearance: Classification,
    actions: &[Action],
) -> PrincipalRecord {
    PrincipalRecord {
        id: id.into(),
        tenant: "acme".into(),
        enabled: true,
        attributes: SubjectAttributes {
            department: department.into(),
            clearance,
        },
        grants: if actions.is_empty() {
            vec![]
        } else {
            vec![scope(actions)]
        },
        installation_actions: BTreeSet::new(),
        delegation: vec![],
    }
}

fn prepare_empty_fixture(
    output: &Path,
) -> (
    crate::encryption::Keyring,
    IssuedCredential,
    PrincipalRecord,
    BTreeMap<String, PropertyRule>,
) {
    std::fs::create_dir(output).expect("evidence directory must be new");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(output, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let data = output.join("data");
    let keyring_path = output.join("encryption-keyring.json");
    let mut material = [0u8; 32];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut material).unwrap();
    write_private(&keyring_path,&serde_json::to_vec(&serde_json::json!({"version":1,"active_key_id":"00000000-0000-0000-0000-000000000001","keys":[{"id":"00000000-0000-0000-0000-000000000001","key_base64":base64::engine::general_purpose::STANDARD.encode(material)}]})).unwrap());
    let keyring = crate::encryption::Keyring::load(&keyring_path).unwrap();
    crate::encryption::install_process_keyring(
        crate::encryption::Keyring::load(&keyring_path).unwrap(),
        true,
    )
    .unwrap();
    crate::storage_layout::initialize_empty(&data).unwrap();
    let db = Db::open(&data).unwrap();
    db.create_collection(
        serde_json::from_value(serde_json::json!({"name":"docs","vector_dim":2})).unwrap(),
    )
    .unwrap();
    let root = db.inner.read().root.clone();
    drop(db);
    let incarnation = Uuid::new_v4();
    let properties = BTreeMap::from([
        (
            "/text".into(),
            PropertyRule {
                classification: Classification::Internal,
                actions: BTreeSet::from([
                    PropertyAction::Read,
                    PropertyAction::Query,
                    PropertyAction::Write,
                ]),
            },
        ),
        (
            "/secret".into(),
            PropertyRule {
                classification: Classification::Restricted,
                actions: BTreeSet::from([PropertyAction::Read, PropertyAction::Write]),
            },
        ),
    ]);
    let mut templates = BTreeMap::new();
    for (name, department, classification) in [
        ("finance", "Finance", Classification::Internal),
        (
            "finance-confidential",
            "Finance",
            Classification::Confidential,
        ),
        ("hr", "HR", Classification::Internal),
    ] {
        templates.insert(
            name.into(),
            IngestTemplate {
                department: department.into(),
                classification,
                properties: properties.clone(),
                representations: BTreeMap::from([(
                    "dense".into(),
                    Representation {
                        source_fields: BTreeSet::from(["/text".into()]),
                        classification,
                    },
                )]),
            },
        );
    }
    let policy = CollectionPolicy {
        department_actions: BTreeSet::from([Action::Read, Action::Search]),
        owner_actions: BTreeSet::from([
            Action::Read,
            Action::Search,
            Action::Update,
            Action::Delete,
        ]),
        templates,
    };
    crate::security::storage::write(
        &root.join("collections/docs"),
        &crate::security::storage::StoredSecurity {
            wal_watermark: 0,
            authority: SecurityCheckpoint {
                version: 1,
                collection: "docs".into(),
                incarnation,
                revision: 1,
                data_generation: 1,
                policy,
                resources: vec![],
            },
        },
    )
    .unwrap();
    let mut catalog = read_catalog(&root).unwrap();
    catalog.protected.insert("docs".into(), incarnation);
    crate::encryption::atomic_write_persistent(
        &root.join(CATALOG_FILE),
        crate::encryption::FileType::Metadata,
        &crate::security::storage::encode_metadata(
            PROTECTED_CATALOG_MAGIC,
            &serde_json::to_vec(&catalog).unwrap(),
        ),
    )
    .unwrap();
    let mut security = role(
        "security-admin",
        "Security",
        Classification::Restricted,
        &[
            Action::GrantsManage,
            Action::LabelsManage,
            Action::PolicyManage,
        ],
    );
    // Existing identity delegation requires administrative capabilities to be
    // held by their issuer. Observe is therefore explicit for this role too.
    security.installation_actions = BTreeSet::from([
        Action::IdentityManage,
        Action::GrantsManage,
        Action::LabelsManage,
        Action::PolicyManage,
        Action::Observe,
    ]);
    security.delegation = vec![scope(&[
        Action::Read,
        Action::Search,
        Action::Create,
        Action::Ingest,
        Action::Update,
        Action::Delete,
        Action::GrantsManage,
        Action::LabelsManage,
        Action::PolicyManage,
    ])];
    let root_key = IdentityAuthority::bootstrap(&data, security.clone()).unwrap();
    (keyring, root_key, security, properties)
}

#[test]
#[ignore = "requires CHIRONDB_SECURITY_E2E_BINARY and a fresh CHIRONDB_SECURITY_E2E_OUTPUT; invokes Python/OpenSSL"]
fn five_roles_over_real_tls_http_and_encrypted_restart() {
    let binary =
        PathBuf::from(std::env::var_os("CHIRONDB_SECURITY_E2E_BINARY").expect("server binary"));
    let output = PathBuf::from(
        std::env::var_os("CHIRONDB_SECURITY_E2E_OUTPUT").expect("fresh evidence directory"),
    );
    let (keyring, root_key, security, properties) = prepare_empty_fixture(&output);
    let data = output.join("data");
    let authority = IdentityAuthority::open(&data).unwrap().unwrap();
    let mut operator = role(
        "operations-admin",
        "Operations",
        Classification::Internal,
        &[],
    );
    operator.installation_actions.insert(Action::Observe);
    let writer = role(
        "ingestion-writer",
        "Ingestion",
        Classification::Restricted,
        &[
            Action::Read,
            Action::Search,
            Action::Create,
            Action::Ingest,
            Action::Update,
            Action::Delete,
        ],
    );
    let finance = role(
        "finance-reader",
        "Finance",
        Classification::Confidential,
        &[Action::Read, Action::Search],
    );
    let hr = role(
        "hr-reader",
        "HR",
        Classification::Internal,
        &[Action::Read, Action::Search],
    );
    let mut credentials =
        BTreeMap::from([(security.id.clone(), serde_json::to_value(root_key).unwrap())]);
    let mut principals = vec![security];
    for principal in [operator, writer, finance, hr] {
        let actor = authority
            .authenticate(credentials["security-admin"]["secret"].as_str().unwrap())
            .unwrap();
        authority
            .put_principal(&actor, authority.revision(), principal.clone())
            .unwrap();
        let actor = authority
            .authenticate(credentials["security-admin"]["secret"].as_str().unwrap())
            .unwrap();
        let key = authority
            .issue_credential(&actor, authority.revision(), &principal.id)
            .unwrap();
        credentials.insert(principal.id.clone(), serde_json::to_value(key).unwrap());
        principals.push(principal);
    }
    drop(authority);
    let db = Db::open(&data).unwrap();
    let authority = db.identity_authority().unwrap();
    let writer = authority
        .authenticate(credentials["ingestion-writer"]["secret"].as_str().unwrap())
        .unwrap();
    let create = db
        .bind_access(&writer, "docs", "acme", Action::Create)
        .unwrap();
    let mut ids = BTreeMap::new();
    for (name, template) in [
        ("finance", "finance"),
        ("confidential", "finance-confidential"),
        ("hr", "hr"),
        ("locked", "finance"),
        ("disposable", "hr"),
    ] {
        let point = NewPoint {
            vector: vec![1.0, 0.0],
            vectors: BTreeMap::new(),
            sparse_vector: None,
            payload: serde_json::json!({"text":name,"secret":"RESTRICTED_PAYROLL_MARKER"}),
        };
        let id = db
            .create_points_authorized(&create, template, vec![point], true)
            .unwrap()
            .publish(|ids| ids[0].clone())
            .unwrap();
        ids.insert(name.to_string(), id);
    }
    let security = authority
        .authenticate(credentials["security-admin"]["secret"].as_str().unwrap())
        .unwrap();
    let labels = db
        .bind_access(&security, "docs", "acme", Action::LabelsManage)
        .unwrap();
    db.replace_object_labels_authorized(
        &labels,
        &ids["locked"],
        RevisionUpdate {
            expected_revision: labels.policy_revision(),
            value: ObjectLabels {
                labels: ResourceLabels {
                    owner: "finance-reader".into(),
                    department: "Finance".into(),
                    classification: Classification::Internal,
                    quarantined: false,
                },
                properties,
            },
        },
    )
    .unwrap()
    .publish(|_| ())
    .unwrap();
    drop(db);
    write_private(
        &output.join("credentials.json"),
        &serde_json::to_vec_pretty(&credentials).unwrap(),
    );
    write_private(
        &output.join("fixture.json"),
        &serde_json::to_vec_pretty(
            &serde_json::json!({"tenant":"acme","ids":ids,"principals":principals}),
        )
        .unwrap(),
    );
    let audit_baseline = crate::audit::records_for_test(&data)
        .unwrap()
        .last()
        .unwrap()["sequence"]
        .as_u64()
        .unwrap();
    let script = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../chirondb-server/tests/security_five_roles_e2e.py");
    let status = Command::new("python3")
        .arg(script)
        .arg("--binary")
        .arg(&binary)
        .arg("--output")
        .arg(&output)
        .status()
        .unwrap();
    assert!(
        status.success(),
        "TLS E2E failed; inspect evidence directory {}",
        output.display()
    );
    crate::audit::verify_hash_chain(&data).unwrap();
    crate::encryption::verify_tree(&keyring, &data).unwrap();
    let audit_records: Vec<_> = crate::audit::records_for_test(&data)
        .unwrap()
        .into_iter()
        .filter(|event| event["sequence"].as_u64().unwrap() > audit_baseline)
        .collect();
    for (actor, operation) in [
        ("ingestion-writer", "upsert"),
        ("ingestion-writer", "delete"),
        ("security-admin", "grants.replace"),
        ("security-admin", "labels.replace"),
        ("security-admin", "identity.put_principal"),
        ("security-admin", "identity.revoke_credential"),
        ("security-admin", "identity.issue_credential"),
    ] {
        assert!(
            audit_records
                .iter()
                .any(|event| event["principal_id"] == actor
                    && event["operation"] == operation
                    && event["outcome"] == "success"),
            "missing HTTP-phase audit success for {actor}/{operation}"
        );
    }
    assert!(
        !audit_records
            .iter()
            .any(|event| ["operations-admin", "finance-reader", "hr-reader"]
                .iter()
                .any(|actor| event["principal_id"] == *actor)
                && event["outcome"] == "success"),
        "a read-only or operations role committed a mutation"
    );
    let audit_evidence: Vec<_> = audit_records
        .iter()
        .map(|event| {
            [
                "sequence",
                "operation",
                "principal_id",
                "tenant_id",
                "outcome",
                "collection",
                "transport",
            ]
            .into_iter()
            .map(|key| (key.to_string(), event[key].clone()))
            .collect::<serde_json::Map<_, _>>()
        })
        .collect();
    std::fs::write(
        output.join("audit-evidence.json"),
        serde_json::to_vec_pretty(&audit_evidence).unwrap(),
    )
    .unwrap();
    let db = Db::open(&data).unwrap();
    let credentials: Value =
        serde_json::from_slice(&std::fs::read(output.join("credentials.json")).unwrap()).unwrap();
    let authority = db.identity_authority().unwrap();
    for principal in credentials.as_object().unwrap().values() {
        authority
            .authenticate(principal["secret"].as_str().unwrap())
            .unwrap();
    }
    let finance = authority
        .authenticate(credentials["finance-reader"]["secret"].as_str().unwrap())
        .unwrap();
    let read = db
        .bind_access(&finance, "docs", "acme", Action::Read)
        .unwrap();
    let finance = db
        .get_points_authorized(&read, std::slice::from_ref(&ids["finance"]))
        .unwrap()
        .publish(|points| points)
        .unwrap();
    assert_eq!(
        finance[0].payload,
        serde_json::json!({"text":"finance-updated"})
    );
    let hr = authority
        .authenticate(credentials["hr-reader"]["secret"].as_str().unwrap())
        .unwrap();
    let read = db.bind_access(&hr, "docs", "acme", Action::Read).unwrap();
    assert_eq!(
        db.count_authorized(&read, None)
            .unwrap()
            .publish(|count| count.count)
            .unwrap(),
        1
    );
    let report_path = output.join("report.json");
    let mut report: Value = serde_json::from_slice(&std::fs::read(&report_path).unwrap()).unwrap();
    report["status"] = serde_json::json!("passed");
    report["core_postconditions"] = serde_json::json!({"audit_hash_chain":"pass","http_phase_audit_actors_and_operations":"pass","encrypted_tree":"pass","five_active_profiles_after_restart":"pass","durable_projected_content":"pass","durable_acl_and_delete":"pass"});
    std::fs::write(report_path, serde_json::to_vec_pretty(&report).unwrap()).unwrap();
    println!(
        "Five-role TLS E2E and encrypted/audit postconditions passed; evidence: {}",
        output.display()
    );
}

#[test]
#[ignore = "creates a fresh trusted root and empty protected fixture for the real ChironQL lab"]
fn chironql_empty_fixture() {
    let output = PathBuf::from(
        std::env::var_os("CHIRONDB_CHIRONQL_E2E_OUTPUT").expect("fresh evidence directory"),
    );
    let (keyring, root, _, _) = prepare_empty_fixture(&output);
    write_private(&output.join("security-admin.key"), root.secret.as_bytes());
    write_private(
        &output.join("credentials.json"),
        &serde_json::to_vec(&serde_json::json!({"security-admin":root})).unwrap(),
    );
    write_private(
        &output.join("fixture.json"),
        br#"{"tenant":"acme","ids":{}}"#,
    );
    crate::encryption::verify_tree(&keyring, &output.join("data")).unwrap();
}

#[test]
#[ignore = "checks the stopped real ChironQL lab's encrypted state and audit evidence"]
fn chironql_verify_evidence() {
    let output = PathBuf::from(
        std::env::var_os("CHIRONDB_CHIRONQL_E2E_OUTPUT").expect("evidence directory"),
    );
    let data = output.join("data");
    let keyring = crate::encryption::Keyring::load(output.join("encryption-keyring.json")).unwrap();
    crate::encryption::install_process_keyring(keyring, true).unwrap();
    crate::audit::verify_hash_chain(&data).unwrap();
    let credentials: Value =
        serde_json::from_slice(&std::fs::read(output.join("credentials.json")).unwrap()).unwrap();
    let db = Db::open(&data).unwrap();
    let authority = db.identity_authority().unwrap();
    let root = authority
        .authenticate(credentials["security-admin"]["secret"].as_str().unwrap())
        .unwrap();
    let mut actors = BTreeMap::new();
    for name in [
        "security-admin",
        "operations-admin",
        "ingestion-writer",
        "finance-reader",
        "hr-reader",
    ] {
        let actor = authority
            .authenticate(credentials[name]["secret"].as_str().unwrap())
            .unwrap();
        assert_eq!(
            authority.resolve_user(&root, name).unwrap(),
            actor.principal().id
        );
        actors.insert(actor.principal().id.clone(), name);
    }
    let records = crate::audit::records_for_test(&data).unwrap();
    for operation in [
        "identity.create_user",
        "identity.create_role",
        "identity.grant_role",
        "identity.revoke_role",
        "identity.issue_credential",
        "identity.rotate_credential",
        "identity.revoke_credential",
    ] {
        assert!(
            records
                .iter()
                .any(|row| row["operation"] == operation && row["outcome"] == "success"),
            "missing {operation}"
        );
    }
    let evidence: Vec<_> = records.iter().map(|row| {
        let actor = row["principal_id"].as_str().unwrap_or("");
        if matches!(actors.get(actor), Some(&"operations-admin" | &"finance-reader" | &"hr-reader")) {
            assert_ne!(row["outcome"], "success", "read-only principal committed a mutation");
        }
        serde_json::json!({"actor":actors.get(actor).copied().unwrap_or("bootstrap-or-test-user"),
            "operation_id":row["operation_id"],"operation":row["operation"],"outcome":row["outcome"],
            "sequence":row["sequence"],"scope":row["collection"],"details":row["details"]})
    }).collect();
    std::fs::write(
        output.join("chironql-audit-evidence.json"),
        serde_json::to_vec_pretty(&evidence).unwrap(),
    )
    .unwrap();
    drop(db);
    let keyring = crate::encryption::Keyring::load(output.join("encryption-keyring.json")).unwrap();
    crate::encryption::verify_tree(&keyring, &data).unwrap();
}
