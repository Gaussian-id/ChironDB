//! Offline setup for the disposable, single-tenant W0 acceptance fixture.
//! Never run against customer data. Refuse any existing fixture directory.

use std::{collections::BTreeSet, env, fs, path::PathBuf};

use chirondb_core::{
    Db,
    security::{Action, ScopeGrant, onboarding},
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let root = PathBuf::from(
        args.next()
            .ok_or("usage: protected_w0_setup NEW_DIRECTORY")?,
    );
    if args.next().is_some() {
        return Err("unexpected argument".into());
    }
    fs::create_dir(&root)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
    }
    let root = root.canonicalize()?;
    let secrets = root.join("secrets");
    fs::create_dir(&secrets)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&secrets, fs::Permissions::from_mode(0o700))?;
    }
    let key = secrets.join("admin.key");
    onboarding::initialize(
        &root.join("live"),
        "acme",
        "admin",
        &secrets.join("storage.json"),
        &key,
        false,
    )?;
    let db = Db::open(root.join("live"))?;
    let authority = db.identity_authority().ok_or("missing authority")?;
    let secret = fs::read_to_string(key)?;
    let actor = authority.authenticate(secret.trim())?;
    let mut principal = actor.principal().clone();
    principal.grants.push(ScopeGrant {
        tenants: BTreeSet::from(["acme".into()]),
        collections: [
            "w0",
            "w0_owners",
            "w0_documents",
            "w0_versions",
            "w0_chunks",
            "w0_edge_rows",
        ]
        .into_iter()
        .map(String::from)
        .collect(),
        actions: BTreeSet::from([
            Action::Create,
            Action::Read,
            Action::Update,
            Action::Delete,
            Action::Ingest,
            Action::Search,
            Action::GraphRead,
            Action::GraphWrite,
        ]),
    });
    authority.put_principal(&actor, actor.revision(), principal)?;
    println!("{}", serde_json::json!({"fixture": root, "tenant": "acme"}));
    Ok(())
}
