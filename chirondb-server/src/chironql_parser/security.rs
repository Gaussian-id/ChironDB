//! Additive 1.2 grammar. Frozen 1.0/1.1 parsers never enter this module.
use super::*;
use chirondb_types::security::{Action, Classification, Effect, SubjectAttributes, UserChanges};
use std::collections::BTreeSet;

#[derive(Clone, Debug, PartialEq)]
pub enum NamedSubject {
    User(String),
    Group(String),
}

#[derive(Clone, Debug, PartialEq)]
pub struct SecurityStatement {
    pub command: SecurityCommand,
    pub expected_revision: Option<u64>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum SecurityCommand {
    ShowCatalogRevision,
    CreateProtectedCollection {
        name: String,
        dim: usize,
        metric: DistanceMetric,
    },
    SetGraphLifecycle {
        collection: String,
        enabled: bool,
    },
    SetEdgeType {
        collection: String,
        name: String,
        weight_property: Option<String>,
    },
    SetCollectionPolicy {
        collection: String,
        policy: chirondb_types::security::CollectionPolicy,
    },
    ShowCollectionPolicy {
        collection: String,
    },
    CreateUser {
        name: String,
        attributes: SubjectAttributes,
    },
    AlterUser {
        name: String,
        changes: UserChanges,
    },
    RenameUser {
        name: String,
        new_name: String,
    },
    DropUser {
        name: String,
    },
    CreateRole {
        name: String,
    },
    RenameRole {
        name: String,
        new_name: String,
    },
    DropRole {
        name: String,
    },
    AssignRole {
        role: String,
        user: String,
        grant: bool,
    },
    RolePrivileges {
        role: String,
        collection: Option<String>,
        table: Option<String>,
        actions: BTreeSet<Action>,
        grant: bool,
    },
    ShowCurrentUser {
        privileges: bool,
    },
    ShowUsers,
    ShowRoles {
        with_users: bool,
    },
    ShowRolePrivileges {
        role: String,
    },
    ShowCredentials {
        user: String,
    },
    ShowRevision {
        collection: Option<String>,
    },
    IssueKey {
        user: String,
    },
    RotateKey {
        id: String,
    },
    RevokeKey {
        id: String,
    },
    ObjectPrivileges {
        collection: String,
        id: String,
        subject: NamedSubject,
        actions: BTreeSet<Action>,
        effect: Effect,
        grant: bool,
    },
    AlterPoint {
        collection: String,
        id: String,
        owner: Option<String>,
        department: Option<String>,
        classification: Option<Classification>,
    },
    CreatePoints {
        collection: String,
        template: String,
        points: Vec<Value>,
        request_id: String,
    },
    UpdatePoints {
        collection: String,
        points: Vec<Value>,
    },
}

impl SecurityStatement {
    pub fn class(&self) -> StatementClass {
        match self.command {
            SecurityCommand::ShowCatalogRevision
            | SecurityCommand::ShowCollectionPolicy { .. }
            | SecurityCommand::ShowCurrentUser { .. }
            | SecurityCommand::ShowUsers
            | SecurityCommand::ShowRoles { .. }
            | SecurityCommand::ShowRolePrivileges { .. }
            | SecurityCommand::ShowCredentials { .. }
            | SecurityCommand::ShowRevision { .. } => StatementClass::Read,
            SecurityCommand::CreatePoints { .. } | SecurityCommand::UpdatePoints { .. } => {
                StatementClass::Write
            }
            _ => StatementClass::Admin,
        }
    }
    pub fn requires_revision(&self) -> bool {
        self.class() == StatementClass::Admin
    }
    pub fn requires_confirmation(&self) -> bool {
        matches!(
            self.command,
            SecurityCommand::SetGraphLifecycle { enabled: false, .. }
                | SecurityCommand::DropUser { .. }
                | SecurityCommand::DropRole { .. }
                | SecurityCommand::AlterUser {
                    changes: UserChanges {
                        enabled: Some(false),
                        ..
                    },
                    ..
                }
        )
    }
    pub fn issues_key(&self) -> bool {
        matches!(
            self.command,
            SecurityCommand::IssueKey { .. } | SecurityCommand::RotateKey { .. }
        )
    }
    pub fn collection(&self) -> Option<&str> {
        match &self.command {
            SecurityCommand::RolePrivileges { collection, .. }
            | SecurityCommand::ShowRevision { collection } => collection.as_deref(),
            SecurityCommand::SetGraphLifecycle { collection, .. }
            | SecurityCommand::SetEdgeType { collection, .. }
            | SecurityCommand::SetCollectionPolicy { collection, .. }
            | SecurityCommand::ShowCollectionPolicy { collection }
            | SecurityCommand::ObjectPrivileges { collection, .. }
            | SecurityCommand::AlterPoint { collection, .. }
            | SecurityCommand::CreatePoints { collection, .. }
            | SecurityCommand::UpdatePoints { collection, .. } => Some(collection),
            _ => None,
        }
    }
    pub fn kind_name(&self) -> &'static str {
        use SecurityCommand::*;
        match self.command {
            ShowCatalogRevision => "SHOW CATALOG REVISION",
            CreateProtectedCollection { .. } => "CREATE PROTECTED COLLECTION",
            SetGraphLifecycle { .. } => "ALTER COLLECTION GRAPH",
            SetEdgeType { .. } => "ALTER COLLECTION EDGE TYPE",
            SetCollectionPolicy { .. } => "ALTER COLLECTION SECURITY POLICY",
            ShowCollectionPolicy { .. } => "SHOW COLLECTION SECURITY POLICY",
            CreateUser { .. } => "CREATE USER",
            AlterUser { .. } => "ALTER USER",
            RenameUser { .. } => "RENAME USER",
            DropUser { .. } => "DROP USER",
            CreateRole { .. } => "CREATE ROLE",
            RenameRole { .. } => "RENAME ROLE",
            DropRole { .. } => "DROP ROLE",
            AssignRole { grant: true, .. } => "GRANT ROLE",
            AssignRole { .. } => "REVOKE ROLE",
            RolePrivileges { grant: true, .. } => "GRANT ROLE PRIVILEGES",
            RolePrivileges { .. } => "REVOKE ROLE PRIVILEGES",
            ShowCurrentUser { .. } => "SHOW CURRENT USER",
            ShowUsers => "SHOW USERS",
            ShowRoles { .. } => "SHOW ROLES",
            ShowRolePrivileges { .. } => "SHOW ROLE PRIVILEGES",
            ShowCredentials { .. } => "SHOW API KEYS",
            ShowRevision { .. } => "SHOW SECURITY REVISION",
            IssueKey { .. } => "ISSUE API KEY",
            RotateKey { .. } => "ROTATE API KEY",
            RevokeKey { .. } => "REVOKE API KEY",
            ObjectPrivileges { .. } => "POINT PRIVILEGES",
            AlterPoint { .. } => "ALTER POINT",
            CreatePoints { .. } => "CREATE POINTS",
            UpdatePoints { .. } => "UPDATE POINTS",
        }
    }
}

pub(super) fn parse(input: &str) -> Option<ParseResult<Statement>> {
    let (first, _, next) = leading_keyword(input)?;
    let first = first.to_ascii_uppercase();
    let recognized = match first.as_str() {
        "CREATE" | "DROP" => matches!(next.as_str(), "USER" | "ROLE" | "POINTS" | "PROTECTED"),
        "ALTER" => matches!(next.as_str(), "USER" | "POINT" | "COLLECTION"),
        "UPDATE" => next == "POINTS",
        "SHOW" => matches!(
            next.as_str(),
            "CATALOG" | "COLLECTION" | "CURRENT" | "USERS" | "ROLES" | "ROLE" | "API" | "SECURITY"
        ),
        "GRANT" | "REVOKE" | "DENY" | "ISSUE" | "ROTATE" | "RENAME" => true,
        _ => false,
    };
    recognized.then(|| {
        let tokens = lex(input)?;
        let mut parser = Parser {
            tokens,
            pos: 0,
            len: input.len(),
            surface: LanguageSurface::GraphV1_1,
        };
        let command = parser.security_command()?;
        let mut statement = SecurityStatement {
            command,
            expected_revision: None,
        };
        if parser.eat_keyword("IF") {
            parser.expect_keyword("REVISION")?;
            if !statement.requires_revision() {
                return Err(parser.security_error("revision clause requires a security mutation"));
            }
            let token = parser
                .next()
                .ok_or_else(|| parser.security_error("expected revision"))?;
            if !matches!(token.tok, Tok::Num(_)) {
                return Err(parser.security_error("revision must be an unsigned integer"));
            }
            // Do not round u64 revisions through the legacy floating-point token.
            let raw: String = input[token.at..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '+' | '-'))
                .collect();
            statement.expected_revision = Some(
                raw.parse()
                    .map_err(|_| parser.security_error("invalid revision"))?,
            );
        }
        parser.eat(&Tok::Semi);
        if parser.peek().is_some() {
            return Err(parser.security_error("unexpected clause or multiple statements"));
        }
        Ok(Statement::Security(statement))
    })
}

impl Parser {
    fn security_error(&self, message: &'static str) -> ParseError {
        ParseError::new("chironql.invalid_security_statement", message, self.at())
    }
    fn security_name(&mut self) -> ParseResult<String> {
        let name = match self.next() {
            Some(Token {
                tok: Tok::Word(name) | Tok::Str(name),
                ..
            }) => name,
            _ => return Err(self.security_error("expected a name")),
        };
        if name.is_empty()
            || name.len() > 128
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-.:".contains(&b))
        {
            return Err(self.security_error("invalid security name"));
        }
        Ok(name)
    }
    fn security_classification(&mut self) -> ParseResult<Classification> {
        match self.expect_word()?.to_ascii_uppercase().as_str() {
            "PUBLIC" => Ok(Classification::Public),
            "INTERNAL" => Ok(Classification::Internal),
            "CONFIDENTIAL" => Ok(Classification::Confidential),
            "RESTRICTED" => Ok(Classification::Restricted),
            _ => Err(self.security_error("unknown classification")),
        }
    }
    fn security_actions(&mut self) -> ParseResult<BTreeSet<Action>> {
        let mut actions = BTreeSet::new();
        loop {
            let name = self.expect_word()?.to_ascii_lowercase();
            let action = serde_json::from_value(Value::String(name))
                .map_err(|_| self.security_error("unknown security action"))?;
            if !actions.insert(action) {
                return Err(self.security_error("duplicate security action"));
            }
            if !self.eat(&Tok::Comma) {
                break;
            }
        }
        Ok(actions)
    }
    fn security_command(&mut self) -> ParseResult<SecurityCommand> {
        use SecurityCommand::*;
        let verb = self.expect_word()?.to_ascii_uppercase();
        match verb.as_str() {
            "CREATE" if self.eat_keyword("PROTECTED") => {
                self.expect_keyword("COLLECTION")?;
                let name = self.security_name()?;
                self.expect_keyword("DIM")?;
                let dim = self.expect_usize()?;
                let metric = if self.eat_keyword("METRIC") {
                    self.parse_metric()?
                } else {
                    DistanceMetric::Cosine
                };
                Ok(CreateProtectedCollection { name, dim, metric })
            }
            "ALTER" if self.eat_keyword("COLLECTION") => {
                let collection = self.security_name()?;
                self.expect_keyword("SET")?;
                if self.eat_keyword("GRAPH") {
                    let enabled = if self.eat_keyword("ENABLED") {
                        true
                    } else if self.eat_keyword("DISABLED") {
                        false
                    } else {
                        return Err(self.security_error("expected ENABLED or DISABLED"));
                    };
                    return Ok(SetGraphLifecycle {
                        collection,
                        enabled,
                    });
                }
                if self.eat_keyword("EDGE") {
                    self.expect_keyword("TYPE")?;
                    let name = self.security_name()?;
                    let weight_property = if self.eat_keyword("WEIGHT") {
                        Some(self.security_name()?)
                    } else {
                        None
                    };
                    return Ok(SetEdgeType {
                        collection,
                        name,
                        weight_property,
                    });
                }
                if !self.eat_keyword("SECURITY") {
                    return Err(ParseError::new(
                        "chironql.no_ddl",
                        "collection schema changes are unsupported",
                        self.at(),
                    ));
                }
                self.expect_keyword("POLICY")?;
                let policy = serde_json::from_value(self.parse_json_value()?)
                    .map_err(|_| self.security_error("invalid typed collection policy"))?;
                Ok(SetCollectionPolicy { collection, policy })
            }
            "CREATE" if self.eat_keyword("USER") => {
                let name = self.security_name()?;
                let changes = self.security_user_changes()?;
                if changes.enabled.is_some() {
                    return Err(self
                        .security_error("new users are active without credentials or privileges"));
                }
                Ok(CreateUser {
                    name,
                    attributes: SubjectAttributes {
                        department: changes
                            .department
                            .ok_or_else(|| self.security_error("department is required"))?,
                        clearance: changes
                            .clearance
                            .ok_or_else(|| self.security_error("clearance is required"))?,
                    },
                })
            }
            "CREATE" if self.eat_keyword("ROLE") => Ok(CreateRole {
                name: self.security_name()?,
            }),
            "CREATE" => {
                self.expect_keyword("POINTS")?;
                self.expect_keyword("INTO")?;
                let collection = self.security_name()?;
                self.expect_keyword("USING")?;
                self.expect_keyword("TEMPLATE")?;
                let template = self.security_name()?;
                let points = self.security_points(false)?;
                self.expect_keyword("REQUEST")?;
                let request_id = self.security_name()?;
                Ok(CreatePoints {
                    collection,
                    template,
                    points,
                    request_id,
                })
            }
            "UPDATE" => {
                self.expect_keyword("POINTS")?;
                self.expect_keyword("IN")?;
                let collection = self.security_name()?;
                Ok(UpdatePoints {
                    collection,
                    points: self.security_points(true)?,
                })
            }
            "ALTER" if self.eat_keyword("USER") => {
                let name = self.security_name()?;
                Ok(AlterUser {
                    name,
                    changes: self.security_user_changes()?,
                })
            }
            "ALTER" => {
                self.expect_keyword("POINT")?;
                let id = self.expect_id()?;
                self.expect_keyword("IN")?;
                let collection = self.security_name()?;
                let (mut owner, mut department, mut classification) = (None, None, None);
                while self.eat_keyword("SET") {
                    match self.expect_word()?.to_ascii_uppercase().as_str() {
                        "OWNER" if owner.is_none() => owner = Some(self.security_name()?),
                        "DEPARTMENT" if department.is_none() => {
                            department = Some(self.security_name()?)
                        }
                        "CLASSIFICATION" if classification.is_none() => {
                            classification = Some(self.security_classification()?)
                        }
                        _ => {
                            return Err(self.security_error("unsupported or duplicate point label"));
                        }
                    }
                }
                if owner.is_none() && department.is_none() && classification.is_none() {
                    return Err(self.security_error("point label change required"));
                }
                Ok(AlterPoint {
                    collection,
                    id,
                    owner,
                    department,
                    classification,
                })
            }
            "RENAME" => {
                let user = if self.eat_keyword("USER") {
                    true
                } else {
                    self.expect_keyword("ROLE")?;
                    false
                };
                let name = self.security_name()?;
                self.expect_keyword("TO")?;
                let new_name = self.security_name()?;
                Ok(if user {
                    RenameUser { name, new_name }
                } else {
                    RenameRole { name, new_name }
                })
            }
            "DROP" => {
                if self.eat_keyword("USER") {
                    Ok(DropUser {
                        name: self.security_name()?,
                    })
                } else {
                    self.expect_keyword("ROLE")?;
                    Ok(DropRole {
                        name: self.security_name()?,
                    })
                }
            }
            "GRANT" | "REVOKE" | "DENY" => self.security_grant(&verb),
            "SHOW" => self.security_show(),
            "ISSUE" => {
                self.expect_keyword("API")?;
                self.expect_keyword("KEY")?;
                self.expect_keyword("FOR")?;
                self.expect_keyword("USER")?;
                Ok(IssueKey {
                    user: self.security_name()?,
                })
            }
            "ROTATE" => {
                self.expect_keyword("API")?;
                self.expect_keyword("KEY")?;
                Ok(RotateKey {
                    id: self.security_name()?,
                })
            }
            _ => Err(self.security_error("unsupported security statement")),
        }
    }
    fn security_user_changes(&mut self) -> ParseResult<UserChanges> {
        let mut changes = UserChanges::default();
        while self.eat_keyword("SET") {
            match self.expect_word()?.to_ascii_uppercase().as_str() {
                "DEPARTMENT" if changes.department.is_none() => {
                    changes.department = Some(self.security_name()?)
                }
                "CLEARANCE" if changes.clearance.is_none() => {
                    changes.clearance = Some(self.security_classification()?)
                }
                "STATUS" if changes.enabled.is_none() => {
                    changes.enabled =
                        Some(match self.expect_word()?.to_ascii_uppercase().as_str() {
                            "ACTIVE" => true,
                            "SUSPENDED" => false,
                            _ => return Err(self.security_error("unknown user status")),
                        });
                }
                _ => return Err(self.security_error("unsupported or duplicate user attribute")),
            }
        }
        if changes == UserChanges::default() {
            return Err(self.security_error("user attribute change required"));
        }
        Ok(changes)
    }
    fn security_points(&mut self, update: bool) -> ParseResult<Vec<Value>> {
        let mut points = vec![];
        loop {
            let point = self.parse_json_value()?;
            if !point.is_object() || point.get("id").is_some() != update {
                return Err(self.security_error("create forbids IDs; update requires IDs"));
            }
            points.push(point);
            if points.len() > 1024 {
                return Err(self.security_error("point batch limit exceeded"));
            }
            if !self.eat(&Tok::Comma) {
                break;
            }
        }
        Ok(points)
    }
    fn security_show(&mut self) -> ParseResult<SecurityCommand> {
        use SecurityCommand::*;
        if self.eat_keyword("CATALOG") {
            self.expect_keyword("REVISION")?;
            return Ok(ShowCatalogRevision);
        }
        if self.eat_keyword("COLLECTION") {
            let collection = self.security_name()?;
            self.expect_keyword("SECURITY")?;
            self.expect_keyword("POLICY")?;
            return Ok(ShowCollectionPolicy { collection });
        }

        if self.eat_keyword("CURRENT") {
            self.expect_keyword("USER")?;
            return Ok(ShowCurrentUser {
                privileges: self.eat_keyword("PRIVILEGES"),
            });
        }
        if self.eat_keyword("USERS") {
            return Ok(ShowUsers);
        }
        if self.eat_keyword("ROLES") {
            let with_users = self.eat_keyword("WITH");
            if with_users {
                self.expect_keyword("USERS")?;
            }
            return Ok(ShowRoles { with_users });
        }
        if self.eat_keyword("ROLE") {
            let role = self.security_name()?;
            self.expect_keyword("PRIVILEGES")?;
            return Ok(ShowRolePrivileges { role });
        }
        if self.eat_keyword("API") {
            self.expect_keyword("KEYS")?;
            self.expect_keyword("FOR")?;
            self.expect_keyword("USER")?;
            return Ok(ShowCredentials {
                user: self.security_name()?,
            });
        }
        self.expect_keyword("SECURITY")?;
        self.expect_keyword("REVISION")?;
        let collection = if self.eat_keyword("ON") {
            self.expect_keyword("COLLECTION")?;
            Some(self.security_name()?)
        } else {
            None
        };
        Ok(ShowRevision { collection })
    }
    fn security_grant(&mut self, verb: &str) -> ParseResult<SecurityCommand> {
        use SecurityCommand::*;
        let grant = verb != "REVOKE";
        if verb == "REVOKE" && self.eat_keyword("API") {
            self.expect_keyword("KEY")?;
            return Ok(RevokeKey {
                id: self.security_name()?,
            });
        }
        if verb != "DENY" && self.eat_keyword("ROLE") {
            let role = self.security_name()?;
            self.expect_keyword(if grant { "TO" } else { "FROM" })?;
            self.expect_keyword("USER")?;
            return Ok(AssignRole {
                role,
                user: self.security_name()?,
                grant,
            });
        }
        let explicit_effect = if verb == "REVOKE" {
            if self.eat_keyword("GRANT") {
                Some(Effect::Permit)
            } else if self.eat_keyword("DENY") {
                Some(Effect::Deny)
            } else {
                None
            }
        } else {
            None
        };
        let actions = self.security_actions()?;
        self.expect_keyword("ON")?;
        if self.eat_keyword("POINT") {
            if !grant && explicit_effect.is_none() {
                return Err(self.security_error("use REVOKE GRANT or REVOKE DENY for a point"));
            }
            let id = self.expect_id()?;
            self.expect_keyword("IN")?;
            let collection = self.security_name()?;
            self.expect_keyword(if grant { "TO" } else { "FROM" })?;
            let subject = if self.eat_keyword("USER") {
                NamedSubject::User(self.security_name()?)
            } else {
                self.expect_keyword("GROUP")?;
                NamedSubject::Group(self.security_name()?)
            };
            let effect = explicit_effect.unwrap_or(if verb == "DENY" {
                Effect::Deny
            } else {
                Effect::Permit
            });
            return Ok(ObjectPrivileges {
                collection,
                id,
                subject,
                actions,
                effect,
                grant,
            });
        }
        if verb == "DENY" || explicit_effect.is_some() {
            return Err(self.security_error("DENY applies to object policy"));
        }
        let (collection, table) = if self.eat_keyword("COLLECTION") {
            (Some(self.security_name()?), None)
        } else if self.eat_keyword("TABLE") {
            (None, Some(self.security_name()?))
        } else {
            self.expect_keyword("SYSTEM")?;
            (None, None)
        };
        self.expect_keyword(if grant { "TO" } else { "FROM" })?;
        self.expect_keyword("ROLE")?;
        Ok(RolePrivileges {
            role: self.security_name()?,
            collection,
            table,
            actions,
            grant,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn installation_commands_preserve_typed_revision_and_policy() {
        let Statement::Security(statement) = super::super::parse(
            "CREATE PROTECTED COLLECTION docs DIM 1536 METRIC cosine IF REVISION 9;",
        )
        .unwrap() else {
            panic!()
        };
        assert_eq!(statement.expected_revision, Some(9));
        assert!(matches!(
            statement.command,
            SecurityCommand::CreateProtectedCollection { dim: 1536, .. }
        ));
        for query in [
            "SHOW CATALOG REVISION;",
            "SHOW COLLECTION docs SECURITY POLICY;",
            "ALTER COLLECTION docs SET SECURITY POLICY {department_actions:[],owner_actions:[],templates:{}} IF REVISION 1;",
        ] {
            assert!(
                matches!(super::super::parse(query), Ok(Statement::Security(_))),
                "{query}"
            );
            assert!(super::super::parse_v1_1(query).is_err(), "{query}");
        }
        for query in [
            "CREATE PROTECTED COLLECTION docs DIM 2 IF REVISION -1;",
            "CREATE PROTECTED COLLECTION docs DIM 2 METRIC expression;",
            "ALTER COLLECTION docs SET SECURITY POLICY {templates:{x:{department:'Finance'}}};",
            "ALTER COLLECTION docs SET SECURITY POLICY {department_actions:['unknown'],owner_actions:[],templates:{}};",
            "ALTER COLLECTION docs SET SECURITY POLICY {script:'allow all'};",
            "SHOW CATALOG REVISION IF REVISION 1;",
        ] {
            assert!(super::super::parse(query).is_err(), "{query}");
        }
    }

    #[test]
    fn bounded_nested_payload_rejects_before_recursive_descent() {
        let query = format!(
            "CREATE POINTS INTO docs USING TEMPLATE t {{vector:[1],payload:{{x:{}0{}}}}} REQUEST r;",
            "[".repeat(10000),
            "]".repeat(10000)
        );
        assert_eq!(
            super::super::parse(&query).unwrap_err().code,
            "chironql.query_too_deep"
        );
    }

    #[test]
    fn security_commands_are_additive_and_typed() {
        for query in [
            "ALTER COLLECTION docs SET GRAPH ENABLED IF REVISION 1;",
            "ALTER COLLECTION docs SET GRAPH DISABLED IF REVISION 2;",
            "ALTER COLLECTION docs SET EDGE TYPE cites IF REVISION 3;",
            "ALTER COLLECTION docs SET EDGE TYPE cites WEIGHT confidence IF REVISION 3;",
            "CREATE ROLE finance_reader;",
            "CREATE USER ana SET DEPARTMENT finance SET CLEARANCE CONFIDENTIAL;",
            "GRANT READ, SEARCH ON COLLECTION docs TO ROLE finance_reader;",
            "GRANT OBSERVE ON SYSTEM TO ROLE ops;",
            "GRANT ROLE finance_reader TO USER ana;",
            "REVOKE ROLE finance_reader FROM USER ana;",
            "SHOW CURRENT USER PRIVILEGES;",
            "SHOW USERS;",
            "SHOW ROLES WITH USERS;",
            "SHOW ROLE finance_reader PRIVILEGES;",
            "ISSUE API KEY FOR USER ana;",
            "ROTATE API KEY 'key-id';",
            "REVOKE API KEY 'key-id';",
            "SHOW API KEYS FOR USER ana;",
            "ALTER USER ana SET STATUS SUSPENDED;",
            "RENAME USER ana TO anne;",
            "DROP USER anne;",
            "RENAME ROLE reader TO viewers;",
            "DROP ROLE viewers;",
            "SHOW SECURITY REVISION ON COLLECTION docs;",
            "GRANT READ ON POINT 'x' IN docs TO USER ana;",
            "DENY READ ON POINT 'x' IN docs TO GROUP payroll;",
            "REVOKE DENY READ ON POINT 'x' IN docs FROM USER ana;",
            "REVOKE GRANT READ ON POINT 'x' IN docs FROM GROUP payroll;",
            "ALTER POINT 'x' IN docs SET OWNER ana SET DEPARTMENT finance SET CLASSIFICATION RESTRICTED;",
            "CREATE POINTS INTO docs USING TEMPLATE finance {vector:[1,0],payload:{text:'x'}} REQUEST 'retry-1';",
            "UPDATE POINTS IN docs {id:'x',vector:[1,0],payload:{text:'new'}};",
        ] {
            assert!(
                matches!(super::super::parse(query), Ok(Statement::Security(_))),
                "{query}"
            );
            assert!(
                super::super::parse_v1_1(query).is_err(),
                "1.1 must remain frozen: {query}"
            );
        }
    }
    #[test]
    fn ambiguous_attributes_and_unsafe_creates_are_rejected() {
        for query in [
            "CREATE USER ana SET DEPARTMENT finance;",
            "CREATE USER ana SET CLEARANCE null SET DEPARTMENT finance;",
            "ALTER USER ana SET CLEARANCE PUBLIC SET CLEARANCE RESTRICTED;",
            "CREATE ROLE reader; DROP ROLE reader;",
            "GRANT READ, READ ON COLLECTION docs TO ROLE reader;",
            "DENY READ ON COLLECTION docs TO ROLE reader;",
            "REVOKE READ ON POINT x IN docs FROM USER ana;",
            "GRANT ROLE a TO ROLE b;",
            "CREATE POINTS INTO docs USING TEMPLATE finance {id:'x',vector:[1,0]} REQUEST retry;",
            "UPDATE POINTS IN docs {vector:[1,0]};",
            "CREATE ROLE reader IF REVISION 1.5;",
            "CREATE ROLE reader IF REVISION 1e3;",
            "CREATE ROLE reader IF REVISION 18446744073709551616;",
            "SHOW USERS IF REVISION 1;",
            "CREATE OR REPLACE USER ana SET PASSWORD 'secret';",
        ] {
            assert!(super::super::parse(query).is_err(), "{query}");
        }
        let Statement::Security(statement) =
            super::super::parse("CREATE ROLE reader IF REVISION 18446744073709551615;").unwrap()
        else {
            panic!()
        };
        assert_eq!(statement.expected_revision, Some(u64::MAX));
    }
}
