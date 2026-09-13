//! ChironQL — handwritten lexer + recursive-descent parser.
//!
//! P0 of the ChironQL plan. Same shape as `pgvector_parser.rs`: no parser
//! dependency, one `parse_*` function per statement, and a reject taxonomy in
//! which every unsupported construct produces a specific error with a stable
//! code, a hint, and a caret position — never a generic parse failure.
//!
//! Three deliberate differences from the pgvector parser (plan §6.1):
//!
//! 1. [`ParseError`] carries a byte `position` from the start. A caret is most
//!    of the value of a REPL error message.
//! 2. No SQLSTATE. ChironQL is not Postgres; errors carry a stable string code
//!    such as `chironql.no_or_across_fields` instead.
//! 3. The AST stays private to the server. Only the DTOs in
//!    `chirondb_types::chironql` cross a wire.
//!
//! ## Grammar note — clause order
//!
//! The plan writes the optional clauses in a fixed order. This parser accepts
//! them in **any** order, which is a strict superset: every statement in the
//! plan parses, plus `SEARCH c LIMIT 5 NEAR [1,0,0]`. Enforcing the order would
//! only add a class of error message that teaches the user nothing. Each clause
//! may still appear at most once.
//!
//! Execution lives in `chironql_exec.rs`; this module only produces the AST.

use std::fmt;

use serde_json::{Map, Value};

use chirondb_types::{
    DistanceMetric, Filter,
    graph::{
        GraphDirection, MAX_EDGE_PROPERTY_BYTES, MAX_GRAPH_ANCHORS, MAX_GRAPH_DEPTH,
        MAX_GRAPH_EDGES_PER_BATCH, MAX_GRAPH_TYPES_PER_CLAUSE,
    },
    model::HybridFusion,
    model::SparseVector,
};

/// The language version, as printed by the front ends and documented in
/// `docs/CHIRONQL.md`.
///
/// Separate from the crate version on purpose: ChironDB is in public beta, the
/// language it answers is not. At 1.1 the statements, clause names, error
/// codes and rejection taxonomy are stable — anything removed goes through a
/// deprecation cycle rather than disappearing between releases.
pub const LANGUAGE_VERSION: &str = "1.1";

/// Explicit alias used by the graph conformance corpus.
#[cfg(test)]
pub(crate) fn parse_v1_1(input: &str) -> ParseResult<Statement> {
    parse(input)
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// A parse failure or a deliberate reject.
///
/// `code` is stable and machine-readable; clients key off it, humans read
/// `message`. `position` is a byte offset into the original query text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseError {
    pub code: &'static str,
    pub message: String,
    pub hint: Option<&'static str>,
    pub position: usize,
}

impl ParseError {
    fn new(code: &'static str, message: impl Into<String>, position: usize) -> Self {
        Self {
            code,
            message: message.into(),
            hint: None,
            position,
        }
    }

    fn with_hint(
        code: &'static str,
        message: impl Into<String>,
        hint: &'static str,
        position: usize,
    ) -> Self {
        Self {
            code,
            message: message.into(),
            hint: Some(hint),
            position,
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (at byte {})", self.message, self.position)
    }
}

impl std::error::Error for ParseError {}

pub type ParseResult<T> = Result<T, ParseError>;

// ---------------------------------------------------------------------------
// AST
// ---------------------------------------------------------------------------

/// One parsed ChironQL statement.
///
/// `collection: Option<String>` throughout — `None` means "use the session
/// collection set by `USE`", which only the executor can resolve.
#[derive(Clone, Debug, PartialEq)]
pub enum Statement {
    Search(Search),
    Hybrid(Hybrid),
    Multi(Multi),
    Recommend(Recommend),
    Count(Count),
    Scroll(Scroll),
    Get(Get),
    ShowCollections,
    Describe {
        collection: Option<String>,
    },
    Upsert(Upsert),
    DeletePoints {
        collection: Option<String>,
        ids: Vec<String>,
    },
    DeleteWhere {
        collection: Option<String>,
        filter: Filter,
    },
    UpdatePayload(UpdatePayload),
    Relate(Relate),
    Unrelate(Unrelate),
    UpdateEdge(UpdateEdge),
    Traverse(Traverse),
    CreateCollection(CreateCollection),
    DropCollection {
        collection: String,
        if_exists: bool,
    },
    Use {
        collection: String,
    },
}

impl Statement {
    /// Read or write. The RBAC check keys off this, before execution.
    pub fn class(&self) -> StatementClass {
        match self {
            Self::Search(_)
            | Self::Hybrid(_)
            | Self::Multi(_)
            | Self::Recommend(_)
            | Self::Count(_)
            | Self::Scroll(_)
            | Self::Get(_)
            | Self::ShowCollections
            | Self::Describe { .. }
            | Self::Traverse(_)
            | Self::Use { .. } => StatementClass::Read,
            Self::Upsert(_)
            | Self::DeletePoints { .. }
            | Self::DeleteWhere { .. }
            | Self::UpdatePayload(_)
            | Self::Relate(_)
            | Self::Unrelate(_)
            | Self::UpdateEdge(_)
            | Self::CreateCollection(_)
            | Self::DropCollection { .. } => StatementClass::Write,
        }
    }

    pub fn is_collection_ddl(&self) -> bool {
        matches!(
            self,
            Self::CreateCollection(_) | Self::DropCollection { .. }
        )
    }

    /// The collection named in the statement itself, if any.
    pub fn collection(&self) -> Option<&str> {
        match self {
            Self::Search(s) => s.collection.as_deref(),
            Self::Hybrid(s) => s.collection.as_deref(),
            Self::Multi(s) => s.collection.as_deref(),
            Self::Recommend(s) => s.collection.as_deref(),
            Self::Count(s) => s.collection.as_deref(),
            Self::Scroll(s) => s.collection.as_deref(),
            Self::Get(s) => s.collection.as_deref(),
            Self::Describe { collection } => collection.as_deref(),
            Self::Upsert(s) => s.collection.as_deref(),
            Self::DeletePoints { collection, .. } => collection.as_deref(),
            Self::DeleteWhere { collection, .. } => collection.as_deref(),
            Self::UpdatePayload(s) => s.collection.as_deref(),
            Self::Relate(s) => Some(&s.collection),
            Self::Unrelate(s) => Some(&s.collection),
            Self::UpdateEdge(s) => Some(&s.collection),
            Self::Traverse(s) => Some(&s.collection),
            Self::CreateCollection(s) => Some(&s.name),
            Self::DropCollection { collection, .. } => Some(collection),
            Self::Use { collection } => Some(collection),
            Self::ShowCollections => None,
        }
    }

    /// Statement name as it appears in a trace or a log line.
    pub fn kind_name(&self) -> &'static str {
        match self {
            Self::Search(_) => "SEARCH",
            Self::Hybrid(_) => "HYBRID",
            Self::Multi(_) => "MULTI",
            Self::Recommend(_) => "RECOMMEND",
            Self::Count(_) => "COUNT",
            Self::Scroll(_) => "SCROLL",
            Self::Get(_) => "GET",
            Self::ShowCollections => "SHOW COLLECTIONS",
            Self::Describe { .. } => "DESCRIBE",
            Self::Upsert(_) => "UPSERT",
            Self::DeletePoints { .. } | Self::DeleteWhere { .. } => "DELETE",
            Self::UpdatePayload(_) => "UPDATE",
            Self::Relate(_) => "RELATE",
            Self::Unrelate(_) => "UNRELATE",
            Self::UpdateEdge(_) => "UPDATE EDGE",
            Self::Traverse(_) => "TRAVERSE",
            Self::CreateCollection(_) => "CREATE COLLECTION",
            Self::DropCollection { .. } => "DROP COLLECTION",
            Self::Use { .. } => "USE",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StatementClass {
    Read,
    Write,
    /// Collection DDL. Separated from `Write` because the blast radius is
    /// different in kind: a write touches points, `DROP COLLECTION` destroys
    /// the collection and its data directory. Folding it into `Write` would
    /// hand that to every `read_write` session.
    Admin,
}

/// `NEAR` operand: an inline vector, or a reference to a stored point's vector.
#[derive(Clone, Debug, PartialEq)]
pub enum VectorExpr {
    Literal(Vec<f32>),
    /// `@id` — the executor fetches the point and uses its vector.
    Point {
        id: String,
        vector_name: Option<String>,
    },
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Search {
    pub collection: Option<String>,
    pub vector: Option<VectorExpr>,
    pub vector_name: Option<String>,
    pub filter: Option<Filter>,
    pub limit: Option<usize>,
    pub with_payload: Option<bool>,
    pub ef_search: Option<u32>,
    pub recall_target: Option<f32>,
    pub budget_ms: Option<u64>,
    pub graph: Option<GraphClause>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Hybrid {
    pub collection: Option<String>,
    pub vector: Option<VectorExpr>,
    pub vector_name: Option<String>,
    pub sparse: Option<SparseVector>,
    pub fusion: Option<HybridFusion>,
    pub dense_weight: Option<f32>,
    pub sparse_weight: Option<f32>,
    pub filter: Option<Filter>,
    pub limit: Option<usize>,
    pub with_payload: Option<bool>,
    pub graph: Option<GraphClause>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Multi {
    pub collection: Option<String>,
    pub vectors: Vec<VectorExpr>,
    pub fusion: Option<HybridFusion>,
    pub weights: Vec<f32>,
    pub filter: Option<Filter>,
    pub limit: Option<usize>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Recommend {
    pub collection: Option<String>,
    pub positive: Vec<String>,
    pub negative: Vec<String>,
    pub vector_name: Option<String>,
    pub filter: Option<Filter>,
    pub limit: Option<usize>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Count {
    pub collection: Option<String>,
    pub filter: Option<Filter>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Scroll {
    pub collection: Option<String>,
    pub filter: Option<Filter>,
    pub limit: Option<usize>,
    pub after: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Get {
    pub collection: Option<String>,
    pub ids: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Upsert {
    pub collection: Option<String>,
    /// Raw point objects. Shape validation beyond "has an id" belongs to the
    /// executor, which knows the collection's dimension and schema.
    pub points: Vec<Value>,
    pub wait: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct UpdatePayload {
    pub collection: Option<String>,
    pub id: String,
    pub payload: Value,
    pub replace: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Relate {
    pub collection: String,
    pub source_id: String,
    pub edge_type: String,
    pub target_id: String,
    pub properties: Value,
    pub idempotency_key: Option<String>,
    pub deferred_endpoints: bool,
    pub wait: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Unrelate {
    pub collection: String,
    pub edge_ids: Vec<String>,
    pub wait: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct UpdateEdge {
    pub collection: String,
    pub edge_id: String,
    pub properties: Value,
    pub replace: bool,
    pub wait: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum GraphReturn {
    #[default]
    Nodes,
    Edges,
    Paths,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Traverse {
    pub collection: String,
    pub anchors: Vec<String>,
    pub edge_types: Vec<String>,
    pub direction: GraphDirection,
    pub depth: u32,
    pub node_filter: Option<Filter>,
    pub edge_filter: Option<Filter>,
    pub budget_ms: Option<u64>,
    pub limit: Option<usize>,
    pub with_payload: bool,
    pub returns: GraphReturn,
}

#[derive(Clone, Debug, PartialEq)]
pub struct GraphClause {
    pub anchors: Vec<String>,
    pub edge_types: Vec<String>,
    pub direction: GraphDirection,
    pub within_hops: u32,
    pub allow_degraded: bool,
}

impl Default for GraphClause {
    fn default() -> Self {
        Self {
            anchors: Vec::new(),
            edge_types: Vec::new(),
            direction: GraphDirection::Outgoing,
            within_hops: 1,
            allow_degraded: false,
        }
    }
}

/// `CREATE COLLECTION <name> DIM <n> [METRIC …] [WITH {…}]`.
#[derive(Clone, Debug, PartialEq)]
pub struct CreateCollection {
    pub name: String,
    pub dim: usize,
    pub metric: Option<DistanceMetric>,
    /// The `WITH` object, verbatim, or `None`.
    ///
    /// `CollectionConfig` has fourteen fields. Two of them — the name and the
    /// dimension — are what every collection needs and they get grammar. The
    /// rest arrive here as an object and are deserialized by the executor, so
    /// a field added to the struct is reachable the day it lands and no
    /// keyword can fall out of step with it.
    pub options: Option<Value>,
}

// ---------------------------------------------------------------------------
// Lexer
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
enum Tok {
    /// Identifier or keyword. Dots are part of the word so `meta.brand` is one
    /// token — payload paths are addressed that way by `Filter`.
    Word(String),
    Str(String),
    Num(f64),
    LBracket,
    RBracket,
    LBrace,
    RBrace,
    Comma,
    Colon,
    Semi,
    At,
    Eq,
    NotEq,
    Lt,
    Lte,
    Gt,
    Gte,
    Arrow,
}

impl Tok {
    fn describe(&self) -> String {
        match self {
            Tok::Word(word) => format!("`{word}`"),
            Tok::Str(_) => "a string".to_string(),
            Tok::Num(_) => "a number".to_string(),
            Tok::LBracket => "`[`".to_string(),
            Tok::RBracket => "`]`".to_string(),
            Tok::LBrace => "`{`".to_string(),
            Tok::RBrace => "`}`".to_string(),
            Tok::Comma => "`,`".to_string(),
            Tok::Colon => "`:`".to_string(),
            Tok::Semi => "`;`".to_string(),
            Tok::At => "`@`".to_string(),
            Tok::Eq => "`=`".to_string(),
            Tok::NotEq => "`!=`".to_string(),
            Tok::Lt => "`<`".to_string(),
            Tok::Lte => "`<=`".to_string(),
            Tok::Gt => "`>`".to_string(),
            Tok::Gte => "`>=`".to_string(),
            Tok::Arrow => "`->`".to_string(),
        }
    }
}

#[derive(Clone, Debug)]
struct Token {
    tok: Tok,
    /// Byte offset of the token's first character in the source text.
    at: usize,
}

fn lex(input: &str) -> ParseResult<Vec<Token>> {
    let bytes = input.as_bytes();
    let mut tokens = Vec::new();
    let mut i = 0usize;

    while i < bytes.len() {
        let c = input[i..].chars().next().expect("in-bounds char");

        if c.is_whitespace() {
            i += c.len_utf8();
            continue;
        }

        // `-- line comment`
        if c == '-' && i + 1 < bytes.len() && bytes[i + 1] == b'-' {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }

        let start = i;

        // Single-quoted string, '' escapes a quote.
        if c == '\'' {
            i += 1;
            let mut value = String::new();
            loop {
                if i >= bytes.len() {
                    return Err(ParseError::new(
                        "chironql.unterminated_string",
                        "unterminated string literal",
                        start,
                    ));
                }
                if bytes[i] == b'\'' {
                    if i + 1 < bytes.len() && bytes[i + 1] == b'\'' {
                        value.push('\'');
                        i += 2;
                        continue;
                    }
                    i += 1;
                    break;
                }
                let ch = input[i..].chars().next().expect("in-bounds char");
                value.push(ch);
                i += ch.len_utf8();
            }
            tokens.push(Token {
                tok: Tok::Str(value),
                at: start,
            });
            continue;
        }

        // Number: -?digits[.digits][e[+-]digits]
        if c.is_ascii_digit()
            || (c == '-' && i + 1 < bytes.len() && (bytes[i + 1] as char).is_ascii_digit())
        {
            i += 1;
            while i < bytes.len() {
                let ch = bytes[i] as char;
                if ch.is_ascii_digit() || ch == '.' {
                    i += 1;
                } else if ch == 'e' || ch == 'E' {
                    i += 1;
                    if i < bytes.len() && (bytes[i] == b'+' || bytes[i] == b'-') {
                        i += 1;
                    }
                } else {
                    break;
                }
            }
            // A numeric run that continues into identifier characters is an
            // identifier, not a number: `7f3d-2a10` and `2024-01-01` are point
            // ids, and lexing their first digits as a number would split them.
            if i < bytes.len() {
                let next = input[i..].chars().next().expect("in-bounds char");
                if next.is_alphanumeric() || next == '_' || next == '-' {
                    while i < bytes.len() {
                        let ch = input[i..].chars().next().expect("in-bounds char");
                        if ch.is_alphanumeric() || ch == '_' || ch == '.' || ch == '-' {
                            i += ch.len_utf8();
                        } else {
                            break;
                        }
                    }
                    tokens.push(Token {
                        tok: Tok::Word(input[start..i].to_string()),
                        at: start,
                    });
                    continue;
                }
            }

            let raw = &input[start..i];
            let value = raw.parse::<f64>().map_err(|_| {
                ParseError::new(
                    "chironql.invalid_number",
                    format!("`{raw}` is not a valid number"),
                    start,
                )
            })?;
            tokens.push(Token {
                tok: Tok::Num(value),
                at: start,
            });
            continue;
        }

        // Word: identifier or keyword. Dots are included for payload paths and
        // hyphens for identifiers, because point ids are routinely `acme-1` or
        // a uuid. A word must still *start* with a letter or `_`, so a leading
        // `-` in a value position still begins a negative number.
        if c.is_alphabetic() || c == '_' {
            while i < bytes.len() {
                let ch = input[i..].chars().next().expect("in-bounds char");
                if ch.is_alphanumeric() || ch == '_' || ch == '.' || ch == '-' {
                    i += ch.len_utf8();
                } else {
                    break;
                }
            }
            tokens.push(Token {
                tok: Tok::Word(input[start..i].to_string()),
                at: start,
            });
            continue;
        }

        let (tok, width) = match c {
            '[' => (Tok::LBracket, 1),
            ']' => (Tok::RBracket, 1),
            '{' => (Tok::LBrace, 1),
            '}' => (Tok::RBrace, 1),
            ',' => (Tok::Comma, 1),
            ':' => (Tok::Colon, 1),
            ';' => (Tok::Semi, 1),
            '@' => (Tok::At, 1),
            '=' => (Tok::Eq, 1),
            '!' if bytes.get(i + 1) == Some(&b'=') => (Tok::NotEq, 2),
            '<' if bytes.get(i + 1) == Some(&b'=') => (Tok::Lte, 2),
            '>' if bytes.get(i + 1) == Some(&b'=') => (Tok::Gte, 2),
            '<' => (Tok::Lt, 1),
            '>' => (Tok::Gt, 1),
            '-' if bytes.get(i + 1) == Some(&b'>') => (Tok::Arrow, 2),
            '*' => {
                return Err(ParseError::with_hint(
                    "chironql.no_aggregates",
                    "`*` is not a ChironQL projection",
                    "ChironQL returns whole points. Use WITH PAYLOAD to include payloads.",
                    start,
                ));
            }
            other => {
                return Err(ParseError::new(
                    "chironql.unexpected_character",
                    format!("unexpected character `{other}`"),
                    start,
                ));
            }
        };
        i += width;
        tokens.push(Token { tok, at: start });
    }

    Ok(tokens)
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

/// Parse exactly one statement. A trailing `;` is optional; a second statement
/// is a reject, because there are no transactions to give multi-statement
/// bodies coherent partial-failure semantics.
pub fn parse(input: &str) -> ParseResult<Statement> {
    parse_language(input, LanguageSurface::GraphV1_1)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LanguageSurface {
    #[cfg_attr(
        not(test),
        allow(dead_code, reason = "retained for the frozen 1.0 parser corpus")
    )]
    VectorV1_0,
    GraphV1_1,
}

#[cfg(test)]
fn parse_v1_0(input: &str) -> ParseResult<Statement> {
    parse_language(input, LanguageSurface::VectorV1_0)
}

fn parse_language(input: &str, surface: LanguageSurface) -> ParseResult<Statement> {
    // Whole-statement rejects are decided on the leading keyword, before
    // lexing. `SELECT * FROM t` must answer "ChironQL is not SQL", not
    // "unexpected character `*`" — the taxonomy is the product, and a lexer
    // error about punctuation teaches nobody anything.
    if let Some((keyword, at, next)) = leading_keyword(input) {
        if let Some(error) = reject_leading_keyword(&keyword, &next, at) {
            return Err(error);
        }
        if surface == LanguageSurface::GraphV1_1
            && let Some(error) = reject_graph_leading_keyword(&keyword, at)
        {
            return Err(error);
        }
    }

    let tokens = lex(input)?;
    if tokens.is_empty() {
        return Err(ParseError::new("chironql.empty_query", "empty query", 0));
    }
    let mut parser = Parser {
        tokens,
        pos: 0,
        len: input.len(),
        surface,
    };
    let statement = parser.parse_statement()?;
    parser.eat(&Tok::Semi);
    if let Some(token) = parser.peek_token() {
        return Err(ParseError::with_hint(
            "chironql.multiple_statements",
            format!(
                "unexpected {} after the end of the statement",
                token.tok.describe()
            ),
            "Send one statement per request. The REPL splits on `;` for you.",
            token.at,
        ));
    }
    Ok(statement)
}

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
    len: usize,
    surface: LanguageSurface,
}

impl Parser {
    // -- token helpers ------------------------------------------------------

    fn peek_token(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn peek(&self) -> Option<&Tok> {
        self.tokens.get(self.pos).map(|token| &token.tok)
    }

    /// Byte offset to blame for an error at the current position.
    fn at(&self) -> usize {
        self.tokens
            .get(self.pos)
            .map(|token| token.at)
            .unwrap_or(self.len)
    }

    fn next(&mut self) -> Option<Token> {
        let token = self.tokens.get(self.pos).cloned();
        if token.is_some() {
            self.pos += 1;
        }
        token
    }

    fn eat(&mut self, want: &Tok) -> bool {
        if self.peek() == Some(want) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn expect(&mut self, want: &Tok) -> ParseResult<()> {
        if self.eat(want) {
            return Ok(());
        }
        let found = self
            .peek()
            .map(Tok::describe)
            .unwrap_or_else(|| "end of input".to_string());
        Err(ParseError::new(
            "chironql.unexpected_token",
            format!("expected {}, found {found}", want.describe()),
            self.at(),
        ))
    }

    /// Case-insensitive keyword peek.
    fn peek_keyword(&self, keyword: &str) -> bool {
        matches!(self.peek(), Some(Tok::Word(word)) if word.eq_ignore_ascii_case(keyword))
    }

    fn eat_keyword(&mut self, keyword: &str) -> bool {
        if self.peek_keyword(keyword) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn expect_keyword(&mut self, keyword: &str) -> ParseResult<()> {
        if self.eat_keyword(keyword) {
            return Ok(());
        }
        let found = self
            .peek()
            .map(Tok::describe)
            .unwrap_or_else(|| "end of input".to_string());
        Err(ParseError::new(
            "chironql.unexpected_token",
            format!("expected `{}`, found {found}", keyword.to_uppercase()),
            self.at(),
        ))
    }

    fn expect_word(&mut self) -> ParseResult<String> {
        let at = self.at();
        match self.next() {
            Some(Token {
                tok: Tok::Word(word),
                ..
            }) => Ok(word),
            Some(token) => Err(ParseError::new(
                "chironql.unexpected_token",
                format!("expected a name, found {}", token.tok.describe()),
                token.at,
            )),
            None => Err(ParseError::new(
                "chironql.unexpected_end",
                "expected a name, found end of input",
                at,
            )),
        }
    }

    /// A point id: bare word or quoted string.
    fn expect_id(&mut self) -> ParseResult<String> {
        let at = self.at();
        match self.next() {
            Some(Token {
                tok: Tok::Word(word),
                ..
            }) => Ok(word),
            Some(Token {
                tok: Tok::Str(text),
                ..
            }) => Ok(text),
            Some(Token {
                tok: Tok::Num(value),
                ..
            }) => Ok(format_number(value)),
            Some(token) => Err(ParseError::new(
                "chironql.unexpected_token",
                format!("expected a point id, found {}", token.tok.describe()),
                token.at,
            )),
            None => Err(ParseError::new(
                "chironql.unexpected_end",
                "expected a point id, found end of input",
                at,
            )),
        }
    }

    fn expect_number(&mut self) -> ParseResult<f64> {
        let at = self.at();
        match self.next() {
            Some(Token {
                tok: Tok::Num(value),
                ..
            }) => Ok(value),
            Some(token) => Err(ParseError::new(
                "chironql.unexpected_token",
                format!("expected a number, found {}", token.tok.describe()),
                token.at,
            )),
            None => Err(ParseError::new(
                "chironql.unexpected_end",
                "expected a number, found end of input",
                at,
            )),
        }
    }

    fn expect_string(&mut self) -> ParseResult<String> {
        let at = self.at();
        match self.next() {
            Some(Token {
                tok: Tok::Str(value),
                ..
            }) => Ok(value),
            Some(token) => Err(ParseError::new(
                "chironql.unexpected_token",
                format!("expected a string, found {}", token.tok.describe()),
                token.at,
            )),
            None => Err(ParseError::new(
                "chironql.unexpected_end",
                "expected a string, found end of input",
                at,
            )),
        }
    }

    fn expect_usize(&mut self) -> ParseResult<usize> {
        let at = self.at();
        let value = self.expect_number()?;
        if value < 0.0 || value.fract() != 0.0 {
            return Err(ParseError::new(
                "chironql.invalid_count",
                format!("expected a non-negative whole number, found {value}"),
                at,
            ));
        }
        Ok(value as usize)
    }

    // -- statements ---------------------------------------------------------

    fn parse_statement(&mut self) -> ParseResult<Statement> {
        let at = self.at();
        let Some(Tok::Word(word)) = self.peek().cloned() else {
            let found = self
                .peek()
                .map(Tok::describe)
                .unwrap_or_else(|| "end of input".to_string());
            return Err(ParseError::new(
                "chironql.unexpected_token",
                format!("a statement must start with a keyword, found {found}"),
                at,
            ));
        };

        // Reject taxonomy first: these are recognised precisely so they get a
        // specific answer instead of "unexpected token".
        let next = match self.tokens.get(self.pos + 1).map(|token| &token.tok) {
            Some(Tok::Word(word)) => word.to_ascii_uppercase(),
            _ => String::new(),
        };
        if let Some(error) = reject_leading_keyword(&word, &next, at) {
            return Err(error);
        }
        if self.surface == LanguageSurface::GraphV1_1
            && let Some(error) = reject_graph_leading_keyword(&word, at)
        {
            return Err(error);
        }

        let upper = word.to_ascii_uppercase();
        self.pos += 1;
        match upper.as_str() {
            "SEARCH" => self.parse_search(),
            "HYBRID" => self.parse_hybrid(),
            "RELATE" if self.surface == LanguageSurface::GraphV1_1 => self.parse_relate(),
            "UNRELATE" if self.surface == LanguageSurface::GraphV1_1 => self.parse_unrelate(),
            "TRAVERSE" if self.surface == LanguageSurface::GraphV1_1 => self.parse_traverse(),
            "MULTI" => self.parse_multi(),
            "RECOMMEND" => self.parse_recommend(),
            "COUNT" => self.parse_count(),
            "SCROLL" => self.parse_scroll(),
            "GET" => self.parse_get(),
            "SHOW" => {
                self.expect_keyword("COLLECTIONS")?;
                Ok(Statement::ShowCollections)
            }
            "DESCRIBE" => Ok(Statement::Describe {
                collection: self.parse_optional_collection(),
            }),
            "UPSERT" => self.parse_upsert(),
            "DELETE" => self.parse_delete(),
            "UPDATE" => self.parse_update(),
            "CREATE" => self.parse_create(),
            "DROP" => self.parse_drop(),
            "USE" => {
                let collection = self.expect_word()?;
                Ok(Statement::Use { collection })
            }
            other => {
                let hint = match self.surface {
                    LanguageSurface::VectorV1_0 => {
                        "Statements: SEARCH, HYBRID, MULTI, RECOMMEND, COUNT, SCROLL, GET, \
                         SHOW COLLECTIONS, DESCRIBE, UPSERT, DELETE, UPDATE, \
                         CREATE COLLECTION, DROP COLLECTION, USE. Try \\h."
                    }
                    LanguageSurface::GraphV1_1 => {
                        "Statements: SEARCH, HYBRID, MULTI, RECOMMEND, COUNT, SCROLL, GET, \
                         TRAVERSE, SHOW COLLECTIONS, DESCRIBE, UPSERT, RELATE, UNRELATE, \
                         UPDATE, CREATE COLLECTION, DROP COLLECTION, USE. Try \\h."
                    }
                };
                Err(ParseError::with_hint(
                    "chironql.unknown_statement",
                    format!("`{other}` is not a ChironQL statement"),
                    hint,
                    at,
                ))
            }
        }
    }

    /// A positional collection name, unless the next word starts a clause.
    fn parse_optional_collection(&mut self) -> Option<String> {
        match self.peek() {
            Some(Tok::Word(word)) if !is_clause_keyword(word, self.surface) => {
                let name = word.clone();
                self.pos += 1;
                Some(name)
            }
            _ => None,
        }
    }

    /// Graph additions must not reserve collection names that were legal in
    /// 1.0. Only treat a leading graph word as a session-scoped search clause
    /// when its following token makes that clause unambiguous.
    fn parse_optional_search_collection(&mut self) -> Option<String> {
        let graph_clause = match (self.peek(), self.tokens.get(self.pos + 1).map(|t| &t.tok)) {
            (Some(Tok::Word(word)), Some(Tok::Word(next)))
                if word.eq_ignore_ascii_case("CONNECTED") =>
            {
                next.eq_ignore_ascii_case("TO")
            }
            (Some(Tok::Word(word)), Some(Tok::Word(next)))
                if word.eq_ignore_ascii_case("DIRECTION") =>
            {
                matches!(next.to_ascii_uppercase().as_str(), "OUT" | "IN" | "ANY")
            }
            (Some(Tok::Word(word)), Some(Tok::Word(next)))
                if word.eq_ignore_ascii_case("ALLOW") =>
            {
                next.eq_ignore_ascii_case("DEGRADED")
            }
            (Some(Tok::Word(word)), Some(Tok::Num(_))) if word.eq_ignore_ascii_case("WITHIN") => {
                true
            }
            (Some(Tok::Word(word)), Some(Tok::Word(next))) if word.eq_ignore_ascii_case("VIA") => {
                !matches!(
                    next.to_ascii_uppercase().as_str(),
                    "NEAR" | "TEXT" | "WHERE" | "LIMIT" | "WITH" | "FUSION"
                )
            }
            _ => false,
        };
        if graph_clause {
            None
        } else {
            self.parse_optional_collection()
        }
    }

    fn parse_search(&mut self) -> ParseResult<Statement> {
        let mut search = Search {
            collection: self.parse_optional_search_collection(),
            ..Search::default()
        };
        let mut graph_direction_seen = false;
        let mut graph_depth_seen = false;

        while let Some(Tok::Word(word)) = self.peek().cloned() {
            let at = self.at();
            let upper = word.to_ascii_uppercase();
            match upper.as_str() {
                "NEAR" => {
                    self.pos += 1;
                    if search.vector.is_some() {
                        return Err(duplicate_clause("NEAR", at));
                    }
                    search.vector = Some(self.parse_vector_expr()?);
                }
                "USING" => {
                    self.pos += 1;
                    if self.surface == LanguageSurface::GraphV1_1 && search.vector_name.is_some() {
                        return Err(duplicate_clause("USING", at));
                    }
                    search.vector_name = Some(self.expect_word()?);
                }
                "WHERE" => {
                    self.pos += 1;
                    if self.surface == LanguageSurface::GraphV1_1 && search.filter.is_some() {
                        return Err(duplicate_clause("WHERE", at));
                    }
                    search.filter = Some(self.parse_filter()?);
                }
                "LIMIT" => {
                    self.pos += 1;
                    if self.surface == LanguageSurface::GraphV1_1 && search.limit.is_some() {
                        return Err(duplicate_clause("LIMIT", at));
                    }
                    search.limit = Some(self.expect_usize()?);
                }
                "WITH" => {
                    self.pos += 1;
                    if self.surface == LanguageSurface::GraphV1_1 && search.with_payload.is_some() {
                        return Err(duplicate_clause("WITH PAYLOAD", at));
                    }
                    self.expect_keyword("PAYLOAD")?;
                    search.with_payload = Some(true);
                }
                "EF" => {
                    self.pos += 1;
                    if self.surface == LanguageSurface::GraphV1_1 && search.ef_search.is_some() {
                        return Err(duplicate_clause("EF", at));
                    }
                    search.ef_search = Some(self.expect_usize()? as u32);
                }
                "RECALL" => {
                    self.pos += 1;
                    if self.surface == LanguageSurface::GraphV1_1 && search.recall_target.is_some()
                    {
                        return Err(duplicate_clause("RECALL", at));
                    }
                    let value = self.expect_number()? as f32;
                    if !(0.0..=1.0).contains(&value) {
                        return Err(ParseError::new(
                            "chironql.invalid_recall",
                            format!("RECALL must be between 0.0 and 1.0, found {value}"),
                            at,
                        ));
                    }
                    search.recall_target = Some(value);
                }
                "BUDGET" => {
                    self.pos += 1;
                    if self.surface == LanguageSurface::GraphV1_1 && search.budget_ms.is_some() {
                        return Err(duplicate_clause("BUDGET", at));
                    }
                    search.budget_ms = Some(self.expect_usize()? as u64);
                }
                "CONNECTED" if self.surface == LanguageSurface::GraphV1_1 => {
                    self.pos += 1;
                    self.expect_keyword("TO")?;
                    let anchors = self.parse_anchor_list()?;
                    let graph = search.graph.get_or_insert_with(GraphClause::default);
                    if !graph.anchors.is_empty() {
                        return Err(duplicate_clause("CONNECTED TO", at));
                    }
                    graph.anchors = anchors;
                }
                "VIA" if self.surface == LanguageSurface::GraphV1_1 => {
                    self.pos += 1;
                    let edge_types = self.parse_type_list()?;
                    let graph = search.graph.get_or_insert_with(GraphClause::default);
                    if !graph.edge_types.is_empty() {
                        return Err(duplicate_clause("VIA", at));
                    }
                    graph.edge_types = edge_types;
                }
                "DIRECTION" if self.surface == LanguageSurface::GraphV1_1 => {
                    self.pos += 1;
                    if graph_direction_seen {
                        return Err(duplicate_clause("DIRECTION", at));
                    }
                    graph_direction_seen = true;
                    search
                        .graph
                        .get_or_insert_with(GraphClause::default)
                        .direction = self.parse_graph_direction()?;
                }
                "WITHIN" if self.surface == LanguageSurface::GraphV1_1 => {
                    self.pos += 1;
                    if graph_depth_seen {
                        return Err(duplicate_clause("WITHIN", at));
                    }
                    graph_depth_seen = true;
                    let depth = self.parse_graph_depth()?;
                    self.expect_keyword("HOPS")?;
                    search
                        .graph
                        .get_or_insert_with(GraphClause::default)
                        .within_hops = depth;
                }
                "ALLOW" if self.surface == LanguageSurface::GraphV1_1 => {
                    self.pos += 1;
                    self.expect_keyword("DEGRADED")?;
                    let graph = search.graph.get_or_insert_with(GraphClause::default);
                    if graph.allow_degraded {
                        return Err(duplicate_clause("ALLOW DEGRADED", at));
                    }
                    graph.allow_degraded = true;
                }
                _ => break,
            }
        }

        if search.vector.is_none() {
            return Err(ParseError::with_hint(
                "chironql.missing_near",
                "SEARCH needs a NEAR clause",
                "SEARCH products NEAR [1,0,0] LIMIT 10;",
                self.at(),
            ));
        }
        validate_graph_clause(search.graph.as_ref(), self.at())?;
        Ok(Statement::Search(search))
    }

    fn parse_hybrid(&mut self) -> ParseResult<Statement> {
        let mut hybrid = Hybrid {
            collection: self.parse_optional_search_collection(),
            ..Hybrid::default()
        };
        let mut graph_direction_seen = false;
        let mut graph_depth_seen = false;

        while let Some(Tok::Word(word)) = self.peek().cloned() {
            let at = self.at();
            match word.to_ascii_uppercase().as_str() {
                "NEAR" => {
                    self.pos += 1;
                    if self.surface == LanguageSurface::GraphV1_1 && hybrid.vector.is_some() {
                        return Err(duplicate_clause("NEAR", at));
                    }
                    hybrid.vector = Some(self.parse_vector_expr()?);
                }
                "USING" => {
                    self.pos += 1;
                    if self.surface == LanguageSurface::GraphV1_1 && hybrid.vector_name.is_some() {
                        return Err(duplicate_clause("USING", at));
                    }
                    hybrid.vector_name = Some(self.expect_word()?);
                }
                "TEXT" => {
                    self.pos += 1;
                    if self.surface == LanguageSurface::GraphV1_1 && hybrid.sparse.is_some() {
                        return Err(duplicate_clause("TEXT", at));
                    }
                    hybrid.sparse = Some(self.parse_sparse_vector()?);
                }
                "FUSION" => {
                    self.pos += 1;
                    if self.surface == LanguageSurface::GraphV1_1 && hybrid.fusion.is_some() {
                        return Err(duplicate_clause("FUSION", at));
                    }
                    hybrid.fusion = Some(self.parse_fusion()?);
                }
                "DENSE" => {
                    self.pos += 1;
                    if self.surface == LanguageSurface::GraphV1_1 && hybrid.dense_weight.is_some() {
                        return Err(duplicate_clause("DENSE/WEIGHTS", at));
                    }
                    hybrid.dense_weight = Some(self.expect_number()? as f32);
                }
                "SPARSE" => {
                    self.pos += 1;
                    if self.surface == LanguageSurface::GraphV1_1 && hybrid.sparse_weight.is_some()
                    {
                        return Err(duplicate_clause("SPARSE/WEIGHTS", at));
                    }
                    hybrid.sparse_weight = Some(self.expect_number()? as f32);
                }
                "WEIGHTS" if self.surface == LanguageSurface::GraphV1_1 => {
                    self.pos += 1;
                    if hybrid.dense_weight.is_some() || hybrid.sparse_weight.is_some() {
                        return Err(duplicate_clause("WEIGHTS", at));
                    }
                    hybrid.dense_weight = Some(self.expect_number()? as f32);
                    hybrid.sparse_weight = Some(self.expect_number()? as f32);
                }
                "WHERE" => {
                    self.pos += 1;
                    if self.surface == LanguageSurface::GraphV1_1 && hybrid.filter.is_some() {
                        return Err(duplicate_clause("WHERE", at));
                    }
                    hybrid.filter = Some(self.parse_filter()?);
                }
                "LIMIT" => {
                    self.pos += 1;
                    if self.surface == LanguageSurface::GraphV1_1 && hybrid.limit.is_some() {
                        return Err(duplicate_clause("LIMIT", at));
                    }
                    hybrid.limit = Some(self.expect_usize()?);
                }
                "WITH" if self.surface == LanguageSurface::GraphV1_1 => {
                    self.pos += 1;
                    if hybrid.with_payload.is_some() {
                        return Err(duplicate_clause("WITH PAYLOAD", at));
                    }
                    self.expect_keyword("PAYLOAD")?;
                    hybrid.with_payload = Some(true);
                }
                "CONNECTED" if self.surface == LanguageSurface::GraphV1_1 => {
                    self.pos += 1;
                    self.expect_keyword("TO")?;
                    let anchors = self.parse_anchor_list()?;
                    let graph = hybrid.graph.get_or_insert_with(GraphClause::default);
                    if !graph.anchors.is_empty() {
                        return Err(duplicate_clause("CONNECTED TO", at));
                    }
                    graph.anchors = anchors;
                }
                "VIA" if self.surface == LanguageSurface::GraphV1_1 => {
                    self.pos += 1;
                    let edge_types = self.parse_type_list()?;
                    let graph = hybrid.graph.get_or_insert_with(GraphClause::default);
                    if !graph.edge_types.is_empty() {
                        return Err(duplicate_clause("VIA", at));
                    }
                    graph.edge_types = edge_types;
                }
                "DIRECTION" if self.surface == LanguageSurface::GraphV1_1 => {
                    self.pos += 1;
                    if graph_direction_seen {
                        return Err(duplicate_clause("DIRECTION", at));
                    }
                    graph_direction_seen = true;
                    hybrid
                        .graph
                        .get_or_insert_with(GraphClause::default)
                        .direction = self.parse_graph_direction()?;
                }
                "WITHIN" if self.surface == LanguageSurface::GraphV1_1 => {
                    self.pos += 1;
                    if graph_depth_seen {
                        return Err(duplicate_clause("WITHIN", at));
                    }
                    graph_depth_seen = true;
                    let depth = self.parse_graph_depth()?;
                    self.expect_keyword("HOPS")?;
                    hybrid
                        .graph
                        .get_or_insert_with(GraphClause::default)
                        .within_hops = depth;
                }
                "ALLOW" if self.surface == LanguageSurface::GraphV1_1 => {
                    self.pos += 1;
                    self.expect_keyword("DEGRADED")?;
                    let graph = hybrid.graph.get_or_insert_with(GraphClause::default);
                    if graph.allow_degraded {
                        return Err(duplicate_clause("ALLOW DEGRADED", at));
                    }
                    graph.allow_degraded = true;
                }
                _ => break,
            }
        }

        if hybrid.vector.is_none() && hybrid.sparse.is_none() {
            return Err(ParseError::with_hint(
                "chironql.missing_hybrid_operand",
                "HYBRID needs at least one of NEAR or TEXT",
                "HYBRID docs NEAR [1,0,0] TEXT {12:1.2} FUSION rrf LIMIT 5;",
                self.at(),
            ));
        }
        validate_graph_clause(hybrid.graph.as_ref(), self.at())?;
        Ok(Statement::Hybrid(hybrid))
    }

    fn parse_multi(&mut self) -> ParseResult<Statement> {
        let mut multi = Multi {
            collection: self.parse_optional_collection(),
            ..Multi::default()
        };

        // One or more `NEAR <vec>`, comma separated.
        loop {
            self.expect_keyword("NEAR")?;
            multi.vectors.push(self.parse_vector_expr()?);
            if !self.eat(&Tok::Comma) {
                break;
            }
        }

        while let Some(Tok::Word(word)) = self.peek().cloned() {
            match word.to_ascii_uppercase().as_str() {
                "FUSION" => {
                    self.pos += 1;
                    multi.fusion = Some(self.parse_fusion()?);
                }
                "WEIGHTS" => {
                    self.pos += 1;
                    loop {
                        multi.weights.push(self.expect_number()? as f32);
                        if !self.eat(&Tok::Comma) {
                            break;
                        }
                    }
                }
                "WHERE" => {
                    self.pos += 1;
                    multi.filter = Some(self.parse_filter()?);
                }
                "LIMIT" => {
                    self.pos += 1;
                    multi.limit = Some(self.expect_usize()?);
                }
                _ => break,
            }
        }

        if !multi.weights.is_empty() && multi.weights.len() != multi.vectors.len() {
            return Err(ParseError::new(
                "chironql.weight_arity",
                format!(
                    "WEIGHTS has {} values but there are {} NEAR clauses",
                    multi.weights.len(),
                    multi.vectors.len()
                ),
                self.at(),
            ));
        }
        Ok(Statement::Multi(multi))
    }

    fn parse_recommend(&mut self) -> ParseResult<Statement> {
        let mut recommend = Recommend {
            collection: self.parse_optional_collection(),
            ..Recommend::default()
        };

        while let Some(Tok::Word(word)) = self.peek().cloned() {
            match word.to_ascii_uppercase().as_str() {
                "LIKE" => {
                    self.pos += 1;
                    recommend.positive.extend(self.parse_id_list()?);
                }
                "UNLIKE" => {
                    self.pos += 1;
                    recommend.negative.extend(self.parse_id_list()?);
                }
                "USING" => {
                    self.pos += 1;
                    recommend.vector_name = Some(self.expect_word()?);
                }
                "WHERE" => {
                    self.pos += 1;
                    recommend.filter = Some(self.parse_filter()?);
                }
                "LIMIT" => {
                    self.pos += 1;
                    recommend.limit = Some(self.expect_usize()?);
                }
                _ => break,
            }
        }

        if recommend.positive.is_empty() {
            return Err(ParseError::with_hint(
                "chironql.missing_like",
                "RECOMMEND needs at least one LIKE id",
                "RECOMMEND products LIKE phone UNLIKE book LIMIT 5;",
                self.at(),
            ));
        }
        Ok(Statement::Recommend(recommend))
    }

    fn parse_count(&mut self) -> ParseResult<Statement> {
        let at = self.at();
        // `COUNT(*)` is a SQL habit; answer it specifically.
        if self.peek() == Some(&Tok::LBracket) {
            return Err(ParseError::with_hint(
                "chironql.no_aggregates",
                "ChironQL has no aggregate functions",
                "Count a collection directly: COUNT products WHERE category = 'a';",
                at,
            ));
        }
        let mut count = Count {
            collection: self.parse_optional_collection(),
            filter: None,
        };
        if self.eat_keyword("WHERE") {
            count.filter = Some(self.parse_filter()?);
        }
        self.reject_group_by()?;
        Ok(Statement::Count(count))
    }

    fn parse_scroll(&mut self) -> ParseResult<Statement> {
        let mut scroll = Scroll {
            collection: self.parse_optional_collection(),
            ..Scroll::default()
        };
        while let Some(Tok::Word(word)) = self.peek().cloned() {
            match word.to_ascii_uppercase().as_str() {
                "WHERE" => {
                    self.pos += 1;
                    scroll.filter = Some(self.parse_filter()?);
                }
                "LIMIT" => {
                    self.pos += 1;
                    scroll.limit = Some(self.expect_usize()?);
                }
                "AFTER" => {
                    self.pos += 1;
                    scroll.after = Some(self.expect_id()?);
                }
                _ => break,
            }
        }
        Ok(Statement::Scroll(scroll))
    }

    fn parse_get(&mut self) -> ParseResult<Statement> {
        let collection = self.parse_optional_collection();
        self.expect_keyword("POINTS")?;
        let ids = self.parse_id_list()?;
        Ok(Statement::Get(Get { collection, ids }))
    }

    fn parse_upsert(&mut self) -> ParseResult<Statement> {
        self.expect_keyword("INTO")?;
        let collection = self.parse_optional_collection();
        let mut points = Vec::new();
        loop {
            let at = self.at();
            let value = self.parse_json_value()?;
            if !value.is_object() {
                return Err(ParseError::with_hint(
                    "chironql.invalid_point",
                    "a point must be an object",
                    "UPSERT INTO products {id: 'phone', vector: [1,0,0]};",
                    at,
                ));
            }
            if value.get("id").is_none() {
                return Err(ParseError::with_hint(
                    "chironql.missing_point_id",
                    "a point needs an `id`",
                    "UPSERT INTO products {id: 'phone', vector: [1,0,0]};",
                    at,
                ));
            }
            points.push(value);
            if !self.eat(&Tok::Comma) {
                break;
            }
        }
        let mut wait = true;
        if self.eat_keyword("NO") {
            self.expect_keyword("WAIT")?;
            wait = false;
        }
        Ok(Statement::Upsert(Upsert {
            collection,
            points,
            wait,
        }))
    }

    fn parse_delete(&mut self) -> ParseResult<Statement> {
        self.expect_keyword("FROM")?;
        let collection = self.parse_optional_collection();
        if self.eat_keyword("POINTS") {
            let ids = self.parse_id_list()?;
            return Ok(Statement::DeletePoints { collection, ids });
        }
        if self.eat_keyword("WHERE") {
            let filter = self.parse_filter()?;
            return Ok(Statement::DeleteWhere { collection, filter });
        }
        Err(ParseError::with_hint(
            "chironql.unbounded_delete",
            "DELETE needs POINTS or WHERE",
            "Deleting a whole collection is an admin operation: use `chironctl`.",
            self.at(),
        ))
    }

    fn parse_relate(&mut self) -> ParseResult<Statement> {
        let collection = self.expect_word()?;
        let source_id = self.expect_id()?;
        self.expect(&Tok::Arrow)?;
        let edge_type = self.expect_word()?;
        self.expect(&Tok::Arrow)?;
        let target_id = self.expect_id()?;
        let mut properties = Value::Object(Map::new());
        let mut properties_seen = false;
        let mut idempotency_key = None;
        let mut deferred_endpoints = false;
        let mut wait = true;
        let mut wait_seen = false;

        while let Some(Tok::Word(word)) = self.peek().cloned() {
            let at = self.at();
            match word.to_ascii_uppercase().as_str() {
                "SET" => {
                    self.pos += 1;
                    if properties_seen {
                        return Err(duplicate_clause("SET", at));
                    }
                    properties_seen = true;
                    properties = self.parse_property_document()?;
                }
                "IDEMPOTENCY" => {
                    self.pos += 1;
                    if idempotency_key.is_some() {
                        return Err(duplicate_clause("IDEMPOTENCY KEY", at));
                    }
                    self.expect_keyword("KEY")?;
                    idempotency_key = Some(self.expect_string()?);
                }
                "WITH" => {
                    self.pos += 1;
                    if deferred_endpoints {
                        return Err(duplicate_clause("WITH DEFERRED ENDPOINTS", at));
                    }
                    self.expect_keyword("DEFERRED")?;
                    self.expect_keyword("ENDPOINTS")?;
                    deferred_endpoints = true;
                }
                "NO" => {
                    self.pos += 1;
                    if wait_seen {
                        return Err(duplicate_clause("NO WAIT", at));
                    }
                    self.expect_keyword("WAIT")?;
                    wait_seen = true;
                    wait = false;
                }
                _ => break,
            }
        }

        Ok(Statement::Relate(Relate {
            collection,
            source_id,
            edge_type,
            target_id,
            properties,
            idempotency_key,
            deferred_endpoints,
            wait,
        }))
    }

    fn parse_unrelate(&mut self) -> ParseResult<Statement> {
        let collection = self.expect_word()?;
        self.expect_keyword("EDGE")?;
        let edge_ids = self.parse_edge_id_list()?;
        let wait = !self.eat_no_wait()?;
        Ok(Statement::Unrelate(Unrelate {
            collection,
            edge_ids,
            wait,
        }))
    }

    fn parse_traverse(&mut self) -> ParseResult<Statement> {
        let collection = self.expect_word()?;
        self.expect_keyword("FROM")?;
        let anchors = self.parse_anchor_list()?;
        let mut traverse = Traverse {
            collection,
            anchors,
            edge_types: Vec::new(),
            direction: GraphDirection::Outgoing,
            depth: 1,
            node_filter: None,
            edge_filter: None,
            budget_ms: None,
            limit: None,
            with_payload: false,
            returns: GraphReturn::Nodes,
        };
        let mut direction_seen = false;
        let mut depth_seen = false;
        let mut return_seen = false;

        while let Some(Tok::Word(word)) = self.peek().cloned() {
            let at = self.at();
            match word.to_ascii_uppercase().as_str() {
                "VIA" => {
                    self.pos += 1;
                    if !traverse.edge_types.is_empty() {
                        return Err(duplicate_clause("VIA", at));
                    }
                    traverse.edge_types = self.parse_type_list()?;
                }
                "DIRECTION" => {
                    self.pos += 1;
                    if direction_seen {
                        return Err(duplicate_clause("DIRECTION", at));
                    }
                    direction_seen = true;
                    traverse.direction = self.parse_graph_direction()?;
                }
                "DEPTH" => {
                    self.pos += 1;
                    if depth_seen {
                        return Err(duplicate_clause("DEPTH", at));
                    }
                    depth_seen = true;
                    traverse.depth = self.parse_graph_depth()?;
                }
                "WHERE" => {
                    self.pos += 1;
                    if traverse.node_filter.is_some() {
                        return Err(duplicate_clause("WHERE", at));
                    }
                    traverse.node_filter = Some(self.parse_filter()?);
                }
                "EDGE" => {
                    self.pos += 1;
                    self.expect_keyword("WHERE")?;
                    if traverse.edge_filter.is_some() {
                        return Err(duplicate_clause("EDGE WHERE", at));
                    }
                    traverse.edge_filter = Some(self.parse_filter()?);
                }
                "BUDGET" => {
                    self.pos += 1;
                    if traverse.budget_ms.is_some() {
                        return Err(duplicate_clause("BUDGET", at));
                    }
                    traverse.budget_ms = Some(self.expect_usize()? as u64);
                    self.expect_keyword("MS")?;
                }
                "LIMIT" => {
                    self.pos += 1;
                    if traverse.limit.is_some() {
                        return Err(duplicate_clause("LIMIT", at));
                    }
                    traverse.limit = Some(self.expect_usize()?);
                }
                "WITH" => {
                    self.pos += 1;
                    if traverse.with_payload {
                        return Err(duplicate_clause("WITH PAYLOAD", at));
                    }
                    self.expect_keyword("PAYLOAD")?;
                    traverse.with_payload = true;
                }
                "RETURN" => {
                    self.pos += 1;
                    if return_seen {
                        return Err(duplicate_clause("RETURN", at));
                    }
                    return_seen = true;
                    traverse.returns = self.parse_graph_return()?;
                }
                _ => break,
            }
        }

        if traverse.returns == GraphReturn::Paths && traverse.limit.is_none() {
            return Err(ParseError::with_hint(
                "chironql.paths_limit_required",
                "RETURN PATHS requires LIMIT",
                "Simple-path enumeration must be bounded: RETURN PATHS LIMIT <n>.",
                self.at(),
            ));
        }
        Ok(Statement::Traverse(traverse))
    }

    fn parse_update(&mut self) -> ParseResult<Statement> {
        let collection = self.parse_optional_collection();
        if self.surface == LanguageSurface::GraphV1_1 && self.eat_keyword("EDGE") {
            let collection = collection.ok_or_else(|| {
                ParseError::new(
                    "chironql.missing_collection",
                    "UPDATE EDGE requires a collection",
                    self.at(),
                )
            })?;
            let edge_id = self.expect_id()?;
            self.expect_keyword("SET")?;
            self.expect_keyword("PROPERTIES")?;
            let properties = self.parse_property_document()?;
            let replace = self.eat_keyword("REPLACE");
            let wait = !self.eat_no_wait()?;
            return Ok(Statement::UpdateEdge(UpdateEdge {
                collection,
                edge_id,
                properties,
                replace,
                wait,
            }));
        }
        self.expect_keyword("POINT")?;
        let id = self.expect_id()?;
        self.expect_keyword("SET")?;
        self.expect_keyword("PAYLOAD")?;
        let at = self.at();
        let payload = self.parse_json_value()?;
        if !payload.is_object() {
            return Err(ParseError::new(
                "chironql.invalid_payload",
                "SET PAYLOAD needs an object",
                at,
            ));
        }
        let replace = self.eat_keyword("REPLACE");
        Ok(Statement::UpdatePayload(UpdatePayload {
            collection,
            id,
            payload,
            replace,
        }))
    }

    /// `CREATE COLLECTION <name> DIM <n> [METRIC cosine|l2|dot] [WITH {…}]`.
    ///
    /// `CREATE INDEX` and `CREATE TABLE` still land in the reject taxonomy:
    /// LS-VEC is the sole index path and there are no tables, so both get a
    /// specific answer rather than a parse error about `COLLECTION`.
    fn parse_create(&mut self) -> ParseResult<Statement> {
        let at = self.at();
        if !self.eat_keyword("COLLECTION") {
            return Err(ParseError::with_hint(
                "chironql.no_ddl",
                "CREATE applies to collections",
                "CREATE COLLECTION <name> DIM <n> [METRIC cosine|l2|dot] [WITH {…}];",
                at,
            ));
        }
        let name = self.expect_word()?;

        let dim_at = self.at();
        if !self.eat_keyword("DIM") {
            return Err(ParseError::with_hint(
                "chironql.missing_dim",
                "CREATE COLLECTION needs DIM",
                "A collection's vector dimension is fixed when it is created: \
                 CREATE COLLECTION products DIM 768;",
                dim_at,
            ));
        }
        let dim = self.expect_usize()?;

        let mut metric = None;
        let mut options = None;
        loop {
            let clause_at = self.at();
            if self.eat_keyword("METRIC") {
                if metric.is_some() {
                    return Err(duplicate_clause("METRIC", clause_at));
                }
                metric = Some(self.parse_metric()?);
                continue;
            }
            if self.eat_keyword("WITH") {
                if options.is_some() {
                    return Err(duplicate_clause("WITH", clause_at));
                }
                let value = self.parse_json_value()?;
                if !value.is_object() {
                    return Err(ParseError::with_hint(
                        "chironql.invalid_collection_options",
                        "WITH needs an object",
                        "WITH {shards: 2, quantization: 'sq8'} — DESCRIBE names the fields.",
                        clause_at,
                    ));
                }
                options = Some(value);
                continue;
            }
            break;
        }

        Ok(Statement::CreateCollection(CreateCollection {
            name,
            dim,
            metric,
            options,
        }))
    }

    /// `DROP COLLECTION <name> [IF EXISTS]`.
    ///
    /// `IF EXISTS` is accepted on either side of the name: SQL puts it before,
    /// and refusing the habit teaches nobody anything.
    fn parse_drop(&mut self) -> ParseResult<Statement> {
        let at = self.at();
        if !self.eat_keyword("COLLECTION") {
            return Err(ParseError::with_hint(
                "chironql.no_ddl",
                "DROP applies to collections",
                "DROP COLLECTION <name> [IF EXISTS]; — there are no tables or indexes here.",
                at,
            ));
        }
        let mut if_exists = self.eat_if_exists()?;
        let collection = self.expect_word()?;
        if !if_exists {
            if_exists = self.eat_if_exists()?;
        }
        Ok(Statement::DropCollection {
            collection,
            if_exists,
        })
    }

    fn eat_if_exists(&mut self) -> ParseResult<bool> {
        if !self.eat_keyword("IF") {
            return Ok(false);
        }
        self.expect_keyword("EXISTS")?;
        Ok(true)
    }

    // -- clause pieces ------------------------------------------------------

    fn parse_id_list(&mut self) -> ParseResult<Vec<String>> {
        let mut ids = vec![self.expect_id()?];
        while self.eat(&Tok::Comma) {
            ids.push(self.expect_id()?);
        }
        Ok(ids)
    }

    fn parse_anchor_list(&mut self) -> ParseResult<Vec<String>> {
        let at = self.at();
        let anchors = self.parse_id_list()?;
        if anchors.len() > MAX_GRAPH_ANCHORS {
            return Err(ParseError::new(
                "graph.too_many_anchors",
                format!(
                    "{} anchors exceed the fixed maximum {MAX_GRAPH_ANCHORS}",
                    anchors.len()
                ),
                at,
            ));
        }
        Ok(anchors)
    }

    fn parse_type_list(&mut self) -> ParseResult<Vec<String>> {
        let at = self.at();
        let mut edge_types = vec![self.expect_word()?];
        while self.eat(&Tok::Comma) {
            edge_types.push(self.expect_word()?);
        }
        if edge_types.len() > MAX_GRAPH_TYPES_PER_CLAUSE {
            return Err(ParseError::new(
                "graph.too_many_types",
                format!(
                    "{} edge types exceed the fixed maximum {MAX_GRAPH_TYPES_PER_CLAUSE}",
                    edge_types.len()
                ),
                at,
            ));
        }
        Ok(edge_types)
    }

    fn parse_edge_id_list(&mut self) -> ParseResult<Vec<String>> {
        let at = self.at();
        let edge_ids = self.parse_id_list()?;
        if edge_ids.len() > MAX_GRAPH_EDGES_PER_BATCH {
            return Err(ParseError::new(
                "graph.batch_too_large",
                format!(
                    "{} edges exceed the fixed batch maximum {MAX_GRAPH_EDGES_PER_BATCH}",
                    edge_ids.len()
                ),
                at,
            ));
        }
        Ok(edge_ids)
    }

    fn parse_graph_direction(&mut self) -> ParseResult<GraphDirection> {
        let at = self.at();
        let direction = self.expect_word()?;
        match direction.to_ascii_uppercase().as_str() {
            "OUT" => Ok(GraphDirection::Outgoing),
            "IN" => Ok(GraphDirection::Incoming),
            "ANY" => Ok(GraphDirection::Both),
            _ => Err(ParseError::with_hint(
                "chironql.invalid_direction",
                format!("`{direction}` is not a graph direction"),
                "Directions: OUT, IN, ANY.",
                at,
            )),
        }
    }

    fn parse_graph_depth(&mut self) -> ParseResult<u32> {
        let at = self.at();
        let depth = self.expect_usize()?;
        if depth > MAX_GRAPH_DEPTH as usize {
            return Err(ParseError::new(
                "graph.depth_exceeded",
                format!("depth {depth} exceeds the fixed maximum {MAX_GRAPH_DEPTH}"),
                at,
            ));
        }
        Ok(depth as u32)
    }

    fn parse_graph_return(&mut self) -> ParseResult<GraphReturn> {
        let at = self.at();
        let returns = self.expect_word()?;
        match returns.to_ascii_uppercase().as_str() {
            "NODES" => Ok(GraphReturn::Nodes),
            "EDGES" => Ok(GraphReturn::Edges),
            "PATHS" => Ok(GraphReturn::Paths),
            "WALKS" => Err(ParseError::with_hint(
                "chironql.walks_unsupported",
                "ChironQL does not enumerate walks",
                "Use RETURN PATHS with LIMIT for bounded simple paths.",
                at,
            )),
            _ => Err(ParseError::with_hint(
                "chironql.unsupported_path_pattern",
                format!("`{returns}` is not a supported traversal return shape"),
                "RETURN NODES, RETURN EDGES, or RETURN PATHS with LIMIT.",
                at,
            )),
        }
    }

    fn parse_property_document(&mut self) -> ParseResult<Value> {
        let at = self.at();
        let properties = self.parse_json_value()?;
        if !properties.is_object() {
            return Err(ParseError::new(
                "chironql.invalid_edge_properties",
                "edge properties must be an object",
                at,
            ));
        }
        let encoded_len = serde_json::to_vec(&properties)
            .map_err(|_| {
                ParseError::new(
                    "chironql.invalid_edge_properties",
                    "edge properties could not be encoded",
                    at,
                )
            })?
            .len();
        if encoded_len > MAX_EDGE_PROPERTY_BYTES {
            return Err(ParseError::new(
                "graph.property_too_large",
                format!(
                    "edge properties encode to {encoded_len} bytes, exceeding the fixed maximum {MAX_EDGE_PROPERTY_BYTES}"
                ),
                at,
            ));
        }
        Ok(properties)
    }

    fn eat_no_wait(&mut self) -> ParseResult<bool> {
        if !self.eat_keyword("NO") {
            return Ok(false);
        }
        self.expect_keyword("WAIT")?;
        Ok(true)
    }

    fn parse_metric(&mut self) -> ParseResult<DistanceMetric> {
        let at = self.at();
        let word = self.expect_word()?;
        // The three names `DistanceMetric` serializes as, and no aliases: a
        // metric typed here must read back identically from DESCRIBE.
        match word.to_ascii_lowercase().as_str() {
            "cosine" => Ok(DistanceMetric::Cosine),
            "l2" => Ok(DistanceMetric::L2),
            "dot" => Ok(DistanceMetric::Dot),
            other => Err(ParseError::with_hint(
                "chironql.unknown_metric",
                format!("`{other}` is not a distance metric"),
                "Metrics: cosine, l2, dot.",
                at,
            )),
        }
    }

    fn parse_fusion(&mut self) -> ParseResult<HybridFusion> {
        let at = self.at();
        let word = self.expect_word()?;
        match word.to_ascii_lowercase().as_str() {
            "rrf" => Ok(HybridFusion::Rrf),
            "weighted" => Ok(HybridFusion::Weighted),
            other => Err(ParseError::new(
                "chironql.unknown_fusion",
                format!("unknown fusion `{other}` — expected `rrf` or `weighted`"),
                at,
            )),
        }
    }

    fn parse_vector_expr(&mut self) -> ParseResult<VectorExpr> {
        let at = self.at();
        if self.eat(&Tok::At) {
            let id = self.expect_id()?;
            let vector_name = if self.eat_keyword("USING") {
                Some(self.expect_word()?)
            } else {
                None
            };
            return Ok(VectorExpr::Point { id, vector_name });
        }
        if self.peek() == Some(&Tok::LBracket) {
            let values = self.parse_float_array()?;
            if values.is_empty() {
                return Err(ParseError::new(
                    "chironql.empty_vector",
                    "a vector literal needs at least one component",
                    at,
                ));
            }
            return Ok(VectorExpr::Literal(values));
        }
        Err(ParseError::with_hint(
            "chironql.invalid_vector",
            "expected a vector literal or a point reference",
            "Either NEAR [1,0,0] or NEAR @point_id.",
            at,
        ))
    }

    fn parse_float_array(&mut self) -> ParseResult<Vec<f32>> {
        self.expect(&Tok::LBracket)?;
        let mut values = Vec::new();
        if self.eat(&Tok::RBracket) {
            return Ok(values);
        }
        loop {
            values.push(self.expect_number()? as f32);
            if self.eat(&Tok::Comma) {
                continue;
            }
            self.expect(&Tok::RBracket)?;
            break;
        }
        Ok(values)
    }

    /// `{12: 1.2, 98: 0.7}` — index → weight.
    fn parse_sparse_vector(&mut self) -> ParseResult<SparseVector> {
        let at = self.at();
        self.expect(&Tok::LBrace)?;
        let mut indices = Vec::new();
        let mut values = Vec::new();
        if self.eat(&Tok::RBrace) {
            return Err(ParseError::new(
                "chironql.empty_sparse_vector",
                "a sparse vector needs at least one index",
                at,
            ));
        }
        loop {
            let index_at = self.at();
            let index = self.expect_number()?;
            if index < 0.0 || index.fract() != 0.0 {
                return Err(ParseError::new(
                    "chironql.invalid_sparse_index",
                    format!("sparse indices must be non-negative whole numbers, found {index}"),
                    index_at,
                ));
            }
            self.expect(&Tok::Colon)?;
            indices.push(index as u32);
            values.push(self.expect_number()? as f32);
            if self.eat(&Tok::Comma) {
                continue;
            }
            self.expect(&Tok::RBrace)?;
            break;
        }
        Ok(SparseVector { indices, values })
    }

    /// Relaxed JSON: unquoted keys and single-quoted strings are accepted, so
    /// hand-typed points stay typable.
    fn parse_json_value(&mut self) -> ParseResult<Value> {
        let at = self.at();
        match self.peek().cloned() {
            Some(Tok::LBrace) => {
                self.pos += 1;
                let mut map = Map::new();
                if self.eat(&Tok::RBrace) {
                    return Ok(Value::Object(map));
                }
                loop {
                    let key_at = self.at();
                    let key = match self.next() {
                        Some(Token {
                            tok: Tok::Word(word),
                            ..
                        }) => word,
                        Some(Token {
                            tok: Tok::Str(text),
                            ..
                        }) => text,
                        Some(token) => {
                            return Err(ParseError::new(
                                "chironql.invalid_object_key",
                                format!("expected a field name, found {}", token.tok.describe()),
                                token.at,
                            ));
                        }
                        None => {
                            return Err(ParseError::new(
                                "chironql.unexpected_end",
                                "unterminated object",
                                key_at,
                            ));
                        }
                    };
                    self.expect(&Tok::Colon)?;
                    let value = self.parse_json_value()?;
                    map.insert(key, value);
                    if self.eat(&Tok::Comma) {
                        continue;
                    }
                    self.expect(&Tok::RBrace)?;
                    break;
                }
                Ok(Value::Object(map))
            }
            Some(Tok::LBracket) => {
                self.pos += 1;
                let mut items = Vec::new();
                if self.eat(&Tok::RBracket) {
                    return Ok(Value::Array(items));
                }
                loop {
                    items.push(self.parse_json_value()?);
                    if self.eat(&Tok::Comma) {
                        continue;
                    }
                    self.expect(&Tok::RBracket)?;
                    break;
                }
                Ok(Value::Array(items))
            }
            Some(Tok::Str(text)) => {
                self.pos += 1;
                Ok(Value::String(text))
            }
            Some(Tok::Num(value)) => {
                self.pos += 1;
                Ok(json_number(value))
            }
            Some(Tok::Word(word)) => {
                self.pos += 1;
                match word.to_ascii_lowercase().as_str() {
                    "true" => Ok(Value::Bool(true)),
                    "false" => Ok(Value::Bool(false)),
                    "null" => Ok(Value::Null),
                    // A bare word is a string; quoting every payload value by
                    // hand in a REPL is friction with no payoff.
                    _ => Ok(Value::String(word)),
                }
            }
            _ => Err(ParseError::new(
                "chironql.invalid_value",
                "expected a value",
                at,
            )),
        }
    }

    // -- filters ------------------------------------------------------------

    /// Conjunction only. `Filter` is a JSON object whose conditions are
    /// combined with `.all()`, so `OR` across fields has no representation and
    /// is rejected rather than silently mistranslated.
    fn parse_filter(&mut self) -> ParseResult<Filter> {
        let mut object = Map::new();
        loop {
            self.parse_condition(&mut object)?;
            if self.eat_keyword("AND") {
                continue;
            }
            let at = self.at();
            if self.peek_keyword("OR") {
                return Err(ParseError::with_hint(
                    "chironql.no_or_across_fields",
                    "ChironQL filters are conjunctions — there is no OR",
                    "Single-field disjunction is IN: category IN ['a', 'b'].",
                    at,
                ));
            }
            break;
        }
        Ok(Filter(Value::Object(object)))
    }

    fn parse_condition(&mut self, object: &mut Map<String, Value>) -> ParseResult<()> {
        let field_at = self.at();
        let field = self.expect_word()?;

        let op_at = self.at();
        let (op, value) = match self.peek().cloned() {
            Some(Tok::Eq) => {
                self.pos += 1;
                ("eq", self.parse_scalar()?)
            }
            Some(Tok::NotEq) => {
                self.pos += 1;
                ("ne", self.parse_scalar()?)
            }
            Some(Tok::Lt) => {
                self.pos += 1;
                ("lt", self.parse_scalar()?)
            }
            Some(Tok::Lte) => {
                self.pos += 1;
                ("lte", self.parse_scalar()?)
            }
            Some(Tok::Gt) => {
                self.pos += 1;
                ("gt", self.parse_scalar()?)
            }
            Some(Tok::Gte) => {
                self.pos += 1;
                ("gte", self.parse_scalar()?)
            }
            Some(Tok::Word(word)) if word.eq_ignore_ascii_case("IN") => {
                self.pos += 1;
                let mut items = Vec::new();
                self.expect(&Tok::LBracket)?;
                if !self.eat(&Tok::RBracket) {
                    loop {
                        items.push(self.parse_scalar()?);
                        if self.eat(&Tok::Comma) {
                            continue;
                        }
                        self.expect(&Tok::RBracket)?;
                        break;
                    }
                }
                ("in", Value::Array(items))
            }
            Some(Tok::Word(word)) if word.eq_ignore_ascii_case("CONTAINS") => {
                self.pos += 1;
                ("text", self.parse_scalar()?)
            }
            Some(Tok::Word(word)) if word.eq_ignore_ascii_case("LIKE") => {
                return Err(ParseError::with_hint(
                    "chironql.no_like",
                    "ChironQL has no LIKE",
                    "Token intersection is CONTAINS: title CONTAINS 'wireless'.",
                    op_at,
                ));
            }
            _ => {
                let found = self
                    .peek()
                    .map(Tok::describe)
                    .unwrap_or_else(|| "end of input".to_string());
                return Err(ParseError::with_hint(
                    "chironql.invalid_condition",
                    format!("expected a comparison after `{field}`, found {found}"),
                    "Operators: = != < <= > >= IN CONTAINS.",
                    op_at,
                ));
            }
        };

        let entry = object
            .entry(field.clone())
            .or_insert_with(|| Value::Object(Map::new()));
        let Some(conditions) = entry.as_object_mut() else {
            return Err(ParseError::new(
                "chironql.invalid_condition",
                format!("conflicting conditions on `{field}`"),
                field_at,
            ));
        };
        if conditions.contains_key(op) {
            return Err(ParseError::with_hint(
                "chironql.duplicate_condition",
                format!("`{field}` already has a `{op}` condition"),
                "Conditions are combined with AND; two of the same operator on one \
                 field cannot both hold.",
                field_at,
            ));
        }
        conditions.insert(op.to_string(), value);
        Ok(())
    }

    fn parse_scalar(&mut self) -> ParseResult<Value> {
        let at = self.at();
        match self.next() {
            Some(Token {
                tok: Tok::Str(text),
                ..
            }) => Ok(Value::String(text)),
            Some(Token {
                tok: Tok::Num(value),
                ..
            }) => Ok(json_number(value)),
            Some(Token {
                tok: Tok::Word(word),
                ..
            }) => match word.to_ascii_lowercase().as_str() {
                "true" => Ok(Value::Bool(true)),
                "false" => Ok(Value::Bool(false)),
                "null" => Ok(Value::Null),
                _ => Ok(Value::String(word)),
            },
            Some(token) => Err(ParseError::new(
                "chironql.invalid_value",
                format!("expected a value, found {}", token.tok.describe()),
                token.at,
            )),
            None => Err(ParseError::new(
                "chironql.unexpected_end",
                "expected a value, found end of input",
                at,
            )),
        }
    }

    // -- rejects ------------------------------------------------------------

    fn reject_group_by(&mut self) -> ParseResult<()> {
        if self.peek_keyword("GROUP") {
            return Err(ParseError::with_hint(
                "chironql.no_aggregates",
                "ChironQL has no GROUP BY",
                "Aggregate in your application, or query PostgreSQL/pgvector for \
                 relational work.",
                self.at(),
            ));
        }
        Ok(())
    }
}

fn duplicate_clause(clause: &'static str, at: usize) -> ParseError {
    ParseError::new(
        "chironql.duplicate_clause",
        format!("`{clause}` appears more than once"),
        at,
    )
}

fn validate_graph_clause(graph: Option<&GraphClause>, at: usize) -> ParseResult<()> {
    if graph.is_some_and(|graph| graph.anchors.is_empty()) {
        return Err(ParseError::with_hint(
            "chironql.missing_connected_to",
            "graph-constrained retrieval needs CONNECTED TO",
            "SEARCH <collection> NEAR <vector> CONNECTED TO <point-id> ...",
            at,
        ));
    }
    Ok(())
}

/// First bare word in the source, with its offset — skipping whitespace and
/// `--` comments. Used for the pre-lex reject check only.
/// The statement's first word, where it starts, and the word after it —
/// uppercased, or empty. The second word is what separates
/// `CREATE COLLECTION` from `CREATE INDEX`, and that has to be decided before
/// the lexer meets the `(` in `CREATE INDEX ... (embedding)`.
fn leading_keyword(input: &str) -> Option<(String, usize, String)> {
    let (word, at) = leading_keyword_at(input, 0)?;
    let next = leading_keyword_at(input, at + word.len())
        .map(|(word, _)| word.to_ascii_uppercase())
        .unwrap_or_default();
    Some((word, at, next))
}

/// The next bare word at or after `from`, skipping whitespace and comments.
fn leading_keyword_at(input: &str, from: usize) -> Option<(String, usize)> {
    let bytes = input.as_bytes();
    let mut i = from;
    loop {
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i + 1 < bytes.len() && bytes[i] == b'-' && bytes[i + 1] == b'-' {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        break;
    }
    let start = i;
    while i < bytes.len() {
        if bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_' {
            i += 1;
        } else {
            break;
        }
    }
    if i == start {
        return None;
    }
    Some((input[start..i].to_string(), start))
}

/// Statements that exist only so they can be rejected with a specific answer.
///
/// `next` is the following word, uppercased, or empty.
fn reject_leading_keyword(word: &str, next: &str, at: usize) -> Option<ParseError> {
    let upper = word.to_ascii_uppercase();
    if matches!(upper.as_str(), "CREATE" | "DROP") {
        if next == "COLLECTION" {
            return None;
        }
        let hint = if next == "INDEX" {
            "LS-VEC is the sole index path — there is no index family to choose."
        } else {
            "Collections are the only thing ChironQL creates or drops: \
             CREATE COLLECTION <name> DIM <n>; · DROP COLLECTION <name>;"
        };
        return Some(ParseError::with_hint(
            "chironql.no_ddl",
            format!("ChironQL has no {upper} {next}")
                .trim_end()
                .to_string(),
            hint,
            at,
        ));
    }
    let error = match upper.as_str() {
        "SELECT" => ParseError::with_hint(
            "chironql.not_sql",
            "ChironQL is not SQL",
            "Did you mean SEARCH? For SQL, use the pgvector wire on port 7403.",
            at,
        ),
        "INSERT" => ParseError::with_hint(
            "chironql.not_sql",
            "ChironQL is not SQL",
            "Writing points is UPSERT INTO <collection> {…};",
            at,
        ),
        "BEGIN" | "COMMIT" | "ROLLBACK" | "SAVEPOINT" | "START" => ParseError::with_hint(
            "chironql.no_transactions",
            "ChironQL has no multi-statement transactions",
            "Each statement is atomic on its own.",
            at,
        ),
        "ALTER" | "TRUNCATE" => ParseError::with_hint(
            "chironql.no_ddl",
            "ChironQL cannot change a collection in place",
            "A collection's settings are fixed at CREATE COLLECTION. To empty one: \
             DELETE ... WHERE. To rebuild it: DROP COLLECTION then CREATE COLLECTION.",
            at,
        ),
        "EXPLAIN" => ParseError::with_hint(
            "chironql.no_explain",
            "ChironQL has no EXPLAIN",
            "Every query can return its execution trace: \\trace on, or `trace: true`.",
            at,
        ),
        "WITH" => ParseError::with_hint(
            "chironql.no_cte",
            "ChironQL has no CTEs",
            "Run relational queries in PostgreSQL/pgvector.",
            at,
        ),
        _ => return None,
    };
    Some(error)
}

fn reject_graph_leading_keyword(word: &str, at: usize) -> Option<ParseError> {
    let error = match word.to_ascii_uppercase().as_str() {
        "MATCH" => ParseError::with_hint(
            "chironql.unsupported_path_pattern",
            "ChironQL 1.1 has no graph pattern language",
            "Use TRAVERSE FROM for bounded topology reads or CONNECTED TO on SEARCH/HYBRID.",
            at,
        ),
        "SHORTEST" => ParseError::with_hint(
            "chironql.unsupported_shortest_path",
            "ChironQL 1.1 has no shortest-path statement",
            "Use bounded TRAVERSE; shortest-path algorithms are not part of the graph surface.",
            at,
        ),
        "WALK" | "WALKS" => ParseError::with_hint(
            "chironql.walks_unsupported",
            "ChironQL 1.1 does not enumerate walks",
            "Use TRAVERSE ... RETURN PATHS LIMIT <n> for bounded simple paths.",
            at,
        ),
        _ => return None,
    };
    Some(error)
}

/// Words that begin a clause, and therefore cannot be a positional collection
/// name in `VERB <collection>`.
fn is_clause_keyword(word: &str, _surface: LanguageSurface) -> bool {
    const VECTOR_CLAUSES: &[&str] = &[
        "NEAR", "USING", "WHERE", "LIMIT", "WITH", "EF", "RECALL", "BUDGET", "TEXT", "FUSION",
        "DENSE", "SPARSE", "WEIGHTS", "LIKE", "UNLIKE", "AFTER", "POINTS", "POINT", "INTO", "FROM",
        "SET", "PAYLOAD", "REPLACE", "NO", "WAIT", "AND", "OR", "GROUP", "ORDER", "JOIN",
    ];
    VECTOR_CLAUSES
        .iter()
        .any(|clause| clause.eq_ignore_ascii_case(word))
}

fn json_number(value: f64) -> Value {
    if value.fract() == 0.0 && value.abs() < 9.007_199_254_740_992e15 {
        Value::from(value as i64)
    } else {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .unwrap_or(Value::Null)
    }
}

fn format_number(value: f64) -> String {
    if value.fract() == 0.0 {
        format!("{}", value as i64)
    } else {
        format!("{value}")
    }
}

// ---------------------------------------------------------------------------
// Tests — the P0 gate: a golden corpus of valid statements and rejects.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ok(input: &str) -> Statement {
        parse(input).unwrap_or_else(|error| panic!("expected `{input}` to parse: {error}"))
    }

    fn err(input: &str) -> ParseError {
        parse(input).expect_err(&format!("expected `{input}` to be rejected"))
    }

    fn graph_ok(input: &str) -> Statement {
        parse_v1_1(input)
            .unwrap_or_else(|error| panic!("expected graph statement `{input}` to parse: {error}"))
    }

    fn graph_err(input: &str) -> ParseError {
        parse_v1_1(input).expect_err(&format!(
            "expected graph statement `{input}` to be rejected"
        ))
    }

    fn search(input: &str) -> Search {
        match ok(input) {
            Statement::Search(search) => search,
            other => panic!("expected SEARCH, got {other:?}"),
        }
    }

    // -- valid corpus ------------------------------------------------------

    #[test]
    fn search_minimal() {
        let statement = search("SEARCH products NEAR [1,0,0];");
        assert_eq!(statement.collection.as_deref(), Some("products"));
        assert_eq!(
            statement.vector,
            Some(VectorExpr::Literal(vec![1.0, 0.0, 0.0]))
        );
        assert_eq!(statement.limit, None);
    }

    #[test]
    fn search_without_trailing_semicolon() {
        assert!(matches!(
            ok("SEARCH products NEAR [1,0,0]"),
            Statement::Search(_)
        ));
    }

    #[test]
    fn non_ascii_leading_text_returns_an_error_without_slicing_inside_utf8() {
        assert!(parse("SѴC").is_err());
    }

    #[test]
    fn search_uses_session_collection_when_omitted() {
        let statement = search("SEARCH NEAR [1,0,0] LIMIT 5;");
        assert_eq!(statement.collection, None);
        assert_eq!(statement.limit, Some(5));
    }

    #[test]
    fn search_keywords_are_case_insensitive() {
        let statement = search("search products near [1,0,0] limit 3 with payload;");
        assert_eq!(statement.limit, Some(3));
        assert_eq!(statement.with_payload, Some(true));
    }

    #[test]
    fn search_full_clause_set() {
        let statement = search(
            "SEARCH products NEAR [1,0,0] USING image WHERE category = 'electronics' \
             LIMIT 10 WITH PAYLOAD EF 64 RECALL 0.99 BUDGET 50;",
        );
        assert_eq!(statement.vector_name.as_deref(), Some("image"));
        assert_eq!(statement.limit, Some(10));
        assert_eq!(statement.ef_search, Some(64));
        assert_eq!(statement.recall_target, Some(0.99));
        assert_eq!(statement.budget_ms, Some(50));
        assert_eq!(
            statement.filter.map(|filter| filter.0),
            Some(json!({"category": {"eq": "electronics"}}))
        );
    }

    #[test]
    fn search_clauses_may_be_reordered() {
        let statement = search("SEARCH products LIMIT 5 NEAR [1,0,0];");
        assert_eq!(statement.limit, Some(5));
        assert!(statement.vector.is_some());
    }

    #[test]
    fn point_ids_may_contain_hyphens() {
        // `acme-1` and uuids are ordinary id shapes; lexing the `-1` as a
        // negative number would break every one of them.
        match ok("GET products POINTS acme-1, 7f3d-2a10-9b;") {
            Statement::Get(get) => assert_eq!(get.ids, vec!["acme-1", "7f3d-2a10-9b"]),
            other => panic!("expected GET, got {other:?}"),
        }
        match ok("DELETE FROM products POINTS globex-1;") {
            Statement::DeletePoints { ids, .. } => assert_eq!(ids, vec!["globex-1"]),
            other => panic!("expected DELETE, got {other:?}"),
        }
    }

    #[test]
    fn a_hyphen_still_starts_a_negative_number_in_value_position() {
        let statement = search("SEARCH c NEAR [-1.5, -2] WHERE score >= -0.5;");
        assert_eq!(
            statement.vector,
            Some(VectorExpr::Literal(vec![-1.5, -2.0]))
        );
        assert_eq!(
            statement.filter.map(|filter| filter.0),
            Some(json!({"score": {"gte": -0.5}}))
        );
    }

    #[test]
    fn search_negative_and_float_components() {
        let statement = search("SEARCH c NEAR [-1.5, 0.25, 3];");
        assert_eq!(
            statement.vector,
            Some(VectorExpr::Literal(vec![-1.5, 0.25, 3.0]))
        );
    }

    #[test]
    fn search_by_point_reference() {
        let statement = search("SEARCH assets NEAR @logo USING image LIMIT 20;");
        assert_eq!(
            statement.vector,
            Some(VectorExpr::Point {
                id: "logo".to_string(),
                vector_name: Some("image".to_string()),
            })
        );
    }

    #[test]
    fn search_ignores_line_comments() {
        let statement = search("-- find phones\nSEARCH products NEAR [1,0,0] LIMIT 2;");
        assert_eq!(statement.limit, Some(2));
    }

    #[test]
    fn filter_operators_map_onto_the_filter_type() {
        let statement = search(
            "SEARCH c NEAR [1] WHERE category = 'electronics' AND price <= 700 \
             AND stock > 0 AND rating >= 4.5 AND age < 10 AND tier != 'free' \
             AND brand IN ['acme', 'globex'] AND title CONTAINS 'wireless' \
             AND meta.brand = 'acme';",
        );
        assert_eq!(
            statement.filter.map(|filter| filter.0),
            Some(json!({
                "category": {"eq": "electronics"},
                "price": {"lte": 700},
                "stock": {"gt": 0},
                "rating": {"gte": 4.5},
                "age": {"lt": 10},
                "tier": {"ne": "free"},
                "brand": {"in": ["acme", "globex"]},
                "title": {"text": "wireless"},
                "meta.brand": {"eq": "acme"}
            }))
        );
    }

    #[test]
    fn filter_merges_a_range_on_one_field() {
        let statement = search("SEARCH c NEAR [1] WHERE price >= 100 AND price <= 700;");
        assert_eq!(
            statement.filter.map(|filter| filter.0),
            Some(json!({"price": {"gte": 100, "lte": 700}}))
        );
    }

    #[test]
    fn filter_accepts_booleans() {
        let statement = search("SEARCH c NEAR [1] WHERE featured = true;");
        assert_eq!(
            statement.filter.map(|filter| filter.0),
            Some(json!({"featured": {"eq": true}}))
        );
    }

    #[test]
    fn hybrid_dense_and_sparse() {
        match ok("HYBRID docs NEAR @seed_doc TEXT {12:1.2, 98:0.7} FUSION rrf LIMIT 5;") {
            Statement::Hybrid(hybrid) => {
                assert_eq!(hybrid.collection.as_deref(), Some("docs"));
                assert_eq!(hybrid.fusion, Some(HybridFusion::Rrf));
                assert_eq!(hybrid.limit, Some(5));
                let sparse = hybrid.sparse.expect("sparse vector");
                assert_eq!(sparse.indices, vec![12, 98]);
                assert_eq!(sparse.values, vec![1.2, 0.7]);
            }
            other => panic!("expected HYBRID, got {other:?}"),
        }
    }

    #[test]
    fn hybrid_weighted_fusion_with_weights() {
        match ok("HYBRID docs NEAR [1,0] TEXT {3:1.0} FUSION weighted DENSE 0.7 SPARSE 0.3;") {
            Statement::Hybrid(hybrid) => {
                assert_eq!(hybrid.fusion, Some(HybridFusion::Weighted));
                assert_eq!(hybrid.dense_weight, Some(0.7));
                assert_eq!(hybrid.sparse_weight, Some(0.3));
            }
            other => panic!("expected HYBRID, got {other:?}"),
        }
    }

    #[test]
    fn multi_vector_search() {
        match ok("MULTI products NEAR [1,0], NEAR [0,1] FUSION weighted WEIGHTS 0.6, 0.4 LIMIT 8;")
        {
            Statement::Multi(multi) => {
                assert_eq!(multi.vectors.len(), 2);
                assert_eq!(multi.weights, vec![0.6, 0.4]);
                assert_eq!(multi.limit, Some(8));
            }
            other => panic!("expected MULTI, got {other:?}"),
        }
    }

    #[test]
    fn recommend_like_and_unlike() {
        match ok("RECOMMEND products LIKE phone, tablet UNLIKE book LIMIT 5;") {
            Statement::Recommend(recommend) => {
                assert_eq!(recommend.positive, vec!["phone", "tablet"]);
                assert_eq!(recommend.negative, vec!["book"]);
                assert_eq!(recommend.limit, Some(5));
            }
            other => panic!("expected RECOMMEND, got {other:?}"),
        }
    }

    #[test]
    fn count_with_and_without_filter() {
        assert!(matches!(ok("COUNT products;"), Statement::Count(_)));
        match ok("COUNT products WHERE category = 'archived';") {
            Statement::Count(count) => assert!(count.filter.is_some()),
            other => panic!("expected COUNT, got {other:?}"),
        }
    }

    #[test]
    fn scroll_with_cursor() {
        match ok("SCROLL products WHERE category = 'a' LIMIT 100 AFTER 'point_42';") {
            Statement::Scroll(scroll) => {
                assert_eq!(scroll.limit, Some(100));
                assert_eq!(scroll.after.as_deref(), Some("point_42"));
            }
            other => panic!("expected SCROLL, got {other:?}"),
        }
    }

    #[test]
    fn get_points() {
        match ok("GET products POINTS phone, 'tablet', 42;") {
            Statement::Get(get) => assert_eq!(get.ids, vec!["phone", "tablet", "42"]),
            other => panic!("expected GET, got {other:?}"),
        }
    }

    #[test]
    fn show_and_describe() {
        assert_eq!(ok("SHOW COLLECTIONS;"), Statement::ShowCollections);
        assert_eq!(
            ok("DESCRIBE products;"),
            Statement::Describe {
                collection: Some("products".to_string())
            }
        );
    }

    #[test]
    fn use_sets_the_session_collection() {
        assert_eq!(
            ok("USE products;"),
            Statement::Use {
                collection: "products".to_string()
            }
        );
    }

    #[test]
    fn upsert_a_point() {
        match ok("UPSERT INTO products {id: 'phone', vector: [1,0,0], \
             payload: {category: 'electronics', price: 699}};")
        {
            Statement::Upsert(upsert) => {
                assert_eq!(upsert.points.len(), 1);
                assert!(upsert.wait);
                assert_eq!(upsert.points[0]["payload"]["price"], json!(699));
            }
            other => panic!("expected UPSERT, got {other:?}"),
        }
    }

    #[test]
    fn upsert_many_points_no_wait() {
        match ok("UPSERT INTO c {id: 'a', vector: [1]}, {id: 'b', vector: [2]} NO WAIT;") {
            Statement::Upsert(upsert) => {
                assert_eq!(upsert.points.len(), 2);
                assert!(!upsert.wait);
            }
            other => panic!("expected UPSERT, got {other:?}"),
        }
    }

    #[test]
    fn update_payload_merge_and_replace() {
        match ok("UPDATE products POINT phone SET PAYLOAD {featured: true};") {
            Statement::UpdatePayload(update) => {
                assert_eq!(update.id, "phone");
                assert!(!update.replace);
                assert_eq!(update.payload, json!({"featured": true}));
            }
            other => panic!("expected UPDATE, got {other:?}"),
        }
        match ok("UPDATE products POINT phone SET PAYLOAD {a: 1} REPLACE;") {
            Statement::UpdatePayload(update) => assert!(update.replace),
            other => panic!("expected UPDATE, got {other:?}"),
        }
    }

    #[test]
    fn delete_by_ids_and_by_filter() {
        assert_eq!(
            ok("DELETE FROM products POINTS phone, book;"),
            Statement::DeletePoints {
                collection: Some("products".to_string()),
                ids: vec!["phone".to_string(), "book".to_string()],
            }
        );
        match ok("DELETE FROM products WHERE category = 'archived';") {
            Statement::DeleteWhere { filter, .. } => {
                assert_eq!(filter.0, json!({"category": {"eq": "archived"}}));
            }
            other => panic!("expected DELETE … WHERE, got {other:?}"),
        }
    }

    #[test]
    fn statement_class_drives_the_rbac_check() {
        assert_eq!(ok("SEARCH c NEAR [1];").class(), StatementClass::Read);
        assert_eq!(ok("COUNT c;").class(), StatementClass::Read);
        assert_eq!(ok("DELETE FROM c POINTS a;").class(), StatementClass::Write);
        assert_eq!(
            ok("UPSERT INTO c {id: 'a', vector: [1]};").class(),
            StatementClass::Write
        );
    }

    // -- reject corpus -----------------------------------------------------

    #[test]
    fn rejects_sql_select() {
        let error = err("SELECT * FROM products;");
        assert_eq!(error.code, "chironql.not_sql");
        assert_eq!(error.position, 0);
        assert!(error.hint.expect("hint").contains("SEARCH"));
    }

    #[test]
    fn rejects_sql_insert() {
        assert_eq!(
            err("INSERT INTO products VALUES (1);").code,
            "chironql.not_sql"
        );
    }

    #[test]
    fn rejects_transactions() {
        for input in ["BEGIN;", "COMMIT;", "ROLLBACK;", "START TRANSACTION;"] {
            assert_eq!(err(input).code, "chironql.no_transactions", "{input}");
        }
    }

    #[test]
    fn rejects_ddl_and_index_families() {
        let error = err("CREATE INDEX idx ON products USING hnsw (embedding);");
        assert_eq!(error.code, "chironql.no_ddl");
        assert!(error.hint.expect("hint").contains("LS-VEC"));
        assert_eq!(err("DROP TABLE products;").code, "chironql.no_ddl");
    }

    #[test]
    fn rejects_cte_and_explain() {
        assert_eq!(
            err("WITH x AS (SELECT 1) SELECT * FROM x;").code,
            "chironql.no_cte"
        );
        let error = err("EXPLAIN SEARCH products NEAR [1,0,0];");
        assert_eq!(error.code, "chironql.no_explain");
        assert!(error.hint.expect("hint").contains("trace"));
    }

    #[test]
    fn rejects_or_across_fields_with_the_in_hint() {
        let error = err("SEARCH c NEAR [1] WHERE category = 'a' OR category = 'b';");
        assert_eq!(error.code, "chironql.no_or_across_fields");
        assert!(error.hint.expect("hint").contains("IN"));
        // The caret lands on `OR`, not at the start of the statement.
        assert_eq!(
            &"SEARCH c NEAR [1] WHERE category = 'a' OR category = 'b';"
                [error.position..error.position + 2],
            "OR"
        );
    }

    #[test]
    fn rejects_group_by() {
        let error = err("COUNT products GROUP BY category;");
        assert_eq!(error.code, "chironql.no_aggregates");
    }

    #[test]
    fn rejects_count_star() {
        assert_eq!(err("COUNT * FROM products;").code, "chironql.no_aggregates");
    }

    #[test]
    fn rejects_like_with_the_contains_hint() {
        let error = err("SEARCH c NEAR [1] WHERE title LIKE 'wireless%';");
        assert_eq!(error.code, "chironql.no_like");
        assert!(error.hint.expect("hint").contains("CONTAINS"));
    }

    #[test]
    fn rejects_unbounded_delete() {
        let error = err("DELETE FROM products;");
        assert_eq!(error.code, "chironql.unbounded_delete");
        assert!(error.hint.expect("hint").contains("chironctl"));
    }

    #[test]
    fn rejects_search_without_near() {
        assert_eq!(
            err("SEARCH products LIMIT 5;").code,
            "chironql.missing_near"
        );
    }

    #[test]
    fn rejects_recommend_without_like() {
        assert_eq!(
            err("RECOMMEND products LIMIT 5;").code,
            "chironql.missing_like"
        );
    }

    #[test]
    fn rejects_point_without_id() {
        assert_eq!(
            err("UPSERT INTO products {vector: [1,0,0]};").code,
            "chironql.missing_point_id"
        );
    }

    #[test]
    fn rejects_unknown_statement() {
        let error = err("FROBNICATE products;");
        assert_eq!(error.code, "chironql.unknown_statement");
        assert_eq!(error.position, 0);
    }

    #[test]
    fn rejects_multiple_statements() {
        let error = err("COUNT a; COUNT b;");
        assert_eq!(error.code, "chironql.multiple_statements");
        assert_eq!(error.position, 9);
    }

    #[test]
    fn rejects_weight_arity_mismatch() {
        assert_eq!(
            err("MULTI c NEAR [1], NEAR [2] WEIGHTS 0.5;").code,
            "chironql.weight_arity"
        );
    }

    #[test]
    fn rejects_out_of_range_recall() {
        assert_eq!(
            err("SEARCH c NEAR [1] RECALL 1.5;").code,
            "chironql.invalid_recall"
        );
    }

    #[test]
    fn rejects_unterminated_string() {
        assert_eq!(
            err("SEARCH c NEAR [1] WHERE a = 'oops;").code,
            "chironql.unterminated_string"
        );
    }

    #[test]
    fn rejects_empty_query() {
        assert_eq!(err("   ").code, "chironql.empty_query");
    }

    #[test]
    fn rejects_duplicate_condition_rather_than_silently_dropping_one() {
        assert_eq!(
            err("COUNT c WHERE price = 1 AND price = 2;").code,
            "chironql.duplicate_condition"
        );
    }

    #[test]
    fn error_positions_point_into_the_source() {
        let input = "SEARCH c NEAR [1] WHERE title LIKE 'x';";
        let error = err(input);
        assert_eq!(&input[error.position..error.position + 4], "LIKE");
    }

    // -----------------------------------------------------------------------
    // Collection DDL
    // -----------------------------------------------------------------------

    #[test]
    fn create_collection_needs_only_a_name_and_a_dimension() {
        match ok("CREATE COLLECTION products DIM 768;") {
            Statement::CreateCollection(create) => {
                assert_eq!(create.name, "products");
                assert_eq!(create.dim, 768);
                assert_eq!(create.metric, None);
                assert_eq!(create.options, None);
            }
            other => panic!("expected CREATE COLLECTION, got {other:?}"),
        }
    }

    #[test]
    fn create_collection_takes_a_metric_and_an_options_object() {
        match ok("CREATE COLLECTION docs DIM 4 METRIC l2 WITH {shards: 2, quantization: 'sq8'};") {
            Statement::CreateCollection(create) => {
                assert_eq!(create.metric, Some(DistanceMetric::L2));
                assert_eq!(
                    create.options,
                    Some(json!({"shards": 2, "quantization": "sq8"}))
                );
            }
            other => panic!("expected CREATE COLLECTION, got {other:?}"),
        }
    }

    #[test]
    fn create_collection_without_dim_says_which_piece_is_missing() {
        let error = err("CREATE COLLECTION products;");
        assert_eq!(error.code, "chironql.missing_dim");
        assert!(error.hint.is_some(), "the hint carries the full form");
    }

    #[test]
    fn create_collection_rejects_an_unknown_metric() {
        assert_eq!(
            err("CREATE COLLECTION c DIM 3 METRIC hamming;").code,
            "chironql.unknown_metric"
        );
    }

    #[test]
    fn create_collection_rejects_a_non_object_with() {
        assert_eq!(
            err("CREATE COLLECTION c DIM 3 WITH [1, 2];").code,
            "chironql.invalid_collection_options"
        );
    }

    #[test]
    fn drop_collection_accepts_if_exists_on_either_side_of_the_name() {
        for input in [
            "DROP COLLECTION IF EXISTS products;",
            "DROP COLLECTION products IF EXISTS;",
        ] {
            match ok(input) {
                Statement::DropCollection {
                    collection,
                    if_exists,
                } => {
                    assert_eq!(collection, "products");
                    assert!(if_exists, "{input}");
                }
                other => panic!("expected DROP COLLECTION, got {other:?}"),
            }
        }
    }

    #[test]
    fn drop_collection_without_if_exists_is_not_forgiving() {
        match ok("DROP COLLECTION products;") {
            Statement::DropCollection { if_exists, .. } => assert!(!if_exists),
            other => panic!("expected DROP COLLECTION, got {other:?}"),
        }
    }

    #[test]
    fn collection_ddl_is_write_class() {
        assert_eq!(
            ok("CREATE COLLECTION c DIM 3;").class(),
            StatementClass::Write
        );
        assert_eq!(ok("DROP COLLECTION c;").class(), StatementClass::Write);
    }

    /// The DDL that arrived did not open the door to the DDL that did not.
    #[test]
    fn schema_ddl_and_index_ddl_are_still_rejected() {
        for input in [
            "CREATE INDEX idx ON products USING hnsw (embedding);",
            "CREATE TABLE products (id text);",
            "DROP TABLE products;",
            "ALTER COLLECTION products SET DIM 4;",
            "TRUNCATE products;",
        ] {
            assert_eq!(err(input).code, "chironql.no_ddl", "{input}");
        }
    }

    // -----------------------------------------------------------------------
    // ChironQL 1.1 graph grammar (D7)
    // -----------------------------------------------------------------------

    #[test]
    fn production_parser_is_v1_1_and_frozen_v1_0_stays_closed() {
        assert_eq!(LANGUAGE_VERSION, "1.1");
        assert!(matches!(
            ok("RELATE docs a -> CITES -> b;"),
            Statement::Relate(_)
        ));
        assert_eq!(
            parse_v1_0("RELATE docs a -> CITES -> b;")
                .expect_err("frozen 1.0 surface")
                .code,
            "chironql.unknown_statement"
        );
    }

    #[test]
    fn graph_keywords_do_not_reserve_collection_names() {
        for collection in ["edge", "via", "connected", "direction", "properties"] {
            assert_eq!(
                search(&format!("SEARCH {collection} NEAR [1];"))
                    .collection
                    .as_deref(),
                Some(collection)
            );
        }
    }

    #[test]
    fn graph_relate_parses_every_normative_option() {
        match graph_ok(
            "RELATE docs 'source-1' -> CITES -> target-2 \
             SET {weight: 0.8, nested: {source: 'manual'}} \
             IDEMPOTENCY KEY 'relate-42' WITH DEFERRED ENDPOINTS NO WAIT;",
        ) {
            Statement::Relate(relate) => {
                assert_eq!(relate.collection, "docs");
                assert_eq!(relate.source_id, "source-1");
                assert_eq!(relate.edge_type, "CITES");
                assert_eq!(relate.target_id, "target-2");
                assert_eq!(
                    relate.properties,
                    json!({"weight": 0.8, "nested": {"source": "manual"}})
                );
                assert_eq!(relate.idempotency_key.as_deref(), Some("relate-42"));
                assert!(relate.deferred_endpoints);
                assert!(!relate.wait);
            }
            other => panic!("expected RELATE, got {other:?}"),
        }
    }

    #[test]
    fn graph_mutation_defaults_and_property_shape_are_frozen() {
        match graph_ok("RELATE docs a -> CITES -> b;") {
            Statement::Relate(relate) => {
                assert_eq!(relate.properties, json!({}));
                assert_eq!(relate.idempotency_key, None);
                assert!(!relate.deferred_endpoints);
                assert!(relate.wait);
            }
            other => panic!("expected RELATE, got {other:?}"),
        }
        match graph_ok("UNRELATE docs EDGE edge-token;") {
            Statement::Unrelate(unrelate) => assert!(unrelate.wait),
            other => panic!("expected UNRELATE, got {other:?}"),
        }
        match graph_ok("UPDATE docs EDGE edge-token SET PROPERTIES {weight: 1};") {
            Statement::UpdateEdge(update) => {
                assert!(!update.replace);
                assert!(update.wait);
            }
            other => panic!("expected UPDATE EDGE, got {other:?}"),
        }
        assert_eq!(
            graph_err("RELATE docs a -> CITES -> b SET [1, 2];").code,
            "chironql.invalid_edge_properties"
        );
        assert_eq!(
            graph_err("UPDATE docs EDGE edge-token SET PROPERTIES true;").code,
            "chironql.invalid_edge_properties"
        );
    }

    #[test]
    fn graph_unrelate_and_edge_update_preserve_opaque_tokens() {
        match graph_ok("UNRELATE docs EDGE AQID-edge_1, token-2 NO WAIT;") {
            Statement::Unrelate(unrelate) => {
                assert_eq!(unrelate.edge_ids, vec!["AQID-edge_1", "token-2"]);
                assert!(!unrelate.wait);
            }
            other => panic!("expected UNRELATE, got {other:?}"),
        }
        match graph_ok(
            "UPDATE docs EDGE AQID-edge_1 SET PROPERTIES {reviewed: true} REPLACE NO WAIT;",
        ) {
            Statement::UpdateEdge(update) => {
                assert_eq!(update.collection, "docs");
                assert_eq!(update.edge_id, "AQID-edge_1");
                assert_eq!(update.properties, json!({"reviewed": true}));
                assert!(update.replace);
                assert!(!update.wait);
            }
            other => panic!("expected UPDATE EDGE, got {other:?}"),
        }
    }

    #[test]
    fn traverse_parses_exact_where_edge_where_and_return_semantics() {
        match graph_ok(
            "TRAVERSE docs FROM a, 'b' VIA CITES, MENTIONS DIRECTION ANY DEPTH 3 \
             WHERE status = 'active' EDGE WHERE weight >= 0.5 BUDGET 25 MS \
             LIMIT 50 WITH PAYLOAD RETURN EDGES;",
        ) {
            Statement::Traverse(traverse) => {
                assert_eq!(traverse.collection, "docs");
                assert_eq!(traverse.anchors, vec!["a", "b"]);
                assert_eq!(traverse.edge_types, vec!["CITES", "MENTIONS"]);
                assert_eq!(traverse.direction, GraphDirection::Both);
                assert_eq!(traverse.depth, 3);
                assert_eq!(
                    traverse.node_filter.map(|filter| filter.0),
                    Some(json!({"status": {"eq": "active"}}))
                );
                assert_eq!(
                    traverse.edge_filter.map(|filter| filter.0),
                    Some(json!({"weight": {"gte": 0.5}}))
                );
                assert_eq!(traverse.budget_ms, Some(25));
                assert_eq!(traverse.limit, Some(50));
                assert!(traverse.with_payload);
                assert_eq!(traverse.returns, GraphReturn::Edges);
            }
            other => panic!("expected TRAVERSE, got {other:?}"),
        }
    }

    #[test]
    fn traverse_defaults_and_paths_limit_are_frozen() {
        match graph_ok("TRAVERSE docs FROM anchor;") {
            Statement::Traverse(traverse) => {
                assert_eq!(traverse.direction, GraphDirection::Outgoing);
                assert_eq!(traverse.depth, 1);
                assert_eq!(traverse.returns, GraphReturn::Nodes);
                assert_eq!(traverse.limit, None);
            }
            other => panic!("expected TRAVERSE, got {other:?}"),
        }
        assert_eq!(
            graph_err("TRAVERSE docs FROM anchor RETURN PATHS;").code,
            "chironql.paths_limit_required"
        );
        assert!(matches!(
            graph_ok("TRAVERSE docs FROM anchor RETURN PATHS LIMIT 10;"),
            Statement::Traverse(Traverse {
                returns: GraphReturn::Paths,
                limit: Some(10),
                ..
            })
        ));
    }

    #[test]
    fn connected_to_extends_search_and_hybrid_without_redefining_where() {
        match graph_ok(
            "SEARCH docs NEAR [1,0] CONNECTED TO root-a, root-b VIA CITES \
             DIRECTION IN WITHIN 2 HOPS WHERE status = 'ready' LIMIT 7 \
             WITH PAYLOAD ALLOW DEGRADED;",
        ) {
            Statement::Search(search) => {
                let graph = search.graph.expect("graph clause");
                assert_eq!(graph.anchors, vec!["root-a", "root-b"]);
                assert_eq!(graph.edge_types, vec!["CITES"]);
                assert_eq!(graph.direction, GraphDirection::Incoming);
                assert_eq!(graph.within_hops, 2);
                assert!(graph.allow_degraded);
                assert_eq!(
                    search.filter.map(|filter| filter.0),
                    Some(json!({"status": {"eq": "ready"}}))
                );
            }
            other => panic!("expected SEARCH, got {other:?}"),
        }

        match graph_ok(
            "HYBRID docs NEAR [1,0] TEXT {4417:2.0, 9:1.0} \
             CONNECTED TO line-3 VIA MENTIONS WITHIN 2 HOPS FUSION weighted \
             WEIGHTS 0.7 0.3 WHERE status = 'RESOLVED' LIMIT 10 WITH PAYLOAD;",
        ) {
            Statement::Hybrid(hybrid) => {
                assert_eq!(hybrid.dense_weight, Some(0.7));
                assert_eq!(hybrid.sparse_weight, Some(0.3));
                assert_eq!(hybrid.with_payload, Some(true));
                assert_eq!(hybrid.graph.expect("graph clause").anchors, vec!["line-3"]);
            }
            other => panic!("expected HYBRID, got {other:?}"),
        }
    }

    #[test]
    fn graph_clauses_require_connected_to_and_reuse_existing_filter_rejects() {
        assert_eq!(
            graph_err("SEARCH docs NEAR [1] VIA CITES;").code,
            "chironql.missing_connected_to"
        );
        assert_eq!(
            graph_err("SEARCH docs NEAR [1] LIMIT 1 LIMIT 2;").code,
            "chironql.duplicate_clause"
        );
        assert_eq!(
            graph_err("HYBRID docs NEAR [1] WEIGHTS 0.5 0.5 DENSE 0.7;").code,
            "chironql.duplicate_clause"
        );
        assert_eq!(
            graph_err("TRAVERSE docs FROM a WHERE status = 'a' OR status = 'b' RETURN NODES;").code,
            "chironql.no_or_across_fields"
        );
        assert_eq!(graph_err("CREATE EDGE TYPE CITES;").code, "chironql.no_ddl");
    }

    #[test]
    fn graph_parser_enforces_fixed_request_caps_before_resolution() {
        let anchors = (0..=MAX_GRAPH_ANCHORS)
            .map(|index| format!("a{index}"))
            .collect::<Vec<_>>()
            .join(",");
        assert_eq!(
            graph_err(&format!("TRAVERSE docs FROM {anchors};")).code,
            "graph.too_many_anchors"
        );

        let types = (0..=MAX_GRAPH_TYPES_PER_CLAUSE)
            .map(|index| format!("T{index}"))
            .collect::<Vec<_>>()
            .join(",");
        assert_eq!(
            graph_err(&format!("TRAVERSE docs FROM a VIA {types};")).code,
            "graph.too_many_types"
        );

        let edge_ids = (0..=MAX_GRAPH_EDGES_PER_BATCH)
            .map(|index| format!("e{index}"))
            .collect::<Vec<_>>()
            .join(",");
        assert_eq!(
            graph_err(&format!("UNRELATE docs EDGE {edge_ids};")).code,
            "graph.batch_too_large"
        );

        assert_eq!(
            graph_err(&format!(
                "TRAVERSE docs FROM a DEPTH {};",
                MAX_GRAPH_DEPTH + 1
            ))
            .code,
            "graph.depth_exceeded"
        );

        let property = "x".repeat(MAX_EDGE_PROPERTY_BYTES);
        assert_eq!(
            graph_err(&format!(
                "RELATE docs a -> CITES -> b SET {{blob: '{property}'}};"
            ))
            .code,
            "graph.property_too_large"
        );
    }

    #[test]
    fn graph_reject_taxonomy_is_stable_and_specific() {
        assert_eq!(
            graph_err("MATCH (a)-[:CITES]->(b);").code,
            "chironql.unsupported_path_pattern"
        );
        assert_eq!(
            graph_err("SHORTEST PATH docs FROM a TO b;").code,
            "chironql.unsupported_shortest_path"
        );
        assert_eq!(
            graph_err("WALK docs FROM a;").code,
            "chironql.walks_unsupported"
        );
        assert_eq!(
            graph_err("TRAVERSE docs FROM a RETURN WALKS;").code,
            "chironql.walks_unsupported"
        );
    }

    #[test]
    fn graph_statement_class_collection_and_kind_are_closed() {
        let relate = graph_ok("RELATE docs a -> CITES -> b;");
        assert_eq!(relate.class(), StatementClass::Write);
        assert_eq!(relate.collection(), Some("docs"));
        assert_eq!(relate.kind_name(), "RELATE");

        let traverse = graph_ok("TRAVERSE docs FROM a;");
        assert_eq!(traverse.class(), StatementClass::Read);
        assert_eq!(traverse.collection(), Some("docs"));
        assert_eq!(traverse.kind_name(), "TRAVERSE");
    }
}
