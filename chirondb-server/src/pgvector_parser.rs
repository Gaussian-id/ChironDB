//! pgvector SQL — handwritten recursive-descent parser.
//!
//! B2 of `.SPEC/gaussdb-vector_cleaned.md`. Spec: `.SPEC/gaussdb-vector_cleaned.md` §3 + §3.0.1.
//!
//! Covers the seven supported shapes:
//!
//! 1. `CREATE EXTENSION [IF NOT EXISTS] vector`            (no-op shim)
//! 2. `CREATE TABLE [IF NOT EXISTS] t (col defs..., embedding vector(N), ...)`
//! 3. `INSERT INTO t [(cols)] VALUES (...), (...)`
//! 4. `SELECT ... FROM t [WHERE ...] [ORDER BY embedding <op> '[...]'::vector]
//!     [LIMIT n]`
//! 5. `DELETE FROM t [WHERE ...]`
//! 6. `CREATE INDEX [IF NOT EXISTS] [name] ON t USING hnsw (col opclass)`
//! 7. `DROP TABLE [IF EXISTS] t[, t2, ...]`
//!
//! Plus parser-level reject taxonomy mapped to SQLSTATE `0A000` (per §3.0.1):
//! JOIN / WITH / subquery / transaction control / extended query / window
//! functions / GROUP BY+agg / multi-table mutations / EXPLAIN ANALYZE / USING
//! ivfflat / `<+>` L1 operator. Each reject carries a stable hint anchor that
//! the wire-protocol error path turns into a `Hint:` URL pointing at
//! `.SPEC/gaussdb-vector_cleaned.md`.
//!
//! Out of scope: PREPARE/EXECUTE, COPY, EXPLAIN (beyond stub), pg_catalog
//! introspection beyond the surface used by `psql \d` (B5 fills that in).

use std::fmt;

/// One parsed SQL statement.
#[derive(Clone, Debug, PartialEq)]
pub enum Statement {
    CreateExtensionVector {
        if_not_exists: bool,
    },
    CreateTable(CreateTable),
    Insert(Insert),
    Select(Select),
    Delete(Delete),
    CreateIndex(CreateIndex),
    DropTable(DropTable),
    /// `SET name = value` / `SET name TO value`. Recorded for session-state
    /// shims; v1 ignores the value.
    Set {
        name: String,
        value: String,
    },
    /// `SHOW name` — used by libpq probes.
    Show {
        name: String,
    },
    /// `BEGIN` / `START TRANSACTION` / `COMMIT` / `ROLLBACK` / `SAVEPOINT`.
    /// We recognise the keyword so we can reject with SQLSTATE `0A000` at the
    /// dispatch layer (per §3.0.1 row 4) without forcing a parser error.
    TransactionControl(TxnKeyword),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TxnKeyword {
    Begin,
    Commit,
    Rollback,
    Savepoint,
    Release,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CreateTable {
    pub if_not_exists: bool,
    pub name: String,
    pub columns: Vec<ColumnDef>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ColumnDef {
    pub name: String,
    pub data_type: SqlType,
    pub primary_key: bool,
    pub not_null: bool,
}

/// SQL types we accept in `CREATE TABLE`. Anything else: SQLSTATE `0A000`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SqlType {
    Vector(usize),
    Integer,
    BigInt,
    SmallInt,
    Real,
    DoublePrecision,
    Numeric,
    Text,
    Varchar(Option<usize>),
    Boolean,
    Jsonb,
    Timestamp,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Insert {
    pub table: String,
    pub columns: Vec<String>,
    pub rows: Vec<Vec<Expr>>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Select {
    pub projection: Vec<SelectItem>,
    pub table: String,
    pub where_clause: Option<Expr>,
    pub order_by: Option<OrderBy>,
    pub limit: Option<u64>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum SelectItem {
    Star,
    Expr { expr: Expr, alias: Option<String> },
}

#[derive(Clone, Debug, PartialEq)]
pub struct OrderBy {
    pub expr: Expr,
    pub asc: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Delete {
    pub table: String,
    pub where_clause: Option<Expr>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CreateIndex {
    pub if_not_exists: bool,
    pub index_name: Option<String>,
    pub table: String,
    pub method: IndexMethod,
    pub column: String,
    pub opclass: Option<OpClass>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IndexMethod {
    Hnsw,
    /// `USING ivfflat` — parsed for the explicit reject in §3.0.1.
    Ivfflat,
    /// `USING rabitq` — accepted shape, but only fires once PC-1 (B7) ships.
    Rabitq,
    Unknown(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OpClass {
    VectorL2Ops,
    VectorIpOps,
    VectorCosineOps,
    Unknown(String),
}

#[derive(Clone, Debug, PartialEq)]
pub struct DropTable {
    pub if_exists: bool,
    pub names: Vec<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Expr {
    Ident(String),
    QualifiedIdent(String, String),
    Number(f64),
    Integer(i64),
    String(String),
    Bool(bool),
    Null,
    VectorLiteral(Vec<f32>),
    Distance {
        left: Box<Expr>,
        op: VectorOp,
        right: Box<Expr>,
    },
    Compare {
        left: Box<Expr>,
        op: CmpOp,
        right: Box<Expr>,
    },
    InList {
        expr: Box<Expr>,
        list: Vec<Expr>,
        negated: bool,
    },
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
    /// `embedding <-> '[...]'::vector AS distance` — captured so the egress
    /// formatter can emit the computed distance column. Parser does not
    /// evaluate.
    Aliased {
        inner: Box<Expr>,
        alias: String,
    },
    /// `vector_dims(x)` / `vector_norm(x)` — recognised for B6 conformance.
    /// Parser only; dispatch may reject if unsupported.
    Func {
        name: String,
        args: Vec<Expr>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VectorOp {
    /// `<->` L2 (Euclidean) distance.
    L2,
    /// `<#>` Negative inner product.
    Dot,
    /// `<=>` Cosine distance.
    Cosine,
    /// `<+>` L1 (Manhattan). Recognised → parser-level reject at dispatch.
    L1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CmpOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

/// Parser errors. Three kinds:
/// 1. `Syntax` — the client wrote something we couldn't parse at all (SQLSTATE
///    `42601`).
/// 2. `Unsupported` — the parser understood the shape but it is explicitly
///    excluded by the §3.0.1 reject taxonomy. Maps to SQLSTATE `0A000` plus a
///    stable hint anchor so the wire path can build the `Hint:` URL.
/// 3. `InvalidData` — well-formed SQL with a value the type rejects (e.g.
///    `NaN` / `Infinity` inside a `vector` literal). Maps to SQLSTATE `22023`
///    (`invalid_parameter_value`), the closest match to pgvector's own
///    behaviour.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParseError {
    Syntax { message: String },
    Unsupported { message: String, hint: &'static str },
    InvalidData { message: String },
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Syntax { message } => write!(f, "syntax error: {message}"),
            Self::Unsupported { message, .. } => write!(f, "{message}"),
            Self::InvalidData { message } => write!(f, "{message}"),
        }
    }
}

impl ParseError {
    pub fn sqlstate(&self) -> &'static str {
        match self {
            Self::Syntax { .. } => "42601",
            Self::Unsupported { .. } => "0A000",
            Self::InvalidData { .. } => "22023",
        }
    }
    pub fn hint(&self) -> Option<&'static str> {
        match self {
            Self::Syntax { .. } => None,
            Self::Unsupported { hint, .. } => Some(*hint),
            Self::InvalidData { .. } => None,
        }
    }
}

pub type ParseResult<T> = std::result::Result<T, ParseError>;

// =========================================================================
// Lexer
// =========================================================================

#[derive(Clone, Debug, PartialEq)]
enum Token {
    Ident(String),
    QuotedIdent(String),
    Int(i64),
    Float(f64),
    Str(String),
    /// `'[...]'::vector` — the lexer captures the vector literal as a single
    /// token to keep the parser simple.
    VectorLit(Vec<f32>),
    LParen,
    RParen,
    Comma,
    Semicolon,
    Star,
    Dot,
    Colon,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    OpL2,
    OpDot,
    OpCosine,
    OpL1,
    DoubleColon,
    Eof,
}

struct Lexer<'a> {
    src: &'a [u8],
    pos: usize,
}

impl<'a> Lexer<'a> {
    fn new(src: &'a str) -> Self {
        Self {
            src: src.as_bytes(),
            pos: 0,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.src.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let b = self.peek()?;
        self.pos += 1;
        Some(b)
    }

    fn skip_ws_and_comments(&mut self) {
        loop {
            match self.peek() {
                Some(b) if b.is_ascii_whitespace() => {
                    self.pos += 1;
                }
                Some(b'-') if self.src.get(self.pos + 1) == Some(&b'-') => {
                    // Line comment.
                    self.pos += 2;
                    while let Some(b) = self.peek() {
                        if b == b'\n' {
                            self.pos += 1;
                            break;
                        }
                        self.pos += 1;
                    }
                }
                Some(b'/') if self.src.get(self.pos + 1) == Some(&b'*') => {
                    self.pos += 2;
                    while self.pos + 1 < self.src.len() {
                        if self.src[self.pos] == b'*' && self.src[self.pos + 1] == b'/' {
                            self.pos += 2;
                            break;
                        }
                        self.pos += 1;
                    }
                }
                _ => break,
            }
        }
    }

    fn next_token(&mut self) -> ParseResult<Token> {
        self.skip_ws_and_comments();
        let Some(b) = self.peek() else {
            return Ok(Token::Eof);
        };
        // Identifier or keyword.
        if b == b'_' || b.is_ascii_alphabetic() {
            let start = self.pos;
            while let Some(b) = self.peek() {
                if b == b'_' || b.is_ascii_alphanumeric() {
                    self.pos += 1;
                } else {
                    break;
                }
            }
            let raw = std::str::from_utf8(&self.src[start..self.pos])
                .map_err(|e| syntax(format!("non-utf8 identifier: {e}")))?;
            return Ok(Token::Ident(raw.to_ascii_lowercase()));
        }
        // Quoted identifier "foo bar".
        if b == b'"' {
            self.pos += 1;
            let start = self.pos;
            while let Some(b) = self.peek() {
                if b == b'"' {
                    let raw = std::str::from_utf8(&self.src[start..self.pos])
                        .map_err(|e| syntax(format!("non-utf8 quoted ident: {e}")))?
                        .to_string();
                    self.pos += 1;
                    return Ok(Token::QuotedIdent(raw));
                }
                self.pos += 1;
            }
            return Err(syntax("unterminated quoted identifier"));
        }
        // Number.
        if b.is_ascii_digit()
            || (b == b'-' && matches!(self.src.get(self.pos + 1), Some(d) if d.is_ascii_digit()))
        {
            return self.lex_number();
        }
        // String / vector literal.
        if b == b'\'' {
            return self.lex_string_or_vector();
        }
        // Operators and punctuation.
        self.bump();
        match b {
            b'(' => Ok(Token::LParen),
            b')' => Ok(Token::RParen),
            b',' => Ok(Token::Comma),
            b';' => Ok(Token::Semicolon),
            b'*' => Ok(Token::Star),
            b'.' => Ok(Token::Dot),
            b':' => {
                if self.peek() == Some(b':') {
                    self.pos += 1;
                    Ok(Token::DoubleColon)
                } else {
                    Ok(Token::Colon)
                }
            }
            b'=' => Ok(Token::Eq),
            b'!' => {
                if self.peek() == Some(b'=') {
                    self.pos += 1;
                    Ok(Token::Ne)
                } else {
                    Err(syntax("unexpected '!'"))
                }
            }
            b'<' => match self.peek() {
                Some(b'=') => {
                    // Distinguish `<=` (Le) from `<=>` (Cosine distance).
                    if self.src.get(self.pos + 1) == Some(&b'>') {
                        self.pos += 2;
                        Ok(Token::OpCosine)
                    } else {
                        self.pos += 1;
                        Ok(Token::Le)
                    }
                }
                Some(b'>') => {
                    self.pos += 1;
                    Ok(Token::Ne)
                }
                Some(b'-') => {
                    if self.src.get(self.pos + 1) == Some(&b'>') {
                        self.pos += 2;
                        Ok(Token::OpL2)
                    } else {
                        Err(syntax("expected '->' after '<-'"))
                    }
                }
                Some(b'#') => {
                    if self.src.get(self.pos + 1) == Some(&b'>') {
                        self.pos += 2;
                        Ok(Token::OpDot)
                    } else {
                        Err(syntax("expected '>' after '<#'"))
                    }
                }
                Some(b'+') => {
                    if self.src.get(self.pos + 1) == Some(&b'>') {
                        self.pos += 2;
                        Ok(Token::OpL1)
                    } else {
                        Err(syntax("expected '>' after '<+'"))
                    }
                }
                _ => Ok(Token::Lt),
            },
            b'>' => match self.peek() {
                Some(b'=') => {
                    self.pos += 1;
                    Ok(Token::Ge)
                }
                _ => Ok(Token::Gt),
            },
            other => Err(syntax(format!("unexpected character {:?}", other as char))),
        }
    }

    fn lex_number(&mut self) -> ParseResult<Token> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        while matches!(self.peek(), Some(b) if b.is_ascii_digit()) {
            self.pos += 1;
        }
        let mut is_float = false;
        if self.peek() == Some(b'.') {
            is_float = true;
            self.pos += 1;
            while matches!(self.peek(), Some(b) if b.is_ascii_digit()) {
                self.pos += 1;
            }
        }
        if matches!(self.peek(), Some(b'e') | Some(b'E')) {
            is_float = true;
            self.pos += 1;
            if matches!(self.peek(), Some(b'+') | Some(b'-')) {
                self.pos += 1;
            }
            while matches!(self.peek(), Some(b) if b.is_ascii_digit()) {
                self.pos += 1;
            }
        }
        let raw = std::str::from_utf8(&self.src[start..self.pos])
            .map_err(|e| syntax(format!("non-utf8 number: {e}")))?;
        if is_float {
            raw.parse::<f64>()
                .map(Token::Float)
                .map_err(|e| syntax(format!("invalid number {raw}: {e}")))
        } else {
            raw.parse::<i64>()
                .map(Token::Int)
                .map_err(|e| syntax(format!("invalid integer {raw}: {e}")))
        }
    }

    fn lex_string_or_vector(&mut self) -> ParseResult<Token> {
        // Already at opening quote.
        self.pos += 1;
        let start = self.pos;
        let mut content = Vec::<u8>::new();
        loop {
            let Some(b) = self.peek() else {
                return Err(syntax("unterminated string literal"));
            };
            if b == b'\'' {
                if self.src.get(self.pos + 1) == Some(&b'\'') {
                    content.push(b'\'');
                    self.pos += 2;
                } else {
                    self.pos += 1;
                    break;
                }
            } else {
                content.push(b);
                self.pos += 1;
            }
        }
        let _ = start; // anchor for future debug spans.
        let body = String::from_utf8(content)
            .map_err(|e| syntax(format!("non-utf8 string literal: {e}")))?;

        // Try `::vector` cast immediately.
        self.skip_ws_and_comments();
        if self.peek() == Some(b':') && self.src.get(self.pos + 1) == Some(&b':') {
            // Lookahead for `::vector` keyword.
            let save = self.pos;
            self.pos += 2;
            self.skip_ws_and_comments();
            let ident_start = self.pos;
            while let Some(b) = self.peek() {
                if b == b'_' || b.is_ascii_alphanumeric() {
                    self.pos += 1;
                } else {
                    break;
                }
            }
            let ident = std::str::from_utf8(&self.src[ident_start..self.pos])
                .map_err(|e| syntax(format!("non-utf8 cast type: {e}")))?
                .to_ascii_lowercase();
            if ident == "vector" {
                let v = parse_vector_literal_body(&body)?;
                return Ok(Token::VectorLit(v));
            }
            // Not a `::vector` cast — rewind so `::` becomes the next token.
            self.pos = save;
        }
        Ok(Token::Str(body))
    }
}

fn parse_vector_literal_body(body: &str) -> ParseResult<Vec<f32>> {
    let trimmed = body.trim();
    if !trimmed.starts_with('[') || !trimmed.ends_with(']') {
        return Err(syntax(format!(
            "invalid vector literal: expected '[...]', got {trimmed:?}"
        )));
    }
    let inner = &trimmed[1..trimmed.len() - 1];
    if inner.trim().is_empty() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for piece in inner.split(',') {
        let trimmed = piece.trim();
        // Catch NaN / Inf textual forms before `parse::<f32>` accepts them.
        let lower = trimmed.to_ascii_lowercase();
        if matches!(
            lower.as_str(),
            "nan"
                | "+nan"
                | "-nan"
                | "inf"
                | "+inf"
                | "-inf"
                | "infinity"
                | "+infinity"
                | "-infinity"
        ) {
            return Err(ParseError::InvalidData {
                message: format!("NaN/Inf rejected in vector literal: {:?}", trimmed),
            });
        }
        let v: f32 = trimmed
            .parse()
            .map_err(|e| syntax(format!("invalid vector component {trimmed:?}: {e}")))?;
        if v.is_nan() || v.is_infinite() {
            return Err(ParseError::InvalidData {
                message: format!("NaN/Inf rejected in vector literal: {trimmed:?}"),
            });
        }
        out.push(v);
    }
    Ok(out)
}

fn syntax(msg: impl Into<String>) -> ParseError {
    ParseError::Syntax {
        message: msg.into(),
    }
}

fn unsupported(message: impl Into<String>, hint: &'static str) -> ParseError {
    ParseError::Unsupported {
        message: message.into(),
        hint,
    }
}

/// Reject graph language at the PostgreSQL boundary before the bounded SQL
/// parser sees punctuation that belongs to ChironQL or SQL/PGQ. The scanner
/// deliberately keeps only unquoted words: graph-looking text in values,
/// comments, and quoted identifiers remains ordinary SQL data.
fn reject_graph_constructs(src: &str) -> ParseResult<()> {
    let statements = unquoted_statement_words(src);
    let graph = statements.iter().any(|words| {
        let first = words.first().map(String::as_str);
        let starts_native_graph = matches!(first, Some("relate" | "unrelate" | "traverse" | "match"));
        let updates_edge = matches!(words.as_slice(), [first, second, ..] if first == "update" && second == "edge");
        let graph_ddl = words.windows(2).any(|pair| {
            pair == ["property", "graph"]
                || pair == ["enable", "graph"]
                || pair == ["disable", "graph"]
        }) || (matches!(first, Some("create" | "alter" | "drop"))
            && words.get(1).is_some_and(|word| word == "graph"))
            || (matches!(first, Some("create" | "configure"))
                && words.windows(2).any(|pair| pair == ["edge", "type"]));
        let graph_clause = words.windows(2).any(|pair| {
            matches!(pair, [left, right] if (left == "connected" && right == "to")
                || (left == "edge" && right == "where")
                || (left == "allow" && right == "degraded"))
        }) || words.windows(3).any(|window| window[0] == "within" && window[2] == "hops");
        let native_retrieval_clause = matches!(first, Some("search" | "hybrid"))
            && words.iter().any(|word| {
                matches!(word.as_str(), "connected" | "via" | "direction" | "within")
            });
        let sql_graph_operator = words
            .iter()
            .any(|word| matches!(word.as_str(), "graph_table" | "cypher"));
        starts_native_graph
            || updates_edge
            || graph_ddl
            || graph_clause
            || native_retrieval_clause
            || sql_graph_operator
    });
    if graph {
        return Err(unsupported(
            "graph constructs are not supported by the PostgreSQL compatibility surface; use ChironQL or a native ChironDB protocol",
            "#graph",
        ));
    }
    Ok(())
}

fn unquoted_statement_words(src: &str) -> Vec<Vec<String>> {
    let bytes = src.as_bytes();
    let mut statements = vec![Vec::new()];
    let mut pos = 0;
    while pos < bytes.len() {
        match bytes[pos] {
            b'\'' | b'"' => {
                let quote = bytes[pos];
                pos += 1;
                while pos < bytes.len() {
                    if bytes[pos] == quote {
                        if bytes.get(pos + 1) == Some(&quote) {
                            pos += 2;
                        } else {
                            pos += 1;
                            break;
                        }
                    } else {
                        pos += 1;
                    }
                }
            }
            b'-' if bytes.get(pos + 1) == Some(&b'-') => {
                pos += 2;
                while pos < bytes.len() && bytes[pos] != b'\n' {
                    pos += 1;
                }
            }
            b'/' if bytes.get(pos + 1) == Some(&b'*') => {
                pos += 2;
                while pos + 1 < bytes.len() && !(bytes[pos] == b'*' && bytes[pos + 1] == b'/') {
                    pos += 1;
                }
                pos = (pos + 2).min(bytes.len());
            }
            b';' => {
                if !statements.last().is_some_and(Vec::is_empty) {
                    statements.push(Vec::new());
                }
                pos += 1;
            }
            byte if byte == b'_' || byte.is_ascii_alphabetic() => {
                let start = pos;
                pos += 1;
                while pos < bytes.len()
                    && (bytes[pos] == b'_' || bytes[pos].is_ascii_alphanumeric())
                {
                    pos += 1;
                }
                let word = std::str::from_utf8(&bytes[start..pos])
                    .expect("ASCII word scanner only captures ASCII bytes")
                    .to_ascii_lowercase();
                statements.last_mut().expect("initial statement").push(word);
            }
            byte if byte.is_ascii_digit() => {
                statements
                    .last_mut()
                    .expect("initial statement")
                    .push("\0".to_string());
                pos += 1;
                while pos < bytes.len() && (bytes[pos].is_ascii_digit() || bytes[pos] == b'.') {
                    pos += 1;
                }
            }
            byte if byte.is_ascii_whitespace() => pos += 1,
            _ => {
                // Preserve punctuation as a separator so ordinary SQL such
                // as `connected = to` cannot become the graph phrase
                // `CONNECTED TO` after scanning.
                statements
                    .last_mut()
                    .expect("initial statement")
                    .push("\0".to_string());
                pos += 1;
            }
        }
    }
    statements
}

// =========================================================================
// Parser
// =========================================================================

pub struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    fn new(src: &str) -> ParseResult<Self> {
        let mut lexer = Lexer::new(src);
        let mut tokens = Vec::new();
        loop {
            let t = lexer.next_token()?;
            let eof = matches!(t, Token::Eof);
            tokens.push(t);
            if eof {
                break;
            }
        }
        Ok(Self { tokens, pos: 0 })
    }

    fn peek(&self) -> &Token {
        &self.tokens[self.pos]
    }

    fn peek_ident(&self) -> Option<&str> {
        match self.peek() {
            Token::Ident(s) => Some(s.as_str()),
            _ => None,
        }
    }

    fn bump(&mut self) -> Token {
        let t = self.tokens[self.pos].clone();
        if !matches!(t, Token::Eof) {
            self.pos += 1;
        }
        t
    }

    fn expect_keyword(&mut self, kw: &str) -> ParseResult<()> {
        match self.peek() {
            Token::Ident(s) if s == kw => {
                self.pos += 1;
                Ok(())
            }
            other => Err(syntax(format!("expected `{kw}`, got {other:?}"))),
        }
    }

    fn consume_keyword(&mut self, kw: &str) -> bool {
        if matches!(self.peek(), Token::Ident(s) if s == kw) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn expect(&mut self, t: &Token) -> ParseResult<()> {
        if std::mem::discriminant(self.peek()) == std::mem::discriminant(t) {
            self.pos += 1;
            Ok(())
        } else {
            Err(syntax(format!("expected {t:?}, got {:?}", self.peek())))
        }
    }

    fn consume(&mut self, t: &Token) -> bool {
        if std::mem::discriminant(self.peek()) == std::mem::discriminant(t) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn parse_identifier(&mut self) -> ParseResult<String> {
        match self.bump() {
            Token::Ident(s) => Ok(s),
            Token::QuotedIdent(s) => Ok(s),
            other => Err(syntax(format!("expected identifier, got {other:?}"))),
        }
    }

    /// Parse one statement off the front of the token stream. Trailing
    /// semicolons / EOF are consumed by the caller.
    fn parse_statement(&mut self) -> ParseResult<Statement> {
        let kw = self
            .peek_ident()
            .ok_or_else(|| syntax(format!("expected statement keyword, got {:?}", self.peek())))?
            .to_string();
        match kw.as_str() {
            "create" => self.parse_create(),
            "insert" => self.parse_insert(),
            "select" => self.parse_select().map(Statement::Select),
            "delete" => self.parse_delete().map(Statement::Delete),
            "drop" => self.parse_drop(),
            "set" => self.parse_set(),
            "show" => self.parse_show(),
            "begin" | "start" => {
                self.pos += 1;
                // 'START TRANSACTION' / 'BEGIN'. Swallow optional 'transaction'/'work'.
                if matches!(self.peek_ident(), Some("transaction") | Some("work")) {
                    self.pos += 1;
                }
                Ok(Statement::TransactionControl(TxnKeyword::Begin))
            }
            "commit" => {
                self.pos += 1;
                if matches!(self.peek_ident(), Some("transaction") | Some("work")) {
                    self.pos += 1;
                }
                Ok(Statement::TransactionControl(TxnKeyword::Commit))
            }
            "rollback" => {
                self.pos += 1;
                Ok(Statement::TransactionControl(TxnKeyword::Rollback))
            }
            "savepoint" => {
                self.pos += 1;
                let _ = self.parse_identifier()?;
                Ok(Statement::TransactionControl(TxnKeyword::Savepoint))
            }
            "release" => {
                self.pos += 1;
                if self.consume_keyword("savepoint") {
                    let _ = self.parse_identifier()?;
                }
                Ok(Statement::TransactionControl(TxnKeyword::Release))
            }
            "with" => Err(unsupported(
                "CTE not supported; inline or split into separate statements against pgvector",
                "#cte",
            )),
            "explain" => {
                // `EXPLAIN <select>` stub plan is allowed by spec §7; full
                // `EXPLAIN ANALYZE` is rejected.
                self.pos += 1;
                if self.consume_keyword("analyze") {
                    return Err(unsupported(
                        "EXPLAIN ANALYZE not supported v1; stub plan only",
                        "#explain",
                    ));
                }
                // Parse and wrap as a SELECT for now. v1 returns a stub plan
                // string at dispatch time.
                self.parse_select().map(Statement::Select)
            }
            "prepare" | "execute" | "deallocate" => Err(unsupported(
                "extended query protocol not supported v1; use simple query mode",
                "#extended-protocol",
            )),
            "update" => Err(unsupported(
                "multi-table mutations not supported; single-table only",
                "#mutations",
            )),
            other => Err(syntax(format!("unrecognized statement keyword `{other}`"))),
        }
    }

    fn parse_create(&mut self) -> ParseResult<Statement> {
        self.expect_keyword("create")?;
        let next = self
            .peek_ident()
            .ok_or_else(|| syntax(format!("expected CREATE target, got {:?}", self.peek())))?
            .to_string();
        match next.as_str() {
            "extension" => {
                self.pos += 1;
                let if_not_exists =
                    self.consume_keyword("if") && self.expect_three("not", "exists")?;
                let name = self.parse_identifier()?;
                if name.eq_ignore_ascii_case("vector") {
                    Ok(Statement::CreateExtensionVector { if_not_exists })
                } else {
                    Err(unsupported(
                        format!("CREATE EXTENSION `{name}` not supported; vector only"),
                        "#extensions",
                    ))
                }
            }
            "table" => self.parse_create_table(),
            "index" | "unique" => self.parse_create_index(),
            other => Err(syntax(format!("unsupported CREATE target `{other}`"))),
        }
    }

    /// After `IF`, consume `NOT EXISTS` keywords.
    fn expect_three(&mut self, a: &str, b: &str) -> ParseResult<bool> {
        self.expect_keyword(a)?;
        self.expect_keyword(b)?;
        Ok(true)
    }

    fn parse_create_table(&mut self) -> ParseResult<Statement> {
        self.expect_keyword("table")?;
        let if_not_exists = if self.consume_keyword("if") {
            self.expect_three("not", "exists")?
        } else {
            false
        };
        let name = self.parse_identifier()?;
        self.expect(&Token::LParen)?;
        let mut columns = Vec::new();
        let mut saw_table_level_pk = false;
        loop {
            if let Token::Ident(s) = self.peek().clone() {
                if s == "primary" {
                    // PRIMARY KEY (col, ...) — capture pk, mark column as pk later.
                    self.pos += 1;
                    self.expect_keyword("key")?;
                    self.expect(&Token::LParen)?;
                    let pk_col = self.parse_identifier()?;
                    while self.consume(&Token::Comma) {
                        // Tolerate composite PK syntax for parse stage — but spec
                        // §3.2 only enforces single-id PK; multi-col PKs are out
                        // of scope, reject at dispatch.
                        let _ = self.parse_identifier()?;
                    }
                    self.expect(&Token::RParen)?;
                    if let Some(col) = columns
                        .iter_mut()
                        .find(|c: &&mut ColumnDef| c.name == pk_col)
                    {
                        col.primary_key = true;
                    }
                    saw_table_level_pk = true;
                } else if matches!(s.as_str(), "constraint" | "foreign" | "check" | "unique") {
                    return Err(unsupported(
                        format!("CREATE TABLE clause `{s}` not supported"),
                        "#ddl",
                    ));
                } else {
                    columns.push(self.parse_column_def()?);
                }
            } else {
                return Err(syntax(format!(
                    "expected column definition, got {:?}",
                    self.peek()
                )));
            }
            if self.consume(&Token::Comma) {
                continue;
            }
            break;
        }
        self.expect(&Token::RParen)?;
        let _ = saw_table_level_pk;
        Ok(Statement::CreateTable(CreateTable {
            if_not_exists,
            name,
            columns,
        }))
    }

    fn parse_column_def(&mut self) -> ParseResult<ColumnDef> {
        let name = self.parse_identifier()?;
        let data_type = self.parse_sql_type()?;
        let mut primary_key = false;
        let mut not_null = false;
        loop {
            match self.peek_ident() {
                Some("primary") => {
                    self.pos += 1;
                    self.expect_keyword("key")?;
                    primary_key = true;
                }
                Some("not") => {
                    self.pos += 1;
                    self.expect_keyword("null")?;
                    not_null = true;
                }
                Some("null") => {
                    self.pos += 1;
                }
                Some("default") => {
                    self.pos += 1;
                    // Skip default expression up to next comma/RParen.
                    while !matches!(self.peek(), Token::Comma | Token::RParen | Token::Eof) {
                        self.pos += 1;
                    }
                }
                Some("unique") => {
                    self.pos += 1;
                }
                _ => break,
            }
        }
        Ok(ColumnDef {
            name,
            data_type,
            primary_key,
            not_null,
        })
    }

    fn parse_sql_type(&mut self) -> ParseResult<SqlType> {
        let name = match self.bump() {
            Token::Ident(s) => s,
            other => return Err(syntax(format!("expected type name, got {other:?}"))),
        };
        let lower = name.to_ascii_lowercase();
        let ty = match lower.as_str() {
            "vector" => {
                self.expect(&Token::LParen)?;
                let n = match self.bump() {
                    Token::Int(i) if i > 0 => i as usize,
                    other => {
                        return Err(syntax(format!(
                            "expected positive dimension for vector(N), got {other:?}"
                        )));
                    }
                };
                self.expect(&Token::RParen)?;
                SqlType::Vector(n)
            }
            "int" | "integer" | "int4" => SqlType::Integer,
            "bigint" | "int8" => SqlType::BigInt,
            "smallint" | "int2" => SqlType::SmallInt,
            "real" | "float4" => SqlType::Real,
            "double" => {
                let _ = self.consume_keyword("precision");
                SqlType::DoublePrecision
            }
            "float8" => SqlType::DoublePrecision,
            "numeric" | "decimal" => {
                if self.consume(&Token::LParen) {
                    while !self.consume(&Token::RParen) {
                        self.pos += 1;
                    }
                }
                SqlType::Numeric
            }
            "text" => SqlType::Text,
            "varchar" | "character" => {
                let mut n = None;
                if lower == "character" {
                    let _ = self.consume_keyword("varying");
                }
                if self.consume(&Token::LParen) {
                    if let Token::Int(i) = self.bump() {
                        n = Some(i as usize);
                    }
                    self.expect(&Token::RParen)?;
                }
                SqlType::Varchar(n)
            }
            "bool" | "boolean" => SqlType::Boolean,
            "jsonb" | "json" => SqlType::Jsonb,
            "timestamp" | "timestamptz" => {
                if self.consume(&Token::LParen) {
                    while !self.consume(&Token::RParen) {
                        self.pos += 1;
                    }
                }
                // Tolerate optional WITH TIME ZONE clause for `timestamp`.
                let _ = self.consume_keyword("with");
                if matches!(self.peek_ident(), Some("time")) {
                    self.pos += 1;
                    let _ = self.consume_keyword("zone");
                }
                SqlType::Timestamp
            }
            other => {
                return Err(unsupported(
                    format!("SQL type `{other}` not supported"),
                    "#types",
                ));
            }
        };
        Ok(ty)
    }

    fn parse_create_index(&mut self) -> ParseResult<Statement> {
        let unique = self.consume_keyword("unique");
        if unique {
            return Err(unsupported("UNIQUE indexes not supported v1", "#index-am"));
        }
        self.expect_keyword("index")?;
        let if_not_exists = if self.consume_keyword("if") {
            self.expect_keyword("not")?;
            self.expect_keyword("exists")?;
            true
        } else {
            false
        };

        let index_name = if matches!(self.peek_ident(), Some("on")) {
            None
        } else {
            Some(self.parse_identifier()?)
        };
        self.expect_keyword("on")?;
        let table = self.parse_identifier()?;
        self.expect_keyword("using")?;
        let method_raw = self.parse_identifier()?;
        let method = match method_raw.to_ascii_lowercase().as_str() {
            "hnsw" => IndexMethod::Hnsw,
            "ivfflat" => {
                return Err(unsupported(
                    "ivfflat backend not supported v1; use `USING hnsw` or wait for RaBitQ (PC-1)",
                    "#index-am",
                ));
            }
            "rabitq" => IndexMethod::Rabitq,
            other => IndexMethod::Unknown(other.to_string()),
        };
        self.expect(&Token::LParen)?;
        let column = self.parse_identifier()?;
        let opclass = if matches!(self.peek(), Token::Ident(_) | Token::QuotedIdent(_)) {
            let raw = self.parse_identifier()?;
            Some(match raw.to_ascii_lowercase().as_str() {
                "vector_l2_ops" => OpClass::VectorL2Ops,
                "vector_ip_ops" => OpClass::VectorIpOps,
                "vector_cosine_ops" => OpClass::VectorCosineOps,
                _ => OpClass::Unknown(raw),
            })
        } else {
            None
        };
        self.expect(&Token::RParen)?;
        // Optional `WITH (m = 16, ef_construction = 64)` — parse + ignore (v1.1 plumbs).
        if self.consume_keyword("with") {
            self.expect(&Token::LParen)?;
            while !self.consume(&Token::RParen) {
                self.pos += 1;
            }
        }
        Ok(Statement::CreateIndex(CreateIndex {
            if_not_exists,
            index_name,
            table,
            method,
            column,
            opclass,
        }))
    }

    fn parse_drop(&mut self) -> ParseResult<Statement> {
        self.expect_keyword("drop")?;
        self.expect_keyword("table")?;
        let if_exists = if self.consume_keyword("if") {
            self.expect_keyword("exists")?;
            true
        } else {
            false
        };
        let mut names = vec![self.parse_identifier()?];
        while self.consume(&Token::Comma) {
            names.push(self.parse_identifier()?);
        }
        // Tolerate optional CASCADE / RESTRICT.
        let _ = self.consume_keyword("cascade") || self.consume_keyword("restrict");
        Ok(Statement::DropTable(DropTable { if_exists, names }))
    }

    fn parse_insert(&mut self) -> ParseResult<Statement> {
        self.expect_keyword("insert")?;
        self.expect_keyword("into")?;
        let table = self.parse_identifier()?;
        let mut columns = Vec::new();
        if self.consume(&Token::LParen) {
            columns.push(self.parse_identifier()?);
            while self.consume(&Token::Comma) {
                columns.push(self.parse_identifier()?);
            }
            self.expect(&Token::RParen)?;
        }
        self.expect_keyword("values")?;
        let mut rows = Vec::new();
        loop {
            self.expect(&Token::LParen)?;
            let mut row = vec![self.parse_expr()?];
            while self.consume(&Token::Comma) {
                row.push(self.parse_expr()?);
            }
            self.expect(&Token::RParen)?;
            rows.push(row);
            if !self.consume(&Token::Comma) {
                break;
            }
        }
        // Reject `RETURNING` for v1 (single-shape policy).
        if self.consume_keyword("returning") {
            return Err(unsupported("RETURNING not supported v1", "#dml"));
        }
        Ok(Statement::Insert(Insert {
            table,
            columns,
            rows,
        }))
    }

    fn parse_select(&mut self) -> ParseResult<Select> {
        self.expect_keyword("select")?;
        let mut projection = Vec::new();
        if self.consume(&Token::Star) {
            projection.push(SelectItem::Star);
        } else {
            projection.push(self.parse_select_item()?);
            while self.consume(&Token::Comma) {
                projection.push(self.parse_select_item()?);
            }
        }
        // FROM is required for our shapes (no SELECT without FROM).
        self.expect_keyword("from")?;
        let table = self.parse_identifier()?;
        // Optional table alias: `FROM items a` or `FROM items AS a`. Aliases
        // are recorded only positionally — qualified column refs use the
        // original table name internally.
        if self.consume_keyword("as") {
            let _ = self.parse_identifier()?;
        } else if let Token::Ident(s) = self.peek().clone()
            && !matches!(
                s.as_str(),
                "where"
                    | "group"
                    | "order"
                    | "limit"
                    | "having"
                    | "offset"
                    | "join"
                    | "left"
                    | "right"
                    | "cross"
                    | "inner"
                    | "outer"
                    | "full"
                    | "on"
                    | "using"
            )
        {
            self.pos += 1;
        }
        if matches!(self.peek_ident(), Some(kw) if matches!(kw, "join" | "left" | "right" | "cross" | "inner" | "outer" | "full"))
        {
            return Err(unsupported(
                "JOIN not supported in pgvector-compat mode; route relational queries to pgvector",
                "#joins",
            ));
        }
        if self.consume(&Token::Comma) {
            return Err(unsupported(
                "JOIN not supported in pgvector-compat mode; route relational queries to pgvector",
                "#joins",
            ));
        }
        let where_clause = if self.consume_keyword("where") {
            Some(self.parse_expr()?)
        } else {
            None
        };
        if matches!(self.peek_ident(), Some("group") | Some("having")) {
            return Err(unsupported(
                "analytical queries not supported; aggregate in your application layer",
                "#aggregates",
            ));
        }
        let order_by = if self.consume_keyword("order") {
            self.expect_keyword("by")?;
            let expr = self.parse_expr()?;
            let asc = if self.consume_keyword("desc") {
                false
            } else {
                let _ = self.consume_keyword("asc");
                true
            };
            Some(OrderBy { expr, asc })
        } else {
            None
        };
        let limit = if self.consume_keyword("limit") {
            match self.bump() {
                Token::Int(i) if i >= 0 => Some(i as u64),
                other => {
                    return Err(syntax(format!(
                        "LIMIT expects non-negative integer, got {other:?}"
                    )));
                }
            }
        } else {
            None
        };
        let _ = self.consume_keyword("offset"); // ignore offset value for parse stage
        if matches!(self.peek(), Token::Int(_)) {
            self.pos += 1;
        }
        Ok(Select {
            projection,
            table,
            where_clause,
            order_by,
            limit,
        })
    }

    fn parse_select_item(&mut self) -> ParseResult<SelectItem> {
        let expr = self.parse_expr()?;
        let alias = if self.consume_keyword("as") {
            Some(self.parse_identifier()?)
        } else if let Token::Ident(s) = self.peek().clone() {
            // Bare alias `col alias` — only accept when not a reserved word.
            if matches!(
                s.as_str(),
                "from" | "where" | "order" | "limit" | "group" | "having" | "offset" | "as"
            ) {
                None
            } else {
                self.pos += 1;
                Some(s)
            }
        } else {
            None
        };
        Ok(SelectItem::Expr { expr, alias })
    }

    fn parse_delete(&mut self) -> ParseResult<Delete> {
        self.expect_keyword("delete")?;
        self.expect_keyword("from")?;
        let table = self.parse_identifier()?;
        let where_clause = if self.consume_keyword("where") {
            Some(self.parse_expr()?)
        } else {
            None
        };
        if self.consume(&Token::Comma) {
            return Err(unsupported(
                "multi-table mutations not supported; single-table only",
                "#mutations",
            ));
        }
        Ok(Delete {
            table,
            where_clause,
        })
    }

    fn parse_set(&mut self) -> ParseResult<Statement> {
        self.expect_keyword("set")?;
        let name = self.parse_identifier()?;
        if !self.consume(&Token::Eq) {
            let _ = self.consume_keyword("to");
        }
        // Consume the value tokens up to ; or EOF — for SET shim we only need
        // to confirm the statement is well-formed.
        let mut value = String::new();
        while !matches!(self.peek(), Token::Semicolon | Token::Eof) {
            match self.bump() {
                Token::Ident(s) | Token::QuotedIdent(s) | Token::Str(s) => value.push_str(&s),
                Token::Int(i) => value.push_str(&i.to_string()),
                Token::Float(f) => value.push_str(&f.to_string()),
                Token::Comma => value.push(','),
                _ => {}
            }
            value.push(' ');
        }
        Ok(Statement::Set {
            name,
            value: value.trim().to_string(),
        })
    }

    fn parse_show(&mut self) -> ParseResult<Statement> {
        self.expect_keyword("show")?;
        let name = self.parse_identifier()?;
        Ok(Statement::Show { name })
    }

    // ===== Expression parser =====

    fn parse_expr(&mut self) -> ParseResult<Expr> {
        self.parse_or()
    }

    fn parse_or(&mut self) -> ParseResult<Expr> {
        let mut left = self.parse_and()?;
        while self.consume_keyword("or") {
            let right = self.parse_and()?;
            left = Expr::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_and(&mut self) -> ParseResult<Expr> {
        let mut left = self.parse_not()?;
        while self.consume_keyword("and") {
            let right = self.parse_not()?;
            left = Expr::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_not(&mut self) -> ParseResult<Expr> {
        if self.consume_keyword("not") {
            let inner = self.parse_not()?;
            return Ok(Expr::Not(Box::new(inner)));
        }
        self.parse_compare()
    }

    fn parse_compare(&mut self) -> ParseResult<Expr> {
        let left = self.parse_distance()?;
        let op = match self.peek() {
            Token::Eq => CmpOp::Eq,
            Token::Ne => CmpOp::Ne,
            Token::Lt => CmpOp::Lt,
            Token::Le => CmpOp::Le,
            Token::Gt => CmpOp::Gt,
            Token::Ge => CmpOp::Ge,
            Token::Ident(s) if s == "is" => {
                self.pos += 1;
                let negated = self.consume_keyword("not");
                self.expect_keyword("null")?;
                let cmp = if negated { CmpOp::Ne } else { CmpOp::Eq };
                return Ok(Expr::Compare {
                    left: Box::new(left),
                    op: cmp,
                    right: Box::new(Expr::Null),
                });
            }
            Token::Ident(s) if s == "in" => {
                self.pos += 1;
                self.expect(&Token::LParen)?;
                if matches!(self.peek_ident(), Some("select")) {
                    return Err(unsupported(
                        "subquery not supported; fetch IDs from pgvector then `WHERE id IN (…)`",
                        "#subquery",
                    ));
                }
                let mut list = Vec::new();
                if !matches!(self.peek(), Token::RParen) {
                    list.push(self.parse_expr()?);
                    while self.consume(&Token::Comma) {
                        list.push(self.parse_expr()?);
                    }
                }
                self.expect(&Token::RParen)?;
                return Ok(Expr::InList {
                    expr: Box::new(left),
                    list,
                    negated: false,
                });
            }
            _ => return Ok(left),
        };
        self.pos += 1;
        let right = self.parse_distance()?;
        Ok(Expr::Compare {
            left: Box::new(left),
            op,
            right: Box::new(right),
        })
    }

    fn parse_distance(&mut self) -> ParseResult<Expr> {
        let left = self.parse_primary()?;
        let op = match self.peek() {
            Token::OpL2 => VectorOp::L2,
            Token::OpDot => VectorOp::Dot,
            Token::OpCosine => VectorOp::Cosine,
            Token::OpL1 => {
                return Err(unsupported(
                    "L1 distance operator not supported; use `<->` (L2), `<#>` (dot), or `<=>` (cosine)",
                    "#operators",
                ));
            }
            _ => return Ok(left),
        };
        self.pos += 1;
        let right = self.parse_primary()?;
        Ok(Expr::Distance {
            left: Box::new(left),
            op,
            right: Box::new(right),
        })
    }

    fn parse_primary(&mut self) -> ParseResult<Expr> {
        match self.bump() {
            Token::LParen => {
                // Subquery rejection — `SELECT` inside parens.
                if matches!(self.peek_ident(), Some("select")) {
                    return Err(unsupported(
                        "subquery not supported; fetch IDs from pgvector then `WHERE id IN (…)`",
                        "#subquery",
                    ));
                }
                let inner = self.parse_expr()?;
                self.expect(&Token::RParen)?;
                Ok(inner)
            }
            Token::Int(i) => Ok(Expr::Integer(i)),
            Token::Float(f) => Ok(Expr::Number(f)),
            Token::Str(s) => Ok(Expr::String(s)),
            Token::VectorLit(v) => Ok(Expr::VectorLiteral(v)),
            Token::Ident(s) => {
                let lower = s.to_ascii_lowercase();
                if lower == "true" {
                    return Ok(Expr::Bool(true));
                }
                if lower == "false" {
                    return Ok(Expr::Bool(false));
                }
                if lower == "null" {
                    return Ok(Expr::Null);
                }
                // Possible function call.
                if matches!(self.peek(), Token::LParen) {
                    if matches!(
                        lower.as_str(),
                        "count" | "sum" | "avg" | "min" | "max" | "array_agg" | "string_agg"
                    ) {
                        return Err(unsupported(
                            "analytical queries not supported; aggregate in your application layer",
                            "#aggregates",
                        ));
                    }
                    self.pos += 1;
                    let mut args = Vec::new();
                    if !matches!(self.peek(), Token::RParen) {
                        args.push(self.parse_expr()?);
                        while self.consume(&Token::Comma) {
                            args.push(self.parse_expr()?);
                        }
                    }
                    self.expect(&Token::RParen)?;
                    return Ok(Expr::Func { name: lower, args });
                }
                // Qualified identifier `t.col`.
                if self.consume(&Token::Dot) {
                    let col = self.parse_identifier()?;
                    return Ok(Expr::QualifiedIdent(s, col));
                }
                Ok(Expr::Ident(s))
            }
            Token::QuotedIdent(s) => Ok(Expr::Ident(s)),
            other => Err(syntax(format!("unexpected token in expression: {other:?}"))),
        }
    }
}

/// Parse a `;`-separated list of statements. Empty input → empty list.
pub fn parse(src: &str) -> ParseResult<Vec<Statement>> {
    reject_graph_constructs(src)?;
    let mut parser = Parser::new(src)?;
    let mut out = Vec::new();
    loop {
        while parser.consume(&Token::Semicolon) {}
        if matches!(parser.peek(), Token::Eof) {
            break;
        }
        let stmt = parser.parse_statement()?;
        out.push(stmt);
        if !parser.consume(&Token::Semicolon) && !matches!(parser.peek(), Token::Eof) {
            return Err(syntax(format!(
                "expected `;` or end of query, got {:?}",
                parser.peek()
            )));
        }
    }
    Ok(out)
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_one(s: &str) -> Statement {
        let mut stmts = parse(s).expect("parse ok");
        assert_eq!(stmts.len(), 1, "{s:?}");
        stmts.pop().unwrap()
    }

    fn err(s: &str) -> ParseError {
        parse(s).expect_err("expected parse error")
    }

    #[test]
    fn create_extension_vector() {
        match parse_one("CREATE EXTENSION IF NOT EXISTS vector;") {
            Statement::CreateExtensionVector { if_not_exists } => assert!(if_not_exists),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn create_extension_other_rejected() {
        let e = err("CREATE EXTENSION postgis;");
        assert_eq!(e.sqlstate(), "0A000");
    }

    #[test]
    fn create_table_with_vector_column() {
        let stmt = parse_one(
            "CREATE TABLE items (id INTEGER PRIMARY KEY, embedding vector(1536) NOT NULL, name TEXT);",
        );
        match stmt {
            Statement::CreateTable(ct) => {
                assert_eq!(ct.name, "items");
                assert_eq!(ct.columns.len(), 3);
                assert!(ct.columns[0].primary_key);
                assert!(matches!(ct.columns[1].data_type, SqlType::Vector(1536)));
                assert!(ct.columns[1].not_null);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn insert_with_vector_literal() {
        let stmt =
            parse_one("INSERT INTO items (id, embedding) VALUES (1, '[0.1, 0.2, 0.3]'::vector);");
        match stmt {
            Statement::Insert(i) => {
                assert_eq!(i.table, "items");
                assert_eq!(i.columns, vec!["id".to_string(), "embedding".to_string()]);
                assert_eq!(i.rows.len(), 1);
                assert!(matches!(i.rows[0][0], Expr::Integer(1)));
                match &i.rows[0][1] {
                    Expr::VectorLiteral(v) => assert_eq!(v, &vec![0.1_f32, 0.2, 0.3]),
                    other => panic!("{other:?}"),
                }
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn select_order_by_distance_limit() {
        let stmt = parse_one(
            "SELECT id, embedding <-> '[0.1, 0.2]'::vector AS d FROM items ORDER BY embedding <-> '[0.1, 0.2]'::vector LIMIT 5;",
        );
        match stmt {
            Statement::Select(s) => {
                assert_eq!(s.table, "items");
                assert_eq!(s.projection.len(), 2);
                assert_eq!(s.limit, Some(5));
                let ob = s.order_by.unwrap();
                assert!(matches!(
                    ob.expr,
                    Expr::Distance {
                        op: VectorOp::L2,
                        ..
                    }
                ));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn select_where_translation_eq_and_and_in() {
        let stmt = parse_one(
            "SELECT * FROM items WHERE category = 'red' AND price < 100 AND tag IN (1, 2, 3);",
        );
        match stmt {
            Statement::Select(s) => {
                let w = s.where_clause.unwrap();
                // Outermost AND.
                assert!(matches!(w, Expr::And(_, _)));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn delete_where_id_eq() {
        let stmt = parse_one("DELETE FROM items WHERE id = 7;");
        match stmt {
            Statement::Delete(d) => {
                assert_eq!(d.table, "items");
                assert!(d.where_clause.is_some());
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn create_index_hnsw() {
        let stmt =
            parse_one("CREATE INDEX ON items USING hnsw (embedding vector_l2_ops) WITH (m = 16);");
        match stmt {
            Statement::CreateIndex(ci) => {
                assert_eq!(ci.table, "items");
                assert_eq!(ci.method, IndexMethod::Hnsw);
                assert_eq!(ci.column, "embedding");
                assert_eq!(ci.opclass, Some(OpClass::VectorL2Ops));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn drop_table_if_exists() {
        let stmt = parse_one("DROP TABLE IF EXISTS items, others;");
        match stmt {
            Statement::DropTable(d) => {
                assert!(d.if_exists);
                assert_eq!(d.names, vec!["items".to_string(), "others".to_string()]);
            }
            other => panic!("{other:?}"),
        }
    }

    // ===== Reject taxonomy — every row of §3.0.1 has a parser unit test =====

    #[test]
    fn reject_join_explicit() {
        let e = err("SELECT * FROM a JOIN b ON a.id = b.id;");
        assert_eq!(e.sqlstate(), "0A000");
        assert_eq!(e.hint(), Some("#joins"));
    }

    #[test]
    fn reject_join_comma() {
        let e = err("SELECT * FROM a, b WHERE a.id = b.id;");
        assert_eq!(e.sqlstate(), "0A000");
        assert_eq!(e.hint(), Some("#joins"));
    }

    #[test]
    fn reject_cte() {
        let e = err("WITH x AS (SELECT 1) SELECT * FROM x;");
        assert_eq!(e.sqlstate(), "0A000");
        assert_eq!(e.hint(), Some("#cte"));
    }

    #[test]
    fn reject_subquery() {
        let e = err("SELECT * FROM items WHERE id IN (SELECT id FROM other);");
        assert_eq!(e.sqlstate(), "0A000");
        assert_eq!(e.hint(), Some("#subquery"));
    }

    #[test]
    fn transactions_recognised_for_dispatch_reject() {
        match parse_one("BEGIN;") {
            Statement::TransactionControl(TxnKeyword::Begin) => {}
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn reject_prepare_execute() {
        let e = err("PREPARE q AS SELECT 1;");
        assert_eq!(e.sqlstate(), "0A000");
        assert_eq!(e.hint(), Some("#extended-protocol"));
    }

    #[test]
    fn reject_group_by_aggregates() {
        let e = err("SELECT category, count(*) FROM items GROUP BY category;");
        assert_eq!(e.sqlstate(), "0A000");
        assert_eq!(e.hint(), Some("#aggregates"));
    }

    #[test]
    fn reject_update_multi_table_is_just_update() {
        let e = err("UPDATE items SET x = 1;");
        assert_eq!(e.sqlstate(), "0A000");
        assert_eq!(e.hint(), Some("#mutations"));
    }

    #[test]
    fn reject_explain_analyze() {
        let e = err("EXPLAIN ANALYZE SELECT id FROM items;");
        assert_eq!(e.sqlstate(), "0A000");
        assert_eq!(e.hint(), Some("#explain"));
    }

    #[test]
    fn reject_using_ivfflat() {
        let e = err("CREATE INDEX ON items USING ivfflat (embedding vector_l2_ops);");
        assert_eq!(e.sqlstate(), "0A000");
        assert_eq!(e.hint(), Some("#index-am"));
    }

    #[test]
    fn reject_l1_operator() {
        let e = err("SELECT id FROM items ORDER BY embedding <+> '[1, 2]'::vector LIMIT 1;");
        assert_eq!(e.sqlstate(), "0A000");
        assert_eq!(e.hint(), Some("#operators"));
    }

    // ===== Vector literal edge cases =====

    #[test]
    fn vector_literal_empty_is_ok() {
        let v = parse_vector_literal_body("[]").unwrap();
        assert!(v.is_empty());
    }

    #[test]
    fn vector_literal_rejects_nan() {
        assert!(parse_vector_literal_body("[1.0, NaN]").is_err());
    }

    #[test]
    fn vector_literal_rejects_inf() {
        assert!(parse_vector_literal_body("[1.0, Infinity]").is_err());
    }

    #[test]
    fn vector_literal_negative_components() {
        let v = parse_vector_literal_body("[-0.5, 1.5, -2.0]").unwrap();
        assert_eq!(v, vec![-0.5, 1.5, -2.0]);
    }

    #[test]
    fn multi_statement_parse() {
        let stmts =
            parse("CREATE EXTENSION vector; CREATE TABLE x (id INTEGER, e vector(4));").unwrap();
        assert_eq!(stmts.len(), 2);
    }

    #[test]
    fn set_application_name_accepted() {
        match parse_one("SET application_name = 'gaussdb-test';") {
            Statement::Set { name, .. } => assert_eq!(name, "application_name"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn show_server_version_accepted() {
        match parse_one("SHOW server_version;") {
            Statement::Show { name } => assert_eq!(name, "server_version"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn graph_constructs_reject_with_feature_not_supported() {
        for sql in [
            "RELATE docs root -> CITES -> child;",
            "UNRELATE docs EDGE opaque-token;",
            "UPDATE EDGE opaque-token SET {weight: 1};",
            "TRAVERSE docs FROM root VIA CITES RETURN NODES;",
            "SEARCH docs NEAR [1,0] CONNECTED TO root VIA CITES;",
            "HYBRID docs DENSE [1,0] CONNECTED TO root;",
            "SELECT id FROM items CONNECTED TO root WITHIN 2 HOPS;",
            "SELECT * FROM GRAPH_TABLE (docs MATCH (a)-[e]->(b));",
            "SELECT * FROM cypher('docs', 'MATCH (n) RETURN n');",
            "CREATE PROPERTY GRAPH docs_graph;",
        ] {
            let error = err(sql);
            assert_eq!(error.sqlstate(), "0A000", "{sql}: {error}");
            assert_eq!(error.hint(), Some("#graph"), "{sql}: {error}");
        }
    }

    #[test]
    fn graph_words_in_sql_data_and_identifiers_are_not_graph_constructs() {
        parse("CREATE TABLE graph (id INTEGER PRIMARY KEY, embedding vector(2), traverse TEXT, connected TEXT, to TEXT);")
            .expect("graph may remain an unquoted table name");
        parse("INSERT INTO graph (id, embedding, traverse) VALUES (1, '[0,0]'::vector, 'CONNECTED TO root VIA cites');")
            .expect("graph-looking string data is not a graph construct");
        parse("SELECT traverse FROM graph; -- TRAVERSE docs FROM root")
            .expect("column names and comments do not trigger graph rejection");
        parse("SELECT connected FROM graph WHERE connected = to;")
            .expect("punctuation between graph-like column names is not a clause");
        parse("SELECT \"traverse\" FROM \"graph\";")
            .expect("quoted identifiers do not trigger graph rejection");
    }
}
