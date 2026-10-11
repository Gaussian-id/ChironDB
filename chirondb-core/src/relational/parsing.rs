//! One span-preserving token stream for relational parsing and its controls.
//! Token/AST allocation admission is separate from avoiding duplicate ownership.
use super::{
    InteractiveControl, ParsedRelationalStatement, Result, SetConstraintsStatement,
    SetConstraintsTarget, invalid, normalize_ident,
};
use sqlparser::{
    dialect::PostgreSqlDialect,
    parser::Parser,
    tokenizer::{Token, TokenWithSpan, Tokenizer},
};

fn tokenize(sql: &str) -> Result<Vec<TokenWithSpan>> {
    Tokenizer::new(&PostgreSqlDialect {}, sql)
        .tokenize_with_location()
        .map_err(|error| invalid(format!("SQL tokenize error: {error}")))
}

pub(super) fn parse_relational_statement(sql: &str) -> Result<ParsedRelationalStatement> {
    let mut tokens = tokenize(sql)?;
    let mut significant = tokens
        .iter()
        .map(|token| &token.token)
        .filter(|token| !matches!(token, Token::Whitespace(_)));
    let set_constraints = significant
        .next()
        .is_some_and(|token| token_word_eq(token, "set"))
        && significant
            .next()
            .is_some_and(|token| token_word_eq(token, "constraints"));
    if set_constraints {
        tokens.retain(|token| !matches!(token.token, Token::Whitespace(_)));
        return parse_set_constraints_tokens(&tokens)
            .map(ParsedRelationalStatement::SetConstraints);
    }
    // Keep whitespace and original locations for the upstream grammar. Move
    // this buffer into Parser instead of tokenizing SQL again while retaining
    // the first buffer. Defaults match Parser::parse_sql (including unescape).
    let mut parser = Parser::new(&PostgreSqlDialect {}).with_tokens_with_locations(tokens);
    while parser.consume_token(&Token::SemiColon) {}
    if matches!(parser.peek_token_ref().token, Token::EOF) {
        return Err(invalid(
            "each SQL statement entry must contain exactly one statement",
        ));
    }
    let parse_error = |error| invalid(format!("SQL parse error: {error}"));
    let statement = parser.parse_statement().map_err(parse_error)?;
    let mut delimiter = false;
    while parser.consume_token(&Token::SemiColon) {
        delimiter = true;
    }
    if !matches!(parser.peek_token_ref().token, Token::EOF) {
        if delimiter {
            return Err(invalid(
                "each SQL statement entry must contain exactly one statement",
            ));
        }
        // parse_statements is also a block parser: it can stop at END while
        // leaving input unread. A native request must consume the entire entry.
        return parser
            .expected_ref("end of statement", parser.peek_token_ref())
            .map_err(parse_error);
    }
    drop(parser);
    Ok(ParsedRelationalStatement::Sql(Box::new(statement)))
}

fn parse_set_constraints_tokens(tokens: &[TokenWithSpan]) -> Result<SetConstraintsStatement> {
    let mut tokens = tokens;
    if matches!(
        tokens.last().map(|token| &token.token),
        Some(Token::SemiColon)
    ) {
        tokens = &tokens[..tokens.len() - 1];
    }
    if tokens.len() < 4 {
        return Err(invalid(
            "SET CONSTRAINTS requires ALL or constraint names and IMMEDIATE or DEFERRED",
        ));
    }
    let deferred = if token_word_eq(&tokens.last().expect("length checked").token, "deferred") {
        true
    } else if token_word_eq(&tokens.last().expect("length checked").token, "immediate") {
        false
    } else {
        return Err(invalid(
            "SET CONSTRAINTS must end with IMMEDIATE or DEFERRED",
        ));
    };
    let body = &tokens[2..tokens.len() - 1];
    let target = if body.len() == 1 && token_word_eq(&body[0].token, "all") {
        SetConstraintsTarget::All
    } else {
        let mut names = Vec::new();
        let mut expect_name = true;
        for token in body {
            let token = &token.token;
            if expect_name {
                let Token::Word(word) = token else {
                    return Err(invalid("SET CONSTRAINTS expects a constraint name"));
                };
                names.push(normalize_ident(&word.value));
            } else if !matches!(token, Token::Comma) {
                return Err(invalid("SET CONSTRAINTS names must be comma separated"));
            }
            expect_name = !expect_name;
        }
        if names.is_empty() || expect_name {
            return Err(invalid("SET CONSTRAINTS has an incomplete constraint list"));
        }
        SetConstraintsTarget::Names(names)
    };
    Ok(SetConstraintsStatement { target, deferred })
}

fn token_word_eq(token: &Token, expected: &str) -> bool {
    matches!(token, Token::Word(word) if word.value.eq_ignore_ascii_case(expected))
}

pub(super) fn parse_interactive_control(sql: &str) -> Result<Option<InteractiveControl>> {
    let mut tokens = tokenize(sql)?;
    tokens.retain(|token| !matches!(token.token, Token::Whitespace(_)));
    if matches!(
        tokens.last().map(|token| &token.token),
        Some(Token::SemiColon)
    ) {
        tokens.pop();
    }
    let name = |token: &TokenWithSpan| match &token.token {
        Token::Word(word) => Ok(normalize_ident(&word.value)),
        _ => Err(invalid("savepoint name must be an identifier")),
    };
    match tokens.as_slice() {
        [savepoint, value] if token_word_eq(&savepoint.token, "savepoint") => {
            Ok(Some(InteractiveControl::Savepoint(name(value)?)))
        }
        [rollback, to, value]
            if token_word_eq(&rollback.token, "rollback") && token_word_eq(&to.token, "to") =>
        {
            Ok(Some(InteractiveControl::RollbackTo(name(value)?)))
        }
        [rollback, to, savepoint, value]
            if token_word_eq(&rollback.token, "rollback")
                && token_word_eq(&to.token, "to")
                && token_word_eq(&savepoint.token, "savepoint") =>
        {
            Ok(Some(InteractiveControl::RollbackTo(name(value)?)))
        }
        [release, value] if token_word_eq(&release.token, "release") => {
            Ok(Some(InteractiveControl::Release(name(value)?)))
        }
        [release, savepoint, value]
            if token_word_eq(&release.token, "release")
                && token_word_eq(&savepoint.token, "savepoint") =>
        {
            Ok(Some(InteractiveControl::Release(name(value)?)))
        }
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reused_tokens_match_upstream_ast_with_comments_literals_and_locations() {
        let samples = [
            "-- heading\nSELECT id FROM items WHERE id = 1",
            "; /* empty entry */ ; SELECT id FROM items; ; -- tail",
            "SELECT 'SET CONSTRAINTS ALL DEFERRED', 'one''two', E'line\\nnext' FROM items",
            "SELECT $$SAVEPOINT misleading;$$ FROM items",
            "SELECT 'first'\n'second' FROM items",
            "SELECT \"雪\" FROM \"quoted table\" WHERE \"雪\" IS NOT NULL",
            "WITH a AS (SELECT id FROM items) SELECT id FROM a",
            "SELECT id FROM items WHERE id IN (SELECT id FROM others)",
            "CREATE TABLE child (id BIGINT PRIMARY KEY, parent BIGINT REFERENCES parents(id) DEFERRABLE INITIALLY DEFERRED)",
            "INSERT INTO items VALUES (1, '/*not comment*/'), (2, '雪') RETURNING id",
            "UPDATE items SET id = id + 1 WHERE id BETWEEN 1 AND 3",
            "SELECT id\nFROM items\nWHERE id = )",
            "SELECT id FROM items WHERE id =",
        ];
        for sql in samples {
            let expected = Parser::parse_sql(&PostgreSqlDialect {}, sql);
            match (parse_relational_statement(sql), expected) {
                (Ok(ParsedRelationalStatement::Sql(actual)), Ok(mut expected)) => {
                    assert_eq!(expected.len(), 1);
                    assert_eq!(*actual, expected.remove(0), "{sql}");
                }
                (Err(actual), Err(expected)) => {
                    assert!(
                        actual.to_string().ends_with(&expected.to_string()),
                        "{sql}: {actual} vs {expected}"
                    );
                }
                (actual, expected) => panic!("{sql}: {actual:?} vs {expected:?}"),
            }
        }
        let error = parse_relational_statement("SELECT id\nFROM items\nWHERE id = )")
            .unwrap_err()
            .to_string();
        assert!(error.contains("Line: 3"), "{error}");
    }

    #[test]
    fn custom_constraints_and_savepoints_ignore_comments_without_reparsing() {
        let ParsedRelationalStatement::SetConstraints(mode) = parse_relational_statement(
            "/* prefix */ SET /* gap */ CONSTRAINTS \"First\", second DEFERRED; -- tail",
        )
        .unwrap() else {
            panic!("constraints")
        };
        assert!(mode.deferred);
        let SetConstraintsTarget::Names(names) = mode.target else {
            panic!("names")
        };
        assert_eq!(names, ["first", "second"]);
        let ParsedRelationalStatement::SetConstraints(mode) =
            parse_relational_statement("SET\nCONSTRAINTS ALL IMMEDIATE /* tail */;").unwrap()
        else {
            panic!("constraints")
        };
        assert!(!mode.deferred);
        assert!(matches!(mode.target, SetConstraintsTarget::All));
        for sql in [
            "SET CONSTRAINTS ALL",
            "SET CONSTRAINTS one, DEFERRED",
            "SET CONSTRAINTS one two DEFERRED",
            "SET CONSTRAINTS ALL DEFERRED; SELECT 1",
        ] {
            assert!(parse_relational_statement(sql).is_err(), "{sql}");
        }
        assert!(
            matches!(parse_interactive_control("-- prefix\n SAVEPOINT \"Anchor\"; /* tail */").unwrap(), Some(InteractiveControl::Savepoint(name)) if name == "anchor")
        );
        for sql in [
            "ROLLBACK TO anchor",
            "ROLLBACK /* gap */ TO SAVEPOINT anchor;",
        ] {
            assert!(
                matches!(parse_interactive_control(sql).unwrap(), Some(InteractiveControl::RollbackTo(name)) if name == "anchor")
            );
        }
        for sql in ["RELEASE anchor", "RELEASE /* gap */ SAVEPOINT anchor;"] {
            assert!(
                matches!(parse_interactive_control(sql).unwrap(), Some(InteractiveControl::Release(name)) if name == "anchor")
            );
        }
        assert!(parse_interactive_control("SAVEPOINT 1").is_err());
        assert!(
            parse_interactive_control("SELECT 'SAVEPOINT anchor' FROM items")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn empty_multiple_and_lexically_invalid_entries_keep_their_rejection_contract() {
        for sql in [
            "",
            "-- empty",
            ";",
            "SELECT id FROM items; DELETE FROM items",
        ] {
            let error = parse_relational_statement(sql).unwrap_err().to_string();
            assert!(error.contains("exactly one statement"), "{sql}: {error}");
        }
        for sql in ["SELECT 'unterminated", "SELECT 1 /* unterminated"] {
            let expected = Tokenizer::new(&PostgreSqlDialect {}, sql)
                .tokenize_with_location()
                .unwrap_err()
                .to_string();
            let actual = parse_relational_statement(sql).unwrap_err().to_string();
            assert!(actual.contains("SQL tokenize error:"));
            assert!(actual.ends_with(&expected), "{actual} vs {expected}");
        }
    }

    #[test]
    fn trailing_block_terminator_cannot_publish_a_statement_prefix() {
        use crate::{
            RelationalEngine, RelationalValue, SqlExecutionRequest, SqlResult, SqlStatementRequest,
            transaction_journal::TransactionJournal,
        };
        let root = tempfile::tempdir().unwrap();
        let engine =
            RelationalEngine::open(root.path(), TransactionJournal::open(root.path()).unwrap())
                .unwrap();
        let request = |sql: &str| SqlExecutionRequest {
            statements: vec![SqlStatementRequest {
                sql: sql.into(),
                parameters: Vec::new(),
            }],
            retry_id: None,
            idempotency_key: None,
        };
        engine
            .execute(request("CREATE TABLE items (id BIGINT PRIMARY KEY)"))
            .unwrap();
        for sql in [
            "INSERT INTO items VALUES (1) END",
            "INSERT INTO items VALUES (2) END DELETE FROM items",
            "INSERT INTO items VALUES (3); INSERT INTO items VALUES (4)",
        ] {
            assert!(
                engine.execute(request(sql)).is_err(),
                "must reject all input: {sql}"
            );
        }
        let response = engine
            .execute(request("SELECT COUNT(*) FROM items"))
            .unwrap()
            .response;
        let SqlResult::Rows { rows, .. } = &response.results[0] else {
            panic!("rows")
        };
        assert_eq!(rows, &vec![vec![RelationalValue::Integer(0)]]);
    }
}
