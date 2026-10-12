use std::path::PathBuf;

use serde::Deserialize;

#[derive(Deserialize)]
struct Corpus {
    language: String,
    examples: Vec<Example>,
}

#[derive(Deserialize)]
struct Example {
    id: String,
    sql: String,
    mode: String,
}

#[test]
fn documented_chironql_1_0_through_1_4_corpus_keeps_its_parse_contract() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/chironql_documentation.json");
    let corpus: Corpus =
        serde_json::from_slice(&std::fs::read(path).expect("read corpus")).expect("decode corpus");
    assert_eq!(corpus.language, chirondb::chironql_parser::LANGUAGE_VERSION);

    for example in corpus.examples {
        let parsed = chirondb::chironql_parser::parse(&example.sql);
        if example.mode == "reject" {
            assert!(parsed.is_err(), "{} must remain rejected", example.id);
        } else {
            assert!(
                parsed.is_ok(),
                "{} must remain valid: {parsed:?}",
                example.id
            );
        }
    }
}
