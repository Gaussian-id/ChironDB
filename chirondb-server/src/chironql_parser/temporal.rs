use super::*;
use chirondb_core::db::temporal::{MAX_BATCH, MAX_HISTORY, SensorValue, TemporalSample};

#[derive(Clone, Debug, PartialEq)]
pub enum AssetSelector {
    Id(String),
    Field(PipelineField),
}
#[derive(Clone, Debug, PartialEq)]
pub struct TemporalRead {
    pub collection: String,
    pub asset: AssetSelector,
    pub property: String,
    pub range: Option<(i64, i64, usize)>,
}
#[derive(Clone, Debug, PartialEq)]
pub struct TemporalStage {
    pub alias: String,
    pub query: TemporalRead,
}

impl Parser {
    fn temporal_time(&mut self) -> ParseResult<i64> {
        let at = self.at();
        self.expect_string()?.parse().map_err(|_| {
            ParseError::new(
                "chironql.invalid_timestamp",
                "expected a signed decimal nanosecond string",
                at,
            )
        })
    }
    pub(super) fn parse_temporal(&mut self) -> ParseResult<Statement> {
        if self.eat_keyword("APPEND") {
            self.expect_keyword("INTO")?;
            let collection = self.expect_word()?;
            self.expect(&Tok::LBracket)?;
            let mut samples = Vec::new();
            loop {
                if samples.len() == MAX_BATCH {
                    return Err(ParseError::new(
                        "chironql.invalid_temporal_batch",
                        "temporal batch exceeds limit",
                        self.at(),
                    ));
                }
                self.expect(&Tok::LBrace)?;
                let (mut asset, mut property, mut time, mut value) = (None, None, None, None);
                loop {
                    let key = match self.peek() {
                        Some(Tok::Str(_)) => self.expect_string()?,
                        _ => self.expect_word()?,
                    };
                    self.expect(&Tok::Colon)?;
                    match key.as_str() {
                        "asset" if asset.is_none() => asset = Some(self.expect_string()?),
                        "property" if property.is_none() => property = Some(self.expect_string()?),
                        "time_ns" if time.is_none() => time = Some(self.temporal_time()?),
                        "value" if value.is_none() => {
                            value = Some(if self.eat_keyword("true") {
                                SensorValue::Boolean(true)
                            } else if self.eat_keyword("false") {
                                SensorValue::Boolean(false)
                            } else {
                                SensorValue::Float(self.expect_number()?)
                            })
                        }
                        _ => {
                            return Err(ParseError::new(
                                "chironql.invalid_temporal_batch",
                                "unknown or repeated temporal field",
                                self.at(),
                            ));
                        }
                    }
                    if !self.eat(&Tok::Comma) {
                        break;
                    }
                }
                self.expect(&Tok::RBrace)?;
                let (Some(a), Some(p), Some(t), Some(v)) = (asset, property, time, value) else {
                    return Err(ParseError::new(
                        "chironql.invalid_temporal_batch",
                        "asset, property, time_ns and value required",
                        self.at(),
                    ));
                };
                samples.push(TemporalSample::new(a, p, t, v));
                if !self.eat(&Tok::Comma) {
                    break;
                }
            }
            self.expect(&Tok::RBracket)?;
            return Ok(Statement::TemporalAppend {
                collection,
                samples,
            });
        }
        let history = self.eat_keyword("HISTORY");
        if !history {
            self.expect_keyword("LATEST")?;
        }
        let collection = self.expect_word()?;
        self.expect_keyword("ASSET")?;
        let asset = match self.peek() {
            Some(Tok::Str(_)) => AssetSelector::Id(self.expect_string()?),
            _ => AssetSelector::Field(parse_pipeline_field(&self.expect_word()?, self.at())?),
        };
        self.expect_keyword("PROPERTY")?;
        let property = self.expect_string()?;
        let range = if history {
            self.expect_keyword("FROM")?;
            let lo = self.temporal_time()?;
            self.expect_keyword("TO")?;
            let hi = self.temporal_time()?;
            self.expect_keyword("LIMIT")?;
            let n = self.expect_usize()?;
            if lo > hi || !(1..=MAX_HISTORY).contains(&n) {
                return Err(ParseError::new(
                    "chironql.invalid_temporal_range",
                    "range or LIMIT outside allowed bounds",
                    self.at(),
                ));
            }
            Some((lo, hi, n))
        } else {
            None
        };
        Ok(Statement::TemporalRead(TemporalRead {
            collection,
            asset,
            property,
            range,
        }))
    }
}
