//! Schema checks shared by ML materialization submission and refresh.

use chirondb_types::{RelationalType, TableDefinition};

use crate::chironql_parser::{MlMaterialize, MlTask};

pub(crate) fn validate_source(
    definition: &MlMaterialize,
    tables: &[TableDefinition],
) -> Result<(), &'static str> {
    let table = tables
        .iter()
        .find(|table| table.name.eq_ignore_ascii_case(&definition.source))
        .ok_or("source table does not exist")?;
    if table.primary_key.is_empty() {
        return Err("source table needs a primary key");
    }
    if table
        .primary_key
        .iter()
        .any(|key| key.eq_ignore_ascii_case(&definition.target))
    {
        return Err("target cannot be a primary key");
    }
    for key in &table.primary_key {
        if ["actual", "prediction", "confidence", "refresh_version"]
            .iter()
            .any(|reserved| key.eq_ignore_ascii_case(reserved))
        {
            return Err("primary key name conflicts with ML output column");
        }
        let column = table
            .columns
            .iter()
            .find(|column| column.name.eq_ignore_ascii_case(key))
            .ok_or("primary key column does not exist")?;
        if !matches!(
            column.data_type,
            RelationalType::SmallInt
                | RelationalType::Integer
                | RelationalType::BigInt
                | RelationalType::Text
                | RelationalType::Varchar { .. }
                | RelationalType::Uuid
        ) {
            return Err("primary key type is unsupported for ML views");
        }
    }
    let target = table
        .columns
        .iter()
        .find(|column| column.name.eq_ignore_ascii_case(&definition.target))
        .ok_or("target column does not exist")?;
    match definition.task {
        MlTask::Regression => {
            if !matches!(
                target.data_type,
                RelationalType::SmallInt
                    | RelationalType::Integer
                    | RelationalType::BigInt
                    | RelationalType::Real
                    | RelationalType::Float
                    | RelationalType::Decimal { .. }
            ) {
                return Err("regression target must be numeric");
            }
        }
        MlTask::Classification => {
            if !matches!(
                target.data_type,
                RelationalType::Boolean
                    | RelationalType::SmallInt
                    | RelationalType::Integer
                    | RelationalType::BigInt
                    | RelationalType::Text
                    | RelationalType::Varchar { .. }
            ) {
                return Err("classification target must be boolean, integer, or text");
            }
        }
    }
    for feature in &definition.features {
        if ["actual", "prediction", "confidence", "refresh_version"]
            .iter()
            .any(|reserved| feature.eq_ignore_ascii_case(reserved))
        {
            return Err("feature name conflicts with ML output column");
        }
        if feature.eq_ignore_ascii_case(&definition.target) {
            return Err("target cannot be a feature");
        }
        if table
            .primary_key
            .iter()
            .any(|key| key.eq_ignore_ascii_case(feature))
        {
            return Err("primary key cannot be a feature");
        }
        let column = table
            .columns
            .iter()
            .find(|column| column.name.eq_ignore_ascii_case(feature))
            .ok_or("feature column does not exist")?;
        if !matches!(
            column.data_type,
            RelationalType::Boolean
                | RelationalType::SmallInt
                | RelationalType::Integer
                | RelationalType::BigInt
                | RelationalType::Real
                | RelationalType::Float
                | RelationalType::Decimal { .. }
                | RelationalType::Text
                | RelationalType::Varchar { .. }
                | RelationalType::Date
                | RelationalType::TimestampUtc
        ) {
            return Err("feature type must be numeric, categorical, or date/time");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chironql_parser::{MlModel, MlTask};
    use chirondb_types::RelationalColumn;

    fn table() -> TableDefinition {
        TableDefinition {
            table_id: 1,
            security_incarnation: None,
            creator_principal_id: None,
            reference_index_ids: Default::default(),
            tenant_id: None,
            managed_by_ml: false,
            name: "sales".into(),
            columns: [
                ("id", RelationalType::Integer),
                ("price", RelationalType::Float),
                ("region", RelationalType::Text),
                ("sale_date", RelationalType::Date),
                ("demand", RelationalType::Float),
            ]
            .into_iter()
            .map(|(name, data_type)| RelationalColumn {
                name: name.into(),
                data_type,
                nullable: true,
                default: None,
                identity: None,
            })
            .collect(),
            primary_key: vec!["id".into()],
            primary_key_name: None,
            primary_key_index_id: None,
            unique_constraints: Vec::new(),
            check_constraints: Vec::new(),
            foreign_keys: Vec::new(),
            indexes: Vec::new(),
        }
    }

    fn definition() -> MlMaterialize {
        MlMaterialize {
            view: "forecast".into(),
            source: "sales".into(),
            target: "demand".into(),
            features: vec!["price".into(), "region".into(), "sale_date".into()],
            task: MlTask::Regression,
            model: MlModel::DecisionTree,
        }
    }

    #[test]
    fn accepts_numeric_categorical_and_date_features() {
        assert_eq!(validate_source(&definition(), &[table()]), Ok(()));
    }

    #[test]
    fn rejects_missing_key_target_leakage_and_wrong_target_type() {
        let mut source = table();
        source.primary_key.clear();
        assert_eq!(
            validate_source(&definition(), &[source]),
            Err("source table needs a primary key")
        );

        let mut candidate = definition();
        candidate.features.push("demand".into());
        assert_eq!(
            validate_source(&candidate, &[table()]),
            Err("target cannot be a feature")
        );

        candidate.features.pop();
        candidate.target = "region".into();
        assert_eq!(
            validate_source(&candidate, &[table()]),
            Err("regression target must be numeric")
        );

        candidate = definition();
        candidate.features.push("id".into());
        assert_eq!(
            validate_source(&candidate, &[table()]),
            Err("primary key cannot be a feature")
        );
    }
}
