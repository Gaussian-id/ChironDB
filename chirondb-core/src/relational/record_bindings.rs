//! Bind only explicit NEW_RECORD expressions in atomic INSERT VALUES.
use super::*;

impl RelationalEngine {
    pub(crate) fn bind_new_records(
        mut request: SqlExecutionRequest,
        records: &BTreeMap<String, crate::RecordRef>,
    ) -> Result<SqlExecutionRequest> {
        for item in &mut request.statements {
            let ParsedRelationalStatement::Sql(mut statement) =
                parse_relational_statement(&item.sql)?
            else {
                return Err(invalid("atomic create requires INSERT VALUES"));
            };
            let Statement::Insert(insert) = statement.as_mut() else {
                return Err(invalid("atomic create requires INSERT VALUES"));
            };
            if insert.on.is_some() {
                return Err(invalid(
                    "atomic create does not support ON CONFLICT; retry with the original idempotency_key",
                ));
            }
            let Some(source) = insert.source.as_mut() else {
                return Err(invalid("atomic create requires VALUES"));
            };
            let SetExpr::Values(values) = source.body.as_mut() else {
                return Err(invalid("atomic create requires VALUES"));
            };
            for row in &mut values.rows {
                for expression in row.iter_mut() {
                    bind_expression(expression, records, 0)?;
                }
            }
            item.sql = statement.to_string();
        }
        Ok(request)
    }
}

fn bind_expression(
    expression: &mut Expr,
    records: &BTreeMap<String, crate::RecordRef>,
    depth: usize,
) -> Result<()> {
    if depth >= 32 {
        return Err(invalid("record binding expression is too deep"));
    }
    match expression {
        Expr::Cast { expr, .. } | Expr::Nested(expr) => bind_expression(expr, records, depth + 1),
        Expr::Function(function)
            if function.name.to_string().eq_ignore_ascii_case("record_ref") =>
        {
            plain_function(function)?;
            let FunctionArguments::List(args) = &mut function.args else {
                return Err(invalid("RECORD_REF requires two positional arguments"));
            };
            if args.args.len() != 2
                || !args.clauses.is_empty()
                || args.duplicate_treatment.is_some()
            {
                return Err(invalid("RECORD_REF requires two positional arguments"));
            }
            let namespace = match &args.args[0] {
                FunctionArg::Unnamed(FunctionArgExpr::Expr(Expr::Value(value))) => {
                    match &value.value {
                        Value::SingleQuotedString(namespace) => namespace.to_ascii_lowercase(),
                        _ => return Err(invalid("RECORD_REF namespace must be a string literal")),
                    }
                }
                _ => return Err(invalid("RECORD_REF namespace must be a string literal")),
            };
            let FunctionArg::Unnamed(FunctionArgExpr::Expr(Expr::Function(binding))) =
                &args.args[1]
            else {
                return Ok(());
            };
            if !binding.name.to_string().eq_ignore_ascii_case("new_record") {
                return Err(invalid("RECORD_REF binding requires NEW_RECORD('binding')"));
            }
            plain_function(binding)?;
            let FunctionArguments::List(binding_args) = &binding.args else {
                return Err(invalid("NEW_RECORD requires one binding name"));
            };
            let [FunctionArg::Unnamed(FunctionArgExpr::Expr(Expr::Value(value)))] =
                binding_args.args.as_slice()
            else {
                return Err(invalid("NEW_RECORD requires one binding name"));
            };
            if !binding_args.clauses.is_empty() || binding_args.duplicate_treatment.is_some() {
                return Err(invalid("NEW_RECORD requires one binding name"));
            }
            let Value::SingleQuotedString(name) = &value.value else {
                return Err(invalid("NEW_RECORD binding must be a string literal"));
            };
            let record = records
                .get(name)
                .filter(|record| record.namespace == namespace)
                .ok_or_else(|| invalid("unknown or cross-collection NEW_RECORD binding"))?;
            args.args[1] = FunctionArg::Unnamed(FunctionArgExpr::Expr(Expr::Value(
                Value::SingleQuotedString(record.id.clone()).into(),
            )));
            Ok(())
        }
        _ => Ok(()),
    }
}

fn plain_function(function: &sqlparser::ast::Function) -> Result<()> {
    if function.uses_odbc_syntax
        || !matches!(function.parameters, FunctionArguments::None)
        || function.filter.is_some()
        || function.null_treatment.is_some()
        || function.over.is_some()
        || !function.within_group.is_empty()
    {
        return Err(invalid("record bindings do not support function modifiers"));
    }
    Ok(())
}
