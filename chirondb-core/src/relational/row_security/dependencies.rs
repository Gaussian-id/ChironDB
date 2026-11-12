//! Resolve property dependencies before evaluating values or probing indexes.
//! CTE aliases retain their physical source-column lineage.
use super::*;

type Origins = BTreeSet<(String, String)>;
#[derive(Clone)]
struct Column {
    qualifier: String,
    name: String,
    origins: Origins,
}
struct Dependencies {
    memory: memory::Charge,
    bytes: u64,
    tables: BTreeSet<String>,
    fields: BTreeMap<(String, String), BTreeSet<PropertyAction>>,
}
impl Default for Dependencies {
    fn default() -> Self {
        Self {
            memory: memory::Charge::storage(),
            bytes: 0,
            tables: BTreeSet::new(),
            fields: BTreeMap::new(),
        }
    }
}
fn origin_bytes(origins: &Origins) -> u64 {
    origins.iter().fold(0_u64, |total, (table, column)| {
        total.saturating_add(512 + (table.len() + column.len()) as u64 * 4)
    })
}
impl Dependencies {
    fn grow(&mut self, bytes: u64) -> Result<()> {
        self.bytes = self
            .bytes
            .checked_add(bytes)
            .ok_or(SecurityError::BudgetExceeded)?;
        self.memory.prepare(self.bytes)
    }
    fn columns(&mut self, columns: &[Column]) -> Result<()> {
        self.grow(columns.iter().fold(0_u64, |total, column| {
            total.saturating_add(
                512 + (column.name.len() + column.qualifier.len()) as u64 * 4
                    + origin_bytes(&column.origins),
            )
        }))
    }
    fn require(&mut self, origins: &Origins, action: PropertyAction) -> Result<()> {
        // Monotonic scratch accounting covers intermediate CTE/union copies as
        // well as retained dependencies; it is released at preflight completion.
        self.grow(origin_bytes(origins))?;
        for origin in origins {
            self.fields
                .entry(origin.clone())
                .or_default()
                .insert(action);
        }
        Ok(())
    }
}

pub(in crate::relational) fn preflight(
    state: &RelationalState,
    statement: &Statement,
    snapshot: u64,
) -> Result<()> {
    let Some(identity) = state.request_identity.as_deref() else {
        return Ok(());
    };
    let mut deps = Dependencies::default();
    let ctes = BTreeMap::new();
    match statement {
        Statement::Query(query) => {
            query_columns(state, query, &ctes, &mut deps)?;
        }
        Statement::Explain { statement, .. } => return preflight(state, statement, snapshot),
        Statement::Update(update) => {
            let columns = source(state, &update.table.relation, &ctes, &mut deps)?;
            if let Some(expr) = &update.selection {
                expression(
                    state,
                    expr,
                    &columns,
                    &ctes,
                    PropertyAction::Query,
                    &mut deps,
                )?;
            }
            if let Some(items) = &update.returning {
                projection(state, items, &columns, &ctes, &mut deps)?;
            }
        }
        Statement::Delete(delete) => {
            let from = match &delete.from {
                FromTable::WithFromKeyword(from) | FromTable::WithoutKeyword(from) => from,
            };
            let mut columns = vec![];
            for from in from {
                columns.extend(source(state, &from.relation, &ctes, &mut deps)?);
            }
            if let Some(expr) = &delete.selection {
                expression(
                    state,
                    expr,
                    &columns,
                    &ctes,
                    PropertyAction::Query,
                    &mut deps,
                )?;
            }
            if let Some(items) = &delete.returning {
                projection(state, items, &columns, &ctes, &mut deps)?;
            }
        }
        Statement::Insert(insert) => {
            let TableObject::TableName(name) = &insert.table else {
                return Err(unsupported("protected INSERT requires a table"));
            };
            let name = normalize_name(name);
            let columns = table_columns(state, &name, &name, &mut deps)?;
            if let Some(items) = &insert.returning {
                projection(state, items, &columns, &ctes, &mut deps)?;
            }
            if let Some(OnInsert::OnConflict(conflict)) = &insert.on {
                if let Some(ConflictTarget::Columns(targets)) = &conflict.conflict_target {
                    for name in targets {
                        let origin = resolve(&Expr::Identifier(name.clone()), &columns, &mut deps)?;
                        deps.require(&origin, PropertyAction::Query)?;
                    }
                }
                if let OnConflictAction::DoUpdate(update) = &conflict.action {
                    // EXCLUDED is caller input; it does not confer any authority on existing fields.
                    deps.columns(&columns)?;
                    deps.columns(&columns)?;
                    let mut scope = columns.clone();
                    scope.extend(columns.iter().map(|column| Column {
                        qualifier: "excluded".into(),
                        name: column.name.clone(),
                        origins: Origins::new(),
                    }));
                    if let Some(expr) = &update.selection {
                        expression(state, expr, &scope, &ctes, PropertyAction::Query, &mut deps)?;
                    }
                    for assignment in &update.assignments {
                        expression(
                            state,
                            &assignment.value,
                            &scope,
                            &ctes,
                            PropertyAction::Read,
                            &mut deps,
                        )?;
                    }
                }
            }
        }
        _ => return Ok(()),
    }
    for name in &deps.tables {
        let table = state.tables.get(name).ok_or(SecurityError::Forbidden)?;
        if table.definition.tenant_id.as_deref() != Some(identity.principal().tenant.as_str())
            || table.definition.row_policy.is_none()
        {
            return Err(SecurityError::Forbidden.into());
        }
        let _policy_permit = table
            .policy_epoch
            .as_ref()
            .ok_or(SecurityError::Forbidden)?
            .enter()?;
        // Inspect the permitted domain independent of predicate values. An
        // indexed predicate cannot turn denial into a hidden-value oracle.
        for row in table.rows.visible_versions(snapshot) {
            check_sql_cancelled()?;
            let (id, version) = row?;
            if !readable(&table.definition, id, &version, Some(identity))? {
                continue;
            }
            let record = resource(&table.definition, id, &version)?;
            for column in &table.definition.columns {
                if let Some(actions) = deps.fields.get(&(name.clone(), column.name.clone())) {
                    for action in actions {
                        if !policy::field_allowed(
                            record,
                            &identity.principal().attributes,
                            &column_path(&column.name),
                            *action,
                        ) {
                            return Err(SecurityError::Forbidden.into());
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

fn table_columns(
    state: &RelationalState,
    name: &str,
    qualifier: &str,
    deps: &mut Dependencies,
) -> Result<Vec<Column>> {
    let table = state
        .tables
        .get(name)
        .ok_or_else(|| invalid(format!("table {name} does not exist")))?;
    deps.grow(
        512 + name.len() as u64 * 4
            + table
                .definition
                .columns
                .iter()
                .map(|column| 2048 + (column.name.len() + name.len() + qualifier.len()) as u64 * 8)
                .sum::<u64>(),
    )?;
    deps.tables.insert(name.into());
    Ok(table
        .definition
        .columns
        .iter()
        .map(|column| Column {
            qualifier: qualifier.into(),
            name: column.name.clone(),
            origins: BTreeSet::from([(name.into(), column.name.clone())]),
        })
        .collect())
}
fn source(
    state: &RelationalState,
    factor: &TableFactor,
    ctes: &BTreeMap<String, Vec<Column>>,
    deps: &mut Dependencies,
) -> Result<Vec<Column>> {
    let TableFactor::Table {
        name, alias, args, ..
    } = factor
    else {
        return Err(unsupported(
            "protected table source is outside relational profile",
        ));
    };
    if args.is_some() {
        return Err(unsupported(
            "table functions are outside relational profile",
        ));
    }
    let name = normalize_name(name);
    let qualifier = alias
        .as_ref()
        .map(|alias| normalize_ident(&alias.name.value))
        .unwrap_or_else(|| name.clone());
    let mut columns = if let Some(columns) = ctes.get(&name) {
        deps.columns(columns)?;
        columns.clone()
    } else {
        table_columns(state, &name, &qualifier, deps)?
    };
    deps.grow(columns.len() as u64 * (256 + qualifier.len() as u64 * 2))?;
    for column in &mut columns {
        column.qualifier = qualifier.clone();
    }
    Ok(columns)
}
fn resolve(expr: &Expr, columns: &[Column], deps: &mut Dependencies) -> Result<Origins> {
    deps.grow(512 + columns.len() as u64 * 32)?;
    let (qualifier, name) = match expr {
        Expr::Identifier(name) => (None, normalize_ident(&name.value)),
        Expr::CompoundIdentifier(names) if names.len() == 2 => (
            Some(normalize_ident(&names[0].value)),
            normalize_ident(&names[1].value),
        ),
        _ => {
            return Err(unsupported(
                "protected column expression is outside relational profile",
            ));
        }
    };
    let found = columns
        .iter()
        .filter(|column| {
            column.name == name
                && qualifier
                    .as_ref()
                    .is_none_or(|qualifier| &column.qualifier == qualifier)
        })
        .collect::<Vec<_>>();
    let found = if qualifier.is_none() && found.iter().any(|column| column.qualifier != "excluded")
    {
        found
            .into_iter()
            .filter(|column| column.qualifier != "excluded")
            .collect::<Vec<_>>()
    } else {
        found
    };
    match found.as_slice() {
        [column] => {
            deps.grow(origin_bytes(&column.origins))?;
            Ok(column.origins.clone())
        }
        [] => Err(invalid(format!("unknown column {name}"))),
        _ => Err(invalid(format!("ambiguous column {name}"))),
    }
}
fn expression(
    state: &RelationalState,
    expr: &Expr,
    columns: &[Column],
    ctes: &BTreeMap<String, Vec<Column>>,
    action: PropertyAction,
    deps: &mut Dependencies,
) -> Result<Origins> {
    check_sql_cancelled()?;
    deps.grow(512)?;
    let origins = match expr {
        Expr::Identifier(_) | Expr::CompoundIdentifier(_) => resolve(expr, columns, deps)?,
        Expr::Value(_) => Origins::new(),
        Expr::BinaryOp { left, right, .. } => {
            let mut origins = expression(state, left, columns, ctes, action, deps)?;
            origins.extend(expression(state, right, columns, ctes, action, deps)?);
            origins
        }
        Expr::UnaryOp { expr, .. }
        | Expr::Nested(expr)
        | Expr::IsNull(expr)
        | Expr::IsNotNull(expr)
        | Expr::Cast { expr, .. } => expression(state, expr, columns, ctes, action, deps)?,
        Expr::Between {
            expr, low, high, ..
        } => {
            let mut origins = expression(state, expr, columns, ctes, action, deps)?;
            origins.extend(expression(state, low, columns, ctes, action, deps)?);
            origins.extend(expression(state, high, columns, ctes, action, deps)?);
            origins
        }
        Expr::InList { expr, list, .. } => {
            let mut origins = expression(state, expr, columns, ctes, action, deps)?;
            for item in list {
                origins.extend(expression(state, item, columns, ctes, action, deps)?);
            }
            origins
        }
        Expr::Subquery(query)
        | Expr::Exists {
            subquery: query, ..
        } => query_columns(state, query, ctes, deps)?
            .into_iter()
            .flat_map(|column| column.origins)
            .collect(),
        Expr::InSubquery { expr, subquery, .. } => {
            let mut origins = expression(state, expr, columns, ctes, action, deps)?;
            origins.extend(
                query_columns(state, subquery, ctes, deps)?
                    .into_iter()
                    .flat_map(|column| column.origins),
            );
            origins
        }
        Expr::Function(function) => {
            let mut origins = Origins::new();
            if let FunctionArguments::List(args) = &function.args {
                for argument in &args.args {
                    match argument {
                        FunctionArg::Unnamed(FunctionArgExpr::Expr(expr)) => {
                            origins.extend(expression(state, expr, columns, ctes, action, deps)?)
                        }
                        FunctionArg::Unnamed(FunctionArgExpr::Wildcard) => (),
                        _ => {
                            return Err(unsupported(
                                "protected function argument is outside relational profile",
                            ));
                        }
                    }
                }
                if !function.name.to_string().eq_ignore_ascii_case("record_ref") {
                    deps.require(&origins, PropertyAction::Query)?;
                }
            } else {
                return Err(unsupported(
                    "protected function arguments are outside relational profile",
                ));
            }
            if let Some(filter) = &function.filter {
                expression(state, filter, columns, ctes, PropertyAction::Query, deps)?;
            }
            origins
        }
        _ => {
            return Err(unsupported(
                "protected expression is outside relational profile",
            ));
        }
    };
    deps.require(&origins, action)?;
    Ok(origins)
}
fn projection(
    state: &RelationalState,
    items: &[SelectItem],
    columns: &[Column],
    ctes: &BTreeMap<String, Vec<Column>>,
    deps: &mut Dependencies,
) -> Result<Vec<Column>> {
    let mut output = vec![];
    deps.grow(512 + items.len() as u64 * 512)?;
    for item in items {
        match item {
            SelectItem::Wildcard(_) => {
                for column in columns {
                    deps.require(&column.origins, PropertyAction::Read)?;
                    deps.columns(std::slice::from_ref(column))?;
                    output.push(column.clone());
                }
            }
            SelectItem::QualifiedWildcard(SelectItemQualifiedWildcardKind::ObjectName(name), _) => {
                let qualifier = normalize_name(name);
                for column in columns
                    .iter()
                    .filter(|column| column.qualifier == qualifier)
                {
                    deps.require(&column.origins, PropertyAction::Read)?;
                    deps.columns(std::slice::from_ref(column))?;
                    output.push(column.clone());
                }
            }
            SelectItem::UnnamedExpr(expr) | SelectItem::ExprWithAlias { expr, .. } => {
                let origins = expression(state, expr, columns, ctes, PropertyAction::Read, deps)?;
                let name = match item {
                    SelectItem::ExprWithAlias { alias, .. } => normalize_ident(&alias.value),
                    _ => match expr {
                        Expr::Identifier(name) => normalize_ident(&name.value),
                        Expr::CompoundIdentifier(names) => {
                            normalize_ident(&names.last().ok_or(SecurityError::Forbidden)?.value)
                        }
                        Expr::Function(function) => function.name.to_string().to_lowercase(),
                        _ => "subquery".into(),
                    },
                };
                output.push(Column {
                    qualifier: String::new(),
                    name,
                    origins,
                });
            }
            _ => {
                return Err(unsupported(
                    "protected projection is outside relational profile",
                ));
            }
        }
    }
    Ok(output)
}
fn query_columns(
    state: &RelationalState,
    query: &Query,
    inherited: &BTreeMap<String, Vec<Column>>,
    deps: &mut Dependencies,
) -> Result<Vec<Column>> {
    for (name, columns) in inherited {
        deps.grow(512 + name.len() as u64 * 4)?;
        deps.columns(columns)?;
    }
    let mut ctes = inherited.clone();
    if let Some(with) = &query.with {
        if with.recursive {
            return Err(unsupported("recursive CTE is outside relational profile"));
        }
        for cte in &with.cte_tables {
            let mut columns = query_columns(state, &cte.query, &ctes, deps)?;
            if !cte.alias.columns.is_empty() {
                if cte.alias.columns.len() != columns.len() {
                    return Err(invalid("CTE column count mismatch"));
                }
                for (column, alias) in columns.iter_mut().zip(&cte.alias.columns) {
                    column.name = normalize_ident(&alias.name.value);
                }
            }
            ctes.insert(normalize_ident(&cte.alias.name.value), columns);
        }
    }
    let SetExpr::Select(select) = query.body.as_ref() else {
        return Err(unsupported("set operations are outside relational profile"));
    };
    let mut columns = vec![];
    for from in &select.from {
        columns.extend(source(state, &from.relation, &ctes, deps)?);
        for join in &from.joins {
            columns.extend(source(state, &join.relation, &ctes, deps)?);
        }
    }
    let output = projection(state, &select.projection, &columns, &ctes, deps)?;
    for from in &select.from {
        for join in &from.joins {
            let constraint = match &join.join_operator {
                JoinOperator::Inner(c)
                | JoinOperator::LeftOuter(c)
                | JoinOperator::RightOuter(c)
                | JoinOperator::FullOuter(c)
                | JoinOperator::Join(c)
                | JoinOperator::Left(c)
                | JoinOperator::Right(c) => c,
                JoinOperator::CrossJoin(_) => continue,
                _ => return Err(unsupported("protected join is outside relational profile")),
            };
            match constraint {
                JoinConstraint::On(expr) => {
                    expression(state, expr, &columns, &ctes, PropertyAction::Query, deps)?;
                }
                JoinConstraint::Using(names) => {
                    for name in names {
                        for column in columns
                            .iter()
                            .filter(|column| column.name == normalize_name(name))
                        {
                            deps.require(&column.origins, PropertyAction::Query)?;
                        }
                    }
                }
                JoinConstraint::None => (),
                _ => {
                    return Err(unsupported(
                        "protected join constraint is outside relational profile",
                    ));
                }
            }
        }
    }
    if let Some(expr) = &select.selection {
        expression(state, expr, &columns, &ctes, PropertyAction::Query, deps)?;
    }
    if let GroupByExpr::Expressions(expressions, _) = &select.group_by {
        for expr in expressions {
            expression(state, expr, &columns, &ctes, PropertyAction::Query, deps)?;
        }
    }
    // Output aliases have SQL precedence for ORDER BY; HAVING in this engine
    // also names aggregate outputs. Resolve them to original source fields.
    deps.columns(&output)?;
    deps.columns(&columns)?;
    let mut aliases = output.clone();
    aliases.extend(
        columns
            .iter()
            .filter(|column| !output.iter().any(|out| out.name == column.name))
            .cloned(),
    );
    if let Some(expr) = &select.having {
        expression(state, expr, &aliases, &ctes, PropertyAction::Query, deps)?;
    }
    if let Some(order) = &query.order_by
        && let OrderByKind::Expressions(expressions) = &order.kind
    {
        for item in expressions {
            if let Some(index) = order_by_ordinal(&item.expr, output.len())? {
                deps.require(&output[index].origins, PropertyAction::Query)?;
            } else {
                expression(
                    state,
                    &item.expr,
                    &aliases,
                    &ctes,
                    PropertyAction::Query,
                    deps,
                )?;
            }
        }
    }
    if matches!(select.distinct, Some(Distinct::Distinct)) {
        for column in &output {
            deps.require(&column.origins, PropertyAction::Query)?;
        }
    }
    Ok(output)
}
