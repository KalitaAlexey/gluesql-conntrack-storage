#![warn(
    absolute_paths_not_starting_with_crate,
    deprecated_in_future,
    elided_lifetimes_in_paths,
    explicit_outlives_requirements,
    keyword_idents,
    let_underscore_drop,
    macro_use_extern_crate,
    meta_variable_misuse,
    missing_debug_implementations,
    non_ascii_idents,
    noop_method_call,
    single_use_lifetimes,
    trivial_casts,
    trivial_numeric_casts,
    unreachable_pub,
    unused_extern_crates,
    unused_import_braces,
    unused_lifetimes,
    unused_macro_rules,
    unused_qualifications,
    unused_tuple_struct_fields,
    variant_size_differences
)]
#![warn(clippy::incorrect_clone_impl_on_copy_type)]

mod error;
mod utils;

use std::collections::HashMap;
use std::fmt::Debug;
use std::net::Ipv4Addr;
use std::sync::Mutex;

use async_trait::async_trait;
use conntrack::{DirFilterBuilder, Filter};
use error::ParseSqlToFilterError;
use futures::stream;
use gluesql::core::data::{BigDecimalExt as _, Key, Schema};
use gluesql::core::error::Error as GError;
use gluesql::core::sqlparser::ast::{BinaryOperator, Expr, Value};
use gluesql::core::sqlparser::dialect::GenericDialect;
use gluesql::core::sqlparser::parser::Parser;
use gluesql::core::store::{DataRow, RowIter as RowStream};
use gluesql::prelude::Result;
use tracing::warn;

pub use self::error::Error;
use crate::utils::Column;

type RowIter = Box<dyn Iterator<Item = Result<(Key, DataRow)>>>;

/// The wrapper around [`conntrack::Conntrack`] that implements required traits to enable SQL operations for conntrack.
pub struct Conntrack(Mutex<conntrack::Conntrack>);

impl Conntrack {
    /// The identifier to be used as a table name to indicate that the target of a SQL operation is conntrack.
    pub const CONNECTIONS_TABLE_NAME: &'static str = "Connections";
}

impl Conntrack {
    pub fn new(conntrack: Mutex<conntrack::Conntrack>) -> Self {
        Self(conntrack)
    }

    fn scan_data_inner(&self, table_name: &str) -> Result<RowIter> {
        assert_eq!(table_name, Self::CONNECTIONS_TABLE_NAME);
        let flows = {
            let mut conntrack = self.0.lock().unwrap();
            conntrack
                .dump()
                .map_err(Error::Conntrack)
                .map_err(|e| GError::StorageMsg(e.to_string()))?
        };
        Ok(Box::new(flows.into_iter().map(|flow| {
            let mut fields = Vec::new();
            for c in Column::all_variants() {
                c.add_field(&flow, &mut fields)
            }
            Ok((Key::None, DataRow::Vec(fields)))
        })))
    }
}

impl Debug for Conntrack {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Conntrack").finish_non_exhaustive()
    }
}

#[async_trait(?Send)]
impl gluesql::core::store::Store for Conntrack {
    async fn fetch_schema(&self, table_name: &str) -> Result<Option<Schema>> {
        assert_eq!(table_name, Self::CONNECTIONS_TABLE_NAME);
        let schema = Schema {
            table_name: Self::CONNECTIONS_TABLE_NAME.to_owned(),
            column_defs: Some(Column::all_variants().iter().map(Column::def).collect()),
            indexes: Vec::default(),
            engine: None,
        };
        Ok(Some(schema))
    }

    async fn fetch_all_schemas(&self) -> Result<Vec<Schema>> {
        Ok(Vec::from_iter(
            self.fetch_schema(Self::CONNECTIONS_TABLE_NAME).await?,
        ))
    }

    async fn fetch_data(&self, _table_name: &str, _key: &Key) -> Result<Option<DataRow>> {
        Ok(None)
    }

    async fn scan_data(&self, table_name: &str) -> Result<RowStream> {
        let rows = self.scan_data_inner(table_name)?;
        Ok(Box::pin(stream::iter(rows)))
    }
}

impl gluesql::core::store::AlterTable for Conntrack {}
impl gluesql::core::store::CustomFunction for Conntrack {}
impl gluesql::core::store::CustomFunctionMut for Conntrack {}
impl gluesql::core::store::Index for Conntrack {}
impl gluesql::core::store::IndexMut for Conntrack {}
impl gluesql::core::store::Metadata for Conntrack {}
impl gluesql::core::store::StoreMut for Conntrack {}
impl gluesql::core::store::Transaction for Conntrack {}

/// Gets [`Filter`] from `selection`. Only `AND` and `=` are supported.
pub fn get_filter(selection: &Expr) -> Result<Filter, ParseSqlToFilterError> {
    fn to_ipv4_addr(value: &Value) -> Option<Ipv4Addr> {
        if let Value::SingleQuotedString(x) = value {
            x.parse().ok()
        } else {
            None
        }
    }

    fn to_u8(value: &Value) -> Option<u8> {
        if let Value::Number(value, _) = value {
            value.to_u8()
        } else {
            None
        }
    }

    fn to_u16(value: &Value) -> Option<u16> {
        if let Value::Number(value, _) = value {
            value.to_u16()
        } else {
            None
        }
    }

    fn process(
        expr: &Expr,
        columns: &HashMap<&'static str, Column>,
        orig_filter: &mut DirFilterBuilder,
        reply_filter: &mut DirFilterBuilder,
    ) {
        macro_rules! do_match {
            (
                $column:expr, $ident:expr, $value:ident,
                $(($arm_column:ident, $arm_convert:ident, $arm_filter:ident, $arm_set_value:ident),)*
            ) => {
                match $column {
                    $(
                        Some(Column::$arm_column) => {
                            if let Some(value) = $arm_convert($value) {
                                $arm_filter.$arm_set_value(value);
                            } else {
                                warn!(identifier = %$ident, value = ?$value, "invalid value")
                            }
                        }
                    )*
                    _ => {
                        warn!(identifier = %$ident, "unsupported identifier");
                    }
                }
            };
        }

        if let Expr::BinaryOp { left, op, right } = expr {
            match op {
                BinaryOperator::And => {
                    process(left.as_ref(), columns, orig_filter, reply_filter);
                    process(right.as_ref(), columns, orig_filter, reply_filter);
                }
                BinaryOperator::Eq => match (left.as_ref(), right.as_ref()) {
                    (Expr::Identifier(ident), Expr::Value(value)) => {
                        do_match!(
                            columns.get(ident.value.as_str()),
                            ident.value,
                            value,
                            (OrigSrc, to_ipv4_addr, orig_filter, ipv4_src),
                            (OrigDst, to_ipv4_addr, orig_filter, ipv4_dst),
                            (OrigProtoNum, to_u8, orig_filter, l4_proto),
                            (OrigProtoSrcPort, to_u16, orig_filter, l4_src_port),
                            (OrigProtoDstPort, to_u16, orig_filter, l4_dst_port),
                            (ReplySrc, to_ipv4_addr, reply_filter, ipv4_src),
                            (ReplyDst, to_ipv4_addr, reply_filter, ipv4_dst),
                            (ReplyProtoNum, to_u8, reply_filter, l4_proto),
                            (ReplyProtoSrcPort, to_u16, reply_filter, l4_src_port),
                            (ReplyProtoDstPort, to_u16, reply_filter, l4_dst_port),
                        );
                    }
                    _ => warn!(?left, ?right, "unsupported operands"),
                },
                _ => warn!(operator = ?op, "unsupported operator"),
            }
        } else {
            warn!(expression = ?expr, "unsupported expression");
        }
    }

    let mut orig_filter = DirFilterBuilder::default();
    let mut reply_filter = DirFilterBuilder::default();
    let columns = Column::all_variants()
        .iter()
        .map(|c| {
            let n = c.name();
            (n, *c)
        })
        .collect::<HashMap<_, _>>();
    process(selection, &columns, &mut orig_filter, &mut reply_filter);
    Ok(Filter::default()
        .with_orig(orig_filter.build()?)
        .with_reply(reply_filter.build()?))
}

/// Parses `sql` as [`Expr`] and calls [`get_filter`] to get [`Filter`].
pub fn parse_filter(sql: &str) -> Result<Filter, ParseSqlToFilterError> {
    let sql = sql.trim();
    if sql.is_empty() {
        return Ok(Filter::default());
    }
    let expr = Parser::new(&GenericDialect)
        .with_recursion_limit(1)
        .try_with_sql(sql)?
        .parse_expr()?;
    get_filter(&expr)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use conntrack::model::IpProto;
    use conntrack::{DirFilterBuilder, Filter};

    #[test]
    fn parse_filter() {
        assert_eq!(super::parse_filter(""), Ok(Filter::default()));
        assert_eq!(super::parse_filter("id = 5"), Ok(Filter::default()));
        assert_eq!(
            super::parse_filter("id = 5 OR orig_ipv4_src = '127.0.0.1'"),
            Ok(Filter::default())
        );
        assert_eq!(
            super::parse_filter(
                r#"
                id = 5
                    AND orig_ipv4_src = '127.0.0.1'
                    AND orig_ipv4_dst = '127.0.0.2'
                    AND orig_l4_proto = 6
                    AND orig_l4_src_port = 1
                    AND orig_l4_dst_port = 2"#
            ),
            {
                let mut orig = DirFilterBuilder::default();
                orig.ipv4_src(Ipv4Addr::new(127, 0, 0, 1))
                    .ipv4_dst(Ipv4Addr::new(127, 0, 0, 2))
                    .l4_proto(IpProto::Tcp)
                    .l4_src_port(1)
                    .l4_dst_port(2);
                let mut filter = Filter::default();
                filter.orig(orig.build().unwrap());
                Ok(filter)
            }
        );
    }
}
