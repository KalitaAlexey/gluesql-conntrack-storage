use conntrack::DirFilterBuilderError;
use gluesql::core::sqlparser::parser::ParserError;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("conntrack failed")]
    Conntrack(#[from] conntrack::Error),
}

#[derive(Debug, PartialEq, thiserror::Error)]
pub enum ParseSqlToFilterError {
    #[error("parser failed")]
    Parser(#[from] ParserError),

    #[error("dir filter builder failed")]
    DirFilterBuilder(#[from] DirFilterBuilderError),
}
