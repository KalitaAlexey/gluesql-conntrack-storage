use std::sync::Mutex;

use eyre::Context as _;
use gluesql::core::executor::Payload;
use gluesql::prelude::Glue;
use gluesql_conntrack_storage::Conntrack;

#[tokio::main]
async fn main() -> eyre::Result<()> {
    // let conditions = "orig_ipv4_src = '172.31.254.51'";
    let conditions = "";
    let filter =
        gluesql_conntrack_storage::parse_filter(conditions).wrap_err("failed to parse filter")?;
    let conntrack = Conntrack::new(Mutex::new(conntrack::Conntrack::connect()?.filter(filter)));
    let mut glue = Glue::new(conntrack);
    let row = glue
        .execute(format!("SELECT * FROM Connections"))
        .await
        .wrap_err("failed to execute query")?;
    println!("{row:?}");
    let row = row.into_iter().next().unwrap();
    let Payload::Select { labels, rows } = row else {
        unreachable!();
    };
    println!("{}", serde_json::to_string_pretty(&rows).unwrap());
    println!("{labels:?}");
    for row in rows {
        println!("{row:?}");
    }
    Ok(())
}
