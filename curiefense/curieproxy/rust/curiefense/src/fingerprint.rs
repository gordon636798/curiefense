use redis::aio::ConnectionManager;

use crate::fingerprint_redis::fp_redis_async_conn;

pub async fn check_visitor_id(id: String) -> bool {
    let mut redis = match fp_redis_async_conn().await {
        Ok(c) => c,
        Err(rr) => {
            println!("Could not connect to the redis server {}", rr);
            return false;
        }
    };
    let cmd = redis::cmd("get")
        .arg(id)
        .query_async::<ConnectionManager, String>(&mut redis)
        .await;

    match cmd {
        Ok(_) => return true,
        Err(_) => return false,
    }
}
