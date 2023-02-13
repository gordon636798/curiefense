use lazy_static::lazy_static;
use redis::{ConnectionAddr, ConnectionInfo, RedisConnectionInfo};

lazy_static! {
    static ref RPOOL: anyhow::Result<redis::aio::ConnectionManager> = async_std::task::block_on(build_pool());
    pub static ref REDIS_KEY_PREFIX: String = std::env::var("REDIS_KEY_PREFIX")
        .map(|mut prefix| {
            prefix.push('_');
            prefix
        })
        .unwrap_or_default();
}

/// creates an async connection to a redis server
pub async fn build_pool() -> anyhow::Result<redis::aio::ConnectionManager> {
    let server = std::env::var("FP_REDIS_HOST").unwrap_or_else(|_| "192.168.23.131".to_string());
    let port = std::env::var("FP_REDIS_PORT").unwrap_or_else(|_| "6379".to_string());
    let db = std::env::var("REDIS_DB").unwrap_or_else(|_| "0".to_string());
    let username = std::env::var("REDIS_USERNAME").ok();
    let password = std::env::var("REDIS_PASSWORD").ok();
    let addr = ConnectionAddr::Tcp(server, port.parse()?);
    let redis = RedisConnectionInfo {
        db: db.parse()?,
        username,
        password,
    };
    let cinfo = ConnectionInfo { addr, redis };
    let client = redis::Client::open(cinfo)?;
    let o = redis::aio::ConnectionManager::new(client).await?;
    Ok(o)
}

/// creates an async connection to a redis server
pub async fn fp_redis_async_conn() -> anyhow::Result<redis::aio::ConnectionManager> {
    match &*RPOOL {
        Ok(c) => Ok(c.clone()),
        Err(rr) => Err(anyhow::anyhow!("{}", rr)),
    }
}
