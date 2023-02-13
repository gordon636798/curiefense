use redis::aio::ConnectionManager;
use reqwest::{blocking::Client, Url};

use crate::fingerprint_redis::fp_redis_async_conn;

pub fn fingerprint_check_visitors(visitor_id: String) -> bool {// Result<bool, Box<dyn Error>> {
    let api_key = "0GuHrOnxYUkLrwJtEXNz";
    let api_path = "visitors";
    // let visitor_id = "KQmd0wHZAaA5i2L9LjBY";

    let base_url = Url::parse("https://api.fpjs.io/").unwrap();
    let mut path = String::new();
    path.push_str(api_path);
    path.push_str("/");
    path.push_str(&visitor_id);
    let url = base_url.join(&path).unwrap();
    //let visitor_url = api_url.join(visitor_id)?;
    println!("{:?}", url);
    let client = Client::builder().timeout(std::time::Duration::from_secs(5)).build();
    let response: Result<reqwest::blocking::Response, _> = client.unwrap()
        .get(url)
        .query(&[("api_key", api_key)])
        .send()
        .map_err(|err| <reqwest::Error as Into<Box<dyn std::error::Error>>>::into(err));

    // let content = response.unwrap().json().unwrap();

    println!("{:?}", response);
    return true;

}

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
