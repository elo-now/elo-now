//! Explicit network probe; no client identity, token, content or automatic redirects.
use std::time::Duration;
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(20))
        .build()?;
    let good = client.get("https://www.rust-lang.org/").send().await?;
    println!("valid public certificate: HTTPS status {}", good.status());
    for url in [
        "https://expired.badssl.com/",
        "https://wrong.host.badssl.com/",
        "https://self-signed.badssl.com/",
    ] {
        match client.get(url).send().await {
            Ok(_) => return Err(format!("unsafe acceptance: {url}").into()),
            Err(e) => {
                let mut reasons = Vec::new();
                let mut source: Option<&(dyn std::error::Error + 'static)> = Some(&e);
                while let Some(s) = source {
                    reasons.push(s.to_string());
                    source = s.source();
                }
                let detail = reasons.join(" / ");
                println!("rejected {url}: {detail}");
                if !detail.to_lowercase().contains("cert") {
                    return Err("failure did not establish certificate rejection".into());
                }
            }
        }
    }
    Ok(())
}
