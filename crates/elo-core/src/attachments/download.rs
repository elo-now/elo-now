//! Bound stalled downloads without cutting off slow, progressing transfers.
use std::time::Duration;

pub fn client(builder: reqwest::ClientBuilder) -> reqwest::Result<reqwest::Client> {
    with_timeouts(builder, Duration::from_secs(30), Duration::from_secs(600))
}

fn with_timeouts(
    builder: reqwest::ClientBuilder,
    idle: Duration,
    total: Duration,
) -> reqwest::Result<reqwest::Client> {
    builder
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(4))
        .read_timeout(idle)
        .timeout(total)
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn attachment_download_allows_progress_but_bounds_stalls_and_total_duration() {
        // Exercise real socket reads with scaled deadlines, including a peer
        // that sends headers and one byte before stalling.
        for (idle_ms, total_ms, pause_ms, completes) in [
            (500, 3_000, 150, true),
            (250, 3_000, 700, false),
            (500, 450, 150, false),
        ] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = [0; 4096];
                let mut received = 0;
                while !request[..received]
                    .windows(4)
                    .any(|part| part == b"\r\n\r\n")
                {
                    assert!(
                        received < request.len(),
                        "Test request headers are too large"
                    );
                    let count = socket.read(&mut request[received..]).await.unwrap();
                    assert_ne!(count, 0, "Test client closed before completing its headers");
                    received += count;
                }
                socket
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nx",
                    )
                    .await
                    .unwrap();
                for _ in 0..5 {
                    tokio::time::sleep(Duration::from_millis(pause_ms)).await;
                    if socket.write_all(b"x").await.is_err() {
                        break;
                    }
                }
            });
            let client = with_timeouts(
                reqwest::Client::builder().no_proxy(),
                Duration::from_millis(idle_ms),
                Duration::from_millis(total_ms),
            )
            .unwrap();
            let response = client
                .get(format!("http://{address}"))
                .send()
                .await
                .unwrap();
            let result = tokio::time::timeout(Duration::from_secs(4), response.bytes())
                .await
                .unwrap();
            if completes {
                assert_eq!(&result.unwrap()[..], b"xxxxxx");
            } else {
                assert!(result.unwrap_err().is_timeout());
            }
            server.abort();
        }
    }
}
