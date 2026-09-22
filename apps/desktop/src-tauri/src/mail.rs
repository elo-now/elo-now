//! Open an explicit support draft in the user's mail application, never send it.
use crate::State;

fn draft_uri(email: &str, subject: &str, body: &str) -> Result<String, String> {
    if email.len() > 254
        || email.split('@').count() != 2
        || email.starts_with('@')
        || email.ends_with('@')
        || !email
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"@._+-".contains(&c))
        || subject.len() > 300
        || subject.contains(['\r', '\n'])
        || body.len() > 16_000
    {
        return Err("Invalid email draft".into());
    }
    let encode = |value: &str| {
        value
            .bytes()
            .map(|c| {
                if c.is_ascii_alphanumeric() || b"-._~".contains(&c) {
                    (c as char).to_string()
                } else {
                    format!("%{c:02X}")
                }
            })
            .collect::<String>()
    };
    Ok(format!(
        "mailto:{email}?subject={}&body={}",
        encode(subject),
        encode(body)
    ))
}

#[tauri::command]
pub async fn open_mail_draft(
    state: tauri::State<'_, State>,
    email: String,
    subject: String,
    body: String,
) -> Result<(), String> {
    if state.lock().await.client.is_none() {
        return Err("The profile is locked".into());
    }
    let uri = draft_uri(&email, &subject, &body)?;
    tauri::async_runtime::spawn_blocking(move || {
        #[cfg(target_os = "macos")]
        let status = std::process::Command::new("/usr/bin/open")
            .arg(uri)
            .status();
        #[cfg(target_os = "windows")]
        let status = std::process::Command::new("rundll32.exe")
            .args(["url.dll,FileProtocolHandler", &uri])
            .status();
        #[cfg(target_os = "linux")]
        let status = std::process::Command::new("xdg-open").arg(uri).status();
        #[cfg(any(target_os = "android", target_os = "ios"))]
        let status: std::io::Result<std::process::ExitStatus> = {
            let _ = uri;
            Err(std::io::Error::other("Use the system share sheet"))
        };
        match status {
            Ok(status) if status.success() => Ok(()),
            _ => Err("Could not open your mail app".to_owned()),
        }
    })
    .await
    .map_err(|_| "Could not open your mail app".to_owned())?
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn draft_content_cannot_inject_mail_headers_or_uri_parameters() {
        let uri = draft_uri(
            "owner+space@example.test",
            "A & B",
            "Hello\n&bcc=other@example.test",
        )
        .unwrap();
        assert_eq!(
            uri,
            "mailto:owner+space@example.test?subject=A%20%26%20B&body=Hello%0A%26bcc%3Dother%40example.test"
        );
        for email in [
            "owner@example.test?bcc=other@example.test",
            "a\nb@test",
            "file:///tmp/a",
            "@example.test",
        ] {
            assert!(draft_uri(email, "Subject", "Body").is_err());
        }
        assert!(draft_uri("a@b.test", "A\r\nB", "Body").is_err());
    }
}
