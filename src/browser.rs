use std::process::{Command, Stdio};

/// Best-effort: opens `url` in the default browser. Only the two addresses this program itself needs
/// are ever opened, and the URL goes to the opener as a plain argument (never through a shell).
pub fn open(url: &str) -> bool {
    if !(url.starts_with("https://github.com/") || url.starts_with("https://checkout.stripe.com/")) {
        return false;
    }
    let mut cmd = if cfg!(windows) {
        let mut c = Command::new("rundll32");
        c.arg("url.dll,FileProtocolHandler");
        c
    } else if cfg!(target_os = "macos") {
        Command::new("open")
    } else {
        Command::new("xdg-open")
    };
    cmd.arg(url).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().is_ok()
}

#[cfg(test)]
mod tests {
    #[test]
    fn refuses_addresses_it_does_not_own() {
        for url in ["http://github.com/login/device", "https://evil.example/", "https://github.com.evil.example/", "file:///etc/passwd", "calc.exe"] {
            assert!(!super::open(url), "{url}");
        }
    }
}
