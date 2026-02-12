use log::warn;
use std::fs;
use std::path::Path;

const DEFAULT_MOTD: &str = "
The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.";

pub fn return_motd<P: AsRef<Path>>(path: P) -> String {
    match fs::read_to_string(path.as_ref()) {
        Ok(motd) => motd,
        Err(err) => {
            warn!(
                "Failed to read MOTD from {}: {}; using default",
                path.as_ref().display(),
                err
            );
            DEFAULT_MOTD.to_string()
        }
    }
}
