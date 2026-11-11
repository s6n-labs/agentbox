//! Network destination patterns: `host`, `*.host` or `*`, optionally with `:port`.

/// One entry of a `network.allow` list.
pub struct Pattern<'a> {
    host: &'a str,
    /// `None` allows every port.
    port: Option<u16>,
}

impl<'a> Pattern<'a> {
    pub fn parse(entry: &'a str) -> Self {
        if let Some((host, port)) = entry.rsplit_once(':')
            && let Ok(port) = port.parse()
        {
            return Self {
                host,
                port: Some(port),
            };
        }

        Self {
            host: entry,
            port: None,
        }
    }

    fn matches_host(&self, host: &str) -> bool {
        let pattern = self.host.to_ascii_lowercase();
        let host = host.to_ascii_lowercase();

        match pattern.strip_prefix('*') {
            // `*`
            Some("") => true,
            // `*.example.com` matches subdomains, not `example.com` itself.
            Some(suffix) if suffix.starts_with('.') => host.ends_with(suffix),
            _ => pattern == host,
        }
    }

    pub fn matches(&self, host: &str, port: u16) -> bool {
        self.matches_host(host) && self.port.is_none_or(|allowed| allowed == port)
    }

    /// Does this pattern permit everything `other` permits?
    fn covers(&self, other: &Pattern) -> bool {
        // `*.a.b` is within `*.b`: compare what follows the wildcard like a hostname.
        let hosts_covered = self.matches_host(other.host.trim_start_matches('*'));
        let ports_covered = self.port.is_none_or(|port| Some(port) == other.port);

        hosts_covered && ports_covered
    }
}

/// The host-layer pattern that permits the whole repository `entry`, if any.
pub fn permitted_by<'a>(host_allow: &'a [String], entry: &str) -> Option<&'a str> {
    let entry = Pattern::parse(entry);

    host_allow
        .iter()
        .map(String::as_str)
        .find(|pattern| Pattern::parse(pattern).covers(&entry))
}
