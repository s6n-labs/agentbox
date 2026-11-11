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

#[cfg(test)]
mod tests {
    use super::*;

    fn matches(pattern: &str, host: &str, port: u16) -> bool {
        Pattern::parse(pattern).matches(host, port)
    }

    fn covers(host_pattern: &str, entry: &str) -> bool {
        Pattern::parse(host_pattern).covers(&Pattern::parse(entry))
    }

    #[test]
    fn exact_hosts_match_only_themselves() {
        assert!(matches("example.com", "example.com", 443));
        assert!(matches("example.com", "EXAMPLE.com", 443));

        assert!(!matches("example.com", "www.example.com", 443));
        assert!(!matches("example.com", "notexample.com", 443));
    }

    #[test]
    fn wildcards_match_subdomains_only() {
        assert!(matches("*.example.com", "a.example.com", 443));
        assert!(matches("*.example.com", "a.b.example.com", 443));

        assert!(!matches("*.example.com", "example.com", 443));
        assert!(!matches("*.example.com", "evilexample.com", 443));
    }

    #[test]
    fn star_matches_everything() {
        assert!(matches("*", "anything.example", 1));
        assert!(matches("*:443", "anything.example", 443));
        assert!(!matches("*:443", "anything.example", 80));
    }

    #[test]
    fn a_port_restricts_and_no_port_allows_all() {
        assert!(matches("example.com", "example.com", 22));
        assert!(matches("example.com:443", "example.com", 443));
        assert!(!matches("example.com:443", "example.com", 22));
    }

    #[test]
    fn something_that_is_not_a_port_stays_part_of_the_host() {
        let pattern = Pattern::parse("example.com:https");

        assert_eq!(pattern.host, "example.com:https");
        assert_eq!(pattern.port, None);
    }

    #[test]
    fn covering_compares_hosts() {
        assert!(covers("*", "example.com"));
        assert!(covers("*.com", "example.com"));
        assert!(covers("*.com", "*.example.com"));
        assert!(covers("example.com", "example.com"));

        assert!(!covers("example.com", "*.example.com"));
        assert!(!covers("*.com", "*"));
        assert!(!covers("*.org", "example.com"));
    }

    #[test]
    fn covering_compares_ports() {
        assert!(covers("example.com", "example.com:443"));
        assert!(covers("example.com:443", "example.com:443"));

        // An any-port request is wider than a single-port permission.
        assert!(!covers("example.com:443", "example.com"));
        assert!(!covers("example.com:443", "example.com:22"));
    }

    #[test]
    fn permitted_by_names_the_host_pattern() {
        let host_allow = vec!["*.org".to_string(), "*.com".to_string()];

        assert_eq!(permitted_by(&host_allow, "example.com"), Some("*.com"));
        assert_eq!(permitted_by(&host_allow, "example.net"), None);
        assert_eq!(permitted_by(&[], "example.com"), None);
    }
}
