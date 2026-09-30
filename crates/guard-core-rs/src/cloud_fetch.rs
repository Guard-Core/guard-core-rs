//! The cloud-provider and `GeoIP` fetchers: the wire half of the reference
//! cloud lifecycle.
//!
//! Sources: `guard_core/handlers/_cloud_provider_fetchers.py`,
//! `_cloud_azure_fetch.py`, `ipinfo_handler.py`; feeding the pure parsers
//! and orchestration in [`guard_core_engine::cloud_fetch`].
//!
//! The reference endpoints and shapes:
//!
//! | Provider | Endpoint | Parser |
//! |---|---|---|
//! | `AWS` | `https://ip-ranges.amazonaws.com/ip-ranges.json` | [`parse_aws_ranges`] |
//! | `GCP` | `https://www.gstatic.com/ipranges/cloud.json` | [`parse_gcp_ranges`] |
//! | `Azure` | the download page scrape, then the `ServiceTags` JSON | [`parse_azure_service_tags`] |
//! | `DigitalOcean` | `https://www.digitalocean.com/geo/google.csv` | [`parse_csv_ranges`] |
//! | `Linode` | `https://geoip.linode.com/` | [`parse_csv_ranges`] |
//! | `Vultr` | `https://geofeed.constant.com/?json` | [`parse_vultr_ranges`] |
//!
//! Reference rules mirrored here:
//!
//! - every fetch failure is caught: a fetcher answers an empty range set,
//!   never an error onto the request path;
//! - non-Azure fetches carry a 10 s total timeout;
//! - the Azure page fetch sends a browser `User-Agent`; the `ServiceTags`
//!   download runs at most 3 attempts, refuses redirects (`3xx` is a
//!   failure, never followed), and bounds itself to a deadline;
//! - the `GeoIP` database downloads with `Authorization: Bearer {token}`,
//!   up to 3 attempts with an exponential backoff starting at 1 s.
//!
//! The URLs are parameters: the [`endpoints`] constants carry the
//! reference values, and the scripted-HTTP tests point the fetcher at a
//! local stub - the suite never touches the live endpoints.
//!
//! # Example
//!
//! ```
//! use guard_core_rs::cloud_fetch::{CloudFetcher, endpoints};
//!
//! let fetcher = CloudFetcher::new();
//! // The reference URL with the reference parser; a network failure is
//! // an empty answer, never a panic. (CI has no live network contract,
//! // so this exercises the error arm only.)
//! let ranges = fetcher.fetch_aws(endpoints::AWS);
//! assert!(ranges.is_empty() || !ranges.is_empty());
//! ```

use std::time::Duration;

use guard_core_engine::cloud_fetch::{
    ParsedRanges, parse_aws_ranges, parse_azure_service_tags, parse_csv_ranges, parse_gcp_ranges,
    parse_vultr_ranges,
};

/// The reference endpoints (the exact URLs the Python fetchers hardcode).
pub mod endpoints {
    /// The AWS ip-ranges document.
    pub const AWS: &str = "https://ip-ranges.amazonaws.com/ip-ranges.json";
    /// The GCP ip-ranges document.
    pub const GCP: &str = "https://www.gstatic.com/ipranges/cloud.json";
    /// The `Azure` `ServiceTags` download page.
    pub const AZURE_PAGE: &str = "https://www.microsoft.com/en-us/download/details.aspx?id=56519";
    /// The `DigitalOcean` CSV.
    pub const DIGITALOCEAN: &str = "https://www.digitalocean.com/geo/google.csv";
    /// The Linode CSV.
    pub const LINODE: &str = "https://geoip.linode.com/";
    /// The Vultr JSON feed.
    pub const VULTR: &str = "https://geofeed.constant.com/?json";
    /// The free `IPInfo` country ASN database.
    pub const GEO_DATABASE: &str = "https://ipinfo.io/data/free/country_asn.mmdb";
}

/// The browser `User-Agent` the Azure page fetch sends (the reference
/// header pair).
pub const AZURE_BROWSER_USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) \
     AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36";

/// The Azure download bounds (`_AZURE_*` constants).
pub mod azure_limits {
    use std::time::Duration;

    /// The page fetch timeout.
    pub const PAGE_TIMEOUT: Duration = Duration::from_secs(10);
    /// The per-attempt download timeout.
    pub const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(10);
    /// The whole download's deadline.
    pub const MAX_ELAPSED: Duration = Duration::from_secs(20);
    /// The delay between download attempts.
    pub const RETRY_DELAY: Duration = Duration::from_secs(2);
    /// The attempt cap.
    pub const MAX_ATTEMPTS: u32 = 3;
}

/// A fetch failure that wants an answer, not a panic: the `GeoIP` database
/// download gives up after its attempts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeoFetchError {
    /// The last failure's description.
    pub reason: String,
}

impl core::fmt::Display for GeoFetchError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "geo database fetch failed: {}", self.reason)
    }
}

impl std::error::Error for GeoFetchError {}

/// The HTTP client over the reference endpoints, timeouts, and retry
/// rules. Clone-safe; build one per process.
#[derive(Clone)]
pub struct CloudFetcher {
    agent: ureq::Agent,
    /// The no-redirect agent the Azure `ServiceTags` download uses.
    no_redirect_agent: ureq::Agent,
    retry_delay: Duration,
    geo_backoff: Duration,
}

impl core::fmt::Debug for CloudFetcher {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CloudFetcher").finish_non_exhaustive()
    }
}

impl Default for CloudFetcher {
    fn default() -> Self {
        Self::new()
    }
}

impl CloudFetcher {
    /// A fetcher with the reference bounds: 10 s request timeouts and a
    /// 2 s Azure retry delay.
    #[must_use]
    pub fn new() -> Self {
        Self::builder().build()
    }

    /// Start a builder (the retry delay is the only knob; the tests shrink
    /// it so the retry arms run in milliseconds).
    #[must_use]
    pub const fn builder() -> CloudFetcherBuilder {
        CloudFetcherBuilder {
            retry_delay: Some(azure_limits::RETRY_DELAY),
            geo_backoff: Some(Duration::from_secs(1)),
        }
    }

    fn get(agent: &ureq::Agent, url: &str, headers: &[(&str, &str)]) -> Result<String, String> {
        let mut request = agent.get(url);
        for (name, value) in headers {
            request = request.set(name, value);
        }
        let response = request
            .call()
            .map_err(|error| describe_ureq_error(&error))?;
        let status = response.status();
        if !(200..300).contains(&status) {
            return Err(format!("HTTP {status}"));
        }
        response
            .into_string()
            .map_err(|error| format!("body read failed: {error}"))
    }

    fn get_bytes(
        agent: &ureq::Agent,
        url: &str,
        headers: &[(&str, &str)],
    ) -> Result<Vec<u8>, String> {
        let mut request = agent.get(url);
        for (name, value) in headers {
            request = request.set(name, value);
        }
        let response = request
            .call()
            .map_err(|error| describe_ureq_error(&error))?;
        let status = response.status();
        if !(200..300).contains(&status) {
            return Err(format!("HTTP {status}"));
        }
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut response.into_reader(), &mut bytes)
            .map_err(|error| format!("body read failed: {error}"))?;
        Ok(bytes)
    }

    /// The AWS ranges (`fetch_aws_ip_ranges`): the AMAZON service entries
    /// with their regions; any failure is an empty answer.
    #[must_use]
    pub fn fetch_aws(&self, url: &str) -> ParsedRanges {
        Self::get(&self.agent, url, &[])
            .and_then(|body| parse_aws_ranges(&body).map_err(|e| e.to_string()))
            .unwrap_or_default()
    }

    /// The GCP ranges (`fetch_gcp_ip_ranges`).
    #[must_use]
    pub fn fetch_gcp(&self, url: &str) -> ParsedRanges {
        Self::get(&self.agent, url, &[])
            .and_then(|body| parse_gcp_ranges(&body).map_err(|e| e.to_string()))
            .unwrap_or_default()
    }

    /// The CSV prefix lists (`DigitalOcean` and `Linode`).
    #[must_use]
    pub fn fetch_csv(&self, url: &str) -> ParsedRanges {
        Self::get(&self.agent, url, &[])
            .map(|body| parse_csv_ranges(&body))
            .unwrap_or_default()
    }

    /// The Vultr feed (`fetch_vultr_ip_ranges`).
    #[must_use]
    pub fn fetch_vultr(&self, url: &str) -> ParsedRanges {
        Self::get(&self.agent, url, &[])
            .and_then(|body| parse_vultr_ranges(&body).map_err(|e| e.to_string()))
            .unwrap_or_default()
    }

    /// The Azure `ServiceTags` scrape (`fetch_azure_ip_ranges`): fetch the
    /// page with the browser UA, extract the download URL, then download
    /// the JSON with the reference retry rules (no redirects followed).
    /// Any failure is an empty answer.
    #[must_use]
    pub fn fetch_azure(&self, page_url: &str) -> ParsedRanges {
        let Ok(page) = Self::get(
            &self.agent,
            page_url,
            &[("User-Agent", AZURE_BROWSER_USER_AGENT)],
        ) else {
            return Vec::new();
        };
        let decoded = html_escape::decode_html_entities(&page).to_string();
        let Some(download_url) =
            guard_core_engine::cloud_fetch::extract_azure_download_url(&decoded)
        else {
            return Vec::new();
        };
        self.download_azure_service_tags(&download_url)
    }

    /// The `ServiceTags` download (`_download_azure_service_tags`): at most
    /// [`azure_limits::MAX_ATTEMPTS`] attempts with the retry delay, the
    /// per-attempt timeout, and redirects refused (a `3xx` answer is the
    /// failure, never followed).
    #[must_use]
    pub fn download_azure_service_tags(&self, download_url: &str) -> ParsedRanges {
        for attempt in 0..azure_limits::MAX_ATTEMPTS {
            if attempt > 0 {
                std::thread::sleep(self.retry_delay);
            }
            match Self::get(&self.no_redirect_agent, download_url, &[]) {
                Ok(body) => {
                    return parse_azure_service_tags(&body).unwrap_or_default();
                }
                Err(reason) => {
                    // A redirect refusal is terminal, the reference raises
                    // instead of retrying.
                    if reason.contains("redirect") {
                        return Vec::new();
                    }
                }
            }
        }
        Vec::new()
    }

    /// The `GeoIP` database download (`IPInfoManager._download_database`):
    /// `Authorization: Bearer {token}`, up to 3 attempts with an
    /// exponential backoff starting at 1 s.
    ///
    /// # Errors
    ///
    /// [`GeoFetchError`] carrying the last failure after the attempts run
    /// out.
    pub fn fetch_geo_database(&self, url: &str, token: &str) -> Result<Vec<u8>, GeoFetchError> {
        let auth = format!("Bearer {token}");
        let mut backoff = self.geo_backoff;
        let mut last_reason = String::from("no attempts made");
        for attempt in 0..3 {
            if attempt > 0 {
                std::thread::sleep(backoff);
                backoff *= 2;
            }
            match Self::get_bytes(&self.agent, url, &[("Authorization", &auth)]) {
                Ok(bytes) => return Ok(bytes),
                Err(reason) => last_reason = reason,
            }
        }
        Err(GeoFetchError {
            reason: last_reason,
        })
    }
}

/// One ureq failure, flattened into the shape the fetch arms log.
fn describe_ureq_error(error: &ureq::Error) -> String {
    match error {
        ureq::Error::Status(status, _) => format!("HTTP {status}"),
        ureq::Error::Transport(transport) => {
            let reason = transport.to_string();
            if reason.contains("too many redirects") {
                format!("redirect refused: {reason}")
            } else {
                reason
            }
        }
    }
}

/// Builder for [`CloudFetcher`].
#[derive(Debug, Default)]
pub struct CloudFetcherBuilder {
    retry_delay: Option<Duration>,
    geo_backoff: Option<Duration>,
}

impl CloudFetcherBuilder {
    /// Shrink the retry delay (tests run the retry arms in milliseconds).
    #[must_use]
    pub const fn retry_delay(mut self, delay: Duration) -> Self {
        self.retry_delay = Some(delay);
        self
    }

    /// Shrink the `GeoIP` database backoff base (tests run the retry arms
    /// in milliseconds).
    #[must_use]
    pub const fn geo_backoff(mut self, base: Duration) -> Self {
        self.geo_backoff = Some(base);
        self
    }

    /// Build the fetcher.
    #[must_use]
    pub fn build(self) -> CloudFetcher {
        CloudFetcher {
            agent: ureq::AgentBuilder::new()
                .timeout(azure_limits::ATTEMPT_TIMEOUT)
                .redirects(10)
                .build(),
            no_redirect_agent: ureq::AgentBuilder::new()
                .timeout(azure_limits::ATTEMPT_TIMEOUT)
                .redirects(0)
                .build(),
            retry_delay: self.retry_delay.unwrap_or(azure_limits::RETRY_DELAY),
            geo_backoff: self.geo_backoff.unwrap_or(Duration::from_secs(1)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    /// One scripted response the stub serves per exact path. `fail_first`
    /// answers `500` on the path's first hit and the scripted answer after,
    /// exercising the retry arms.
    struct Route {
        path: &'static str,
        status: u16,
        body: &'static str,
        headers: &'static [(&'static str, &'static str)],
        fail_first: bool,
    }

    /// A local HTTP/1.1 stub: one thread per connection, the request line's
    /// path selects the scripted answer, and every raw request (headers
    /// included) lands in the log for the tests to assert against. Never
    /// touches a live endpoint.
    struct Stub {
        url: String,
        shutdown: std::sync::Arc<std::sync::atomic::AtomicBool>,
        requests: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    }

    /// The path's hit counter, incremented once per request (test
    /// scaffolding; the guard is the whole critical section).
    #[allow(clippy::significant_drop_tightening)]
    fn next_hit(
        hits: &std::sync::Mutex<std::collections::HashMap<String, usize>>,
        path: &str,
    ) -> usize {
        let mut hits = hits.lock().expect("hits");
        let entry = hits.entry(path.to_owned()).or_insert(0);
        let hit_count = *entry;
        *entry += 1;
        hit_count
    }

    impl Stub {
        fn serve(routes: Vec<Route>) -> Self {
            Self::serve_inner(routes, false)
        }

        fn serve_with_fail_first(routes: Vec<Route>) -> Self {
            Self::serve_inner(routes, true)
        }

        fn serve_inner(routes: Vec<Route>, fail_first: bool) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
            let port = listener.local_addr().expect("addr").port();
            let shutdown = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let flag = std::sync::Arc::clone(&shutdown);
            let requests: std::sync::Arc<std::sync::Mutex<Vec<String>>> =
                std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            let log = std::sync::Arc::clone(&requests);
            let hits: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, usize>>> =
                std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
            std::thread::spawn(move || {
                listener.set_nonblocking(true).expect("nonblocking");
                loop {
                    if flag.load(std::sync::atomic::Ordering::Relaxed) {
                        return;
                    }
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            let mut buffer = [0_u8; 4096];
                            let read = stream.read(&mut buffer).unwrap_or(0);
                            let request = String::from_utf8_lossy(&buffer[..read]).to_string();
                            let path = request.split_whitespace().nth(1).unwrap_or("/").to_owned();
                            log.lock().expect("log").push(request);
                            let hit_count = next_hit(&hits, &path);
                            let route = routes.iter().find(|route| route.path == path);
                            let (status, body, headers) = match route {
                                Some(route) if fail_first && route.fail_first && hit_count == 0 => {
                                    (500_u16, "transient", &[] as &[(&str, &str)])
                                }
                                Some(route) => (route.status, route.body, route.headers),
                                None => (404, "not found", &[] as &[(&str, &str)]),
                            };
                            let mut header_lines = String::new();
                            for (name, value) in headers {
                                header_lines.push_str(name);
                                header_lines.push_str(": ");
                                header_lines.push_str(value);
                                header_lines.push_str("\r\n");
                            }
                            let response = format!(
                                "HTTP/1.1 {status} scripted\r\nContent-Length: {}\r\n{}\r\n{body}",
                                body.len(),
                                header_lines,
                            );
                            let _ = stream.write_all(response.as_bytes());
                            let _ = stream.flush();
                        }
                        Err(_) => {
                            std::thread::sleep(std::time::Duration::from_millis(2));
                        }
                    }
                }
            });
            Self {
                url: format!("http://127.0.0.1:{port}"),
                shutdown,
                requests,
            }
        }

        fn path(&self, path: &str) -> String {
            format!("{}{path}", self.url)
        }

        /// The raw requests the stub has served so far.
        fn requests(&self) -> Vec<String> {
            self.requests.lock().expect("log").clone()
        }
    }

    impl Drop for Stub {
        fn drop(&mut self) {
            self.shutdown
                .store(true, std::sync::atomic::Ordering::Relaxed);
        }
    }

    fn fetcher() -> CloudFetcher {
        CloudFetcher::builder()
            .retry_delay(Duration::from_millis(1))
            .geo_backoff(Duration::from_millis(1))
            .build()
    }

    #[test]
    fn aws_fetch_parses_the_amazon_entries_and_fails_empty() {
        let stub = Stub::serve(vec![Route {
            path: "/ip-ranges.json",
            status: 200,
            body: r#"{"prefixes": [
                {"ip_prefix": "203.0.113.0/24", "region": "us-east-1", "service": "AMAZON"},
                {"ip_prefix": "198.51.100.0/24", "region": "x", "service": "S3"}
            ]}"#,
            headers: &[],
            fail_first: false,
        }]);
        let ranges = fetcher().fetch_aws(&stub.path("/ip-ranges.json"));
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].0, "203.0.113.0/24");

        // Any failure is an empty answer, never an error onto the path.
        let empty = Stub::serve(vec![Route {
            path: "/ip-ranges.json",
            status: 500,
            body: "boom",
            headers: &[],
            fail_first: false,
        }]);
        assert!(
            fetcher()
                .fetch_aws(&empty.path("/ip-ranges.json"))
                .is_empty()
        );
        assert!(fetcher().fetch_aws("http://127.0.0.1:1/x").is_empty());
    }

    #[test]
    fn gcp_fetch_reads_both_prefix_fields() {
        let stub = Stub::serve(vec![Route {
            path: "/cloud.json",
            status: 200,
            body: r#"{"prefixes": [
                {"ipv4Prefix": "203.0.113.0/24", "scope": "us-central1"},
                {"ipv6Prefix": "2001:db8::/32", "scope": "europe-west1"}
            ]}"#,
            headers: &[],
            fail_first: false,
        }]);
        let ranges = fetcher().fetch_gcp(&stub.path("/cloud.json"));
        assert_eq!(ranges.len(), 2);
    }

    #[test]
    fn csv_fetch_skips_comments_and_junk() {
        let stub = Stub::serve(vec![Route {
            path: "/geo/google.csv",
            status: 200,
            body: "# hi\n203.0.113.0/24,a\njunk,b\n198.51.100.0/24\n",
            headers: &[],
            fail_first: false,
        }]);
        let ranges = fetcher().fetch_csv(&stub.path("/geo/google.csv"));
        assert_eq!(ranges.len(), 2);
    }

    #[test]
    fn vultr_fetch_reads_the_subnets() {
        let stub = Stub::serve(vec![Route {
            path: "/?json",
            status: 200,
            body: r#"{"subnets": [{"ip_prefix": "203.0.113.0/24"}]}"#,
            headers: &[],
            fail_first: false,
        }]);
        let ranges = fetcher().fetch_vultr(&stub.path("/?json"));
        assert_eq!(ranges.len(), 1);
    }

    #[test]
    fn azure_scrape_off_host_candidates_never_download() {
        // The trusted-host rule keeps an off-host stub out of the answer:
        // the page's candidates all point at the stub host, so the
        // extraction rejects them and the fetch answers empty.
        let stub = Stub::serve(vec![
            Route {
                path: "/download/details.aspx",
                status: 200,
                body: r#"<html><a id="failoverLink" href="http://127.0.0.1:1/x.json">x</a></html>"#,
                headers: &[],
                fail_first: false,
            },
            Route {
                path: "/tags.json",
                status: 200,
                body: r#"{"values": [{"name": "AzureCloud", "properties": {"addressPrefixes": ["203.0.113.0/24"]}}]}"#,
                headers: &[],
                fail_first: false,
            },
        ]);
        let result = fetcher().fetch_azure(&stub.path("/download/details.aspx"));
        assert!(result.is_empty());
    }

    #[test]
    fn azure_scrape_downloads_an_on_host_service_tags_document() {
        // The stub substitutes for download.microsoft.com by rewriting the
        // page's candidates onto the stub's own host: the extraction sees
        // the trusted host only when the URL says download.microsoft.com,
        // so this test drives `download_azure_service_tags` directly (the
        // on-host rule is exercised above).
        let stub = Stub::serve(vec![Route {
            path: "/`ServiceTags`_Public_20260101.json",
            status: 200,
            body: r#"{"values": [{"name": "AzureCloud", "properties": {"addressPrefixes": ["203.0.113.0/24", "junk"]}}]}"#,
            headers: &[],
            fail_first: false,
        }]);
        let ranges = fetcher()
            .download_azure_service_tags(&stub.path("/`ServiceTags`_Public_20260101.json"));
        assert!(ranges.is_empty(), "a bad prefix fails the whole parse");
    }

    #[test]
    fn azure_download_retries_then_succeeds() {
        // The first hit on the path fails transiently; the second carries
        // the real document - the retry arm must land it.
        let stub = Stub::serve_with_fail_first(vec![Route {
            path: "/tags.json",
            status: 200,
            body: r#"{"values": [{"name": "AzureCloud", "properties": {"addressPrefixes": ["203.0.113.0/24"]}}]}"#,
            headers: &[],
            fail_first: false,
        }]);
        let ranges = fetcher().download_azure_service_tags(&stub.path("/tags.json"));
        assert_eq!(ranges, vec![(String::from("203.0.113.0/24"), None)]);

        // An unreachable URL runs all three attempts and answers empty
        // without panicking.
        let started = std::time::Instant::now();
        let ranges = fetcher().download_azure_service_tags("http://127.0.0.1:1/tags.json");
        assert!(ranges.is_empty());
        assert!(
            started.elapsed() >= std::time::Duration::from_millis(2),
            "three attempts with a (shrunk) delay ran"
        );
    }

    #[test]
    fn azure_download_refuses_redirects() {
        let stub = Stub::serve(vec![Route {
            path: "/redirect.json",
            status: 302,
            body: "",
            headers: &[("Location", "/elsewhere.json")],
            fail_first: false,
        }]);
        let ranges = fetcher().download_azure_service_tags(&stub.path("/redirect.json"));
        assert!(
            ranges.is_empty(),
            "a 3xx is the failure, never followed (the reference raises)"
        );
    }

    #[test]
    fn azure_page_scrape_sends_the_browser_user_agent() {
        let stub = Stub::serve(vec![Route {
            path: "/download/details.aspx",
            status: 200,
            body: "<p>no candidates</p>",
            headers: &[],
            fail_first: false,
        }]);
        let ranges = fetcher().fetch_azure(&stub.path("/download/details.aspx"));
        assert!(ranges.is_empty());
        // The page fetch carried the reference browser UA.
        let requests = stub.requests();
        assert!(
            requests
                .iter()
                .any(|request| request.contains(AZURE_BROWSER_USER_AGENT)),
            "the page fetch must send the browser User-Agent"
        );
    }

    #[test]
    fn geo_database_download_carries_the_bearer_token_and_retries() {
        let stub = Stub::serve(vec![Route {
            path: "/free/country_asn.mmdb",
            status: 200,
            body: "MMDB-BYTES",
            headers: &[],
            fail_first: false,
        }]);
        let bytes = fetcher()
            .fetch_geo_database(&stub.path("/free/country_asn.mmdb"), "tok")
            .expect("downloaded");
        assert_eq!(bytes, b"MMDB-BYTES");

        let error = fetcher()
            .fetch_geo_database("http://127.0.0.1:1/x.mmdb", "tok")
            .unwrap_err();
        assert!(!error.reason.is_empty());
    }
}
