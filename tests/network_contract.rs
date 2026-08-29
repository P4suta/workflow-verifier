use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;
use workflow_verifier::internal::conformance::application::network::{
    DnsResolver, HttpLimits, HttpResponse, HttpsTransport, ProxyEndpoint, RedirectState,
    SecureHttpClient, TrustedHost, decode_http1, is_forbidden_address, proxy_connect_request,
    select_pinned_address,
};

#[test]
fn private_reserved_metadata_and_transition_addresses_are_rejected() {
    for address in [
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)),
        IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)),
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
        "fd00::1".parse().unwrap(),
        "fe80::1".parse().unwrap(),
        "2001:db8::1".parse().unwrap(),
        "::ffff:127.0.0.1".parse().unwrap(),
    ] {
        assert!(is_forbidden_address(address), "accepted {address}");
    }
    assert!(!is_forbidden_address("93.184.216.34".parse().unwrap()));
    assert!(!is_forbidden_address(
        "2606:2800:220:1:248:1893:25c8:1946".parse().unwrap()
    ));
}

#[test]
fn proxy_endpoint_is_explicit_public_dns_only_and_connects_to_the_pinned_target() {
    let proxy = ProxyEndpoint::parse("http://proxy.enterprise.example:8443").unwrap();
    assert_eq!(proxy.host(), "proxy.enterprise.example");
    assert_eq!(proxy.port(), 8443);
    for invalid in [
        "https://proxy.example",
        "http://user:secret@proxy.example",
        "http://127.0.0.1:8080",
        "http://proxy.example/path",
    ] {
        assert!(ProxyEndpoint::parse(invalid).is_err(), "accepted {invalid}");
    }
    assert_eq!(
        proxy_connect_request("2001:db8::1".parse().unwrap(), 443),
        b"CONNECT [2001:db8::1]:443 HTTP/1.1\r\nHost: [2001:db8::1]:443\r\n\r\n"
    );
}

#[test]
fn dns_answer_is_pinned_and_any_mixed_private_answer_fails_closed() {
    let public: IpAddr = "93.184.216.34".parse().unwrap();
    let other: IpAddr = "93.184.216.35".parse().unwrap();
    assert_eq!(
        select_pinned_address("example.com", &[other, public]),
        Ok(public)
    );
    assert!(
        select_pinned_address(
            "example.com",
            &[public, IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254))]
        )
        .is_err()
    );
    assert!(select_pinned_address("example.com", &[]).is_err());
}

#[test]
fn redirects_revalidate_trust_paths_break_loops_and_strip_cross_origin_credentials() {
    let hosts = vec![
        TrustedHost::new("https://github.com", ["/acme/"]).unwrap(),
        TrustedHost::new("https://objects.example.test", ["/download/"]).unwrap(),
    ];
    let initial = RedirectState::new(
        "https://github.com/acme/repository/archive/main.tar.gz",
        true,
        &hosts,
    )
    .unwrap();
    let same = initial
        .next("/acme/repository/archive/sha.tar.gz", &hosts)
        .unwrap();
    assert!(same.has_credentials());
    let cross = same
        .next(
            "https://objects.example.test/download/archive.tar.gz",
            &hosts,
        )
        .unwrap();
    assert!(!cross.has_credentials());
    assert!(cross.next("https://127.0.0.1/metadata", &hosts).is_err());
    assert!(
        cross
            .next("https://github.com/other/private", &hosts)
            .is_err()
    );

    let looped = initial
        .next("/acme/repository/archive/main.tar.gz", &hosts)
        .unwrap_err();
    assert!(looped.contains("loop"));
}

#[test]
fn trusted_hosts_are_https_only_and_canonical() {
    assert!(TrustedHost::new("http://github.com", ["/acme/"]).is_err());
    assert!(TrustedHost::new("https://user@github.com", ["/acme/"]).is_err());
    assert!(TrustedHost::new("https://127.0.0.1", ["/"]).is_err());
    assert!(TrustedHost::new("https://github.com", ["../escape"]).is_err());
    assert_eq!(
        TrustedHost::new("https://GitHub.COM:443", ["/acme"]).unwrap(),
        TrustedHost::new("https://github.com", ["/acme/"]).unwrap()
    );
}

#[derive(Default)]
struct FakeResolver;

impl DnsResolver for FakeResolver {
    fn resolve(&self, host: &str, _port: u16) -> Result<Vec<IpAddr>, String> {
        match host {
            "github.com" => Ok(vec!["93.184.216.34".parse().unwrap()]),
            "objects.example.test" => Ok(vec!["93.184.216.35".parse().unwrap()]),
            _ => Err("unexpected DNS host".to_owned()),
        }
    }
}

#[derive(Default)]
struct FakeTransport {
    requests: Mutex<Vec<(String, IpAddr, bool)>>,
}

impl HttpsTransport for FakeTransport {
    fn get(
        &self,
        url: &url::Url,
        pinned: IpAddr,
        credential: Option<&str>,
        _limits: HttpLimits,
    ) -> Result<HttpResponse, String> {
        self.requests
            .lock()
            .unwrap()
            .push((url.to_string(), pinned, credential.is_some()));
        if url.host_str() == Some("github.com") {
            Ok(HttpResponse {
                status: 302,
                headers: BTreeMap::from([(
                    "location".to_owned(),
                    "https://objects.example.test/download/object".to_owned(),
                )]),
                body: Vec::new(),
            })
        } else {
            Ok(HttpResponse {
                status: 200,
                headers: BTreeMap::new(),
                body: b"resolved".to_vec(),
            })
        }
    }
}

#[test]
fn client_reresolves_every_redirect_pins_ips_and_never_forwards_cross_origin_auth() {
    let hosts = vec![
        TrustedHost::new("https://github.com", ["/acme/"]).unwrap(),
        TrustedHost::new("https://objects.example.test", ["/download/"]).unwrap(),
    ];
    let transport = FakeTransport::default();
    let client = SecureHttpClient::new(FakeResolver, transport, HttpLimits::default());
    let response = client
        .get(
            "https://github.com/acme/archive",
            Some("secret-token"),
            &hosts,
        )
        .unwrap();
    assert_eq!(response.body, b"resolved");
    let requests = client.transport().requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].2);
    assert!(!requests[1].2);
    assert_eq!(requests[0].1, "93.184.216.34".parse::<IpAddr>().unwrap());
    assert_eq!(requests[1].1, "93.184.216.35".parse::<IpAddr>().unwrap());
}

#[test]
fn client_rejects_oversized_and_non_success_responses() {
    struct ResponseTransport(HttpResponse);
    impl HttpsTransport for ResponseTransport {
        fn get(
            &self,
            _url: &url::Url,
            _pinned: IpAddr,
            _credential: Option<&str>,
            _limits: HttpLimits,
        ) -> Result<HttpResponse, String> {
            Ok(self.0.clone())
        }
    }
    let host = [TrustedHost::new("https://github.com", ["/acme/"]).unwrap()];
    let oversized = SecureHttpClient::new(
        FakeResolver,
        ResponseTransport(HttpResponse {
            status: 200,
            headers: BTreeMap::new(),
            body: vec![0; 9],
        }),
        HttpLimits {
            max_response_bytes: 8,
            ..HttpLimits::default()
        },
    );
    assert!(
        oversized
            .get("https://github.com/acme/archive", None, &host)
            .unwrap_err()
            .contains("limit")
    );
    let failed = SecureHttpClient::new(
        FakeResolver,
        ResponseTransport(HttpResponse {
            status: 500,
            headers: BTreeMap::new(),
            body: Vec::new(),
        }),
        HttpLimits::default(),
    );
    assert!(
        failed
            .get("https://github.com/acme/archive", None, &host)
            .unwrap_err()
            .contains("500")
    );
}

#[test]
fn custom_headers_are_validated_and_stripped_on_cross_origin_redirects() {
    type RecordedRequest = (String, Vec<(String, String)>);

    #[derive(Default)]
    struct HeaderTransport {
        requests: Mutex<Vec<RecordedRequest>>,
    }
    impl HttpsTransport for HeaderTransport {
        fn get(
            &self,
            url: &url::Url,
            pinned: IpAddr,
            credential: Option<&str>,
            limits: HttpLimits,
        ) -> Result<HttpResponse, String> {
            self.get_with_headers(url, pinned, credential, &[], limits)
        }

        fn get_with_headers(
            &self,
            url: &url::Url,
            _pinned: IpAddr,
            _credential: Option<&str>,
            headers: &[(String, String)],
            _limits: HttpLimits,
        ) -> Result<HttpResponse, String> {
            self.requests
                .lock()
                .unwrap()
                .push((url.to_string(), headers.to_vec()));
            if url.host_str() == Some("github.com") {
                Ok(HttpResponse {
                    status: 302,
                    headers: BTreeMap::from([(
                        "location".to_owned(),
                        "https://objects.example.test/download/object".to_owned(),
                    )]),
                    body: Vec::new(),
                })
            } else {
                Ok(HttpResponse {
                    status: 200,
                    headers: BTreeMap::new(),
                    body: b"ok".to_vec(),
                })
            }
        }
    }

    let hosts = vec![
        TrustedHost::new("https://github.com", ["/acme/"]).unwrap(),
        TrustedHost::new("https://objects.example.test", ["/download/"]).unwrap(),
    ];
    let client = SecureHttpClient::new(
        FakeResolver,
        HeaderTransport::default(),
        HttpLimits::default(),
    );
    client
        .get_with_headers(
            "https://github.com/acme/archive",
            None,
            &hosts,
            &[
                ("Accept".to_owned(), "application/json".to_owned()),
                (
                    "Authorization".to_owned(),
                    "Bearer internal-secret".to_owned(),
                ),
            ],
        )
        .expect("bounded request");
    let requests = client.transport().requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].1.len(), 2);
    assert!(requests[1].1.is_empty());
    drop(requests);

    assert!(
        client
            .get_with_headers(
                "https://github.com/acme/archive",
                None,
                &hosts,
                &[("X-Test".to_owned(), "safe\r\nInjected: yes".to_owned())],
            )
            .is_err()
    );
}

#[test]
fn http_framing_is_strict_bounded_and_supports_chunked_streams() {
    let limits = HttpLimits {
        max_header_bytes: 128,
        max_response_bytes: 8,
        ..HttpLimits::default()
    };
    let fixed = decode_http1(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-A: b\r\n\r\nok",
        limits,
    )
    .unwrap();
    assert_eq!(fixed.status, 200);
    assert_eq!(fixed.body, b"ok");
    let chunked = decode_http1(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n",
        limits,
    )
    .unwrap();
    assert_eq!(chunked.body, b"abcde");

    assert!(
        decode_http1(
            b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\n123456789",
            limits
        )
        .is_err()
    );
    assert!(
        decode_http1(
            b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            limits
        )
        .is_err()
    );
    assert!(decode_http1(&[b'a'; 129], limits).is_err());
}
