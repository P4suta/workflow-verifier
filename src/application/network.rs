//! Fail-closed URL, DNS, and redirect policy for the HTTPS resolver adapter.

use rustls::pki_types::{CertificateDer, ServerName};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;
use url::{Host, Url};
use zeroize::Zeroizing;

// Fixed v0.1 resolver transport profile. The response cap is the config-v2
// resolver budget; the remaining limits bound handshake, framing, and redirect
// amplification independently of server behavior.
const MAX_REDIRECTS: usize = 10;
const DEFAULT_CONNECT_TIMEOUT_SECONDS: u64 = 10;
const DEFAULT_IO_TIMEOUT_SECONDS: u64 = 30;
const BYTES_PER_KIBIBYTE: usize = 1_024;
const DEFAULT_MAX_HEADER_KIBIBYTES: usize = 64;
const BYTES_PER_MEBIBYTE: usize = 1_048_576;
const DEFAULT_MAX_RESPONSE_MEBIBYTES: usize = 16;
const MAX_WIRE_FRAMING_MEBIBYTES: usize = 1;

// HTTP/1 framing and status widths are protocol grammar, not tuning values.
const HTTP_HEAD_TERMINATOR: &[u8] = b"\r\n\r\n";
const HTTP_LINE_TERMINATOR: &[u8] = b"\r\n";
const HTTP_STATUS_DIGITS: usize = 3;
const HTTP_INFORMATIONAL_STATUS_MIN: u16 = 100;
const HTTP_SERVER_ERROR_STATUS_MAX: u16 = 599;
const HTTP_SUCCESS_STATUS_MIN: u16 = 200;
const HTTP_SUCCESS_STATUS_MAX: u16 = 299;
const HTTP_REDIRECT_STATUSES: [u16; 5] = [301, 302, 303, 307, 308];
const HTTPS_DEFAULT_PORT: u16 = 443;
const HEX_RADIX: u32 = 16;
const HEX_DIGITS_PER_BYTE: usize = 2;
const MAX_CHUNK_SIZE_HEX_DIGITS: usize = std::mem::size_of::<usize>() * HEX_DIGITS_PER_BYTE;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HttpLimits {
    pub connect_timeout: Duration,
    pub io_timeout: Duration,
    pub max_header_bytes: usize,
    pub max_response_bytes: usize,
}

impl Default for HttpLimits {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(DEFAULT_CONNECT_TIMEOUT_SECONDS),
            io_timeout: Duration::from_secs(DEFAULT_IO_TIMEOUT_SECONDS),
            max_header_bytes: DEFAULT_MAX_HEADER_KIBIBYTES * BYTES_PER_KIBIBYTE,
            max_response_bytes: DEFAULT_MAX_RESPONSE_MEBIBYTES * BYTES_PER_MEBIBYTE,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

/// Decode one connection-close HTTP/1 response under deterministic limits.
///
/// # Errors
/// Rejects malformed/duplicate headers, response smuggling ambiguity,
/// unsupported encodings, truncated framing, trailing bytes, and all limit
/// violations.
pub fn decode_http1(bytes: &[u8], limits: HttpLimits) -> Result<HttpResponse, String> {
    let (status, headers, header_end) = decode_http1_head(bytes, limits.max_header_bytes)?;
    if headers
        .get("content-encoding")
        .is_some_and(|value| !value.eq_ignore_ascii_case("identity"))
    {
        return Err("compressed HTTP responses are forbidden".to_owned());
    }
    let content_length = headers
        .get("content-length")
        .map(|value| {
            value
                .parse::<usize>()
                .map_err(|_| "HTTP Content-Length is malformed".to_owned())
        })
        .transpose()?;
    let transfer_encoding = headers.get("transfer-encoding");
    if transfer_encoding.is_some() && content_length.is_some() {
        return Err("HTTP response has ambiguous body framing".to_owned());
    }
    let wire_body = &bytes[header_end..];
    let body = match transfer_encoding {
        Some(value) if value.eq_ignore_ascii_case("chunked") => {
            decode_chunked(wire_body, limits.max_response_bytes)?
        }
        Some(_) => return Err("unsupported HTTP Transfer-Encoding".to_owned()),
        None => decode_fixed_body(wire_body, content_length, limits.max_response_bytes)?,
    };
    Ok(HttpResponse {
        status,
        headers,
        body,
    })
}

fn decode_http1_head(
    bytes: &[u8],
    maximum: usize,
) -> Result<(u16, BTreeMap<String, String>, usize), String> {
    let boundary = bytes
        .windows(HTTP_HEAD_TERMINATOR.len())
        .position(|window| window == HTTP_HEAD_TERMINATOR)
        .map(|offset| offset.saturating_add(HTTP_HEAD_TERMINATOR.len()));
    let Some(header_end) = boundary else {
        return Err(if bytes.len() > maximum {
            "HTTP response header exceeded byte limit".to_owned()
        } else {
            "HTTP response header is incomplete".to_owned()
        });
    };
    if header_end > maximum {
        return Err("HTTP response header exceeded byte limit".to_owned());
    }
    let header =
        std::str::from_utf8(&bytes[..header_end.saturating_sub(HTTP_HEAD_TERMINATOR.len())])
            .map_err(|_| "HTTP response header is not UTF-8".to_owned())?;
    let mut lines = header.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| "HTTP response has no status line".to_owned())?;
    let mut status_parts = status_line.split_ascii_whitespace();
    let version = status_parts
        .next()
        .ok_or_else(|| "HTTP response has no version".to_owned())?;
    if !matches!(version, "HTTP/1.0" | "HTTP/1.1") {
        return Err("HTTP response uses an unsupported version".to_owned());
    }
    let status_text = status_parts
        .next()
        .ok_or_else(|| "HTTP response has no status".to_owned())?;
    if status_text.len() != HTTP_STATUS_DIGITS
        || !status_text.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err("HTTP response status is malformed".to_owned());
    }
    let status = status_text
        .parse::<u16>()
        .map_err(|_| "HTTP response status is out of range".to_owned())?;
    if !(HTTP_INFORMATIONAL_STATUS_MIN..=HTTP_SERVER_ERROR_STATUS_MAX).contains(&status) {
        return Err("HTTP response status is out of range".to_owned());
    }
    let mut headers = BTreeMap::new();
    for line in lines {
        if line.starts_with([' ', '\t']) {
            return Err("HTTP folded headers are forbidden".to_owned());
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| "HTTP response header is malformed".to_owned())?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err("HTTP response header name is malformed".to_owned());
        }
        let name = name.to_ascii_lowercase();
        if headers
            .insert(name.clone(), value.trim().to_owned())
            .is_some()
        {
            return Err(format!("HTTP response contains duplicate header {name}"));
        }
    }
    Ok((status, headers, header_end))
}

fn decode_fixed_body(
    bytes: &[u8],
    content_length: Option<usize>,
    maximum: usize,
) -> Result<Vec<u8>, String> {
    if let Some(length) = content_length {
        if length > maximum {
            return Err("HTTP response body exceeded byte limit".to_owned());
        }
        if bytes.len() != length {
            return Err("HTTP response Content-Length mismatch".to_owned());
        }
    } else if bytes.len() > maximum {
        return Err("HTTP response body exceeded byte limit".to_owned());
    }
    Ok(bytes.to_vec())
}

fn decode_chunked(bytes: &[u8], maximum: usize) -> Result<Vec<u8>, String> {
    let mut cursor = 0usize;
    let mut output = Vec::new();
    loop {
        let line_end = bytes[cursor..]
            .windows(HTTP_LINE_TERMINATOR.len())
            .position(|window| window == HTTP_LINE_TERMINATOR)
            .map(|offset| cursor.saturating_add(offset))
            .ok_or_else(|| "HTTP chunk size is incomplete".to_owned())?;
        let line = std::str::from_utf8(&bytes[cursor..line_end])
            .map_err(|_| "HTTP chunk size is not ASCII".to_owned())?;
        if line.is_empty() || line.contains(';') || line.len() > MAX_CHUNK_SIZE_HEX_DIGITS {
            return Err("HTTP chunk size is malformed".to_owned());
        }
        let length = usize::from_str_radix(line, HEX_RADIX)
            .map_err(|_| "HTTP chunk size is malformed".to_owned())?;
        cursor = line_end.saturating_add(HTTP_LINE_TERMINATOR.len());
        if length == 0 {
            if bytes.get(cursor..) != Some(HTTP_LINE_TERMINATOR) {
                return Err("HTTP chunk trailer is malformed".to_owned());
            }
            return Ok(output);
        }
        if output.len().saturating_add(length) > maximum {
            return Err("HTTP response body exceeded byte limit".to_owned());
        }
        let end = cursor
            .checked_add(length)
            .ok_or_else(|| "HTTP chunk length overflow".to_owned())?;
        let data = bytes
            .get(cursor..end)
            .ok_or_else(|| "HTTP chunk data is incomplete".to_owned())?;
        if bytes.get(end..end.saturating_add(HTTP_LINE_TERMINATOR.len()))
            != Some(HTTP_LINE_TERMINATOR)
        {
            return Err("HTTP chunk delimiter is malformed".to_owned());
        }
        output.extend_from_slice(data);
        cursor = end.saturating_add(HTTP_LINE_TERMINATOR.len());
    }
}

pub trait DnsResolver {
    /// Return every address advertised for this hostname.
    ///
    /// # Errors
    /// Returns a stable transport message without silently falling back.
    fn resolve(&self, host: &str, port: u16) -> Result<Vec<IpAddr>, String>;
}

pub trait HttpsTransport {
    /// Perform one TLS request to exactly `pinned`, while authenticating TLS
    /// against the DNS name in `url`.
    ///
    /// # Errors
    /// Returns TLS, timeout, framing, and bounded-stream failures.
    fn get(
        &self,
        url: &Url,
        pinned: IpAddr,
        credential: Option<&str>,
        limits: HttpLimits,
    ) -> Result<HttpResponse, String>;

    /// Perform one request with prevalidated additional headers. Implementors
    /// that do not support them remain fail-closed.
    ///
    /// # Errors
    /// Returns a transport failure or rejects non-empty custom headers.
    fn get_with_headers(
        &self,
        url: &Url,
        pinned: IpAddr,
        credential: Option<&str>,
        headers: &[(String, String)],
        limits: HttpLimits,
    ) -> Result<HttpResponse, String> {
        if headers.is_empty() {
            self.get(url, pinned, credential, limits)
        } else {
            Err("HTTPS transport does not support custom request headers".to_owned())
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemDnsResolver;

impl DnsResolver for SystemDnsResolver {
    fn resolve(&self, host: &str, port: u16) -> Result<Vec<IpAddr>, String> {
        let mut addresses = (host, port)
            .to_socket_addrs()
            .map_err(|error| format!("DNS resolution failed for {host}: {error}"))?
            .map(|address| address.ip())
            .collect::<Vec<_>>();
        addresses.sort();
        addresses.dedup();
        Ok(addresses)
    }
}

#[derive(Clone)]
pub struct RustlsTransport {
    config: Arc<rustls::ClientConfig>,
    proxy: Option<SocketAddr>,
}

impl std::fmt::Debug for RustlsTransport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RustlsTransport")
            .finish_non_exhaustive()
    }
}

impl RustlsTransport {
    /// Build a Rustls transport from the operating-system trust store plus
    /// explicitly trusted DER certificates. Repository input never reaches
    /// this constructor directly.
    ///
    /// # Errors
    /// Fails closed when native certificate loading or any extra certificate
    /// validation fails.
    pub fn from_native_roots(additional_der_roots: &[Vec<u8>]) -> Result<Self, String> {
        Self::from_native_roots_with_proxy(additional_der_roots, None)
    }

    /// Build a Rustls transport with an optional, explicitly trusted HTTP
    /// CONNECT proxy. The proxy DNS answer is validated and pinned before use.
    ///
    /// # Errors
    /// Fails closed for invalid roots, unsafe proxy DNS answers, or resolution
    /// failures.
    pub fn from_native_roots_with_proxy(
        additional_der_roots: &[Vec<u8>],
        proxy: Option<&ProxyEndpoint>,
    ) -> Result<Self, String> {
        let native = rustls_native_certs::load_native_certs();
        if !native.errors.is_empty() {
            return Err(format!(
                "operating-system certificate store could not be loaded: {:?}",
                native.errors
            ));
        }
        let mut roots = rustls::RootCertStore::empty();
        for certificate in native.certs {
            roots
                .add(certificate)
                .map_err(|error| format!("invalid operating-system certificate: {error}"))?;
        }
        for certificate in additional_der_roots {
            roots
                .add(CertificateDer::from(certificate.clone()))
                .map_err(|error| format!("invalid trusted custom certificate: {error}"))?;
        }
        if roots.is_empty() {
            return Err("operating-system certificate store is empty".to_owned());
        }
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let proxy = proxy.map(ProxyEndpoint::resolve_pinned).transpose()?;
        Ok(Self {
            config: Arc::new(config),
            proxy,
        })
    }
}

impl HttpsTransport for RustlsTransport {
    fn get(
        &self,
        url: &Url,
        pinned: IpAddr,
        credential: Option<&str>,
        limits: HttpLimits,
    ) -> Result<HttpResponse, String> {
        self.get_with_headers(url, pinned, credential, &[], limits)
    }

    fn get_with_headers(
        &self,
        url: &Url,
        pinned: IpAddr,
        credential: Option<&str>,
        headers: &[(String, String)],
        limits: HttpLimits,
    ) -> Result<HttpResponse, String> {
        let host = url
            .host_str()
            .ok_or_else(|| "HTTPS URL has no DNS host".to_owned())?;
        let port = url
            .port_or_known_default()
            .ok_or_else(|| "HTTPS URL has no effective port".to_owned())?;
        let target = SocketAddr::new(pinned, port);
        let address = self.proxy.unwrap_or(target);
        let mut socket = TcpStream::connect_timeout(&address, limits.connect_timeout)
            .map_err(|error| format!("HTTPS connect to pinned address failed: {error}"))?;
        socket
            .set_read_timeout(Some(limits.io_timeout))
            .and_then(|()| socket.set_write_timeout(Some(limits.io_timeout)))
            .map_err(|error| format!("HTTPS timeout configuration failed: {error}"))?;
        if self.proxy.is_some() {
            establish_proxy_tunnel(&mut socket, target, limits)?;
        }
        let server_name = ServerName::try_from(host.to_owned())
            .map_err(|error| format!("invalid TLS server name: {error}"))?;
        let connection = rustls::ClientConnection::new(Arc::clone(&self.config), server_name)
            .map_err(|error| format!("TLS client initialization failed: {error}"))?;
        let mut stream = rustls::StreamOwned::new(connection, socket);
        let request = request_bytes(url, credential, headers)?;
        stream
            .write_all(request.as_bytes())
            .and_then(|()| stream.flush())
            .map_err(|error| format!("HTTPS request write failed: {error}"))?;
        let wire_limit = limits
            .max_header_bytes
            .saturating_add(limits.max_response_bytes)
            .saturating_add(MAX_WIRE_FRAMING_MEBIBYTES * BYTES_PER_MEBIBYTE);
        let take_limit = u64::try_from(wire_limit.saturating_add(1)).unwrap_or(u64::MAX);
        let mut wire = Vec::new();
        stream
            .take(take_limit)
            .read_to_end(&mut wire)
            .map_err(|error| format!("HTTPS response read failed or timed out: {error}"))?;
        if wire.len() > wire_limit {
            return Err("HTTPS response wire representation exceeded byte limit".to_owned());
        }
        decode_http1(&wire, limits)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProxyEndpoint {
    host: String,
    port: u16,
}

impl ProxyEndpoint {
    /// Parse a user-trusted, credential-free HTTP CONNECT proxy endpoint.
    ///
    /// # Errors
    /// Rejects TLS proxy nesting, credentials, IP literals, local names,
    /// paths, queries, fragments, and malformed ports.
    pub fn parse(value: &str) -> Result<Self, String> {
        let url = Url::parse(value).map_err(|error| format!("invalid proxy URL: {error}"))?;
        if url.scheme() != "http"
            || !url.username().is_empty()
            || url.password().is_some()
            || !matches!(url.path(), "" | "/")
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(
                "proxy must be a credential-free HTTP origin without path, query, or fragment"
                    .to_owned(),
            );
        }
        let host = match url.host() {
            Some(Host::Domain(host))
                if !host.eq_ignore_ascii_case("localhost")
                    && !host.to_ascii_lowercase().ends_with(".localhost") =>
            {
                host.to_ascii_lowercase()
            }
            _ => return Err("proxy host must be a non-local DNS name".to_owned()),
        };
        let port = url
            .port_or_known_default()
            .ok_or_else(|| "proxy has no effective port".to_owned())?;
        Ok(Self { host, port })
    }

    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }

    fn resolve_pinned(&self) -> Result<SocketAddr, String> {
        let addresses = SystemDnsResolver.resolve(&self.host, self.port)?;
        let pinned = select_pinned_address(&self.host, &addresses)?;
        Ok(SocketAddr::new(pinned, self.port))
    }
}

#[must_use]
pub fn proxy_connect_request(pinned: IpAddr, port: u16) -> Vec<u8> {
    let authority = match pinned {
        IpAddr::V4(address) => format!("{address}:{port}"),
        IpAddr::V6(address) => format!("[{address}]:{port}"),
    };
    format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").into_bytes()
}

fn establish_proxy_tunnel(
    socket: &mut TcpStream,
    target: SocketAddr,
    limits: HttpLimits,
) -> Result<(), String> {
    socket
        .write_all(&proxy_connect_request(target.ip(), target.port()))
        .and_then(|()| socket.flush())
        .map_err(|error| format!("HTTPS proxy CONNECT write failed: {error}"))?;
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        if header.len() >= limits.max_header_bytes {
            return Err("HTTPS proxy CONNECT header exceeded byte limit".to_owned());
        }
        let mut byte = [0u8; 1];
        socket
            .read_exact(&mut byte)
            .map_err(|error| format!("HTTPS proxy CONNECT response failed: {error}"))?;
        header.push(byte[0]);
    }
    let (status, headers, consumed) = decode_http1_head(&header, limits.max_header_bytes)?;
    if consumed != header.len()
        || headers
            .get("content-length")
            .is_some_and(|value| value != "0")
        || headers.contains_key("transfer-encoding")
    {
        return Err("HTTPS proxy CONNECT response has an unexpected body".to_owned());
    }
    if status != 200 {
        return Err(format!("HTTPS proxy CONNECT returned status {status}"));
    }
    Ok(())
}

fn request_bytes(
    url: &Url,
    credential: Option<&str>,
    headers: &[(String, String)],
) -> Result<Zeroizing<String>, String> {
    if credential.is_some_and(|value| {
        value.is_empty()
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_graphic() && !matches!(byte, b'\r' | b'\n'))
    }) {
        return Err("resolver credential contains invalid bytes".to_owned());
    }
    let host = url
        .host_str()
        .ok_or_else(|| "HTTPS URL has no DNS host".to_owned())?;
    let authority = match url.port() {
        Some(port) if port != HTTPS_DEFAULT_PORT => format!("{host}:{port}"),
        _ => host.to_owned(),
    };
    let mut target = url.path().to_owned();
    if let Some(query) = url.query() {
        target.push('?');
        target.push_str(query);
    }
    let mut request = Zeroizing::new(format!(
        concat!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: workflow-verifier/",
            env!("CARGO_PKG_VERSION"),
            "\r\nAccept: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\n"
        ),
        target, authority
    ));
    if let Some(value) = credential {
        request.push_str("Authorization: Bearer ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    validate_request_headers(credential, headers)?;
    for (name, value) in headers {
        request.push_str(name);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    Ok(request)
}

fn validate_request_headers(
    credential: Option<&str>,
    headers: &[(String, String)],
) -> Result<(), String> {
    let mut names = BTreeSet::new();
    for (name, value) in headers {
        if name.is_empty()
            || !name.bytes().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(
                        byte,
                        b'!' | b'#'
                            | b'$'
                            | b'%'
                            | b'&'
                            | b'\''
                            | b'*'
                            | b'+'
                            | b'-'
                            | b'.'
                            | b'^'
                            | b'_'
                            | b'`'
                            | b'|'
                            | b'~'
                    )
            })
        {
            return Err("resolver request header name is malformed".to_owned());
        }
        if value.is_empty()
            || !value
                .bytes()
                .all(|byte| byte == b'\t' || byte == b' ' || byte.is_ascii_graphic())
        {
            return Err("resolver request header value is malformed".to_owned());
        }
        let lower = name.to_ascii_lowercase();
        if !names.insert(lower.clone()) {
            return Err(format!("duplicate resolver request header {lower}"));
        }
        if matches!(
            lower.as_str(),
            "host"
                | "content-length"
                | "transfer-encoding"
                | "connection"
                | "proxy-authorization"
                | "proxy-connection"
                | "user-agent"
        ) {
            return Err(format!("resolver request header {lower} is reserved"));
        }
        if lower == "authorization" && credential.is_some() {
            return Err("resolver request has conflicting authorization credentials".to_owned());
        }
    }
    Ok(())
}

#[cfg(test)]
mod proxy_tests {
    use super::{HttpLimits, establish_proxy_tunnel, proxy_connect_request};
    use std::io::{Read, Write};
    use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    fn run_proxy(response: Vec<u8>, limits: HttpLimits) -> (Result<(), String>, Vec<u8>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind local proxy fixture");
        let address = listener.local_addr().expect("proxy fixture address");
        let (request_tx, request_rx) = mpsc::channel();
        let server = thread::spawn(move || {
            let (mut socket, _) = listener.accept().expect("accept proxy client");
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                let mut byte = [0u8; 1];
                socket.read_exact(&mut byte).expect("read CONNECT request");
                request.push(byte[0]);
            }
            request_tx.send(request).expect("record CONNECT request");
            socket.write_all(&response).expect("write proxy response");
        });
        let mut client = TcpStream::connect(address).expect("connect proxy fixture");
        client
            .set_read_timeout(Some(limits.io_timeout))
            .expect("set read timeout");
        client
            .set_write_timeout(Some(limits.io_timeout))
            .expect("set write timeout");
        let target = SocketAddr::new("93.184.216.34".parse().unwrap(), 443);
        let result = establish_proxy_tunnel(&mut client, target, limits);
        let request = request_rx.recv().expect("CONNECT request");
        server.join().expect("proxy fixture");
        (result, request)
    }

    fn limits(max_header_bytes: usize) -> HttpLimits {
        HttpLimits {
            connect_timeout: Duration::from_secs(1),
            io_timeout: Duration::from_secs(1),
            max_header_bytes,
            max_response_bytes: 1024,
        }
    }

    #[test]
    fn connect_tunnel_targets_the_pinned_ip_and_accepts_only_an_empty_200_response() {
        let (result, request) = run_proxy(
            b"HTTP/1.1 200 Connection Established\r\nContent-Length: 0\r\n\r\n".to_vec(),
            limits(1024),
        );
        result.expect("bounded empty CONNECT response");
        assert_eq!(
            request,
            proxy_connect_request(IpAddr::V4("93.184.216.34".parse().unwrap()), 443)
        );
    }

    #[test]
    fn connect_tunnel_rejects_auth_challenges_body_framing_and_oversized_headers() {
        for (response, expected) in [
            (
                b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n".to_vec(),
                "status 407",
            ),
            (
                b"HTTP/1.1 200 Connection Established\r\nContent-Length: 1\r\n\r\nX".to_vec(),
                "unexpected body",
            ),
            (
                b"HTTP/1.1 200 Connection Established\r\nTransfer-Encoding: chunked\r\n\r\n"
                    .to_vec(),
                "unexpected body",
            ),
        ] {
            let error = run_proxy(response, limits(1024)).0.unwrap_err();
            assert!(error.contains(expected), "unexpected error: {error}");
        }

        let error = run_proxy(
            b"HTTP/1.1 200 Connection Established\r\nX-Padding: 0123456789\r\n\r\n".to_vec(),
            limits(32),
        )
        .0
        .unwrap_err();
        assert!(error.contains("byte limit"), "unexpected error: {error}");
    }

    #[test]
    fn connect_tunnel_honors_the_response_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind local proxy fixture");
        let address = listener.local_addr().expect("proxy fixture address");
        let server = thread::spawn(move || {
            let (mut socket, _) = listener.accept().expect("accept proxy client");
            let mut request = [0u8; 256];
            let _ = socket.read(&mut request).expect("read CONNECT request");
            thread::sleep(Duration::from_millis(75));
        });
        let mut client = TcpStream::connect(address).expect("connect proxy fixture");
        client
            .set_read_timeout(Some(Duration::from_millis(20)))
            .expect("set read timeout");
        let error = establish_proxy_tunnel(
            &mut client,
            SocketAddr::new("93.184.216.34".parse().unwrap(), 443),
            HttpLimits {
                io_timeout: Duration::from_millis(20),
                ..limits(1024)
            },
        )
        .unwrap_err();
        assert!(
            error.contains("response failed"),
            "unexpected error: {error}"
        );
        server.join().expect("proxy fixture");
    }
}

#[derive(Clone, Debug)]
pub struct SecureHttpClient<R, T> {
    resolver: R,
    transport: T,
    limits: HttpLimits,
}

impl<R, T> SecureHttpClient<R, T>
where
    R: DnsResolver,
    T: HttpsTransport,
{
    #[must_use]
    pub fn new(resolver: R, transport: T, limits: HttpLimits) -> Self {
        Self {
            resolver,
            transport,
            limits,
        }
    }

    #[must_use]
    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// Fetch one bounded response while pinning each independently validated
    /// DNS answer and revalidating every redirect.
    ///
    /// # Errors
    /// Rejects unsafe DNS answers, redirects, response sizes, and non-success
    /// terminal status codes, in addition to transport failures.
    pub fn get(
        &self,
        url: &str,
        credential: Option<&str>,
        trusted_hosts: &[TrustedHost],
    ) -> Result<HttpResponse, String> {
        self.get_with_headers(url, credential, trusted_hosts, &[])
    }

    /// Fetch one bounded response with validated additional request headers.
    /// Additional headers are never forwarded across an origin change.
    ///
    /// # Errors
    /// Rejects malformed headers and all failures documented by [`Self::get`].
    pub fn get_with_headers(
        &self,
        url: &str,
        credential: Option<&str>,
        trusted_hosts: &[TrustedHost],
        headers: &[(String, String)],
    ) -> Result<HttpResponse, String> {
        validate_request_headers(credential, headers)?;
        let mut state = RedirectState::new(url, credential.is_some(), trusted_hosts)?;
        let mut forward_headers = true;
        loop {
            let host = state
                .url()
                .host_str()
                .ok_or_else(|| "HTTPS URL has no host".to_owned())?;
            let port = state
                .url()
                .port_or_known_default()
                .ok_or_else(|| "HTTPS URL has no effective port".to_owned())?;
            let addresses = self.resolver.resolve(host, port)?;
            let pinned = select_pinned_address(host, &addresses)?;
            let response = self.transport.get_with_headers(
                state.url(),
                pinned,
                if state.has_credentials() {
                    credential
                } else {
                    None
                },
                if forward_headers { headers } else { &[] },
                self.limits,
            )?;
            if response.body.len() > self.limits.max_response_bytes {
                return Err(format!(
                    "HTTPS response exceeded byte limit {}",
                    self.limits.max_response_bytes
                ));
            }
            if HTTP_REDIRECT_STATUSES.contains(&response.status) {
                let location = response
                    .headers
                    .get("location")
                    .ok_or_else(|| "HTTPS redirect omitted Location".to_owned())?;
                let next = state.next(location, trusted_hosts)?;
                if canonical_origin(next.url())? != canonical_origin(state.url())? {
                    forward_headers = false;
                }
                state = next;
            } else if (HTTP_SUCCESS_STATUS_MIN..=HTTP_SUCCESS_STATUS_MAX).contains(&response.status)
            {
                return Ok(response);
            } else {
                return Err(format!("HTTPS request returned status {}", response.status));
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedHost {
    origin: String,
    path_prefixes: Vec<String>,
}

impl TrustedHost {
    /// Create a trusted resolver boundary from user-owned configuration.
    ///
    /// # Errors
    /// Rejects non-HTTPS origins, IP literals, credentials, unsafe paths, and
    /// origins containing query or fragment data.
    pub fn new(
        origin: &str,
        path_prefixes: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> Result<Self, String> {
        let url = parse_https(origin)?;
        if url.path() != "/" || url.query().is_some() {
            return Err("trusted origin cannot contain a path or query".to_owned());
        }
        let origin = canonical_origin(&url)?;
        let mut prefixes = path_prefixes
            .into_iter()
            .map(|value| normalize_prefix(value.as_ref()))
            .collect::<Result<Vec<_>, _>>()?;
        prefixes.sort();
        prefixes.dedup();
        if prefixes.is_empty() {
            return Err("trusted host requires at least one path prefix".to_owned());
        }
        Ok(Self {
            origin,
            path_prefixes: prefixes,
        })
    }

    #[must_use]
    pub fn origin(&self) -> &str {
        &self.origin
    }

    #[must_use]
    pub fn path_prefixes(&self) -> &[String] {
        &self.path_prefixes
    }

    fn permits(&self, url: &Url) -> bool {
        canonical_origin(url).is_ok_and(|origin| origin == self.origin)
            && self.path_prefixes.iter().any(|prefix| {
                prefix == "/"
                    || url.path() == prefix.trim_end_matches('/')
                    || url.path().starts_with(prefix)
            })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RedirectState {
    url: Url,
    credentials: bool,
    visited: BTreeSet<String>,
    redirects: usize,
}

impl RedirectState {
    /// Start one resolver request after validating its host/path profile.
    ///
    /// # Errors
    /// Rejects URLs outside `trusted_hosts` and all unsafe HTTPS authorities.
    pub fn new(
        url: &str,
        credentials: bool,
        trusted_hosts: &[TrustedHost],
    ) -> Result<Self, String> {
        let url = validated_url(url, trusted_hosts)?;
        let canonical = canonical_url(&url);
        Ok(Self {
            url,
            credentials,
            visited: BTreeSet::from([canonical]),
            redirects: 0,
        })
    }

    /// Resolve one HTTP redirect, re-applying all trust policy.
    ///
    /// # Errors
    /// Rejects loops, excessive hops, untrusted targets, invalid locations,
    /// and unsafe authorities or paths.
    pub fn next(&self, location: &str, trusted_hosts: &[TrustedHost]) -> Result<Self, String> {
        if self.redirects >= MAX_REDIRECTS {
            return Err("HTTPS redirect limit exceeded".to_owned());
        }
        let candidate = self
            .url
            .join(location)
            .map_err(|error| format!("invalid HTTPS redirect: {error}"))?;
        validate_url(&candidate, trusted_hosts)?;
        let canonical = canonical_url(&candidate);
        if self.visited.contains(&canonical) {
            return Err("HTTPS redirect loop detected".to_owned());
        }
        let mut visited = self.visited.clone();
        visited.insert(canonical);
        let same_origin = canonical_origin(&candidate)? == canonical_origin(&self.url)?;
        Ok(Self {
            url: candidate,
            credentials: self.credentials && same_origin,
            visited,
            redirects: self.redirects + 1,
        })
    }

    #[must_use]
    pub fn url(&self) -> &Url {
        &self.url
    }

    #[must_use]
    pub fn has_credentials(&self) -> bool {
        self.credentials
    }
}

fn validated_url(value: &str, trusted_hosts: &[TrustedHost]) -> Result<Url, String> {
    let url = parse_https(value)?;
    validate_url(&url, trusted_hosts)?;
    Ok(url)
}

fn validate_url(url: &Url, trusted_hosts: &[TrustedHost]) -> Result<(), String> {
    parse_https(url.as_str())?;
    if !trusted_hosts.iter().any(|host| host.permits(url)) {
        return Err("HTTPS destination is outside the trusted host/path profile".to_owned());
    }
    Ok(())
}

fn parse_https(value: &str) -> Result<Url, String> {
    let url = Url::parse(value).map_err(|error| format!("invalid HTTPS URL: {error}"))?;
    if url.scheme() != "https" {
        return Err("resolver URLs must use HTTPS".to_owned());
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("resolver URLs cannot embed credentials".to_owned());
    }
    if url.fragment().is_some() {
        return Err("resolver URLs cannot contain fragments".to_owned());
    }
    let Some(Host::Domain(host)) = url.host() else {
        return Err("resolver URLs require a DNS hostname, not an IP literal".to_owned());
    };
    if host.eq_ignore_ascii_case("localhost")
        || host.to_ascii_lowercase().ends_with(".localhost")
        || host.is_empty()
    {
        return Err("localhost resolver hosts are forbidden".to_owned());
    }
    if url.path().contains(['\\', '%']) {
        return Err("resolver paths cannot contain encoded or backslash delimiters".to_owned());
    }
    Ok(url)
}

fn canonical_origin(url: &Url) -> Result<String, String> {
    let host = url
        .host_str()
        .ok_or_else(|| "HTTPS URL has no host".to_owned())?
        .to_ascii_lowercase();
    Ok(match url.port_or_known_default() {
        Some(HTTPS_DEFAULT_PORT) => format!("https://{host}"),
        Some(port) => format!("https://{host}:{port}"),
        None => return Err("HTTPS URL has no effective port".to_owned()),
    })
}

fn canonical_url(url: &Url) -> String {
    let mut value = url.clone();
    value.set_fragment(None);
    value.to_string()
}

fn normalize_prefix(value: &str) -> Result<String, String> {
    if !value.starts_with('/')
        || value.contains(['\\', '?', '#', '%'])
        || value.split('/').any(|part| matches!(part, "." | ".."))
    {
        return Err("trusted path prefix is unsafe".to_owned());
    }
    Ok(if value.ends_with('/') {
        value.to_owned()
    } else {
        format!("{value}/")
    })
}

/// Select a deterministic address and retain it for the subsequent connect.
///
/// # Errors
/// Rejects empty answers and the whole DNS answer set if any address is
/// private, reserved, local, metadata-capable, or otherwise non-global.
pub fn select_pinned_address(host: &str, addresses: &[IpAddr]) -> Result<IpAddr, String> {
    if addresses.is_empty() {
        return Err(format!("DNS returned no addresses for {host}"));
    }
    if let Some(address) = addresses
        .iter()
        .copied()
        .find(|address| is_forbidden_address(*address))
    {
        return Err(format!(
            "DNS answer for {host} contains forbidden address {address}"
        ));
    }
    let mut public = addresses.to_vec();
    public.sort();
    public.dedup();
    public
        .first()
        .copied()
        .ok_or_else(|| format!("DNS returned no addresses for {host}"))
}

#[must_use]
pub fn is_forbidden_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => forbidden_v4(address),
        IpAddr::V6(address) => forbidden_v6(address),
    }
}

fn forbidden_v4(address: Ipv4Addr) -> bool {
    // Fail-closed union of the IANA IPv4 Special-Purpose Address Registry
    // blocks relevant to outbound resolver SSRF (RFC 6890), including the
    // documentation, benchmarking, shared, loopback, link-local, private,
    // multicast, reserved, and limited-broadcast ranges.
    let [a, b, c, d] = address.octets();
    a == 0
        || a == 10
        || a == 127
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 192 && b == 0 && c == 2)
        || (a == 192 && b == 88 && c == 99)
        || (a == 192 && b == 168)
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
        || a >= 224
        || [a, b, c, d] == [255, 255, 255, 255]
}

fn forbidden_v6(address: Ipv6Addr) -> bool {
    if let Some(mapped) = address.to_ipv4_mapped() {
        return forbidden_v4(mapped);
    }
    // The same IANA registry plus the RFC-defined documentation, Teredo,
    // benchmarking, ORCHID, and 6to4 allocations. Only ordinary global
    // unicast remains eligible for pinning.
    let segments = address.segments();
    let global_unicast = (segments[0] & 0xe000) == 0x2000;
    let documentation = segments[0] == 0x2001 && segments[1] == 0x0db8;
    let teredo = segments[0] == 0x2001 && segments[1] == 0;
    let benchmark = segments[0] == 0x2001 && segments[1] == 2;
    let orchid = segments[0] == 0x2001 && (segments[1] & 0xfff0) == 0x0010;
    let six_to_four = segments[0] == 0x2002;
    let future_documentation = (segments[0] & 0xfff0) == 0x3ff0;
    !global_unicast
        || documentation
        || teredo
        || benchmark
        || orchid
        || six_to_four
        || future_documentation
}
