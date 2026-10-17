use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

#[derive(Debug, Clone)]
struct Finding {
    ip: IpAddr,
    port: u16,
    service: String,
    version: Option<String>,
    evidence: Option<String>,
    status: char,
}

fn service_name(port: u16) -> &'static str {
    match port {
        20 => "FTP-DATA",
        21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        25 => "SMTP",
        53 => "DNS",
        80 => "HTTP",
        110 => "POP3",
        111 => "RPC",
        135 => "MSRPC",
        139 => "NetBIOS",
        143 => "IMAP",
        389 => "LDAP",
        443 => "HTTPS",
        445 => "SMB",
        465 => "SMTPS",
        587 => "SMTP",
        993 => "IMAPS",
        995 => "POP3S",
        1433 => "MSSQL",
        1521 => "Oracle",
        2049 => "NFS",
        2375 => "Docker",
        3000 => "HTTP",
        3306 => "MySQL",
        3389 => "RDP",
        5432 => "PostgreSQL",
        5672 => "AMQP",
        5900 => "VNC",
        6379 => "Redis",
        8000 => "HTTP",
        8080 => "HTTP",
        8443 => "HTTPS",
        9200 => "Elasticsearch",
        27017 => "MongoDB",
        _ => "Unknown",
    }
}

fn is_http_port(port: u16) -> bool {
    matches!(port, 80 | 3000 | 8000 | 8080)
}

fn is_tls_port(port: u16) -> bool {
    matches!(port, 443 | 8443)
}

fn normalize_target(input: &str) -> String {
    let mut target = input.trim().to_string();

    if let Some(value) = target.strip_prefix("https://") {
        target = value.to_string();
    } else if let Some(value) = target.strip_prefix("http://") {
        target = value.to_string();
    }

    target
        .split('/')
        .next()
        .unwrap_or(&target)
        .split(':')
        .next()
        .unwrap_or(&target)
        .to_string()
}

fn resolve_target(target: &str) -> Result<Vec<IpAddr>, String> {
    let addresses = (target, 0)
        .to_socket_addrs()
        .map_err(|error| error.to_string())?;

    let mut result: Vec<IpAddr> = addresses
        .map(|address| address.ip())
        .filter(|ip| ip.is_ipv4())
        .collect();

    result.sort();
    result.dedup();

    if result.is_empty() {
        return Err("No IPv4 address found".to_string());
    }

    Ok(result)
}

fn read_until_headers(stream: &mut TcpStream) -> Option<String> {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));

    let mut data = Vec::new();
    let mut buffer = [0u8; 1024];

    for _ in 0..8 {
        let bytes = match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(bytes) => bytes,
            Err(_) => break,
        };

        data.extend_from_slice(&buffer[..bytes]);

        if data.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }

        if data.len() >= 8192 {
            break;
        }
    }

    if data.is_empty() {
        return None;
    }

    Some(String::from_utf8_lossy(&data).to_string())
}

fn probe_http(
    stream: &mut TcpStream,
    target: &str,
) -> Option<(String, Option<String>, Option<String>)> {
    let request = format!(
        "GET / HTTP/1.0\r\nHost: {}\r\nUser-Agent: PortIntel/0.1\r\nConnection: close\r\n\r\n",
        target
    );

    stream.write_all(request.as_bytes()).ok()?;

    let response = read_until_headers(stream)?;

    let status = response.lines().next()?.trim().to_string();

    let server = response
        .lines()
        .find(|line| line.to_ascii_lowercase().starts_with("server:"))
        .map(|line| line.trim().to_string());

    let location = response
        .lines()
        .find(|line| line.to_ascii_lowercase().starts_with("location:"))
        .map(|line| line.trim().to_string());

    Some((status, server, location))
}

fn extract_version(text: &str) -> Option<String> {
    let lower = text.to_ascii_lowercase();

    for marker in [
        "openssh_",
        "apache/",
        "nginx/",
        "microsoft-iis/",
        "redis_version:",
        "postgresql ",
        "mysql",
    ] {
        if let Some(position) = lower.find(marker) {
            let original = &text[position..];

            let value = original
                .split_whitespace()
                .next()
                .unwrap_or(original)
                .trim_matches(|c: char| {
                    c == ';' || c == ',' || c == ')' || c == '(' || c == '\r' || c == '\n'
                });

            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }

    None
}

fn probe_banner(ip: IpAddr, port: u16) -> Option<(String, Option<String>)> {
    let address = SocketAddr::new(ip, port);

    let mut stream = TcpStream::connect_timeout(&address, Duration::from_millis(800)).ok()?;

    let _ = stream.set_read_timeout(Some(Duration::from_millis(1200)));

    if matches!(port, 25 | 110 | 143 | 21) {
        let mut buffer = [0u8; 1024];

        let bytes = stream.read(&mut buffer).ok()?;

        if bytes == 0 {
            return None;
        }

        let banner = String::from_utf8_lossy(&buffer[..bytes]).trim().to_string();

        let version = extract_version(&banner);

        return Some((banner, version));
    }

    if port == 22 {
        let mut buffer = [0u8; 512];

        let bytes = stream.read(&mut buffer).ok()?;

        if bytes == 0 {
            return None;
        }

        let banner = String::from_utf8_lossy(&buffer[..bytes])
            .lines()
            .next()
            .unwrap_or("")
            .trim()
            .to_string();

        let version = extract_version(&banner);

        return Some((banner, version));
    }

    None
}

fn probe_tls(target: &str, ip: IpAddr, port: u16) -> Option<(String, bool)> {
    let address = SocketAddr::new(ip, port);

    let stream = TcpStream::connect_timeout(&address, Duration::from_secs(1)).ok()?;

    let mut root_store = RootCertStore::empty();

    let certs = rustls_native_certs::load_native_certs();

    for cert in certs.certs {
        let _ = root_store.add(cert);
    }

    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let server_name = ServerName::try_from(target.to_string()).ok()?;

    let connection = ClientConnection::new(Arc::new(config), server_name).ok()?;

    let mut tls = StreamOwned::new(connection, stream);

    tls.flush().ok()?;

    let version = tls.conn.protocol_version()?;

    let certificate_received = tls
        .conn
        .peer_certificates()
        .map(|certificates| !certificates.is_empty())
        .unwrap_or(false);

    Some((format!("{:?}", version), certificate_received))
}

fn status_symbol(service: &str, version: &Option<String>) -> char {
    if version.is_some() {
        return '✓';
    }

    match service {
        "Unknown" => '?',
        _ => '?',
    }
}

fn vulnerability_note(service: &str, version: &Option<String>) -> Option<String> {
    let version = version.as_deref()?;

    /*
     * Deliberately conservative.
     *
     * PortIntel does NOT claim a CVE merely because a service exists.
     * A real vulnerability database will be added later.
     */

    if service == "Telnet" {
        return Some(
            "Telnet transmits authentication traffic without modern encryption.".to_string(),
        );
    }

    if service == "Redis" {
        return Some(
            "Redis exposure should be reviewed carefully; restrict it to trusted networks."
                .to_string(),
        );
    }

    if service == "Unknown" {
        return Some(format!(
            "Service responded with version/evidence: {}",
            version
        ));
    }

    None
}

fn print_finding(finding: &Finding) {
    let version = finding.version.as_deref().unwrap_or("unknown");

    println!(
        "{:<6}/tcp  {:<12} {}",
        finding.port, finding.service, finding.status
    );

    println!("       Version: {}", version);

    if let Some(evidence) = &finding.evidence {
        println!("       Evidence: {}", evidence);
    }
}

fn save_report(target: &str, findings: &[Finding], duration: Duration) -> std::io::Result<()> {
    fs::create_dir_all("reports")?;

    let timestamp = chrono_like_timestamp();

    let filename = format!(
        "reports/scan-{}-{}.txt",
        sanitize_filename(target),
        timestamp
    );

    let mut output = String::new();

    output.push_str("PORTINTEL SCAN REPORT\n");
    output.push_str("=====================\n\n");

    output.push_str(&format!("Target: {}\n", target));
    output.push_str(&format!("Duration: {:.2?}\n\n", duration));

    for finding in findings {
        output.push_str(&format!(
            "{}:{}/tcp {}\n",
            finding.ip, finding.port, finding.service
        ));

        output.push_str(&format!("  Status: {}\n", finding.status));

        if let Some(version) = &finding.version {
            output.push_str(&format!("  Version: {}\n", version));
        }

        if let Some(evidence) = &finding.evidence {
            output.push_str(&format!("  Evidence: {}\n", evidence));
        }

        if let Some(note) = vulnerability_note(&finding.service, &finding.version) {
            output.push_str(&format!("  Security note: {}\n", note));
        }

        output.push('\n');
    }

    fs::write(&filename, output)?;

    println!();
    println!("Report saved: {}", filename);

    Ok(())
}

fn sanitize_filename(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric()
                || character == '.'
                || character == '-'
                || character == '_'
            {
                character
            } else {
                '_'
            }
        })
        .collect()
}

fn chrono_like_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_secs().to_string(),
        Err(_) => "unknown".to_string(),
    }
}

fn print_help() {
    println!("PortIntel");
    println!();
    println!("Usage:");
    println!("  portintel <target> <start-end>");
    println!();
    println!("Examples:");
    println!("  portintel example.com 80-443");
    println!("  portintel https://example.com 80-443");
    println!("  portintel 127.0.0.1 1-1024");
    println!();
    println!("PortIntel performs defensive TCP/service assessment.");
}

fn main() {
    let scan_start = Instant::now();

    let args: Vec<String> = env::args().collect();

    if args.len() != 3 {
        print_help();
        return;
    }

    let raw_target = &args[1];
    let target = normalize_target(raw_target);

    if target.is_empty() {
        eprintln!("Invalid target.");
        return;
    }

    let range: Vec<&str> = args[2].split('-').collect();

    if range.len() != 2 {
        eprintln!("Invalid port range. Use start-end.");
        return;
    }

    let start: u16 = match range[0].parse() {
        Ok(port) => port,
        Err(_) => {
            eprintln!("Invalid starting port.");
            return;
        }
    };

    let end: u16 = match range[1].parse() {
        Ok(port) => port,
        Err(_) => {
            eprintln!("Invalid ending port.");
            return;
        }
    };

    if start == 0 || end == 0 {
        eprintln!("Ports must be between 1 and 65535.");
        return;
    }

    if start > end {
        eprintln!("Starting port cannot be greater than ending port.");
        return;
    }

    println!("PortIntel");
    println!("Target: {}", target);
    println!("Resolving target...");

    let addresses = match resolve_target(&target) {
        Ok(addresses) => addresses,
        Err(error) => {
            eprintln!("Could not resolve target: {}", error);
            return;
        }
    };

    println!("Resolved addresses:");

    for ip in &addresses {
        println!("  {}", ip);
    }

    println!();
    println!("Scanning ports {}-{}", start, end);

    let mut findings = Vec::new();

    for ip in addresses {
        println!();
        println!("ADDRESS: {}", ip);
        println!("OPEN PORTS");
        println!();

        let mut found = false;

        for port in start..=end {
            let address = SocketAddr::new(ip, port);

            let Ok(mut stream) = TcpStream::connect_timeout(&address, Duration::from_millis(500))
            else {
                continue;
            };

            found = true;

            let base_service = service_name(port);

            if is_http_port(port) {
                let mut version = None;
                let mut evidence = None;

                if let Some((status, server, location)) = probe_http(&mut stream, &target) {
                    let mut parts = vec![status.clone()];

                    if let Some(server) = server {
                        parts.push(server.clone());

                        if let Some(extracted) = extract_version(&server) {
                            version = Some(extracted);
                        }
                    }

                    if let Some(location) = location {
                        parts.push(location);
                    }

                    evidence = Some(parts.join(" | "));
                }

                let finding = Finding {
                    ip,
                    port,
                    service: "HTTP".to_string(),
                    version,
                    evidence,
                    status: '✓',
                };

                print_finding(&finding);
                findings.push(finding);

                continue;
            }

            if is_tls_port(port) {
                let mut version = None;
                let mut evidence = None;
                let mut status = '?';

                if let Some((tls_version, certificate)) = probe_tls(&target, ip, port) {
                    version = Some(tls_version.clone());

                    evidence = Some(format!(
                        "TLS {}, certificate: {}",
                        tls_version,
                        if certificate {
                            "received"
                        } else {
                            "not received"
                        }
                    ));

                    status = '✓';
                }

                let finding = Finding {
                    ip,
                    port,
                    service: "HTTPS".to_string(),
                    version,
                    evidence,
                    status,
                };

                print_finding(&finding);
                findings.push(finding);

                continue;
            }

            drop(stream);

            let mut version = None;
            let mut evidence = None;

            if let Some((banner, detected_version)) = probe_banner(ip, port) {
                version = detected_version;
                evidence = Some(banner);
            }

            let status = status_symbol(base_service, &version);

            let finding = Finding {
                ip,
                port,
                service: base_service.to_string(),
                version,
                evidence,
                status,
            };

            print_finding(&finding);
            findings.push(finding);
        }

        if !found {
            println!("No open ports found.");
        }
    }

    let elapsed = scan_start.elapsed();

    println!();
    println!("Scan complete.");
    println!("Duration: {:.2?}", elapsed);

    if !findings.is_empty() {
        println!();
        println!("SUMMARY");
        println!("-------");

        for finding in &findings {
            println!(
                "{}:{}  {}  {}",
                finding.ip, finding.port, finding.service, finding.status
            );
        }

        if let Err(error) = save_report(&target, &findings, elapsed) {
            eprintln!("Could not save report: {}", error);
        }
    }
}
