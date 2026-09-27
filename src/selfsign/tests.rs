use super::*;
use crate::certcore::{build_pfx, cert_info, unlock_pfx, Items, Source};
use std::net::{Ipv4Addr, Ipv6Addr};
use x509_parser::prelude::*;

fn full_req(key_type: KeyType) -> SelfSignRequest {
    SelfSignRequest {
        common_name: "server.example.local".into(),
        organization: "測試 公司".into(),
        sans: "www.example.local\n192.168.1.10\n2001:db8::1".into(),
        key_type,
        days: 365,
    }
}

fn check_generated(key_type: KeyType, is_rsa: bool) -> Items {
    let items = generate(&full_req(key_type)).unwrap();
    assert_eq!(items.source, Source::Generated);
    assert_eq!(items.certs.len(), 1);
    assert_eq!(items.key_matches_leaf(), Some(true));

    let info = cert_info(&items.certs[0]).unwrap();
    assert_eq!(info.common_name.as_deref(), Some("server.example.local"));
    assert_eq!(info.subject, info.issuer);
    assert!(info.subject.contains("O=測試 公司"), "{}", info.subject);
    assert!((364..=365).contains(&info.days_left), "{}", info.days_left);
    for san in [
        "DNS: server.example.local",
        "DNS: www.example.local",
        "IP: 192.168.1.10",
        "IP: 2001:db8::1",
    ] {
        assert!(info.sans.contains(&san.to_string()), "{san}");
    }

    let (_, c) = X509Certificate::from_der(&items.certs[0]).unwrap();
    let serial = c.tbs_certificate.raw_serial();
    assert_eq!(serial.len(), 16);
    assert!(serial[0] < 0x80, "serial must be positive");

    let bc = c.basic_constraints().unwrap().unwrap();
    assert!(bc.critical);
    assert!(!bc.value.ca);

    let ku = c.key_usage().unwrap().unwrap();
    assert!(ku.critical);
    assert!(ku.value.digital_signature());
    assert_eq!(ku.value.key_encipherment(), is_rsa);
    assert!(!ku.value.non_repudiation());

    let eku = c.extended_key_usage().unwrap().unwrap();
    assert!(!eku.critical);
    assert!(eku.value.server_auth);

    assert!(c.extensions().iter().any(|e| matches!(
        e.parsed_extension(),
        ParsedExtension::SubjectKeyIdentifier(_)
    )));

    let pfx = build_pfx(&items.certs, items.key.as_ref().unwrap(), "pw", false).unwrap();
    assert!(unlock_pfx(&pfx, "pw").is_ok());
    items
}

#[test]
fn generates_rsa_2048() {
    check_generated(KeyType::Rsa2048, true);
}

#[test]
fn generates_ec_p256() {
    check_generated(KeyType::EcP256, false);
}

#[test]
fn generates_ec_p384() {
    check_generated(KeyType::EcP384, false);
}

#[test]
fn generates_rsa_3072() {
    check_generated(KeyType::Rsa3072, true);
}

#[test]
fn generates_rsa_4096() {
    check_generated(KeyType::Rsa4096, true);
}

#[test]
fn special_characters_in_subject_are_kept() {
    let cn = "#a, b \"c\" + d=e <f>;g\\h 中文";
    let req = SelfSignRequest {
        common_name: cn.into(),
        organization: "O, \"quoted\" + 公司".into(),
        sans: "host.local".into(),
        key_type: KeyType::EcP256,
        days: 30,
    };
    let items = generate(&req).unwrap();
    let info = cert_info(&items.certs[0]).unwrap();
    assert_eq!(info.common_name.as_deref(), Some(cn));
    assert_eq!(info.sans, vec!["DNS: host.local".to_string()]);
}

#[test]
fn wildcard_cn_becomes_san() {
    let mut req = full_req(KeyType::EcP256);
    req.common_name = "*.example.local".into();
    req.sans.clear();
    let items = generate(&req).unwrap();
    let info = cert_info(&items.certs[0]).unwrap();
    assert_eq!(info.sans, vec!["DNS: *.example.local".to_string()]);
}

#[test]
fn max_validity_days_left_is_correct() {
    let mut req = full_req(KeyType::EcP256);
    req.days = MAX_DAYS;
    let items = generate(&req).unwrap();
    let info = cert_info(&items.certs[0]).unwrap();
    assert!(
        (MAX_DAYS as i64 - 1..=MAX_DAYS as i64).contains(&info.days_left),
        "{}",
        info.days_left
    );
}

#[test]
fn generate_rejects_invalid_request() {
    let mut req = full_req(KeyType::EcP256);
    req.common_name.clear();
    assert!(generate(&req).is_err());
}

fn req(cn: &str, sans: &str) -> SelfSignRequest {
    SelfSignRequest {
        common_name: cn.into(),
        sans: sans.into(),
        ..Default::default()
    }
}

fn dns(s: &str) -> San {
    San::Dns(s.to_string())
}

#[test]
fn defaults() {
    let r = SelfSignRequest::default();
    assert_eq!(r.key_type, KeyType::Rsa2048);
    assert_eq!(r.days, 365);
}

#[test]
fn cn_is_added_to_sans_first() {
    assert_eq!(
        validate(&req("server.local", "www.local")).unwrap(),
        vec![dns("server.local"), dns("www.local")]
    );
}

#[test]
fn ip_sans_ipv4_and_ipv6() {
    assert_eq!(
        validate(&req("10.0.0.1", "::1\n2001:db8::1")).unwrap(),
        vec![
            San::Ip(Ipv4Addr::new(10, 0, 0, 1).into()),
            San::Ip(Ipv6Addr::LOCALHOST.into()),
            San::Ip("2001:db8::1".parse().unwrap()),
        ]
    );
}

#[test]
fn blank_lines_crlf_and_spaces_are_ignored() {
    assert_eq!(
        validate(&req(" a.local ", "  b.local  \r\n\r\n\tc.local\r\n")).unwrap(),
        vec![dns("a.local"), dns("b.local"), dns("c.local")]
    );
}

#[test]
fn duplicates_and_case_are_normalized() {
    assert_eq!(
        validate(&req(
            "Server.Local",
            "server.local\nSERVER.LOCAL\n10.0.0.1\n10.0.0.1"
        ))
        .unwrap(),
        vec![
            dns("server.local"),
            San::Ip(Ipv4Addr::new(10, 0, 0, 1).into())
        ]
    );
}

#[test]
fn wildcard_rules() {
    assert_eq!(
        validate(&req("*.example.local", "")).unwrap(),
        vec![dns("*.example.local")]
    );
    for bad in ["*", "a.*.local", "*a.local", "*.*.local"] {
        assert!(validate(&req("x.local", bad)).is_err(), "{bad}");
    }
}

#[test]
fn invalid_entries_are_rejected_with_the_entry_in_message() {
    let long_label = format!("{}.local", "a".repeat(64));
    for bad in [
        "under_score.local",
        "-a.local",
        "a-.local",
        ".a.local",
        "a.local.",
        "a..local",
        "[::1]",
        "a b.local",
        long_label.as_str(),
    ] {
        let err = validate(&req("x.local", bad)).unwrap_err().to_string();
        assert!(err.contains(bad), "{bad}: {err}");
    }
}

#[test]
fn mistyped_ip_is_rejected_not_treated_as_dns() {
    // 解析不成 IP、但全為數字段的輸入不可悄悄變成 DNS 名稱
    for bad in [
        "192.168.1.300",
        "10.0.0.010",
        "192.168.001.010",
        "1.2.3",
        "example.123",
    ] {
        let err = validate(&req("x.local", bad)).unwrap_err().to_string();
        assert!(err.contains(bad), "{bad}: {err}");
    }
    // 開頭或中間段是數字的正常主機名稱仍可使用
    assert!(validate(&req(
        "x.local",
        "1password.local
host1.10.local"
    ))
    .is_ok());
}

#[test]
fn non_hostname_cn_is_allowed_but_needs_a_san() {
    let err = validate(&req("測試伺服器", "")).unwrap_err().to_string();
    assert!(err.contains("至少"), "{err}");
    assert_eq!(
        validate(&req("測試伺服器", "host.local")).unwrap(),
        vec![dns("host.local")]
    );
}

#[test]
fn cn_and_organization_limits() {
    assert!(validate(&req("   ", "a.local")).is_err());
    assert!(validate(&req(&"a".repeat(65), "a.local")).is_err());
    assert!(validate(&req(&"a".repeat(64), "a.local")).is_ok());
    let mut r = req("a.local", "");
    r.organization = "組".repeat(65);
    assert!(validate(&r).is_err());
    r.organization = "組".repeat(64);
    assert!(validate(&r).is_ok());
}

#[test]
fn days_range() {
    for (days, ok) in [
        (0, false),
        (1, true),
        (MAX_DAYS, true),
        (MAX_DAYS + 1, false),
    ] {
        let mut r = req("a.local", "");
        r.days = days;
        assert_eq!(validate(&r).is_ok(), ok, "{days}");
    }
}

#[test]
fn default_file_stem_avoids_windows_reserved_names() {
    assert_eq!(default_file_stem("CON"), "CON_");
    assert_eq!(default_file_stem("nul"), "nul_");
    assert_eq!(default_file_stem("com1"), "com1_");
    assert_eq!(default_file_stem("LPT9"), "LPT9_");
    // Windows 只看第一個 . 之前的部分
    assert_eq!(default_file_stem("aux.example.local"), "aux_.example.local");
    // 只是開頭相同的一般名稱不受影響
    assert_eq!(default_file_stem("console.local"), "console.local");
    assert_eq!(default_file_stem("com10"), "com10");
}

#[test]
fn cn_hint_warns_when_hostname_like_cn_is_not_valid() {
    let hint = cn_san_hint("file_server.corp").unwrap();
    assert!(hint.contains("file_server.corp"), "{hint}");
    assert!(cn_san_hint("192.168.1.300").is_some());
    // 合法的主機名稱或 IP、以及一般描述文字都不提示
    for ok in [
        "server.local",
        "*.example.local",
        "10.0.0.1",
        "::1",
        "測試伺服器",
        "My Server",
        "",
    ] {
        assert_eq!(cn_san_hint(ok), None, "{ok}");
    }
}

#[test]
fn default_file_stem_sanitizes() {
    assert_eq!(default_file_stem("*.example.local"), "_.example.local");
    assert_eq!(default_file_stem("a/b:c?\"<>|\\d"), "a_b_c______d");
    assert_eq!(default_file_stem("   "), "selfsigned");
    assert_eq!(default_file_stem(" 測試 "), "測試");
}
