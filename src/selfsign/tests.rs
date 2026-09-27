use super::*;
use std::net::{Ipv4Addr, Ipv6Addr};

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
fn default_file_stem_sanitizes() {
    assert_eq!(default_file_stem("*.example.local"), "_.example.local");
    assert_eq!(default_file_stem("a/b:c?\"<>|\\d"), "a_b_c______d");
    assert_eq!(default_file_stem("   "), "selfsigned");
    assert_eq!(default_file_stem(" 測試 "), "測試");
}
