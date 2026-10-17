mod common;

use certsign_core::Error;
use certsign_tsp::{
    HttpTransport, RecordedTransport, Tsa, TsaClient, TsaError, TsaExtension, TsaHash, TsaRequest,
};
use common::{Answer, TestTsa};
use der::{Any, Decode};
use x509_cert::ext::Extension;

const DATA: &[u8] = b"the bytes of a PDF signature value";

fn tsa() -> Option<TestTsa> {
    TestTsa::new()
}

fn encode(req: &TsaRequest) -> Vec<u8> {
    TsaClient::<RecordedTransport>::encode_request(req).unwrap()
}

fn recorded(tsa: &TestTsa, answered_request: &TsaRequest) -> TsaClient<RecordedTransport> {
    let reply = tsa.reply(&encode(answered_request));
    TsaClient::new(RecordedTransport::new("recorded://tsa").respond(reply))
}

fn children(der: &[u8]) -> Vec<Any> {
    Any::from_der(der).unwrap().decode_as::<Vec<Any>>().unwrap()
}

// ---- request encoding

#[test]
fn request_matches_openssl_encoding() {
    let Some(tsa) = tsa() else { return };
    for (hash, name) in [
        (TsaHash::Sha1, "sha1"),
        (TsaHash::Sha256, "sha256"),
        (TsaHash::Sha384, "sha384"),
        (TsaHash::Sha512, "sha512"),
    ] {
        for cert in [true, false] {
            let req = TsaRequest {
                cert_req: cert,
                ..TsaRequest::for_data(hash, DATA)
            };
            assert_eq!(
                encode(&req),
                tsa.reference_query(DATA, name, cert),
                "{name} cert={cert}"
            );
        }
    }
}

#[test]
fn request_carries_policy_nonce_and_extension() {
    let req = TsaRequest {
        policy: Some("1.2.3.4.5".into()),
        nonce: Some(0x1234_5678_9ABC_DEF0),
        extension: Some(TsaExtension {
            oid: "1.2.3.99".into(),
            critical: true,
            value: vec![0x05, 0x00],
        }),
        ..TsaRequest::for_data(TsaHash::Sha512, DATA)
    };
    let parts = children(&encode(&req));
    // version, imprint, policy, nonce, certReq, [0] extensions
    assert_eq!(parts.len(), 6);
    assert_eq!(parts[0].value(), &[1]);
    assert_eq!(
        parts[2].value(),
        &[0x2A, 0x03, 0x04, 0x05],
        "policy 1.2.3.4.5"
    );
    assert_eq!(parts[3].value(), &0x1234_5678_9ABC_DEF0u64.to_be_bytes());
    assert_eq!(parts[4].value(), &[0xFF], "certReq TRUE");
    let ext = Extension::from_der(parts[5].value()).unwrap();
    assert_eq!(ext.extn_id.to_string(), "1.2.3.99");
    assert!(ext.critical);
    assert_eq!(ext.extn_value.as_bytes(), &[0x05, 0x00]);

    let plain = TsaRequest {
        extension: Some(TsaExtension {
            oid: "1.2.3.99".into(),
            critical: false,
            value: vec![1],
        }),
        ..TsaRequest::for_data(TsaHash::Sha256, DATA)
    };
    let ext = Extension::from_der(children(&encode(&plain)).last().unwrap().value()).unwrap();
    assert!(!ext.critical);
}

#[test]
fn request_errors() {
    let bad = [
        TsaRequest {
            digest: vec![0; 5],
            ..TsaRequest::for_data(TsaHash::Sha256, DATA)
        },
        TsaRequest {
            policy: Some("not.an.oid".into()),
            ..TsaRequest::for_data(TsaHash::Sha256, DATA)
        },
        TsaRequest {
            extension: Some(TsaExtension {
                oid: "x".into(),
                critical: false,
                value: vec![],
            }),
            ..TsaRequest::for_data(TsaHash::Sha256, DATA)
        },
    ];
    for req in bad {
        assert!(matches!(
            TsaClient::<RecordedTransport>::encode_request(&req),
            Err(TsaError::Malformed { .. })
        ));
    }
}

#[test]
fn hash_names() {
    assert_eq!(TsaHash::from_name("SHA-512"), Some(TsaHash::Sha512));
    assert_eq!(TsaHash::from_name("sha1"), Some(TsaHash::Sha1));
    assert_eq!(TsaHash::from_name("Sha-384"), Some(TsaHash::Sha384));
    assert_eq!(TsaHash::from_name("md5"), None);
}

// ---- granted tokens

/// Canned answers by request body, so that no child process runs while a request is in flight.
type Canned = std::sync::Arc<std::sync::Mutex<std::collections::HashMap<Vec<u8>, Vec<u8>>>>;

fn canned_server(tsa: &TestTsa) -> (common::Server, Canned) {
    let canned: Canned = Canned::default();
    let lookup = std::sync::Arc::clone(&canned);
    let server = tsa.serve(move |req| match lookup.lock().unwrap().get(&req.body) {
        Some(reply) => Answer::Body(reply.clone()),
        None => Answer::Status(404),
    });
    (server, canned)
}

#[test]
fn tokens_from_a_local_tsa_over_http() {
    let Some(tsa) = tsa() else { return };
    let (server, canned) = canned_server(&tsa);
    let client = TsaClient::new(HttpTransport::new(server.url.clone()));

    for hash in [
        TsaHash::Sha1,
        TsaHash::Sha256,
        TsaHash::Sha384,
        TsaHash::Sha512,
    ] {
        let req = TsaRequest::for_data(hash, DATA).with_random_nonce();
        let wire = encode(&req);
        canned
            .lock()
            .unwrap()
            .insert(wire.clone(), tsa.reply(&wire));

        let token = client.timestamp(&req).unwrap();
        assert_eq!(token.policy, "1.2.3.4.1");
        assert!((chrono::Utc::now() - token.gen_time).num_seconds().abs() < 60);
        assert!(!token.serial_number.is_empty());
        // The token is a CMS the TSA signed over exactly this request: OpenSSL agrees.
        assert!(tsa.verify_token(&wire, &token.der), "{hash:?}");
        // Stamped by a different TSA key it would not.
        let other = TestTsa::new().unwrap();
        assert!(!other.verify_token(&wire, &token.der), "{hash:?}: wrong CA");
    }
    // Content type and headers on the wire.
    let seen = server.received.lock().unwrap();
    assert_eq!(seen.len(), 4);
    assert_eq!(
        seen[0].header("content-type"),
        Some("application/timestamp-query")
    );
    assert_eq!(
        seen[0].header("accept"),
        Some("application/timestamp-reply")
    );
    assert!(
        seen[0].header("authorization").is_none(),
        "no credentials unless configured"
    );
}

#[test]
fn requested_policy_is_honored() {
    let Some(tsa) = tsa() else { return };
    let req = TsaRequest {
        policy: Some("1.2.3.4.5".into()),
        ..TsaRequest::for_data(TsaHash::Sha256, DATA)
    };
    let token = recorded(&tsa, &req).request(&req).unwrap();
    assert_eq!(token.policy, "1.2.3.4.5");
}

#[test]
fn nonce_is_echoed() {
    let Some(tsa) = tsa() else { return };
    let req = TsaRequest {
        nonce: Some(42),
        ..TsaRequest::for_data(TsaHash::Sha256, DATA)
    };
    assert!(recorded(&tsa, &req).request(&req).is_ok());
}

// ---- wrong answers

#[test]
fn imprint_mismatch_is_rejected() {
    let Some(tsa) = tsa() else { return };
    let asked = TsaRequest::for_data(TsaHash::Sha256, DATA);
    let answered_for = TsaRequest::for_data(TsaHash::Sha256, b"other data");
    let err = recorded(&tsa, &answered_for).request(&asked).unwrap_err();
    assert!(matches!(err, TsaError::ImprintMismatch { .. }), "{err}");
    assert!(err.to_string().contains("recorded://tsa"));

    // Same digest bytes under another hash algorithm is also a different imprint.
    let sha384 = TsaRequest {
        hash: TsaHash::Sha384,
        digest: vec![7; 48],
        ..asked.clone()
    };
    let err = recorded(&tsa, &sha384).request(&asked).unwrap_err();
    assert!(matches!(err, TsaError::ImprintMismatch { .. }), "{err}");
}

#[test]
fn nonce_mismatch_is_rejected() {
    let Some(tsa) = tsa() else { return };
    let sent = TsaRequest {
        nonce: Some(111),
        ..TsaRequest::for_data(TsaHash::Sha256, DATA)
    };
    let answered_for = TsaRequest {
        nonce: Some(222),
        ..sent.clone()
    };
    let err = recorded(&tsa, &answered_for).request(&sent).unwrap_err();
    assert!(matches!(err, TsaError::NonceMismatch { .. }), "{err}");

    // A reply with no nonce at all, to a request that sent one.
    let without = TsaRequest {
        nonce: None,
        ..sent.clone()
    };
    let err = recorded(&tsa, &without).request(&sent).unwrap_err();
    assert!(matches!(err, TsaError::NonceMismatch { .. }), "{err}");
}

#[test]
fn policy_mismatch_is_rejected() {
    let Some(tsa) = tsa() else { return };
    let wanted = TsaRequest {
        policy: Some("1.2.3.4.5".into()),
        ..TsaRequest::for_data(TsaHash::Sha256, DATA)
    };
    // The TSA answered a request without a policy, so it used its default.
    let default_policy = TsaRequest {
        policy: None,
        ..wanted.clone()
    };
    let err = recorded(&tsa, &default_policy)
        .request(&wanted)
        .unwrap_err();
    assert!(
        matches!(&err, TsaError::PolicyMismatch { wanted, got, .. } if wanted == "1.2.3.4.5" && got == "1.2.3.4.1"),
        "{err}"
    );
}

#[test]
fn refusals_name_the_status_and_reason() {
    let Some(tsa) = tsa() else { return };
    // The TSA itself refuses an unknown policy.
    let req = TsaRequest {
        policy: Some("1.9.9.9".into()),
        ..TsaRequest::for_data(TsaHash::Sha256, DATA)
    };
    let err = recorded(&tsa, &req).request(&req).unwrap_err();
    match &err {
        TsaError::Rejected {
            status,
            name,
            detail,
            url,
        } => {
            assert_eq!((*status, *name), (2, "rejection"));
            assert!(detail.contains("unacceptedPolicy"), "{detail}");
            assert_eq!(url, "recorded://tsa");
        }
        other => panic!("{other}"),
    }
    assert!(err.to_string().contains("rejection"));

    // OpenSSL's TSA turns away any request extension.
    let req = TsaRequest {
        extension: Some(TsaExtension {
            oid: "1.2.3.99".into(),
            critical: false,
            value: vec![5, 0],
        }),
        ..TsaRequest::for_data(TsaHash::Sha256, DATA)
    };
    let err = recorded(&tsa, &req).request(&req).unwrap_err();
    assert!(matches!(err, TsaError::Rejected { .. }), "{err}");
}

#[test]
fn hand_made_rejection_with_text_and_failure_bits() {
    // status 2, statusString ["Nope"], failInfo systemFailure
    let resp = vec![
        0x30, 0x14, 0x30, 0x12, 0x02, 0x01, 0x02, 0x30, 0x06, 0x0C, 0x04, b'N', b'o', b'p', b'e',
        0x03, 0x05, 0x06, 0x00, 0x00, 0x00, 0x40,
    ];
    let client = TsaClient::new(RecordedTransport::new("https://tsa.example/ts").respond(resp));
    let err = client
        .request(&TsaRequest::for_data(TsaHash::Sha256, DATA))
        .unwrap_err();
    assert_eq!(
        err.to_string(),
        "https://tsa.example/ts refused the request: status 2 (rejection): Nope [systemFailure]"
    );
}

#[test]
fn unusable_responses() {
    let granted_without_token = vec![0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x00];
    let waiting = vec![0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x03];
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("empty", vec![]),
        ("garbage", b"<html>502 Bad Gateway</html>".to_vec()),
        ("truncated", vec![0x30, 0x82, 0x01]),
        ("granted without token", granted_without_token),
    ];
    for (name, body) in cases {
        let client = TsaClient::new(RecordedTransport::new("recorded://tsa").respond(body));
        let err = client
            .request(&TsaRequest::for_data(TsaHash::Sha256, DATA))
            .unwrap_err();
        assert!(matches!(err, TsaError::Malformed { .. }), "{name}: {err}");
    }
    let client = TsaClient::new(RecordedTransport::new("recorded://tsa").respond(waiting));
    let err = client
        .request(&TsaRequest::for_data(TsaHash::Sha256, DATA))
        .unwrap_err();
    assert!(
        matches!(
            err,
            TsaError::Rejected {
                status: 3,
                name: "waiting",
                ..
            }
        ),
        "{err}"
    );
}

// ---- transport

#[test]
fn http_errors_report_url_and_status() {
    let Some(tsa) = tsa() else { return };
    let server = tsa.serve(|_| Answer::Status(500));
    let client = TsaClient::new(HttpTransport::new(server.url.clone()));
    let err = client
        .request(&TsaRequest::for_data(TsaHash::Sha256, DATA))
        .unwrap_err();
    assert_eq!(
        err,
        TsaError::Http {
            url: server.url.clone(),
            status: 500
        }
    );
    let text = err.to_string();
    assert!(text.contains(&server.url) && text.contains("500"), "{text}");
}

#[test]
fn unreachable_tsa_names_the_url() {
    // Bind a port and drop the listener, so connecting fails fast.
    let url = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        format!("http://{}/tsa", l.local_addr().unwrap())
    };
    let client = TsaClient::new(HttpTransport::new(url.clone()));
    let err = client
        .request(&TsaRequest::for_data(TsaHash::Sha256, DATA))
        .unwrap_err();
    assert!(
        matches!(&err, TsaError::Unreachable { url: u, .. } if *u == url),
        "{err}"
    );
    assert!(err.to_string().contains(&url));
}

#[test]
fn basic_credentials_are_sent() {
    let Some(tsa) = tsa() else { return };
    let req = TsaRequest::for_data(TsaHash::Sha256, DATA);
    let reply = tsa.reply(&encode(&req));
    let server = tsa.serve(move |r| match r.header("authorization") {
        Some("Basic dXNlcjpwYXNz") => Answer::Body(reply.clone()),
        _ => Answer::Status(401),
    });

    let anonymous = TsaClient::new(HttpTransport::new(server.url.clone()));
    assert_eq!(
        anonymous.request(&req).unwrap_err(),
        TsaError::Http {
            url: server.url.clone(),
            status: 401
        }
    );

    let wrong =
        TsaClient::new(HttpTransport::new(server.url.clone()).with_credentials("user", "nope"));
    assert!(matches!(
        wrong.request(&req),
        Err(TsaError::Http { status: 401, .. })
    ));

    let right =
        TsaClient::new(HttpTransport::new(server.url.clone()).with_credentials("user", "pass"));
    assert!(right.request(&req).is_ok());
    let seen = server.received.lock().unwrap();
    assert_eq!(
        seen.last().unwrap().header("authorization"),
        Some("Basic dXNlcjpwYXNz")
    );
}

#[test]
fn credentials_stay_out_of_debug_output() {
    let t = HttpTransport::new("http://tsa.example").with_credentials("user", "hunter2");
    let text = format!("{t:?}");
    assert!(!text.contains("hunter2"), "{text}");
}

// ---- recorded TSA

#[test]
fn recorded_tsa_replays_in_order_and_keeps_requests() {
    let Some(tsa) = tsa() else { return };
    let one = TsaRequest::for_data(TsaHash::Sha256, b"one");
    let two = TsaRequest::for_data(TsaHash::Sha512, b"two");
    let transport = RecordedTransport::new("recorded://tsa")
        .respond(tsa.reply(&encode(&one)))
        .fail(TsaError::Http {
            url: "recorded://tsa".into(),
            status: 503,
        })
        .respond(tsa.reply(&encode(&two)));
    let client = TsaClient::new(transport);

    assert!(client.request(&one).is_ok());
    assert!(matches!(
        client.request(&one),
        Err(TsaError::Http { status: 503, .. })
    ));
    assert!(client.request(&two).is_ok());
    let err = client.request(&two).unwrap_err();
    assert!(
        matches!(err, TsaError::Unreachable { .. }),
        "queue exhausted: {err}"
    );

    let sent = client.transport().requests();
    assert_eq!(sent.len(), 4);
    assert_eq!(sent[0], encode(&one));
    assert_eq!(sent[2], encode(&two));
}

#[test]
fn works_as_a_trait_object_and_converts_errors() {
    let Some(tsa) = tsa() else { return };
    let req = TsaRequest::for_data(TsaHash::Sha256, DATA);
    let ok: Box<dyn Tsa> = Box::new(recorded(&tsa, &req));
    assert!(ok.timestamp(&req).is_ok());

    let failing: Box<dyn Tsa> = Box::new(TsaClient::new(RecordedTransport::new("recorded://tsa")));
    let err = failing.timestamp(&req).unwrap_err();
    assert!(
        matches!(&err, Error::Timestamp(m) if m.contains("recorded://tsa")),
        "{err}"
    );
}
