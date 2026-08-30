use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::Sha256;
use thiserror::Error;
use time::OffsetDateTime;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct VerifiedEvent {
    pub(crate) event_id: String,
    pub(crate) event_type: String,
    pub(crate) created_at: i64,
    pub(crate) livemode: bool,
    pub(crate) target: Option<ReconciliationTarget>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReconciliationTarget {
    pub(crate) subscription_id: String,
    pub(crate) customer_id: String,
    pub(crate) checkout_subject: Option<CheckoutSubject>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CheckoutSubject {
    pub(crate) scope_kind: String,
    pub(crate) scope_id: String,
    pub(crate) subject: String,
    pub(crate) price_alias: String,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(crate) enum WebhookError {
    #[error("webhook body exceeds the configured limit")]
    BodyTooLarge,
    #[error("Stripe-Signature header is invalid")]
    InvalidSignature,
    #[error("Stripe-Signature timestamp is outside the configured tolerance")]
    StaleSignature,
    #[error("Stripe event payload is invalid")]
    InvalidEvent,
    #[error("Stripe event live mode does not match this Plugin Instance")]
    ModeMismatch,
}

pub(crate) fn verify_and_parse(
    secret: &[u8],
    raw_body: &str,
    signature_header: &str,
    now: OffsetDateTime,
    tolerance_seconds: i64,
    max_body_bytes: usize,
    expected_livemode: bool,
) -> Result<VerifiedEvent, WebhookError> {
    if raw_body.len() > max_body_bytes {
        return Err(WebhookError::BodyTooLarge);
    }
    let signature = parse_signature_header(signature_header)?;
    if now.unix_timestamp().abs_diff(signature.timestamp) > tolerance_seconds.unsigned_abs() {
        return Err(WebhookError::StaleSignature);
    }
    let signed_payload = format!("{}.{}", signature.timestamp, raw_body);
    let verified = signature.v1.iter().any(|candidate| {
        let Ok(candidate) = decode_hex(candidate) else {
            return false;
        };
        let Ok(mut mac) = HmacSha256::new_from_slice(secret) else {
            return false;
        };
        mac.update(signed_payload.as_bytes());
        mac.verify_slice(&candidate).is_ok()
    });
    if !verified {
        return Err(WebhookError::InvalidSignature);
    }
    let payload: Value = serde_json::from_str(raw_body).map_err(|_| WebhookError::InvalidEvent)?;
    let event_id = required_string(&payload, &["id"])?;
    let event_type = required_string(&payload, &["type"])?;
    let created_at = payload
        .pointer("/created")
        .and_then(Value::as_i64)
        .ok_or(WebhookError::InvalidEvent)?;
    let livemode = payload
        .pointer("/livemode")
        .and_then(Value::as_bool)
        .ok_or(WebhookError::InvalidEvent)?;
    if livemode != expected_livemode {
        return Err(WebhookError::ModeMismatch);
    }
    Ok(VerifiedEvent {
        event_id,
        target: reconciliation_target(&event_type, &payload)?,
        event_type,
        created_at,
        livemode,
    })
}

struct StripeSignature<'a> {
    timestamp: i64,
    v1: Vec<&'a str>,
}

fn parse_signature_header(value: &str) -> Result<StripeSignature<'_>, WebhookError> {
    let mut timestamp = None;
    let mut v1 = Vec::new();
    for field in value.split(',') {
        let (name, field_value) = field
            .trim()
            .split_once('=')
            .ok_or(WebhookError::InvalidSignature)?;
        match name {
            "t" => {
                if timestamp.is_some() {
                    return Err(WebhookError::InvalidSignature);
                }
                timestamp = Some(
                    field_value
                        .parse::<i64>()
                        .map_err(|_| WebhookError::InvalidSignature)?,
                );
            }
            "v1" if !field_value.is_empty() => v1.push(field_value),
            _ => {}
        }
    }
    let timestamp = timestamp.ok_or(WebhookError::InvalidSignature)?;
    if timestamp < 0 || v1.is_empty() {
        return Err(WebhookError::InvalidSignature);
    }
    Ok(StripeSignature { timestamp, v1 })
}

fn reconciliation_target(
    event_type: &str,
    payload: &Value,
) -> Result<Option<ReconciliationTarget>, WebhookError> {
    let object = payload
        .pointer("/data/object")
        .ok_or(WebhookError::InvalidEvent)?;
    if event_type.starts_with("customer.subscription.") {
        return Ok(Some(ReconciliationTarget {
            subscription_id: required_string(object, &["id"])?,
            customer_id: required_string(object, &["customer"])?,
            checkout_subject: None,
        }));
    }
    if event_type == "checkout.session.completed" {
        return Ok(Some(ReconciliationTarget {
            subscription_id: required_string(object, &["subscription"])?,
            customer_id: required_string(object, &["customer"])?,
            checkout_subject: Some(CheckoutSubject {
                scope_kind: required_string(object, &["metadata", "lenso_scope_kind"])?,
                scope_id: required_string(object, &["metadata", "lenso_scope_id"])?,
                subject: required_string(object, &["metadata", "lenso_subject"])?,
                price_alias: required_string(object, &["metadata", "lenso_price_alias"])?,
            }),
        }));
    }
    if matches!(
        event_type,
        "invoice.paid" | "invoice.payment_failed" | "invoice.payment_action_required"
    ) {
        let subscription_id = optional_string(
            object,
            &[
                &["subscription"],
                &["parent", "subscription_details", "subscription"],
            ],
        );
        let customer_id = optional_string(object, &[&["customer"]]);
        return match (subscription_id, customer_id) {
            (Some(subscription_id), Some(customer_id)) => Ok(Some(ReconciliationTarget {
                subscription_id,
                customer_id,
                checkout_subject: None,
            })),
            _ => Ok(None),
        };
    }
    Ok(None)
}

fn required_string(value: &Value, path: &[&str]) -> Result<String, WebhookError> {
    descend(value, path)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 512)
        .map(ToOwned::to_owned)
        .ok_or(WebhookError::InvalidEvent)
}

fn optional_string(value: &Value, paths: &[&[&str]]) -> Option<String> {
    paths.iter().find_map(|path| {
        descend(value, path)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty() && value.len() <= 512)
            .map(ToOwned::to_owned)
    })
}

fn descend<'a>(mut value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    for segment in path {
        value = value.get(*segment)?;
    }
    Some(value)
}

fn decode_hex(value: &str) -> Result<Vec<u8>, WebhookError> {
    if value.len() != 64 || !value.len().is_multiple_of(2) {
        return Err(WebhookError::InvalidSignature);
    }
    value
        .as_bytes()
        .chunks(2)
        .map(|pair| {
            let high = hex_nibble(pair[0])?;
            let low = hex_nibble(pair[1])?;
            Ok((high << 4) | low)
        })
        .collect()
}

#[cfg(test)]
fn encode_hex(value: &[u8]) -> String {
    const ALPHABET: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(value.len() * 2);
    for byte in value {
        encoded.push(char::from(ALPHABET[usize::from(byte >> 4)]));
        encoded.push(char::from(ALPHABET[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn hex_nibble(value: u8) -> Result<u8, WebhookError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(WebhookError::InvalidSignature),
    }
}

#[cfg(test)]
mod tests {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    use time::OffsetDateTime;

    use super::{CheckoutSubject, ReconciliationTarget, WebhookError, verify_and_parse};

    const SECRET: &[u8] = b"whsec_test_secret_at_least_32_bytes";

    fn signature(timestamp: i64, body: &str) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(SECRET).unwrap();
        mac.update(format!("{timestamp}.{body}").as_bytes());
        let bytes = mac.finalize().into_bytes();
        let hex = super::encode_hex(&bytes);
        format!("t={timestamp},v1={hex}")
    }

    #[test]
    fn verifies_exact_body_and_extracts_checkout_subject() {
        let body = r#"{"id":"evt_1","type":"checkout.session.completed","created":1000,"livemode":false,"data":{"object":{"customer":"cus_1","subscription":"sub_1","metadata":{"lenso_scope_kind":"organization","lenso_scope_id":"org_1","lenso_subject":"org_1","lenso_price_alias":"pro"}}}}"#;
        let event = verify_and_parse(
            SECRET,
            body,
            &signature(1_000, body),
            OffsetDateTime::from_unix_timestamp(1_010).unwrap(),
            300,
            1_048_576,
            false,
        )
        .unwrap();
        assert_eq!(event.event_id, "evt_1");
        assert_eq!(
            event.target,
            Some(ReconciliationTarget {
                subscription_id: "sub_1".to_owned(),
                customer_id: "cus_1".to_owned(),
                checkout_subject: Some(CheckoutSubject {
                    scope_kind: "organization".to_owned(),
                    scope_id: "org_1".to_owned(),
                    subject: "org_1".to_owned(),
                    price_alias: "pro".to_owned(),
                }),
            })
        );
    }

    #[test]
    fn rejects_mutation_stale_headers_and_mode_confusion() {
        let body = r#"{"id":"evt_1","type":"customer.subscription.updated","created":1000,"livemode":false,"data":{"object":{"id":"sub_1","customer":"cus_1"}}}"#;
        let header = signature(1_000, body);
        let now = OffsetDateTime::from_unix_timestamp(1_010).unwrap();
        assert_eq!(
            verify_and_parse(
                SECRET,
                &format!("{body} "),
                &header,
                now,
                300,
                1_048_576,
                false
            ),
            Err(WebhookError::InvalidSignature)
        );
        assert_eq!(
            verify_and_parse(SECRET, body, &header, now, 5, 1_048_576, false),
            Err(WebhookError::StaleSignature)
        );
        assert_eq!(
            verify_and_parse(SECRET, body, &header, now, 300, 1_048_576, true),
            Err(WebhookError::ModeMismatch)
        );
    }

    #[test]
    fn accepts_any_valid_v1_during_secret_rotation_and_ignores_unknown_events() {
        let body = r#"{"id":"evt_2","type":"customer.created","created":1000,"livemode":false,"data":{"object":{"id":"cus_1"}}}"#;
        let valid = signature(1_000, body);
        let valid_digest = valid.split("v1=").nth(1).unwrap();
        let header = format!("t=1000,v1={},v1={valid_digest},v0=legacy", "00".repeat(32));
        let event = verify_and_parse(
            SECRET,
            body,
            &header,
            OffsetDateTime::from_unix_timestamp(1_000).unwrap(),
            300,
            1_048_576,
            false,
        )
        .unwrap();
        assert_eq!(event.target, None);
    }
}
