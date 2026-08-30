use lenso_capability_billing_meter_sink::{
    PublishMeterEventError, PublishMeterEventRequest, PublishMeterEventResponse,
    PublishMeterEventResponseOutcome,
};
use lenso_capability_http_client::{ClientInvocationError, SendRequest, SendResponse};
use lenso_kernel::{InvocationContext, RuntimeFailure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};

use crate::{
    PreparedStripe, StripeSubscriptionPlugin,
    config::valid_name,
    service::{failure, stripe_headers},
    storage::{
        self, EffectStatus, MeterEffectClaim, MeterEffectRecord, NewMeterEffect, StoreError,
    },
};

const MAX_STRIPE_RESPONSE_BYTES: usize = 1_048_576;
const MAX_DELIVERY_ID_BYTES: usize = 100;
const MAX_QUANTITY_DIGITS: usize = 100;

#[derive(Debug)]
pub(crate) enum MeterFlowError {
    Domain(PublishMeterEventError),
    Runtime(RuntimeFailure),
}

impl StripeSubscriptionPlugin {
    pub(crate) async fn publish_meter(
        &self,
        context: InvocationContext,
        request: PublishMeterEventRequest,
    ) -> Result<PublishMeterEventResponse, MeterFlowError> {
        if !self.config.meter_allowed(context.caller_instance()) {
            return Err(MeterFlowError::Domain(PublishMeterEventError::Forbidden));
        }
        let now = OffsetDateTime::now_utc();
        let Some(occurred_at) = validate_request(&request, now) else {
            return Err(MeterFlowError::Domain(PublishMeterEventError::InvalidEvent));
        };
        let Some(meter) = self.config.meter(&request.meter).cloned() else {
            return Err(MeterFlowError::Domain(
                PublishMeterEventError::MeterNotConfigured,
            ));
        };
        let prepared = self.prepared().map_err(MeterFlowError::Runtime)?;
        let customer_id = storage::load_billing_customer(
            &prepared.postgres,
            &request.scope_kind,
            &request.scope_id,
            &request.subject,
        )
        .await
        .map_err(|error| store_runtime(&error))?
        .ok_or_else(|| MeterFlowError::Domain(PublishMeterEventError::AccountNotFound))?;
        let caller = context.caller_instance().unwrap_or_default().to_owned();
        let request_hash = request_hash(&request).map_err(MeterFlowError::Runtime)?;
        let claim = storage::claim_meter_effect(
            &prepared.postgres,
            &NewMeterEffect {
                delivery_id: request.delivery_id.clone(),
                caller_instance: caller,
                request_hash,
                scope_kind: request.scope_kind.clone(),
                scope_id: request.scope_id.clone(),
                subject: request.subject.clone(),
                meter_alias: request.meter.clone(),
                stripe_event_name: meter.event_name.clone(),
                quantity: request.quantity.clone(),
                occurred_at,
            },
            self.config.effect_uncertainty_seconds(),
        )
        .await
        .map_err(|error| store_runtime(&error))?;

        match claim {
            MeterEffectClaim::Conflict => Err(MeterFlowError::Domain(
                PublishMeterEventError::IdempotencyConflict,
            )),
            MeterEffectClaim::Existing(record) => existing_response(record),
            MeterEffectClaim::Dispatch(record) => {
                let body = meter_event_form(
                    &request,
                    &meter.event_name,
                    &customer_id,
                    occurred_at.unix_timestamp(),
                );
                let response = self
                    .http
                    .send_with_context(
                        context,
                        SendRequest {
                            body: body.into_bytes().into(),
                            headers: stripe_headers(
                                &prepared.api_key,
                                Some(&request.delivery_id),
                                true,
                            ),
                            method: "POST".to_owned(),
                            url: prepared
                                .api_base
                                .join("v1/billing/meter_events")
                                .expect("validated Stripe API base")
                                .to_string(),
                        },
                    )
                    .await;
                finish_meter(&prepared, &record.delivery_id, response).await
            }
        }
    }
}

fn validate_request(
    request: &PublishMeterEventRequest,
    now: OffsetDateTime,
) -> Option<OffsetDateTime> {
    if request.delivery_id.len() > MAX_DELIVERY_ID_BYTES
        || !valid_name(&request.delivery_id)
        || !valid_name(&request.scope_kind)
        || !valid_name(&request.scope_id)
        || !valid_name(&request.subject)
        || !valid_name(&request.meter)
        || request.quantity.is_empty()
        || request.quantity.len() > MAX_QUANTITY_DIGITS
        || !request.quantity.bytes().all(|byte| byte.is_ascii_digit())
        || (request.quantity.len() > 1 && request.quantity.starts_with('0'))
    {
        return None;
    }
    let occurred_at = OffsetDateTime::parse(&request.occurred_at, &Rfc3339).ok()?;
    if occurred_at < now - Duration::days(35) || occurred_at > now + Duration::minutes(5) {
        return None;
    }
    Some(occurred_at)
}

fn meter_event_form(
    request: &PublishMeterEventRequest,
    event_name: &str,
    customer_id: &str,
    occurred_at: i64,
) -> String {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    serializer
        .append_pair("event_name", event_name)
        .append_pair("payload[stripe_customer_id]", customer_id)
        .append_pair("payload[value]", &request.quantity)
        .append_pair("identifier", &request.delivery_id)
        .append_pair("timestamp", &occurred_at.to_string());
    serializer.finish()
}

async fn finish_meter(
    prepared: &PreparedStripe,
    delivery_id: &str,
    response: Result<SendResponse, ClientInvocationError>,
) -> Result<PublishMeterEventResponse, MeterFlowError> {
    match classify_response(response) {
        MeterHttpResponse::KnownFailure => {
            let failed =
                storage::fail_meter_effect(&prepared.postgres, delivery_id, "stripe_rejected")
                    .await
                    .map_err(|error| store_runtime(&error))?;
            if !failed {
                return Err(MeterFlowError::Domain(
                    PublishMeterEventError::EffectUnknown,
                ));
            }
            Err(MeterFlowError::Domain(PublishMeterEventError::InvalidEvent))
        }
        MeterHttpResponse::Success(body) => {
            let Some(reference) = parse_meter_reference(&body, delivery_id) else {
                mark_unknown(prepared, delivery_id).await;
                return Err(MeterFlowError::Domain(
                    PublishMeterEventError::EffectUnknown,
                ));
            };
            let accepted =
                storage::accept_meter_effect(&prepared.postgres, delivery_id, &reference)
                    .await
                    .map_err(|error| store_runtime(&error))?;
            if !accepted {
                return Err(MeterFlowError::Domain(
                    PublishMeterEventError::EffectUnknown,
                ));
            }
            Ok(PublishMeterEventResponse {
                accepted: true,
                outcome: PublishMeterEventResponseOutcome::Accepted,
                provider_reference: reference,
            })
        }
        MeterHttpResponse::Unknown => {
            mark_unknown(prepared, delivery_id).await;
            Err(MeterFlowError::Domain(
                PublishMeterEventError::EffectUnknown,
            ))
        }
    }
}

fn existing_response(
    record: MeterEffectRecord,
) -> Result<PublishMeterEventResponse, MeterFlowError> {
    match record.status {
        EffectStatus::Accepted => {
            let Some(provider_reference) = record.provider_reference else {
                return Err(MeterFlowError::Runtime(failure(
                    "accepted Stripe meter effect has no provider reference",
                )));
            };
            Ok(PublishMeterEventResponse {
                accepted: true,
                outcome: PublishMeterEventResponseOutcome::Replayed,
                provider_reference,
            })
        }
        EffectStatus::KnownFailure if record.failure_code.as_deref() == Some("stripe_rejected") => {
            Err(MeterFlowError::Domain(PublishMeterEventError::InvalidEvent))
        }
        EffectStatus::KnownFailure => Err(MeterFlowError::Runtime(failure(
            "known Stripe meter failure has an invalid failure code",
        ))),
        EffectStatus::Prepared | EffectStatus::InFlight | EffectStatus::EffectUnknown => Err(
            MeterFlowError::Domain(PublishMeterEventError::EffectUnknown),
        ),
    }
}

enum MeterHttpResponse {
    Success(Vec<u8>),
    KnownFailure,
    Unknown,
}

fn classify_response(response: Result<SendResponse, ClientInvocationError>) -> MeterHttpResponse {
    match response {
        Ok(response)
            if (200..300).contains(&response.status)
                && response.body.len() <= MAX_STRIPE_RESPONSE_BYTES =>
        {
            MeterHttpResponse::Success(response.body.as_slice().to_vec())
        }
        Ok(response)
            if (400..500).contains(&response.status)
                && !matches!(response.status, 408 | 409 | 425 | 429) =>
        {
            MeterHttpResponse::KnownFailure
        }
        Ok(_) | Err(_) => MeterHttpResponse::Unknown,
    }
}

#[derive(Deserialize)]
struct StripeMeterEvent {
    identifier: String,
}

fn parse_meter_reference(body: &[u8], delivery_id: &str) -> Option<String> {
    let event: StripeMeterEvent = serde_json::from_slice(body).ok()?;
    (event.identifier == delivery_id).then_some(event.identifier)
}

fn request_hash<T: Serialize>(value: &T) -> Result<Vec<u8>, RuntimeFailure> {
    let bytes = serde_json::to_vec(value).map_err(|error| failure(error.to_string()))?;
    Ok(Sha256::digest(bytes).to_vec())
}

async fn mark_unknown(prepared: &PreparedStripe, delivery_id: &str) {
    let _ = storage::mark_meter_effect_unknown(&prepared.postgres, delivery_id).await;
}

fn store_runtime(error: &StoreError) -> MeterFlowError {
    MeterFlowError::Runtime(failure(error.to_string()))
}

#[cfg(test)]
mod tests {
    use lenso_capability_billing_meter_sink::PublishMeterEventRequest;
    use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};

    use super::{meter_event_form, parse_meter_reference, validate_request};

    fn request(now: OffsetDateTime) -> PublishMeterEventRequest {
        PublishMeterEventRequest {
            delivery_id: "usage_delivery_0123456789abcdef".to_owned(),
            meter: "api.requests".to_owned(),
            occurred_at: now.format(&Rfc3339).unwrap(),
            quantity: "42".to_owned(),
            scope_id: "org_1".to_owned(),
            scope_kind: "organization".to_owned(),
            subject: "org_1".to_owned(),
        }
    }

    #[test]
    fn request_window_and_integer_shape_fail_closed() {
        let now = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
        assert!(validate_request(&request(now), now).is_some());

        let mut stale = request(now - Duration::days(35) - Duration::seconds(1));
        assert!(validate_request(&stale, now).is_none());
        stale.occurred_at = (now + Duration::minutes(5) + Duration::seconds(1))
            .format(&Rfc3339)
            .unwrap();
        assert!(validate_request(&stale, now).is_none());

        let mut fractional = request(now);
        fractional.quantity = "1.5".to_owned();
        assert!(validate_request(&fractional, now).is_none());
    }

    #[test]
    fn stripe_form_uses_customer_value_identifier_and_timestamp() {
        let now = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
        let request = request(now);
        let form = meter_event_form(&request, "api_requests", "cus_123", now.unix_timestamp());
        let pairs = url::form_urlencoded::parse(form.as_bytes()).collect::<Vec<_>>();
        assert!(pairs.contains(&("event_name".into(), "api_requests".into())));
        assert!(pairs.contains(&("payload[stripe_customer_id]".into(), "cus_123".into())));
        assert!(pairs.contains(&("payload[value]".into(), "42".into())));
        assert!(pairs.contains(&("identifier".into(), request.delivery_id.as_str().into())));
    }

    #[test]
    fn success_response_must_echo_the_delivery_identifier() {
        let body = br#"{"identifier":"delivery-1","object":"billing.meter_event"}"#;
        assert_eq!(
            parse_meter_reference(body, "delivery-1").as_deref(),
            Some("delivery-1")
        );
        assert!(parse_meter_reference(body, "delivery-2").is_none());
    }
}
