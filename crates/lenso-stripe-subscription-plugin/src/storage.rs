use lenso_postgres_kit::OwnedPostgres;
use sqlx::{Postgres, Row, Transaction};
use thiserror::Error;
use time::OffsetDateTime;

use crate::webhook::{CheckoutSubject, ReconciliationTarget, VerifiedEvent};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EffectOperation {
    Checkout,
    Portal,
}

impl EffectOperation {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Checkout => "checkout",
            Self::Portal => "portal",
        }
    }

    fn parse(value: &str) -> Result<Self, StoreError> {
        match value {
            "checkout" => Ok(Self::Checkout),
            "portal" => Ok(Self::Portal),
            other => Err(StoreError::Invariant(format!(
                "unknown persisted Stripe effect operation `{other}`"
            ))),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EffectStatus {
    Prepared,
    InFlight,
    Accepted,
    KnownFailure,
    EffectUnknown,
}

impl EffectStatus {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::InFlight => "in_flight",
            Self::Accepted => "accepted",
            Self::KnownFailure => "known_failure",
            Self::EffectUnknown => "effect_unknown",
        }
    }

    fn parse(value: &str) -> Result<Self, StoreError> {
        match value {
            "prepared" => Ok(Self::Prepared),
            "in_flight" => Ok(Self::InFlight),
            "accepted" => Ok(Self::Accepted),
            "known_failure" => Ok(Self::KnownFailure),
            "effect_unknown" => Ok(Self::EffectUnknown),
            other => Err(StoreError::Invariant(format!(
                "unknown persisted Stripe effect status `{other}`"
            ))),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct NewEffect {
    pub(crate) effect_id: String,
    pub(crate) caller_instance: String,
    pub(crate) operation: EffectOperation,
    pub(crate) idempotency_key: String,
    pub(crate) request_hash: Vec<u8>,
    pub(crate) scope_kind: String,
    pub(crate) scope_id: String,
    pub(crate) subject: String,
    pub(crate) price_alias: Option<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct EffectRecord {
    pub(crate) effect_id: String,
    pub(crate) operation: EffectOperation,
    pub(crate) request_hash: Vec<u8>,
    pub(crate) status: EffectStatus,
    pub(crate) stripe_object_id: Option<String>,
    pub(crate) response_nonce: Option<Vec<u8>>,
    pub(crate) response_ciphertext: Option<Vec<u8>>,
    pub(crate) failure_code: Option<String>,
}

#[derive(Clone, Debug)]
pub(crate) enum EffectClaim {
    Dispatch(EffectRecord),
    Existing(EffectRecord),
    Conflict,
}

pub(crate) async fn recover_stranded_effects(
    postgres: &OwnedPostgres,
    uncertainty_seconds: i64,
) -> Result<u64, StoreError> {
    Ok(sqlx::query(
        "UPDATE stripe_effects SET status='effect_unknown', updated_at=transaction_timestamp() WHERE status='in_flight' AND updated_at <= transaction_timestamp()-make_interval(secs => $1::double precision)",
    )
    .bind(uncertainty_seconds)
    .execute(postgres.pool())
    .await?
    .rows_affected())
}

pub(crate) async fn claim_effect(
    postgres: &OwnedPostgres,
    effect: &NewEffect,
    uncertainty_seconds: i64,
) -> Result<EffectClaim, StoreError> {
    let inserted = sqlx::query(
        "INSERT INTO stripe_effects(effect_id,caller_instance,operation,idempotency_key,request_hash,scope_kind,scope_id,subject,price_alias,status) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'prepared') ON CONFLICT(caller_instance,operation,idempotency_key) DO NOTHING RETURNING effect_id",
    )
    .bind(&effect.effect_id)
    .bind(&effect.caller_instance)
    .bind(effect.operation.as_str())
    .bind(&effect.idempotency_key)
    .bind(&effect.request_hash)
    .bind(&effect.scope_kind)
    .bind(&effect.scope_id)
    .bind(&effect.subject)
    .bind(&effect.price_alias)
    .fetch_optional(postgres.pool())
    .await?
    .is_some();

    let row = sqlx::query(
        "SELECT effect_id,operation,request_hash,status,stripe_object_id,response_nonce,response_ciphertext,failure_code FROM stripe_effects WHERE caller_instance=$1 AND operation=$2 AND idempotency_key=$3",
    )
    .bind(&effect.caller_instance)
    .bind(effect.operation.as_str())
    .bind(&effect.idempotency_key)
    .fetch_one(postgres.pool())
    .await?;
    let mut record = decode_effect(&row)?;
    if record.request_hash != effect.request_hash {
        return Ok(EffectClaim::Conflict);
    }
    if !inserted && record.status == EffectStatus::InFlight {
        let recovered = sqlx::query(
            "UPDATE stripe_effects SET status='effect_unknown',updated_at=transaction_timestamp() WHERE effect_id=$1 AND status='in_flight' AND updated_at <= transaction_timestamp()-make_interval(secs => $2::double precision)",
        )
        .bind(&record.effect_id)
        .bind(uncertainty_seconds)
        .execute(postgres.pool())
        .await?
        .rows_affected();
        if recovered == 1 {
            record.status = EffectStatus::EffectUnknown;
        }
    }
    if !inserted && record.status != EffectStatus::Prepared {
        return Ok(EffectClaim::Existing(record));
    }
    let changed = sqlx::query(
        "UPDATE stripe_effects SET status='in_flight',updated_at=transaction_timestamp() WHERE effect_id=$1 AND status='prepared'",
    )
    .bind(&record.effect_id)
    .execute(postgres.pool())
    .await?
    .rows_affected();
    if changed != 1 {
        let current = load_effect(postgres, &record.effect_id)
            .await?
            .ok_or_else(|| StoreError::Invariant("Stripe effect disappeared".to_owned()))?;
        return Ok(EffectClaim::Existing(current));
    }
    record.status = EffectStatus::InFlight;
    Ok(EffectClaim::Dispatch(record))
}

pub(crate) async fn load_effect(
    postgres: &OwnedPostgres,
    effect_id: &str,
) -> Result<Option<EffectRecord>, StoreError> {
    sqlx::query(
        "SELECT effect_id,operation,request_hash,status,stripe_object_id,response_nonce,response_ciphertext,failure_code FROM stripe_effects WHERE effect_id=$1",
    )
    .bind(effect_id)
    .fetch_optional(postgres.pool())
    .await?
    .as_ref()
    .map(decode_effect)
    .transpose()
}

pub(crate) async fn accept_effect(
    postgres: &OwnedPostgres,
    effect_id: &str,
    stripe_object_id: &str,
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<bool, StoreError> {
    Ok(sqlx::query(
        "UPDATE stripe_effects SET status='accepted',stripe_object_id=$2,response_nonce=$3,response_ciphertext=$4,failure_code=NULL,updated_at=transaction_timestamp(),completed_at=transaction_timestamp() WHERE effect_id=$1 AND status='in_flight'",
    )
    .bind(effect_id)
    .bind(stripe_object_id)
    .bind(nonce)
    .bind(ciphertext)
    .execute(postgres.pool())
    .await?
    .rows_affected()
        == 1)
}

pub(crate) async fn fail_effect(
    postgres: &OwnedPostgres,
    effect_id: &str,
    failure_code: &str,
) -> Result<bool, StoreError> {
    Ok(sqlx::query(
        "UPDATE stripe_effects SET status='known_failure',failure_code=$2,updated_at=transaction_timestamp(),completed_at=transaction_timestamp() WHERE effect_id=$1 AND status='in_flight'",
    )
    .bind(effect_id)
    .bind(failure_code)
    .execute(postgres.pool())
    .await?
    .rows_affected()
        == 1)
}

pub(crate) async fn mark_effect_unknown(
    postgres: &OwnedPostgres,
    effect_id: &str,
) -> Result<bool, StoreError> {
    Ok(sqlx::query(
        "UPDATE stripe_effects SET status='effect_unknown',updated_at=transaction_timestamp() WHERE effect_id=$1 AND status='in_flight'",
    )
    .bind(effect_id)
    .execute(postgres.pool())
    .await?
    .rows_affected()
        == 1)
}

#[derive(Clone, Debug)]
pub(crate) struct ManualResolution<'a> {
    pub(crate) effect_id: &'a str,
    pub(crate) target_status: EffectStatus,
    pub(crate) stripe_object_id: Option<&'a str>,
    pub(crate) nonce: Option<&'a [u8]>,
    pub(crate) ciphertext: Option<&'a [u8]>,
    pub(crate) failure_code: Option<&'a str>,
}

pub(crate) async fn resolve_effect(
    postgres: &OwnedPostgres,
    resolution: &ManualResolution<'_>,
) -> Result<bool, StoreError> {
    Ok(sqlx::query(
        "UPDATE stripe_effects SET status=$2,stripe_object_id=$3,response_nonce=$4,response_ciphertext=$5,failure_code=$6,updated_at=transaction_timestamp(),completed_at=transaction_timestamp() WHERE effect_id=$1 AND status='effect_unknown'",
    )
    .bind(resolution.effect_id)
    .bind(resolution.target_status.as_str())
    .bind(resolution.stripe_object_id)
    .bind(resolution.nonce)
    .bind(resolution.ciphertext)
    .bind(resolution.failure_code)
    .execute(postgres.pool())
    .await?
    .rows_affected()
        == 1)
}

fn decode_effect(row: &sqlx::postgres::PgRow) -> Result<EffectRecord, StoreError> {
    Ok(EffectRecord {
        effect_id: row.try_get("effect_id")?,
        operation: EffectOperation::parse(row.try_get("operation")?)?,
        request_hash: row.try_get("request_hash")?,
        status: EffectStatus::parse(row.try_get("status")?)?,
        stripe_object_id: row.try_get("stripe_object_id")?,
        response_nonce: row.try_get("response_nonce")?,
        response_ciphertext: row.try_get("response_ciphertext")?,
        failure_code: row.try_get("failure_code")?,
    })
}

#[derive(Clone, Debug)]
pub(crate) struct NewMeterEffect {
    pub(crate) delivery_id: String,
    pub(crate) caller_instance: String,
    pub(crate) request_hash: Vec<u8>,
    pub(crate) scope_kind: String,
    pub(crate) scope_id: String,
    pub(crate) subject: String,
    pub(crate) meter_alias: String,
    pub(crate) stripe_event_name: String,
    pub(crate) quantity: String,
    pub(crate) occurred_at: OffsetDateTime,
}

#[derive(Clone, Debug)]
pub(crate) struct MeterEffectRecord {
    pub(crate) delivery_id: String,
    pub(crate) caller_instance: String,
    pub(crate) request_hash: Vec<u8>,
    pub(crate) status: EffectStatus,
    pub(crate) provider_reference: Option<String>,
    pub(crate) failure_code: Option<String>,
}

#[derive(Clone, Debug)]
pub(crate) enum MeterEffectClaim {
    Dispatch(MeterEffectRecord),
    Existing(MeterEffectRecord),
    Conflict,
}

pub(crate) async fn recover_stranded_meter_effects(
    postgres: &OwnedPostgres,
    uncertainty_seconds: i64,
) -> Result<u64, StoreError> {
    Ok(sqlx::query(
        "UPDATE stripe_meter_effects SET status='effect_unknown',updated_at=transaction_timestamp() WHERE status='in_flight' AND updated_at <= transaction_timestamp()-make_interval(secs => $1::double precision)",
    )
    .bind(uncertainty_seconds)
    .execute(postgres.pool())
    .await?
    .rows_affected())
}

pub(crate) async fn load_billing_customer(
    postgres: &OwnedPostgres,
    scope_kind: &str,
    scope_id: &str,
    subject: &str,
) -> Result<Option<String>, StoreError> {
    Ok(sqlx::query_scalar(
        "SELECT stripe_customer_id FROM stripe_billing_subjects WHERE scope_kind=$1 AND scope_id=$2 AND subject=$3",
    )
    .bind(scope_kind)
    .bind(scope_id)
    .bind(subject)
    .fetch_optional(postgres.pool())
    .await?)
}

pub(crate) async fn claim_meter_effect(
    postgres: &OwnedPostgres,
    effect: &NewMeterEffect,
    uncertainty_seconds: i64,
) -> Result<MeterEffectClaim, StoreError> {
    let inserted = sqlx::query(
        "INSERT INTO stripe_meter_effects(delivery_id,caller_instance,request_hash,scope_kind,scope_id,subject,meter_alias,stripe_event_name,quantity,occurred_at,status) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'prepared') ON CONFLICT(delivery_id) DO NOTHING RETURNING delivery_id",
    )
    .bind(&effect.delivery_id)
    .bind(&effect.caller_instance)
    .bind(&effect.request_hash)
    .bind(&effect.scope_kind)
    .bind(&effect.scope_id)
    .bind(&effect.subject)
    .bind(&effect.meter_alias)
    .bind(&effect.stripe_event_name)
    .bind(&effect.quantity)
    .bind(effect.occurred_at)
    .fetch_optional(postgres.pool())
    .await?
    .is_some();

    let row = sqlx::query(
        "SELECT delivery_id,caller_instance,request_hash,status,provider_reference,failure_code FROM stripe_meter_effects WHERE delivery_id=$1",
    )
    .bind(&effect.delivery_id)
    .fetch_one(postgres.pool())
    .await?;
    let mut record = decode_meter_effect(&row)?;
    if record.caller_instance != effect.caller_instance
        || record.request_hash != effect.request_hash
    {
        return Ok(MeterEffectClaim::Conflict);
    }
    if !inserted && record.status == EffectStatus::InFlight {
        let recovered = sqlx::query(
            "UPDATE stripe_meter_effects SET status='effect_unknown',updated_at=transaction_timestamp() WHERE delivery_id=$1 AND status='in_flight' AND updated_at <= transaction_timestamp()-make_interval(secs => $2::double precision)",
        )
        .bind(&record.delivery_id)
        .bind(uncertainty_seconds)
        .execute(postgres.pool())
        .await?
        .rows_affected();
        if recovered == 1 {
            record.status = EffectStatus::EffectUnknown;
        }
    }
    if !inserted && record.status != EffectStatus::Prepared {
        return Ok(MeterEffectClaim::Existing(record));
    }
    let changed = sqlx::query(
        "UPDATE stripe_meter_effects SET status='in_flight',updated_at=transaction_timestamp() WHERE delivery_id=$1 AND status='prepared'",
    )
    .bind(&record.delivery_id)
    .execute(postgres.pool())
    .await?
    .rows_affected();
    if changed != 1 {
        let current = load_meter_effect(postgres, &record.delivery_id)
            .await?
            .ok_or_else(|| StoreError::Invariant("Stripe meter effect disappeared".to_owned()))?;
        return Ok(MeterEffectClaim::Existing(current));
    }
    record.status = EffectStatus::InFlight;
    Ok(MeterEffectClaim::Dispatch(record))
}

pub(crate) async fn load_meter_effect(
    postgres: &OwnedPostgres,
    delivery_id: &str,
) -> Result<Option<MeterEffectRecord>, StoreError> {
    sqlx::query(
        "SELECT delivery_id,caller_instance,request_hash,status,provider_reference,failure_code FROM stripe_meter_effects WHERE delivery_id=$1",
    )
    .bind(delivery_id)
    .fetch_optional(postgres.pool())
    .await?
    .as_ref()
    .map(decode_meter_effect)
    .transpose()
}

pub(crate) async fn accept_meter_effect(
    postgres: &OwnedPostgres,
    delivery_id: &str,
    provider_reference: &str,
) -> Result<bool, StoreError> {
    Ok(sqlx::query(
        "UPDATE stripe_meter_effects SET status='accepted',provider_reference=$2,failure_code=NULL,updated_at=transaction_timestamp(),completed_at=transaction_timestamp() WHERE delivery_id=$1 AND status='in_flight'",
    )
    .bind(delivery_id)
    .bind(provider_reference)
    .execute(postgres.pool())
    .await?
    .rows_affected()
        == 1)
}

pub(crate) async fn fail_meter_effect(
    postgres: &OwnedPostgres,
    delivery_id: &str,
    failure_code: &str,
) -> Result<bool, StoreError> {
    Ok(sqlx::query(
        "UPDATE stripe_meter_effects SET status='known_failure',provider_reference=NULL,failure_code=$2,updated_at=transaction_timestamp(),completed_at=transaction_timestamp() WHERE delivery_id=$1 AND status='in_flight'",
    )
    .bind(delivery_id)
    .bind(failure_code)
    .execute(postgres.pool())
    .await?
    .rows_affected()
        == 1)
}

pub(crate) async fn mark_meter_effect_unknown(
    postgres: &OwnedPostgres,
    delivery_id: &str,
) -> Result<bool, StoreError> {
    Ok(sqlx::query(
        "UPDATE stripe_meter_effects SET status='effect_unknown',updated_at=transaction_timestamp() WHERE delivery_id=$1 AND status='in_flight'",
    )
    .bind(delivery_id)
    .execute(postgres.pool())
    .await?
    .rows_affected()
        == 1)
}

fn decode_meter_effect(row: &sqlx::postgres::PgRow) -> Result<MeterEffectRecord, StoreError> {
    Ok(MeterEffectRecord {
        delivery_id: row.try_get("delivery_id")?,
        caller_instance: row.try_get("caller_instance")?,
        request_hash: row.try_get("request_hash")?,
        status: EffectStatus::parse(row.try_get("status")?)?,
        provider_reference: row.try_get("provider_reference")?,
        failure_code: row.try_get("failure_code")?,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WebhookRecordOutcome {
    Created,
    Duplicate,
}

pub(crate) async fn record_webhook(
    postgres: &OwnedPostgres,
    event: &VerifiedEvent,
    payload_sha256: &[u8],
) -> Result<WebhookRecordOutcome, StoreError> {
    let mut transaction = postgres.pool().begin().await?;
    let outcome = if event.target.is_some() {
        "accepted"
    } else {
        "ignored"
    };
    let target = event.target.as_ref();
    let inserted = sqlx::query(
        "INSERT INTO stripe_webhook_events(event_id,event_type,stripe_created,livemode,payload_sha256,customer_id,subscription_id,outcome) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(event_id) DO NOTHING RETURNING event_id",
    )
    .bind(&event.event_id)
    .bind(&event.event_type)
    .bind(event.created_at)
    .bind(event.livemode)
    .bind(payload_sha256)
    .bind(target.map(|value| value.customer_id.as_str()))
    .bind(target.map(|value| value.subscription_id.as_str()))
    .bind(outcome)
    .fetch_optional(&mut *transaction)
    .await?
    .is_some();
    if !inserted {
        let row = sqlx::query(
            "SELECT event_type,stripe_created,livemode,payload_sha256,customer_id,subscription_id,outcome FROM stripe_webhook_events WHERE event_id=$1",
        )
        .bind(&event.event_id)
        .fetch_one(&mut *transaction)
        .await?;
        let exact = row.try_get::<String, _>("event_type")? == event.event_type
            && row.try_get::<i64, _>("stripe_created")? == event.created_at
            && row.try_get::<bool, _>("livemode")? == event.livemode
            && row.try_get::<Vec<u8>, _>("payload_sha256")? == payload_sha256
            && row.try_get::<Option<String>, _>("customer_id")?
                == target.map(|value| value.customer_id.clone())
            && row.try_get::<Option<String>, _>("subscription_id")?
                == target.map(|value| value.subscription_id.clone())
            && row.try_get::<String, _>("outcome")? == outcome;
        if !exact {
            return Err(StoreError::Invariant(format!(
                "Stripe event `{}` was replayed with different content",
                event.event_id
            )));
        }
        transaction.rollback().await?;
        return Ok(WebhookRecordOutcome::Duplicate);
    }
    if let Some(target) = target {
        if let Some(subject) = &target.checkout_subject {
            upsert_checkout_subject(&mut transaction, target, subject).await?;
        }
        sqlx::query(
            "INSERT INTO stripe_reconciliations(subscription_id,customer_id,state) VALUES($1,$2,'pending') ON CONFLICT(subscription_id) DO UPDATE SET customer_id=EXCLUDED.customer_id,state='pending',lease_owner=NULL,lease_token_hash=NULL,lease_expires_at=NULL,last_failure_code=NULL,updated_at=transaction_timestamp()",
        )
        .bind(&target.subscription_id)
        .bind(&target.customer_id)
        .execute(&mut *transaction)
        .await?;
    }
    transaction.commit().await?;
    Ok(WebhookRecordOutcome::Created)
}

async fn upsert_checkout_subject(
    transaction: &mut Transaction<'_, Postgres>,
    target: &ReconciliationTarget,
    subject: &CheckoutSubject,
) -> Result<(), StoreError> {
    sqlx::query(
        "INSERT INTO stripe_billing_subjects(scope_kind,scope_id,subject,stripe_customer_id,stripe_subscription_id,price_alias,subscription_status,entitlement_state) VALUES($1,$2,$3,$4,$5,$6,'incomplete','pending') ON CONFLICT(scope_kind,scope_id,subject) DO UPDATE SET stripe_customer_id=EXCLUDED.stripe_customer_id,stripe_subscription_id=EXCLUDED.stripe_subscription_id,price_alias=EXCLUDED.price_alias,entitlement_state='pending',revision=stripe_billing_subjects.revision+1,updated_at=transaction_timestamp()",
    )
    .bind(&subject.scope_kind)
    .bind(&subject.scope_id)
    .bind(&subject.subject)
    .bind(&target.customer_id)
    .bind(&target.subscription_id)
    .bind(&subject.price_alias)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

#[derive(Clone, Debug)]
pub(crate) struct BillingSubject {
    pub(crate) scope_kind: String,
    pub(crate) scope_id: String,
    pub(crate) subject: String,
    pub(crate) customer_id: String,
    pub(crate) subscription_id: Option<String>,
    pub(crate) price_alias: Option<String>,
    pub(crate) subscription_status: String,
    pub(crate) cancel_at_period_end: bool,
    pub(crate) current_period_end: Option<OffsetDateTime>,
    pub(crate) entitlement_state: String,
    pub(crate) revision: i64,
}

pub(crate) async fn load_subject(
    postgres: &OwnedPostgres,
    scope_kind: &str,
    scope_id: &str,
    subject: &str,
) -> Result<Option<BillingSubject>, StoreError> {
    sqlx::query(
        "SELECT scope_kind,scope_id,subject,stripe_customer_id,stripe_subscription_id,price_alias,subscription_status,cancel_at_period_end,current_period_end,entitlement_state,revision FROM stripe_billing_subjects WHERE scope_kind=$1 AND scope_id=$2 AND subject=$3",
    )
    .bind(scope_kind)
    .bind(scope_id)
    .bind(subject)
    .fetch_optional(postgres.pool())
    .await?
    .as_ref()
    .map(decode_subject)
    .transpose()
}

pub(crate) async fn load_subject_for_reconciliation(
    postgres: &OwnedPostgres,
    subscription_id: &str,
    customer_id: &str,
) -> Result<Option<BillingSubject>, StoreError> {
    sqlx::query(
        "SELECT scope_kind,scope_id,subject,stripe_customer_id,stripe_subscription_id,price_alias,subscription_status,cancel_at_period_end,current_period_end,entitlement_state,revision FROM stripe_billing_subjects WHERE stripe_subscription_id=$1 OR stripe_customer_id=$2 ORDER BY (stripe_subscription_id=$1) DESC LIMIT 1",
    )
    .bind(subscription_id)
    .bind(customer_id)
    .fetch_optional(postgres.pool())
    .await?
    .as_ref()
    .map(decode_subject)
    .transpose()
}

fn decode_subject(row: &sqlx::postgres::PgRow) -> Result<BillingSubject, StoreError> {
    Ok(BillingSubject {
        scope_kind: row.try_get("scope_kind")?,
        scope_id: row.try_get("scope_id")?,
        subject: row.try_get("subject")?,
        customer_id: row.try_get("stripe_customer_id")?,
        subscription_id: row.try_get("stripe_subscription_id")?,
        price_alias: row.try_get("price_alias")?,
        subscription_status: row.try_get("subscription_status")?,
        cancel_at_period_end: row.try_get("cancel_at_period_end")?,
        current_period_end: row.try_get("current_period_end")?,
        entitlement_state: row.try_get("entitlement_state")?,
        revision: row.try_get("revision")?,
    })
}

#[derive(Clone, Debug)]
pub(crate) struct ReconciliationClaim {
    pub(crate) subscription_id: String,
    pub(crate) customer_id: String,
    pub(crate) token_hash: Vec<u8>,
}

pub(crate) async fn claim_reconciliation(
    postgres: &OwnedPostgres,
    worker: &str,
    token_hash: &[u8],
    lease_seconds: i64,
) -> Result<Option<ReconciliationClaim>, StoreError> {
    let row = sqlx::query(
        "WITH candidate AS (SELECT subscription_id FROM stripe_reconciliations WHERE state='pending' OR (state='running' AND lease_expires_at <= transaction_timestamp()) ORDER BY updated_at,subscription_id FOR UPDATE SKIP LOCKED LIMIT 1) UPDATE stripe_reconciliations r SET state='running',attempts=attempts+1,lease_generation=lease_generation+1,lease_owner=$1,lease_token_hash=$2,lease_expires_at=transaction_timestamp()+make_interval(secs => $3::double precision),updated_at=transaction_timestamp() FROM candidate WHERE r.subscription_id=candidate.subscription_id RETURNING r.subscription_id,r.customer_id,r.lease_token_hash",
    )
    .bind(worker)
    .bind(token_hash)
    .bind(lease_seconds)
    .fetch_optional(postgres.pool())
    .await?;
    row.map(|row| {
        Ok(ReconciliationClaim {
            subscription_id: row.try_get("subscription_id")?,
            customer_id: row.try_get("customer_id")?,
            token_hash: row.try_get("lease_token_hash")?,
        })
    })
    .transpose()
}

pub(crate) async fn retry_reconciliation(
    postgres: &OwnedPostgres,
    claim: &ReconciliationClaim,
    failure_code: &str,
) -> Result<bool, StoreError> {
    Ok(sqlx::query(
        "UPDATE stripe_reconciliations SET state='pending',lease_owner=NULL,lease_token_hash=NULL,lease_expires_at=NULL,last_failure_code=$3,updated_at=transaction_timestamp() WHERE subscription_id=$1 AND state='running' AND lease_token_hash=$2",
    )
    .bind(&claim.subscription_id)
    .bind(&claim.token_hash)
    .bind(failure_code)
    .execute(postgres.pool())
    .await?
    .rows_affected()
        == 1)
}

#[derive(Clone, Debug)]
pub(crate) struct EntitlementBinding {
    pub(crate) feature: String,
    pub(crate) grant_id: String,
}

pub(crate) async fn load_bindings(
    postgres: &OwnedPostgres,
    subscription_id: &str,
) -> Result<Vec<EntitlementBinding>, StoreError> {
    let rows = sqlx::query(
        "SELECT feature,grant_id FROM stripe_entitlement_bindings WHERE subscription_id=$1 ORDER BY feature",
    )
    .bind(subscription_id)
    .fetch_all(postgres.pool())
    .await?;
    rows.iter()
        .map(|row| {
            Ok(EntitlementBinding {
                feature: row.try_get("feature")?,
                grant_id: row.try_get("grant_id")?,
            })
        })
        .collect()
}

pub(crate) async fn put_binding(
    postgres: &OwnedPostgres,
    subscription_id: &str,
    feature: &str,
    grant_id: &str,
    revision: i64,
) -> Result<(), StoreError> {
    sqlx::query(
        "INSERT INTO stripe_entitlement_bindings(subscription_id,feature,grant_id,applied_revision) VALUES($1,$2,$3,$4) ON CONFLICT(subscription_id,feature) DO UPDATE SET grant_id=EXCLUDED.grant_id,applied_revision=EXCLUDED.applied_revision,updated_at=transaction_timestamp()",
    )
    .bind(subscription_id)
    .bind(feature)
    .bind(grant_id)
    .bind(revision)
    .execute(postgres.pool())
    .await?;
    Ok(())
}

pub(crate) async fn delete_binding(
    postgres: &OwnedPostgres,
    subscription_id: &str,
    feature: &str,
) -> Result<(), StoreError> {
    sqlx::query("DELETE FROM stripe_entitlement_bindings WHERE subscription_id=$1 AND feature=$2")
        .bind(subscription_id)
        .bind(feature)
        .execute(postgres.pool())
        .await?;
    Ok(())
}

#[derive(Clone, Debug)]
pub(crate) struct CanonicalState<'a> {
    pub(crate) subscription_id: &'a str,
    pub(crate) customer_id: &'a str,
    pub(crate) price_alias: Option<&'a str>,
    pub(crate) status: &'a str,
    pub(crate) cancel_at_period_end: bool,
    pub(crate) current_period_end: Option<OffsetDateTime>,
    pub(crate) entitlement_state: &'a str,
}

pub(crate) async fn converge_reconciliation(
    postgres: &OwnedPostgres,
    claim: &ReconciliationClaim,
    state: &CanonicalState<'_>,
) -> Result<Option<i64>, StoreError> {
    let mut transaction = postgres.pool().begin().await?;
    let still_owned = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM stripe_reconciliations WHERE subscription_id=$1 AND state='running' AND lease_token_hash=$2 AND lease_expires_at > transaction_timestamp())",
    )
    .bind(&claim.subscription_id)
    .bind(&claim.token_hash)
    .fetch_one(&mut *transaction)
    .await?;
    if !still_owned {
        transaction.rollback().await?;
        return Ok(None);
    }
    let revision = sqlx::query_scalar::<_, i64>(
        "UPDATE stripe_billing_subjects SET stripe_customer_id=$2,stripe_subscription_id=$1,price_alias=$3,subscription_status=$4,cancel_at_period_end=$5,current_period_end=$6,entitlement_state=$7,revision=revision+1,updated_at=transaction_timestamp() WHERE stripe_subscription_id=$1 OR stripe_customer_id=$2 RETURNING revision",
    )
    .bind(state.subscription_id)
    .bind(state.customer_id)
    .bind(state.price_alias)
    .bind(state.status)
    .bind(state.cancel_at_period_end)
    .bind(state.current_period_end)
    .bind(state.entitlement_state)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some(revision) = revision else {
        transaction.rollback().await?;
        return Ok(None);
    };
    sqlx::query(
        "UPDATE stripe_reconciliations SET state='converged',lease_owner=NULL,lease_token_hash=NULL,lease_expires_at=NULL,last_failure_code=NULL,updated_at=transaction_timestamp() WHERE subscription_id=$1 AND lease_token_hash=$2",
    )
    .bind(&claim.subscription_id)
    .bind(&claim.token_hash)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(Some(revision))
}

#[derive(Debug, Error)]
pub(crate) enum StoreError {
    #[error("Stripe Subscription storage invariant failed: {0}")]
    Invariant(String),
    #[error("Stripe Subscription PostgreSQL operation failed: {0}")]
    Database(#[from] sqlx::Error),
}
