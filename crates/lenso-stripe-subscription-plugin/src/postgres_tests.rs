use lenso_postgres_kit::OwnedPostgres;
use sha2::{Digest, Sha256};
use sqlx::{AssertSqlSafe, Executor as _};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    StripeSubscriptionOperator, schema,
    storage::{
        self, CanonicalState, EffectClaim, EffectOperation, EffectStatus, NewEffect,
        WebhookRecordOutcome,
    },
    webhook::{CheckoutSubject, ReconciliationTarget, VerifiedEvent},
};

async fn prepare_postgres() -> Option<(String, String, OwnedPostgres)> {
    let Ok(database_url) = std::env::var("LENSO_STRIPE_SUBSCRIPTION_TEST_DATABASE_URL") else {
        return None;
    };
    let database_name = database_url.rsplit('/').next().unwrap_or_default();
    assert!(
        database_name.contains("test"),
        "acceptance requires a disposable test database"
    );
    let schema_name = format!("stripe_subscription_test_{}", Uuid::new_v4().simple());
    StripeSubscriptionOperator::setup(&database_url, &schema_name)
        .await
        .unwrap();
    let postgres = OwnedPostgres::prepare(
        &database_url,
        schema::schema_plan(schema_name.clone()).unwrap(),
    )
    .await
    .unwrap();
    Some((database_url, schema_name, postgres))
}

async fn seed_subjects_and_reject_invalid_receipts(postgres: &OwnedPostgres) {
    for (scope_id, customer_id) in [("org_1", "cus_1"), ("org_2", "cus_2")] {
        sqlx::query(
            "INSERT INTO stripe_billing_subjects(scope_kind,scope_id,subject,stripe_customer_id) VALUES('organization',$1,$1,$2)",
        )
        .bind(scope_id)
        .bind(customer_id)
        .execute(postgres.pool())
        .await
        .unwrap();
    }
    let subjects: i64 = sqlx::query_scalar("SELECT count(*) FROM stripe_billing_subjects")
        .fetch_one(postgres.pool())
        .await
        .unwrap();
    assert_eq!(subjects, 2, "multiple subjects may await a subscription");

    let invalid_effect = sqlx::query(
        "INSERT INTO stripe_effects(effect_id,caller_instance,operation,idempotency_key,request_hash,scope_kind,scope_id,subject,status,stripe_object_id) VALUES('effect_invalid','billing-ui','checkout','key-1',decode(repeat('00',32),'hex'),'organization','org_1','org_1','accepted','cs_1')",
    )
    .execute(postgres.pool())
    .await;
    assert!(
        invalid_effect.is_err(),
        "accepted effects require an encrypted receipt"
    );
}

fn checkout_effect() -> NewEffect {
    NewEffect {
        effect_id: "stripe_effect_00000000000000000000000000000001".to_owned(),
        caller_instance: "billing-ui".to_owned(),
        operation: EffectOperation::Checkout,
        idempotency_key: "checkout-1".to_owned(),
        request_hash: Sha256::digest(b"request-one").to_vec(),
        scope_kind: "organization".to_owned(),
        scope_id: "org_1".to_owned(),
        subject: "org_1".to_owned(),
        price_alias: Some("pro".to_owned()),
    }
}

async fn assert_effect_idempotency_and_uncertainty(postgres: &OwnedPostgres) {
    let effect = checkout_effect();
    assert!(matches!(
        storage::claim_effect(postgres, &effect, 120).await.unwrap(),
        EffectClaim::Dispatch(_)
    ));
    assert!(matches!(
        storage::claim_effect(postgres, &effect, 120).await.unwrap(),
        EffectClaim::Existing(_)
    ));
    assert_eq!(
        storage::recover_stranded_effects(postgres, 120)
            .await
            .unwrap(),
        0,
        "a rolling activation must not invalidate a live dispatch"
    );
    let mut conflicting = effect.clone();
    conflicting.request_hash = Sha256::digest(b"request-two").to_vec();
    assert!(matches!(
        storage::claim_effect(postgres, &conflicting, 120)
            .await
            .unwrap(),
        EffectClaim::Conflict
    ));
    sqlx::query(
        "UPDATE stripe_effects SET updated_at=transaction_timestamp()-interval '121 seconds' WHERE effect_id=$1",
    )
    .bind(&effect.effect_id)
    .execute(postgres.pool())
    .await
    .unwrap();
    assert_eq!(
        storage::recover_stranded_effects(postgres, 120)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        storage::load_effect(postgres, &effect.effect_id)
            .await
            .unwrap()
            .unwrap()
            .status,
        EffectStatus::EffectUnknown
    );
}

fn checkout_event() -> VerifiedEvent {
    VerifiedEvent {
        event_id: "evt_checkout_1".to_owned(),
        event_type: "checkout.session.completed".to_owned(),
        created_at: OffsetDateTime::now_utc().unix_timestamp(),
        livemode: false,
        target: Some(ReconciliationTarget {
            subscription_id: "sub_1".to_owned(),
            customer_id: "cus_1".to_owned(),
            checkout_subject: Some(CheckoutSubject {
                scope_kind: "organization".to_owned(),
                scope_id: "org_1".to_owned(),
                subject: "org_1".to_owned(),
                price_alias: "pro".to_owned(),
            }),
        }),
    }
}

async fn assert_webhook_deduplication_and_reconciliation(postgres: &OwnedPostgres) {
    let event = checkout_event();
    let payload_hash = Sha256::digest(b"signed raw body");
    assert_eq!(
        storage::record_webhook(postgres, &event, &payload_hash)
            .await
            .unwrap(),
        WebhookRecordOutcome::Created
    );
    assert_eq!(
        storage::record_webhook(postgres, &event, &payload_hash)
            .await
            .unwrap(),
        WebhookRecordOutcome::Duplicate
    );
    assert!(
        storage::record_webhook(postgres, &event, &Sha256::digest(b"different body"))
            .await
            .is_err(),
        "one Stripe event id cannot be rebound to different bytes"
    );

    let (first, second) = tokio::join!(
        storage::claim_reconciliation(postgres, "worker-a", &[1; 32], 30),
        storage::claim_reconciliation(postgres, "worker-b", &[2; 32], 30)
    );
    let claims = [first.unwrap(), second.unwrap()];
    assert_eq!(claims.iter().filter(|claim| claim.is_some()).count(), 1);
    let claim = claims.into_iter().flatten().next().unwrap();
    assert!(
        storage::retry_reconciliation(postgres, &claim, "retry-test")
            .await
            .unwrap()
    );
    let claim = storage::claim_reconciliation(postgres, "worker-a", &[3; 32], 30)
        .await
        .unwrap()
        .unwrap();
    let revision = storage::converge_reconciliation(
        postgres,
        &claim,
        &CanonicalState {
            subscription_id: "sub_1",
            customer_id: "cus_1",
            price_alias: Some("pro"),
            status: "active",
            cancel_at_period_end: false,
            current_period_end: Some(OffsetDateTime::now_utc()),
            entitlement_state: "granted",
        },
    )
    .await
    .unwrap()
    .unwrap();
    assert!(revision > 0);
    let subject = storage::load_subject(postgres, "organization", "org_1", "org_1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(subject.subscription_status, "active");
    assert_eq!(subject.subscription_id.as_deref(), Some("sub_1"));
}

async fn assert_restart_and_cleanup(
    database_url: String,
    schema_name: String,
    postgres: OwnedPostgres,
) {
    postgres.pool().close().await;
    let restarted = OwnedPostgres::prepare(
        &database_url,
        schema::schema_plan(schema_name.clone()).unwrap(),
    )
    .await
    .unwrap();
    let subjects_after_restart: i64 =
        sqlx::query_scalar("SELECT count(*) FROM stripe_billing_subjects")
            .fetch_one(restarted.pool())
            .await
            .unwrap();
    assert_eq!(subjects_after_restart, 2);
    restarted.pool().close().await;

    let cleanup = sqlx::PgPool::connect(&database_url).await.unwrap();
    cleanup
        .execute(AssertSqlSafe(format!(
            "DROP SCHEMA \"{schema_name}\" CASCADE"
        )))
        .await
        .unwrap();
    cleanup.close().await;
}

#[tokio::test]
async fn schema_restart_and_effect_constraints_are_postgres_durable() {
    let Some((database_url, schema_name, postgres)) = prepare_postgres().await else {
        return;
    };
    seed_subjects_and_reject_invalid_receipts(&postgres).await;
    assert_effect_idempotency_and_uncertainty(&postgres).await;
    assert_webhook_deduplication_and_reconciliation(&postgres).await;
    assert_restart_and_cleanup(database_url, schema_name, postgres).await;
}
