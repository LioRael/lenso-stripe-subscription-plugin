use lenso_postgres_kit::OwnedPostgres;
use sqlx::{AssertSqlSafe, Executor as _};
use uuid::Uuid;

use crate::{StripeSubscriptionOperator, schema};

#[tokio::test]
async fn schema_restart_and_effect_constraints_are_postgres_durable() {
    let Ok(database_url) = std::env::var("LENSO_STRIPE_SUBSCRIPTION_TEST_DATABASE_URL") else {
        return;
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
