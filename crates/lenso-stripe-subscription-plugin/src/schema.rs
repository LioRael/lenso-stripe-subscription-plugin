use lenso_postgres_kit::{Migration, PlanError, SchemaPlan, sql_migrations};

const MIGRATIONS: &[Migration] = sql_migrations![
    (
        1,
        "create-stripe-subscription",
        "migrations/001_create_stripe_subscription.sql",
    ),
    (
        2,
        "create-stripe-meter-effects",
        "migrations/002_create_stripe_meter_effects.sql",
    ),
];

pub(crate) fn schema_plan(schema: impl Into<std::sync::Arc<str>>) -> Result<SchemaPlan, PlanError> {
    SchemaPlan::new(schema, MIGRATIONS)
}
