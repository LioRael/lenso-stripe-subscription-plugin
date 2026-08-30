//! Durable Stripe subscription and usage-meter behavior for Lenso applications.

mod config;
mod meter;
mod operator;
#[cfg(all(test, feature = "postgres-acceptance"))]
mod postgres_tests;
mod schema;
mod service;
mod storage;
mod webhook;

use std::{cell::RefCell, fmt, rc::Rc, time::Duration as StdDuration};

use lenso::{ActivateContext, DeactivateContext, Lifecycle, Port, provides};
use lenso_capability_billing_meter_sink as meter_sink;
use lenso_capability_billing_meter_sink::PublishMeterEventRequest;
use lenso_capability_entitlements_admin as entitlements_admin;
use lenso_capability_http_client as http_client;
use lenso_capability_secrets as secrets;
use lenso_capability_secrets::{ResolveRequest, SecretsInvocationError};
use lenso_capability_stripe_subscription as public;
use lenso_capability_stripe_subscription::{
    CreateCheckoutSessionRequest, CreatePortalSessionRequest, GetSubscriptionRequest,
    StripeSubscriptionCreateCheckoutSession, StripeSubscriptionCreatePortalSession,
    StripeSubscriptionGetSubscription,
};
use lenso_capability_stripe_subscription_admin as admin;
use lenso_capability_stripe_subscription_admin::{
    IngestWebhookRequest, InspectEffectRequest, ReconcileNextRequest, ResolveUnknownEffectRequest,
    StripeSubscriptionAdminIngestWebhook, StripeSubscriptionAdminInspectEffect,
    StripeSubscriptionAdminReconcileNext, StripeSubscriptionAdminResolveUnknownEffect,
};
use lenso_kernel::{InvocationContext, NativeRequestFuture, RuntimeFailure};
use lenso_postgres_kit::OwnedPostgres;
use url::Url;
use zeroize::Zeroizing;

pub use config::{EntitlementMapping, MeterMapping, PriceMapping, StripeSubscriptionConfig};
pub use operator::{StripeSubscriptionOperator, StripeSubscriptionOperatorError};
use service::{
    AdminFlowError, CheckoutFlowError, PortalFlowError, ReceiptCipher, SubscriptionFlowError,
};

pub(crate) const STRIPE_API_VERSION: &str = "2026-02-25.clover";
const DEPENDENCY_TIMEOUT: StdDuration = StdDuration::from_secs(10);

fn validate_config(config: &StripeSubscriptionConfig) -> Result<(), RuntimeFailure> {
    config
        .validate()
        .map_err(|detail| RuntimeFailure::InvalidResolvedPlan {
            detail: format!("Stripe Subscription configuration is invalid: {detail}"),
        })
}

#[derive(Clone)]
pub(crate) struct PreparedStripe {
    postgres: OwnedPostgres,
    api_base: Url,
    api_key: Zeroizing<String>,
    webhook_signing_secret: Zeroizing<Vec<u8>>,
    receipt_cipher: ReceiptCipher,
}

impl fmt::Debug for PreparedStripe {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedStripe")
            .field("schema", &self.postgres.schema())
            .field("api_origin", &self.api_base.origin().ascii_serialization())
            .field("api_key", &"<redacted>")
            .field("webhook_signing_secret", &"<redacted>")
            .field("receipt_cipher", &self.receipt_cipher)
            .finish()
    }
}

#[lenso::plugin(
    lifecycle,
    configuration_schema = "configuration.schema.json",
    validate = validate_config
)]
#[derive(Clone)]
pub(crate) struct StripeSubscriptionPlugin {
    #[config]
    config: StripeSubscriptionConfig,
    secrets: Port<secrets::SecretsClient>,
    http: Port<http_client::ClientClient>,
    entitlements: Port<entitlements_admin::EntitlementsAdminClient>,
    prepared: Rc<RefCell<Option<PreparedStripe>>>,
}

impl fmt::Debug for StripeSubscriptionPlugin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StripeSubscriptionPlugin")
            .field("config", &self.config)
            .field("prepared", &self.prepared.borrow().is_some())
            .finish_non_exhaustive()
    }
}

#[provides(
    public::StripeSubscription,
    admin::StripeSubscriptionAdmin,
    meter_sink::BillingMeterSink
)]
impl StripeSubscriptionPlugin {}

impl StripeSubscriptionPlugin {
    fn publish_meter_event(
        &self,
        context: InvocationContext,
        request: PublishMeterEventRequest,
    ) -> NativeRequestFuture<meter_sink::BillingMeterSink> {
        let plugin = self.clone();
        Box::pin(async move {
            match plugin.publish_meter(context, request).await {
                Ok(response) => Ok(Ok(response)),
                Err(meter::MeterFlowError::Domain(error)) => Ok(Err(error)),
                Err(meter::MeterFlowError::Runtime(error)) => Err(error),
            }
        })
    }

    fn create_checkout_session(
        &self,
        context: InvocationContext,
        request: CreateCheckoutSessionRequest,
    ) -> NativeRequestFuture<StripeSubscriptionCreateCheckoutSession> {
        let plugin = self.clone();
        Box::pin(async move {
            match plugin.create_checkout(context, request).await {
                Ok(response) => Ok(Ok(response)),
                Err(CheckoutFlowError::Domain(error)) => Ok(Err(error)),
                Err(CheckoutFlowError::Runtime(error)) => Err(error),
            }
        })
    }

    fn create_portal_session(
        &self,
        context: InvocationContext,
        request: CreatePortalSessionRequest,
    ) -> NativeRequestFuture<StripeSubscriptionCreatePortalSession> {
        let plugin = self.clone();
        Box::pin(async move {
            match plugin.create_portal(context, request).await {
                Ok(response) => Ok(Ok(response)),
                Err(PortalFlowError::Domain(error)) => Ok(Err(error)),
                Err(PortalFlowError::Runtime(error)) => Err(error),
            }
        })
    }

    fn get_subscription(
        &self,
        context: InvocationContext,
        request: GetSubscriptionRequest,
    ) -> NativeRequestFuture<StripeSubscriptionGetSubscription> {
        let plugin = self.clone();
        Box::pin(async move {
            match plugin.get_subscription_record(context, request).await {
                Ok(response) => Ok(Ok(response)),
                Err(SubscriptionFlowError::Domain(error)) => Ok(Err(error)),
                Err(SubscriptionFlowError::Runtime(error)) => Err(error),
            }
        })
    }

    fn ingest_webhook(
        &self,
        context: InvocationContext,
        request: IngestWebhookRequest,
    ) -> NativeRequestFuture<StripeSubscriptionAdminIngestWebhook> {
        let plugin = self.clone();
        Box::pin(async move {
            match plugin.ingest(context, request).await {
                Ok(response) => Ok(Ok(response)),
                Err(AdminFlowError::Webhook(error)) => Ok(Err(error)),
                Err(AdminFlowError::Runtime(error)) => Err(error),
                Err(
                    AdminFlowError::Inspect(_)
                    | AdminFlowError::Reconcile(_)
                    | AdminFlowError::Resolve(_),
                ) => Err(service::failure("unexpected Stripe admin flow error")),
            }
        })
    }

    fn inspect_effect(
        &self,
        context: InvocationContext,
        request: InspectEffectRequest,
    ) -> NativeRequestFuture<StripeSubscriptionAdminInspectEffect> {
        let plugin = self.clone();
        Box::pin(async move {
            match plugin.inspect(context, request).await {
                Ok(response) => Ok(Ok(response)),
                Err(AdminFlowError::Inspect(error)) => Ok(Err(error)),
                Err(AdminFlowError::Runtime(error)) => Err(error),
                Err(
                    AdminFlowError::Webhook(_)
                    | AdminFlowError::Reconcile(_)
                    | AdminFlowError::Resolve(_),
                ) => Err(service::failure("unexpected Stripe admin flow error")),
            }
        })
    }

    fn reconcile_next(
        &self,
        context: InvocationContext,
        _request: ReconcileNextRequest,
    ) -> NativeRequestFuture<StripeSubscriptionAdminReconcileNext> {
        let plugin = self.clone();
        Box::pin(async move {
            match plugin.reconcile(context).await {
                Ok(response) => Ok(Ok(response)),
                Err(AdminFlowError::Reconcile(error)) => Ok(Err(error)),
                Err(AdminFlowError::Runtime(error)) => Err(error),
                Err(
                    AdminFlowError::Webhook(_)
                    | AdminFlowError::Inspect(_)
                    | AdminFlowError::Resolve(_),
                ) => Err(service::failure("unexpected Stripe admin flow error")),
            }
        })
    }

    fn resolve_unknown_effect(
        &self,
        context: InvocationContext,
        request: ResolveUnknownEffectRequest,
    ) -> NativeRequestFuture<StripeSubscriptionAdminResolveUnknownEffect> {
        let plugin = self.clone();
        Box::pin(async move {
            match plugin.resolve(context, request).await {
                Ok(response) => Ok(Ok(response)),
                Err(AdminFlowError::Resolve(error)) => Ok(Err(error)),
                Err(AdminFlowError::Runtime(error)) => Err(error),
                Err(
                    AdminFlowError::Webhook(_)
                    | AdminFlowError::Inspect(_)
                    | AdminFlowError::Reconcile(_),
                ) => Err(service::failure("unexpected Stripe admin flow error")),
            }
        })
    }

    pub(crate) fn prepared(&self) -> Result<PreparedStripe, RuntimeFailure> {
        self.prepared
            .borrow()
            .clone()
            .ok_or_else(|| service::failure("Stripe Subscription Plugin is not active"))
    }
}

impl Lifecycle for StripeSubscriptionPlugin {
    async fn activate(&self, context: ActivateContext) -> Result<(), RuntimeFailure> {
        let dependencies = context.dependencies().clone();
        let cancellation = context.cancellation();
        let database_url = resolve_secret(
            &self.secrets,
            &dependencies,
            cancellation.clone(),
            self.config.database_url_secret(),
        )
        .await?;
        let api_key = resolve_secret(
            &self.secrets,
            &dependencies,
            cancellation.clone(),
            self.config.stripe_api_key_secret(),
        )
        .await?;
        let webhook_secret = resolve_secret(
            &self.secrets,
            &dependencies,
            cancellation.clone(),
            self.config.webhook_signing_secret(),
        )
        .await?;
        let receipt_secret = resolve_secret(
            &self.secrets,
            &dependencies,
            cancellation,
            self.config.receipt_encryption_secret(),
        )
        .await?;
        if !api_key.starts_with("sk_") || api_key.len() < 16 {
            return Err(service::failure("Stripe API key has an invalid shape"));
        }
        if !webhook_secret.starts_with("whsec_") || webhook_secret.len() < 16 {
            return Err(service::failure(
                "Stripe webhook signing secret has an invalid shape",
            ));
        }
        if receipt_secret.len() < 32 {
            return Err(service::failure(
                "Stripe receipt encryption secret must contain at least 32 bytes",
            ));
        }
        let postgres = OwnedPostgres::prepare(
            &database_url,
            schema::schema_plan(self.config.schema().to_owned()).map_err(|error| {
                RuntimeFailure::InvalidResolvedPlan {
                    detail: format!("Stripe Subscription schema plan is invalid: {error}"),
                }
            })?,
        )
        .await
        .map_err(|error| service::failure(format!("Stripe storage is unavailable: {error}")))?;
        storage::recover_stranded_effects(&postgres, self.config.effect_uncertainty_seconds())
            .await
            .map_err(|error| service::failure(error.to_string()))?;
        storage::recover_stranded_meter_effects(
            &postgres,
            self.config.effect_uncertainty_seconds(),
        )
        .await
        .map_err(|error| service::failure(error.to_string()))?;
        self.prepared.borrow_mut().replace(PreparedStripe {
            postgres,
            api_base: self.config.api_base(),
            api_key,
            webhook_signing_secret: Zeroizing::new(webhook_secret.as_bytes().to_vec()),
            receipt_cipher: ReceiptCipher::derive(receipt_secret.as_bytes()),
        });
        Ok(())
    }

    async fn deactivate(&self, _context: DeactivateContext) -> Result<(), RuntimeFailure> {
        let prepared = self.prepared.borrow_mut().take();
        if let Some(prepared) = prepared {
            prepared.postgres.pool().close().await;
        }
        Ok(())
    }
}

async fn resolve_secret(
    secrets: &secrets::SecretsClient,
    dependencies: &lenso_kernel::PluginDependencies,
    cancellation: lenso_kernel::CancellationToken,
    reference: &str,
) -> Result<Zeroizing<String>, RuntimeFailure> {
    let context = dependencies.invocation_context_after(DEPENDENCY_TIMEOUT, cancellation)?;
    secrets
        .resolve_with_context(
            context,
            ResolveRequest {
                reference: reference.to_owned(),
            },
        )
        .await
        .map(|response| Zeroizing::new(response.value))
        .map_err(|error| match error {
            SecretsInvocationError::Domain(_) => service::failure(format!(
                "required Stripe Subscription secret `{reference}` was rejected"
            )),
            SecretsInvocationError::Runtime(error) => error,
        })
}

#[cfg(test)]
mod tests {
    use super::PLUGIN_DESCRIPTOR_JSON;

    #[test]
    fn descriptor_exposes_the_provider_neutral_meter_sink() {
        let descriptor: serde_json::Value = serde_json::from_str(PLUGIN_DESCRIPTOR_JSON).unwrap();
        let provided = descriptor["provided_capabilities"].as_array().unwrap();
        assert!(provided.iter().any(|capability| {
            capability["capability_id"] == "lenso.billing-meter-sink@1"
                && capability["descriptor_version"] == "1.0.0"
        }));
    }
}
