use std::collections::BTreeSet;

use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use lenso_capability_entitlements_admin::{
    EntitlementsAdminPutGrantInvocationError, EntitlementsAdminRevokeGrantInvocationError,
    PutGrantRequest, RevokeGrantError, RevokeGrantRequest,
};
use lenso_capability_http_client::{
    ClientInvocationError, SendRequest, SendRequestHeadersItem, SendResponse,
};
use lenso_capability_stripe_subscription::{
    CreateCheckoutSessionError, CreateCheckoutSessionRequest, CreateCheckoutSessionResponse,
    CreateCheckoutSessionResponseStatus, CreatePortalSessionError, CreatePortalSessionRequest,
    CreatePortalSessionResponse, CreatePortalSessionResponseStatus, GetSubscriptionError,
    GetSubscriptionRequest, GetSubscriptionResponse, GetSubscriptionResponseEntitlementState,
    GetSubscriptionResponseStatus,
};
use lenso_capability_stripe_subscription_admin::{
    IngestWebhookError, IngestWebhookRequest, IngestWebhookResponse, IngestWebhookResponseOutcome,
    InspectEffectError, InspectEffectRequest, InspectEffectResponse,
    InspectEffectResponseOperation, InspectEffectResponseStatus, ReconcileNextError,
    ReconcileNextResponse, ReconcileNextResponseStatus, ResolveUnknownEffectError,
    ResolveUnknownEffectRequest, ResolveUnknownEffectRequestResolution,
    ResolveUnknownEffectResponse, ResolveUnknownEffectResponseStatus,
};
use lenso_kernel::{InvocationContext, RuntimeFailure};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use url::Url;
use zeroize::Zeroizing;

use crate::{
    PreparedStripe, STRIPE_API_VERSION, StripeSubscriptionPlugin,
    config::{valid_name, valid_stripe_id},
    storage::{
        self, BillingSubject, CanonicalState, EffectClaim, EffectOperation, EffectRecord,
        EffectStatus, ManualResolution, NewEffect, ReconciliationClaim, StoreError,
        WebhookRecordOutcome,
    },
    webhook::{WebhookError, verify_and_parse},
};

const MAX_IDEMPOTENCY_BYTES: usize = 255;
const MAX_STRIPE_RESPONSE_BYTES: usize = 1_048_576;

struct EntitlementConvergence<'a> {
    prepared: &'a PreparedStripe,
    claim: &'a ReconciliationClaim,
    subject: &'a BillingSubject,
    bindings: &'a [storage::EntitlementBinding],
    price: Option<&'a crate::PriceMapping>,
    grant_enabled: bool,
    expires_at: Option<OffsetDateTime>,
}

#[derive(Debug)]
pub(crate) enum CheckoutFlowError {
    Domain(CreateCheckoutSessionError),
    Runtime(RuntimeFailure),
}

#[derive(Debug)]
pub(crate) enum PortalFlowError {
    Domain(CreatePortalSessionError),
    Runtime(RuntimeFailure),
}

#[derive(Debug)]
pub(crate) enum SubscriptionFlowError {
    Domain(GetSubscriptionError),
    Runtime(RuntimeFailure),
}

#[derive(Debug)]
pub(crate) enum AdminFlowError {
    Webhook(IngestWebhookError),
    Inspect(InspectEffectError),
    Reconcile(ReconcileNextError),
    Resolve(ResolveUnknownEffectError),
    Runtime(RuntimeFailure),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct EffectReceipt {
    url: String,
    expires_at: Option<String>,
}

#[derive(Clone)]
pub(crate) struct ReceiptCipher(Zeroizing<[u8; 32]>);

impl ReceiptCipher {
    pub(crate) fn derive(secret: &[u8]) -> Self {
        let digest = Sha256::digest(secret);
        let mut key = [0_u8; 32];
        key.copy_from_slice(&digest);
        Self(Zeroizing::new(key))
    }

    fn encrypt<T: Serialize>(
        &self,
        value: &T,
        aad: &[u8],
    ) -> Result<([u8; 12], Vec<u8>), RuntimeFailure> {
        let bytes = serde_json::to_vec(value).map_err(|error| failure(error.to_string()))?;
        let mut nonce = [0_u8; 12];
        getrandom::fill(&mut nonce).map_err(|error| failure(error.to_string()))?;
        let cipher = Aes256Gcm::new_from_slice(self.0.as_ref())
            .map_err(|_| failure("invalid Stripe receipt encryption key"))?;
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: &bytes, aad })
            .map_err(|_| failure("Stripe receipt encryption failed"))?;
        Ok((nonce, ciphertext))
    }

    fn decrypt<T: DeserializeOwned>(
        &self,
        nonce: &[u8],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<T, RuntimeFailure> {
        let nonce: [u8; 12] = nonce
            .try_into()
            .map_err(|_| failure("Stripe receipt nonce is invalid"))?;
        let cipher = Aes256Gcm::new_from_slice(self.0.as_ref())
            .map_err(|_| failure("invalid Stripe receipt encryption key"))?;
        let bytes = cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| failure("Stripe receipt decryption failed"))?;
        serde_json::from_slice(&bytes).map_err(|error| failure(error.to_string()))
    }
}

impl std::fmt::Debug for ReceiptCipher {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ReceiptCipher(<redacted>)")
    }
}

impl StripeSubscriptionPlugin {
    pub(crate) async fn create_checkout(
        &self,
        context: InvocationContext,
        request: CreateCheckoutSessionRequest,
    ) -> Result<CreateCheckoutSessionResponse, CheckoutFlowError> {
        if !self.config.product_allowed(context.caller_instance()) {
            return Err(CheckoutFlowError::Domain(
                CreateCheckoutSessionError::Forbidden,
            ));
        }
        if !valid_subject_request(&request.scope_kind, &request.scope_id, &request.subject)
            || !valid_idempotency_key(&request.idempotency_key)
            || !self.config.redirect_allowed(&request.success_url)
            || !self.config.redirect_allowed(&request.cancel_url)
        {
            return Err(CheckoutFlowError::Domain(
                CreateCheckoutSessionError::InvalidRequest,
            ));
        }
        let Some(price) = self.config.price(&request.price_alias).cloned() else {
            return Err(CheckoutFlowError::Domain(
                CreateCheckoutSessionError::PriceNotFound,
            ));
        };
        let prepared = self.prepared().map_err(CheckoutFlowError::Runtime)?;
        let caller = context.caller_instance().unwrap_or_default().to_owned();
        let request_hash = request_hash(&request).map_err(CheckoutFlowError::Runtime)?;
        let effect_id =
            stable_effect_id(&caller, EffectOperation::Checkout, &request.idempotency_key);
        let claim = storage::claim_effect(
            &prepared.postgres,
            &NewEffect {
                effect_id: effect_id.clone(),
                caller_instance: caller,
                operation: EffectOperation::Checkout,
                idempotency_key: request.idempotency_key.clone(),
                request_hash,
                scope_kind: request.scope_kind.clone(),
                scope_id: request.scope_id.clone(),
                subject: request.subject.clone(),
                price_alias: Some(request.price_alias.clone()),
            },
            self.config.effect_uncertainty_seconds(),
        )
        .await
        .map_err(|error| store_runtime(&error))?;
        match claim {
            EffectClaim::Conflict => Err(CheckoutFlowError::Domain(
                CreateCheckoutSessionError::IdempotencyConflict,
            )),
            EffectClaim::Existing(record) => checkout_existing(&prepared, record),
            EffectClaim::Dispatch(record) => {
                if storage::load_subject(
                    &prepared.postgres,
                    &request.scope_kind,
                    &request.scope_id,
                    &request.subject,
                )
                .await
                .map_err(|error| store_runtime(&error))?
                .is_some_and(|subject| {
                    matches!(subject.subscription_status.as_str(), "trialing" | "active")
                }) {
                    storage::fail_effect(
                        &prepared.postgres,
                        &record.effect_id,
                        "already_subscribed",
                    )
                    .await
                    .map_err(|error| store_runtime(&error))?;
                    return Err(CheckoutFlowError::Domain(
                        CreateCheckoutSessionError::AlreadySubscribed,
                    ));
                }
                let body = checkout_form(&request, &price.price_id);
                let response = self
                    .stripe_post(
                        context,
                        &prepared,
                        "v1/checkout/sessions",
                        body,
                        &record.effect_id,
                    )
                    .await;
                finish_checkout(&prepared, &record, response).await
            }
        }
    }

    pub(crate) async fn create_portal(
        &self,
        context: InvocationContext,
        request: CreatePortalSessionRequest,
    ) -> Result<CreatePortalSessionResponse, PortalFlowError> {
        if !self.config.product_allowed(context.caller_instance()) {
            return Err(PortalFlowError::Domain(CreatePortalSessionError::Forbidden));
        }
        if !valid_subject_request(&request.scope_kind, &request.scope_id, &request.subject)
            || !valid_idempotency_key(&request.idempotency_key)
            || !self.config.redirect_allowed(&request.return_url)
        {
            return Err(PortalFlowError::Domain(
                CreatePortalSessionError::InvalidRequest,
            ));
        }
        let prepared = self.prepared().map_err(PortalFlowError::Runtime)?;
        let Some(subject) = storage::load_subject(
            &prepared.postgres,
            &request.scope_kind,
            &request.scope_id,
            &request.subject,
        )
        .await
        .map_err(|error| store_runtime(&error))?
        else {
            return Err(PortalFlowError::Domain(
                CreatePortalSessionError::CustomerNotFound,
            ));
        };
        let caller = context.caller_instance().unwrap_or_default().to_owned();
        let request_hash = request_hash(&request).map_err(PortalFlowError::Runtime)?;
        let effect_id =
            stable_effect_id(&caller, EffectOperation::Portal, &request.idempotency_key);
        let claim = storage::claim_effect(
            &prepared.postgres,
            &NewEffect {
                effect_id: effect_id.clone(),
                caller_instance: caller,
                operation: EffectOperation::Portal,
                idempotency_key: request.idempotency_key.clone(),
                request_hash,
                scope_kind: request.scope_kind.clone(),
                scope_id: request.scope_id.clone(),
                subject: request.subject.clone(),
                price_alias: None,
            },
            self.config.effect_uncertainty_seconds(),
        )
        .await
        .map_err(|error| store_runtime(&error))?;
        match claim {
            EffectClaim::Conflict => Err(PortalFlowError::Domain(
                CreatePortalSessionError::IdempotencyConflict,
            )),
            EffectClaim::Existing(record) => portal_existing(&prepared, record),
            EffectClaim::Dispatch(record) => {
                let body = portal_form(&subject.customer_id, &request.return_url);
                let response = self
                    .stripe_post(
                        context,
                        &prepared,
                        "v1/billing_portal/sessions",
                        body,
                        &record.effect_id,
                    )
                    .await;
                finish_portal(&prepared, &record, response).await
            }
        }
    }

    pub(crate) async fn get_subscription_record(
        &self,
        context: InvocationContext,
        request: GetSubscriptionRequest,
    ) -> Result<GetSubscriptionResponse, SubscriptionFlowError> {
        if !self.config.product_allowed(context.caller_instance()) {
            return Err(SubscriptionFlowError::Domain(
                GetSubscriptionError::Forbidden,
            ));
        }
        if !valid_subject_request(&request.scope_kind, &request.scope_id, &request.subject) {
            return Err(SubscriptionFlowError::Domain(
                GetSubscriptionError::InvalidRequest,
            ));
        }
        let prepared = self.prepared().map_err(SubscriptionFlowError::Runtime)?;
        let subject = storage::load_subject(
            &prepared.postgres,
            &request.scope_kind,
            &request.scope_id,
            &request.subject,
        )
        .await
        .map_err(|error| store_runtime(&error))?
        .ok_or(SubscriptionFlowError::Domain(
            GetSubscriptionError::NotFound,
        ))?;
        subscription_response(subject).map_err(SubscriptionFlowError::Runtime)
    }

    pub(crate) async fn ingest(
        &self,
        context: InvocationContext,
        request: IngestWebhookRequest,
    ) -> Result<IngestWebhookResponse, AdminFlowError> {
        if !self.config.webhook_allowed(context.caller_instance()) {
            return Err(AdminFlowError::Webhook(IngestWebhookError::Forbidden));
        }
        let prepared = self.prepared().map_err(AdminFlowError::Runtime)?;
        let event = verify_and_parse(
            &prepared.webhook_signing_secret,
            &request.raw_body,
            &request.signature_header,
            OffsetDateTime::now_utc(),
            self.config.signature_tolerance_seconds(),
            self.config.max_webhook_body_bytes(),
            self.config.livemode(),
        )
        .map_err(|error| AdminFlowError::Webhook(webhook_domain(error)))?;
        if let Some(target) = &event.target
            && (!valid_stripe_id(&target.subscription_id, "sub_")
                || !valid_stripe_id(&target.customer_id, "cus_")
                || target.checkout_subject.as_ref().is_some_and(|subject| {
                    !valid_subject_request(&subject.scope_kind, &subject.scope_id, &subject.subject)
                        || self.config.price(&subject.price_alias).is_none()
                }))
        {
            return Err(AdminFlowError::Webhook(IngestWebhookError::InvalidEvent));
        }
        let payload_hash = Sha256::digest(request.raw_body.as_bytes());
        let outcome = storage::record_webhook(&prepared.postgres, &event, &payload_hash)
            .await
            .map_err(|error| AdminFlowError::Runtime(store_failure(&error)))?;
        Ok(IngestWebhookResponse {
            event_id: event.event_id,
            event_type: event.event_type,
            outcome: match (outcome, event.target.is_some()) {
                (WebhookRecordOutcome::Duplicate, _) => IngestWebhookResponseOutcome::Duplicate,
                (WebhookRecordOutcome::Created, true) => IngestWebhookResponseOutcome::Accepted,
                (WebhookRecordOutcome::Created, false) => IngestWebhookResponseOutcome::Ignored,
            },
            reconciliation_enqueued: outcome == WebhookRecordOutcome::Created
                && event.target.is_some(),
        })
    }

    pub(crate) async fn inspect(
        &self,
        context: InvocationContext,
        request: InspectEffectRequest,
    ) -> Result<InspectEffectResponse, AdminFlowError> {
        if !self.config.operator_allowed(context.caller_instance()) {
            return Err(AdminFlowError::Inspect(InspectEffectError::Forbidden));
        }
        if !valid_effect_id(&request.effect_id) {
            return Err(AdminFlowError::Inspect(InspectEffectError::InvalidEffect));
        }
        let prepared = self.prepared().map_err(AdminFlowError::Runtime)?;
        let record = storage::load_effect(&prepared.postgres, &request.effect_id)
            .await
            .map_err(|error| AdminFlowError::Runtime(store_failure(&error)))?
            .ok_or(AdminFlowError::Inspect(InspectEffectError::NotFound))?;
        inspect_response(&prepared, &record).map_err(AdminFlowError::Runtime)
    }

    pub(crate) async fn resolve(
        &self,
        context: InvocationContext,
        request: ResolveUnknownEffectRequest,
    ) -> Result<ResolveUnknownEffectResponse, AdminFlowError> {
        if !self.config.operator_allowed(context.caller_instance()) {
            return Err(AdminFlowError::Resolve(
                ResolveUnknownEffectError::Forbidden,
            ));
        }
        if !valid_effect_id(&request.effect_id) {
            return Err(AdminFlowError::Resolve(
                ResolveUnknownEffectError::InvalidResolution,
            ));
        }
        let prepared = self.prepared().map_err(AdminFlowError::Runtime)?;
        let record = storage::load_effect(&prepared.postgres, &request.effect_id)
            .await
            .map_err(|error| AdminFlowError::Runtime(store_failure(&error)))?
            .ok_or(AdminFlowError::Resolve(ResolveUnknownEffectError::NotFound))?;
        let (target_status, object_id, encrypted, failure_code, response_status) =
            validate_resolution(&prepared, &record, &request).map_err(AdminFlowError::Resolve)?;
        if record.status == target_status {
            if !resolution_matches(&prepared, &record, &request).map_err(AdminFlowError::Resolve)? {
                return Err(AdminFlowError::Resolve(
                    ResolveUnknownEffectError::InvalidResolution,
                ));
            }
            return Ok(ResolveUnknownEffectResponse {
                changed: false,
                effect_id: request.effect_id,
                status: response_status,
            });
        }
        if record.status != EffectStatus::EffectUnknown {
            return Err(AdminFlowError::Resolve(
                ResolveUnknownEffectError::NotUnknown,
            ));
        }
        let (nonce, ciphertext) = encrypted.unzip();
        let changed = storage::resolve_effect(
            &prepared.postgres,
            &ManualResolution {
                effect_id: &request.effect_id,
                target_status,
                stripe_object_id: object_id.as_deref(),
                nonce: nonce.as_ref().map(<[u8; 12]>::as_slice),
                ciphertext: ciphertext.as_deref(),
                failure_code: failure_code.as_deref(),
            },
        )
        .await
        .map_err(|error| AdminFlowError::Runtime(store_failure(&error)))?;
        if !changed {
            return Err(AdminFlowError::Resolve(
                ResolveUnknownEffectError::NotUnknown,
            ));
        }
        Ok(ResolveUnknownEffectResponse {
            changed: true,
            effect_id: request.effect_id,
            status: response_status,
        })
    }

    pub(crate) async fn reconcile(
        &self,
        context: InvocationContext,
    ) -> Result<ReconcileNextResponse, AdminFlowError> {
        let Some(worker) = context.caller_instance().map(ToOwned::to_owned) else {
            return Err(AdminFlowError::Reconcile(ReconcileNextError::Forbidden));
        };
        if !self.config.worker_allowed(Some(&worker)) {
            return Err(AdminFlowError::Reconcile(ReconcileNextError::Forbidden));
        }
        let prepared = self.prepared().map_err(AdminFlowError::Runtime)?;
        let mut lease_token = [0_u8; 32];
        getrandom::fill(&mut lease_token)
            .map_err(|error| AdminFlowError::Runtime(failure(error.to_string())))?;
        let lease_hash = Sha256::digest(lease_token);
        let Some(claim) = storage::claim_reconciliation(
            &prepared.postgres,
            &worker,
            &lease_hash,
            self.config.reconciliation_lease_seconds(),
        )
        .await
        .map_err(|error| AdminFlowError::Runtime(store_failure(&error)))?
        else {
            return Ok(ReconcileNextResponse {
                revision: None,
                status: ReconcileNextResponseStatus::Idle,
                subscription_id: None,
            });
        };
        self.finish_reconciliation(context, prepared, claim).await
    }

    async fn finish_reconciliation(
        &self,
        context: InvocationContext,
        prepared: PreparedStripe,
        claim: ReconciliationClaim,
    ) -> Result<ReconcileNextResponse, AdminFlowError> {
        let canonical = match self
            .fetch_subscription(context.clone(), &prepared, &claim.subscription_id)
            .await
        {
            Ok(value) => value,
            Err(code) => return self.retry_result(&prepared, &claim, code).await,
        };
        if canonical.customer_id != claim.customer_id {
            return self
                .retry_result(&prepared, &claim, "stripe_customer_mismatch")
                .await;
        }
        let Some(subject) = storage::load_subject_for_reconciliation(
            &prepared.postgres,
            &claim.subscription_id,
            &claim.customer_id,
        )
        .await
        .map_err(|error| AdminFlowError::Runtime(store_failure(&error)))?
        else {
            return self
                .retry_result(&prepared, &claim, "billing_subject_not_linked")
                .await;
        };
        let mapped_price = self.config.price_by_id(&canonical.price_id).cloned();
        let grant_enabled =
            matches!(canonical.status.as_str(), "trialing" | "active") && mapped_price.is_some();
        let bindings = storage::load_bindings(&prepared.postgres, &claim.subscription_id)
            .await
            .map_err(|error| AdminFlowError::Runtime(store_failure(&error)))?;
        if let Err(code) = self
            .converge_entitlements(
                context,
                EntitlementConvergence {
                    prepared: &prepared,
                    claim: &claim,
                    subject: &subject,
                    bindings: &bindings,
                    price: mapped_price.as_ref(),
                    grant_enabled,
                    expires_at: canonical.current_period_end,
                },
            )
            .await
        {
            return self.retry_result(&prepared, &claim, code).await;
        }
        let entitlement_state = if mapped_price.is_none() {
            "failed"
        } else if grant_enabled {
            "granted"
        } else {
            "revoked"
        };
        let revision = storage::converge_reconciliation(
            &prepared.postgres,
            &claim,
            &CanonicalState {
                subscription_id: &canonical.subscription_id,
                customer_id: &canonical.customer_id,
                price_alias: mapped_price.as_ref().map(|price| price.alias.as_str()),
                status: &canonical.status,
                cancel_at_period_end: canonical.cancel_at_period_end,
                current_period_end: canonical.current_period_end,
                entitlement_state,
            },
        )
        .await
        .map_err(|error| AdminFlowError::Runtime(store_failure(&error)))?;
        let Some(revision) = revision else {
            return Err(AdminFlowError::Reconcile(ReconcileNextError::InvalidState));
        };
        Ok(ReconcileNextResponse {
            revision: Some(revision),
            status: ReconcileNextResponseStatus::Converged,
            subscription_id: Some(claim.subscription_id),
        })
    }

    async fn stripe_post(
        &self,
        context: InvocationContext,
        prepared: &PreparedStripe,
        path: &str,
        body: String,
        idempotency_key: &str,
    ) -> Result<SendResponse, ClientInvocationError> {
        self.http
            .send_with_context(
                context,
                SendRequest {
                    body: body.into_bytes().into(),
                    headers: stripe_headers(&prepared.api_key, Some(idempotency_key), true),
                    method: "POST".to_owned(),
                    url: prepared
                        .api_base
                        .join(path)
                        .expect("validated Stripe API base")
                        .to_string(),
                },
            )
            .await
    }

    async fn fetch_subscription(
        &self,
        context: InvocationContext,
        prepared: &PreparedStripe,
        subscription_id: &str,
    ) -> Result<CanonicalSubscription, &'static str> {
        let path = format!("v1/subscriptions/{subscription_id}");
        let response = self
            .http
            .send_with_context(
                context,
                SendRequest {
                    body: Vec::new().into(),
                    headers: stripe_headers(&prepared.api_key, None, false),
                    method: "GET".to_owned(),
                    url: prepared
                        .api_base
                        .join(&path)
                        .expect("validated Stripe API base")
                        .to_string(),
                },
            )
            .await
            .map_err(|_| "stripe_fetch_failed")?;
        if !(200..300).contains(&response.status) {
            return Err("stripe_fetch_rejected");
        }
        parse_canonical_subscription(response.body.as_slice()).ok_or("stripe_subscription_invalid")
    }

    async fn converge_entitlements(
        &self,
        context: InvocationContext,
        convergence: EntitlementConvergence<'_>,
    ) -> Result<(), &'static str> {
        let EntitlementConvergence {
            prepared,
            claim,
            subject,
            bindings,
            price,
            grant_enabled,
            expires_at,
        } = convergence;
        let desired = price
            .filter(|_| grant_enabled)
            .map_or_else(BTreeSet::new, |price| {
                price
                    .entitlements
                    .iter()
                    .map(|entitlement| entitlement.feature.as_str())
                    .collect()
            });
        for binding in bindings {
            if !desired.contains(binding.feature.as_str()) {
                match self
                    .entitlements
                    .revoke_grant_with_context(
                        context.clone(),
                        RevokeGrantRequest {
                            grant_id: binding.grant_id.clone(),
                        },
                    )
                    .await
                {
                    Ok(_)
                    | Err(EntitlementsAdminRevokeGrantInvocationError::Domain(
                        RevokeGrantError::NotFound,
                    )) => {
                        storage::delete_binding(
                            &prepared.postgres,
                            &claim.subscription_id,
                            &binding.feature,
                        )
                        .await
                        .map_err(|_| "entitlement_binding_store_failed")?;
                    }
                    Err(EntitlementsAdminRevokeGrantInvocationError::Domain(_)) => {
                        return Err("entitlement_revoke_rejected");
                    }
                    Err(EntitlementsAdminRevokeGrantInvocationError::Runtime(_)) => {
                        return Err("entitlement_revoke_unavailable");
                    }
                }
            }
        }
        if let Some(price) = price.filter(|_| grant_enabled) {
            let expires_at = expires_at.and_then(|value| value.format(&Rfc3339).ok());
            for entitlement in &price.entitlements {
                let grant = self
                    .entitlements
                    .put_grant_with_context(
                        context.clone(),
                        PutGrantRequest {
                            expires_at: expires_at.clone(),
                            feature: entitlement.feature.clone(),
                            limit: entitlement.limit.clone(),
                            scope_id: subject.scope_id.clone(),
                            scope_kind: subject.scope_kind.clone(),
                            subject: subject.subject.clone(),
                        },
                    )
                    .await
                    .map_err(|error| match error {
                        EntitlementsAdminPutGrantInvocationError::Domain(_) => {
                            "entitlement_put_rejected"
                        }
                        EntitlementsAdminPutGrantInvocationError::Runtime(_) => {
                            "entitlement_put_unavailable"
                        }
                    })?;
                storage::put_binding(
                    &prepared.postgres,
                    &claim.subscription_id,
                    &entitlement.feature,
                    &grant.grant_id,
                    subject.revision.saturating_add(1),
                )
                .await
                .map_err(|_| "entitlement_binding_store_failed")?;
            }
        }
        Ok(())
    }

    async fn retry_result(
        &self,
        prepared: &PreparedStripe,
        claim: &ReconciliationClaim,
        failure_code: &'static str,
    ) -> Result<ReconcileNextResponse, AdminFlowError> {
        let released = storage::retry_reconciliation(&prepared.postgres, claim, failure_code)
            .await
            .map_err(|error| AdminFlowError::Runtime(store_failure(&error)))?;
        if !released {
            return Err(AdminFlowError::Reconcile(ReconcileNextError::InvalidState));
        }
        Ok(ReconcileNextResponse {
            revision: None,
            status: ReconcileNextResponseStatus::RetryPending,
            subscription_id: Some(claim.subscription_id.clone()),
        })
    }
}

fn checkout_existing(
    prepared: &PreparedStripe,
    record: EffectRecord,
) -> Result<CreateCheckoutSessionResponse, CheckoutFlowError> {
    match record.status {
        EffectStatus::Accepted => {
            let receipt = decrypt_receipt(prepared, &record).map_err(CheckoutFlowError::Runtime)?;
            Ok(CreateCheckoutSessionResponse {
                effect_id: record.effect_id,
                expires_at: receipt.expires_at,
                session_id: record.stripe_object_id,
                status: CreateCheckoutSessionResponseStatus::Accepted,
                url: Some(receipt.url),
            })
        }
        EffectStatus::KnownFailure => Err(CheckoutFlowError::Domain(checkout_failure(
            record.failure_code.as_deref(),
        ))),
        EffectStatus::Prepared | EffectStatus::InFlight | EffectStatus::EffectUnknown => {
            Ok(checkout_unknown(record.effect_id))
        }
    }
}

fn portal_existing(
    prepared: &PreparedStripe,
    record: EffectRecord,
) -> Result<CreatePortalSessionResponse, PortalFlowError> {
    match record.status {
        EffectStatus::Accepted => {
            let receipt = decrypt_receipt(prepared, &record).map_err(PortalFlowError::Runtime)?;
            Ok(CreatePortalSessionResponse {
                effect_id: record.effect_id,
                expires_at: receipt.expires_at,
                session_id: record.stripe_object_id,
                status: CreatePortalSessionResponseStatus::Accepted,
                url: Some(receipt.url),
            })
        }
        EffectStatus::KnownFailure => Err(PortalFlowError::Domain(portal_failure(
            record.failure_code.as_deref(),
        ))),
        EffectStatus::Prepared | EffectStatus::InFlight | EffectStatus::EffectUnknown => {
            Ok(portal_unknown(record.effect_id))
        }
    }
}

async fn finish_checkout(
    prepared: &PreparedStripe,
    record: &EffectRecord,
    response: Result<SendResponse, ClientInvocationError>,
) -> Result<CreateCheckoutSessionResponse, CheckoutFlowError> {
    let Some(response) = classify_http(response) else {
        mark_unknown(prepared, &record.effect_id).await;
        return Ok(checkout_unknown(record.effect_id.clone()));
    };
    match response {
        ClassifiedResponse::KnownFailure(code) => {
            storage::fail_effect(&prepared.postgres, &record.effect_id, code)
                .await
                .map_err(|error| store_runtime(&error))?;
            Err(CheckoutFlowError::Domain(checkout_failure(Some(code))))
        }
        ClassifiedResponse::Success(body) => {
            let Some(session) = parse_session(&body, EffectOperation::Checkout) else {
                mark_unknown(prepared, &record.effect_id).await;
                return Ok(checkout_unknown(record.effect_id.clone()));
            };
            let receipt = EffectReceipt {
                url: session.url.clone(),
                expires_at: session.expires_at,
            };
            let (nonce, ciphertext) = prepared
                .receipt_cipher
                .encrypt(&receipt, record.effect_id.as_bytes())
                .map_err(CheckoutFlowError::Runtime)?;
            let accepted = storage::accept_effect(
                &prepared.postgres,
                &record.effect_id,
                &session.id,
                &nonce,
                &ciphertext,
            )
            .await
            .map_err(|error| store_runtime(&error))?;
            if !accepted {
                return Ok(checkout_unknown(record.effect_id.clone()));
            }
            Ok(CreateCheckoutSessionResponse {
                effect_id: record.effect_id.clone(),
                expires_at: receipt.expires_at,
                session_id: Some(session.id),
                status: CreateCheckoutSessionResponseStatus::Accepted,
                url: Some(receipt.url),
            })
        }
    }
}

async fn finish_portal(
    prepared: &PreparedStripe,
    record: &EffectRecord,
    response: Result<SendResponse, ClientInvocationError>,
) -> Result<CreatePortalSessionResponse, PortalFlowError> {
    let Some(response) = classify_http(response) else {
        mark_unknown(prepared, &record.effect_id).await;
        return Ok(portal_unknown(record.effect_id.clone()));
    };
    match response {
        ClassifiedResponse::KnownFailure(code) => {
            storage::fail_effect(&prepared.postgres, &record.effect_id, code)
                .await
                .map_err(|error| store_runtime(&error))?;
            Err(PortalFlowError::Domain(portal_failure(Some(code))))
        }
        ClassifiedResponse::Success(body) => {
            let Some(session) = parse_session(&body, EffectOperation::Portal) else {
                mark_unknown(prepared, &record.effect_id).await;
                return Ok(portal_unknown(record.effect_id.clone()));
            };
            let receipt = EffectReceipt {
                url: session.url.clone(),
                expires_at: session.expires_at,
            };
            let (nonce, ciphertext) = prepared
                .receipt_cipher
                .encrypt(&receipt, record.effect_id.as_bytes())
                .map_err(PortalFlowError::Runtime)?;
            let accepted = storage::accept_effect(
                &prepared.postgres,
                &record.effect_id,
                &session.id,
                &nonce,
                &ciphertext,
            )
            .await
            .map_err(|error| store_runtime(&error))?;
            if !accepted {
                return Ok(portal_unknown(record.effect_id.clone()));
            }
            Ok(CreatePortalSessionResponse {
                effect_id: record.effect_id.clone(),
                expires_at: receipt.expires_at,
                session_id: Some(session.id),
                status: CreatePortalSessionResponseStatus::Accepted,
                url: Some(receipt.url),
            })
        }
    }
}

enum ClassifiedResponse {
    Success(Vec<u8>),
    KnownFailure(&'static str),
}

fn classify_http(
    response: Result<SendResponse, ClientInvocationError>,
) -> Option<ClassifiedResponse> {
    match response {
        Ok(response)
            if (200..300).contains(&response.status)
                && response.body.len() <= MAX_STRIPE_RESPONSE_BYTES =>
        {
            Some(ClassifiedResponse::Success(
                response.body.as_slice().to_vec(),
            ))
        }
        Ok(response)
            if (400..500).contains(&response.status)
                && !matches!(response.status, 408 | 409 | 425 | 429) =>
        {
            Some(ClassifiedResponse::KnownFailure("stripe_rejected"))
        }
        Ok(_) | Err(_) => None,
    }
}

async fn mark_unknown(prepared: &PreparedStripe, effect_id: &str) {
    let _ = storage::mark_effect_unknown(&prepared.postgres, effect_id).await;
}

fn checkout_unknown(effect_id: String) -> CreateCheckoutSessionResponse {
    CreateCheckoutSessionResponse {
        effect_id,
        expires_at: None,
        session_id: None,
        status: CreateCheckoutSessionResponseStatus::EffectUnknown,
        url: None,
    }
}

fn portal_unknown(effect_id: String) -> CreatePortalSessionResponse {
    CreatePortalSessionResponse {
        effect_id,
        expires_at: None,
        session_id: None,
        status: CreatePortalSessionResponseStatus::EffectUnknown,
        url: None,
    }
}

fn checkout_failure(code: Option<&str>) -> CreateCheckoutSessionError {
    if code == Some("already_subscribed") {
        CreateCheckoutSessionError::AlreadySubscribed
    } else {
        CreateCheckoutSessionError::InvalidRequest
    }
}

fn portal_failure(_code: Option<&str>) -> CreatePortalSessionError {
    CreatePortalSessionError::InvalidRequest
}

fn decrypt_receipt(
    prepared: &PreparedStripe,
    record: &EffectRecord,
) -> Result<EffectReceipt, RuntimeFailure> {
    prepared.receipt_cipher.decrypt(
        record
            .response_nonce
            .as_deref()
            .ok_or_else(|| failure("accepted Stripe effect has no receipt nonce"))?,
        record
            .response_ciphertext
            .as_deref()
            .ok_or_else(|| failure("accepted Stripe effect has no encrypted receipt"))?,
        record.effect_id.as_bytes(),
    )
}

fn inspect_response(
    prepared: &PreparedStripe,
    record: &EffectRecord,
) -> Result<InspectEffectResponse, RuntimeFailure> {
    let receipt = if record.status == EffectStatus::Accepted {
        Some(decrypt_receipt(prepared, record)?)
    } else {
        None
    };
    Ok(InspectEffectResponse {
        effect_id: record.effect_id.clone(),
        expires_at: receipt.as_ref().and_then(|value| value.expires_at.clone()),
        failure_code: record.failure_code.clone(),
        operation: match record.operation {
            EffectOperation::Checkout => InspectEffectResponseOperation::Checkout,
            EffectOperation::Portal => InspectEffectResponseOperation::Portal,
        },
        status: match record.status {
            EffectStatus::Prepared => InspectEffectResponseStatus::Prepared,
            EffectStatus::InFlight => InspectEffectResponseStatus::InFlight,
            EffectStatus::Accepted => InspectEffectResponseStatus::Accepted,
            EffectStatus::KnownFailure => InspectEffectResponseStatus::KnownFailure,
            EffectStatus::EffectUnknown => InspectEffectResponseStatus::EffectUnknown,
        },
        stripe_object_id: record.stripe_object_id.clone(),
        url: receipt.map(|value| value.url),
    })
}

type ResolutionParts = (
    EffectStatus,
    Option<String>,
    Option<([u8; 12], Vec<u8>)>,
    Option<String>,
    ResolveUnknownEffectResponseStatus,
);

fn validate_resolution(
    prepared: &PreparedStripe,
    record: &EffectRecord,
    request: &ResolveUnknownEffectRequest,
) -> Result<ResolutionParts, ResolveUnknownEffectError> {
    match request.resolution {
        ResolveUnknownEffectRequestResolution::Accepted => {
            let object_id = request
                .stripe_object_id
                .as_deref()
                .filter(|value| match record.operation {
                    EffectOperation::Checkout => valid_stripe_id(value, "cs_"),
                    EffectOperation::Portal => valid_stripe_id(value, "bps_"),
                })
                .ok_or(ResolveUnknownEffectError::InvalidResolution)?;
            let url = request
                .url
                .as_deref()
                .filter(|value| valid_session_url(value, record.operation))
                .ok_or(ResolveUnknownEffectError::InvalidResolution)?;
            if request.failure_code.is_some()
                || request
                    .expires_at
                    .as_deref()
                    .is_some_and(|value| OffsetDateTime::parse(value, &Rfc3339).is_err())
            {
                return Err(ResolveUnknownEffectError::InvalidResolution);
            }
            let receipt = EffectReceipt {
                url: url.to_owned(),
                expires_at: request.expires_at.clone(),
            };
            let encrypted = prepared
                .receipt_cipher
                .encrypt(&receipt, request.effect_id.as_bytes())
                .map_err(|_| ResolveUnknownEffectError::InvalidResolution)?;
            Ok((
                EffectStatus::Accepted,
                Some(object_id.to_owned()),
                Some(encrypted),
                None,
                ResolveUnknownEffectResponseStatus::Accepted,
            ))
        }
        ResolveUnknownEffectRequestResolution::KnownFailure => {
            let code = request
                .failure_code
                .as_deref()
                .filter(|value| valid_name(value))
                .ok_or(ResolveUnknownEffectError::InvalidResolution)?;
            if request.stripe_object_id.is_some()
                || request.url.is_some()
                || request.expires_at.is_some()
            {
                return Err(ResolveUnknownEffectError::InvalidResolution);
            }
            Ok((
                EffectStatus::KnownFailure,
                None,
                None,
                Some(code.to_owned()),
                ResolveUnknownEffectResponseStatus::KnownFailure,
            ))
        }
    }
}

fn resolution_matches(
    prepared: &PreparedStripe,
    record: &EffectRecord,
    request: &ResolveUnknownEffectRequest,
) -> Result<bool, ResolveUnknownEffectError> {
    match record.status {
        EffectStatus::Accepted => {
            let receipt = decrypt_receipt(prepared, record)
                .map_err(|_| ResolveUnknownEffectError::InvalidResolution)?;
            Ok(record.stripe_object_id == request.stripe_object_id
                && receipt.url == request.url.as_deref().unwrap_or_default()
                && receipt.expires_at == request.expires_at)
        }
        EffectStatus::KnownFailure => Ok(record.failure_code == request.failure_code),
        EffectStatus::Prepared | EffectStatus::InFlight | EffectStatus::EffectUnknown => Ok(false),
    }
}

#[derive(Deserialize)]
struct StripeSession {
    id: String,
    url: String,
    expires_at: Option<i64>,
}

struct ParsedSession {
    id: String,
    url: String,
    expires_at: Option<String>,
}

fn parse_session(bytes: &[u8], operation: EffectOperation) -> Option<ParsedSession> {
    let session: StripeSession = serde_json::from_slice(bytes).ok()?;
    let prefix = match operation {
        EffectOperation::Checkout => "cs_",
        EffectOperation::Portal => "bps_",
    };
    if !valid_stripe_id(&session.id, prefix) || !valid_session_url(&session.url, operation) {
        return None;
    }
    let expires_at = session.expires_at.and_then(|timestamp| {
        OffsetDateTime::from_unix_timestamp(timestamp)
            .ok()?
            .format(&Rfc3339)
            .ok()
    });
    Some(ParsedSession {
        id: session.id,
        url: session.url,
        expires_at,
    })
}

fn valid_session_url(value: &str, operation: EffectOperation) -> bool {
    Url::parse(value).is_ok_and(|url| {
        url.scheme() == "https"
            && url.username().is_empty()
            && url.password().is_none()
            && url.host_str()
                == Some(match operation {
                    EffectOperation::Checkout => "checkout.stripe.com",
                    EffectOperation::Portal => "billing.stripe.com",
                })
    })
}

#[derive(Deserialize)]
struct StripeSubscriptionWire {
    id: String,
    customer: String,
    status: String,
    #[serde(default)]
    cancel_at_period_end: bool,
    current_period_end: Option<i64>,
    items: StripeItems,
}

#[derive(Deserialize)]
struct StripeItems {
    data: Vec<StripeItem>,
}

#[derive(Deserialize)]
struct StripeItem {
    price: StripePrice,
    current_period_end: Option<i64>,
}

#[derive(Deserialize)]
struct StripePrice {
    id: String,
}

struct CanonicalSubscription {
    subscription_id: String,
    customer_id: String,
    status: String,
    cancel_at_period_end: bool,
    current_period_end: Option<OffsetDateTime>,
    price_id: String,
}

fn parse_canonical_subscription(bytes: &[u8]) -> Option<CanonicalSubscription> {
    if bytes.len() > MAX_STRIPE_RESPONSE_BYTES {
        return None;
    }
    let wire: StripeSubscriptionWire = serde_json::from_slice(bytes).ok()?;
    if !valid_stripe_id(&wire.id, "sub_")
        || !valid_stripe_id(&wire.customer, "cus_")
        || wire.items.data.len() != 1
        || !valid_stripe_id(&wire.items.data[0].price.id, "price_")
    {
        return None;
    }
    let status = match wire.status.as_str() {
        "incomplete" | "incomplete_expired" | "trialing" | "active" | "past_due" | "canceled"
        | "unpaid" | "paused" => wire.status,
        _ => "unknown".to_owned(),
    };
    let current_period_end = wire
        .current_period_end
        .or(wire.items.data[0].current_period_end)
        .and_then(|value| OffsetDateTime::from_unix_timestamp(value).ok());
    Some(CanonicalSubscription {
        subscription_id: wire.id,
        customer_id: wire.customer,
        status,
        cancel_at_period_end: wire.cancel_at_period_end,
        current_period_end,
        price_id: wire.items.data[0].price.id.clone(),
    })
}

fn checkout_form(request: &CreateCheckoutSessionRequest, price_id: &str) -> String {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    serializer
        .append_pair("mode", "subscription")
        .append_pair("line_items[0][price]", price_id)
        .append_pair("line_items[0][quantity]", "1")
        .append_pair("success_url", &request.success_url)
        .append_pair("cancel_url", &request.cancel_url)
        .append_pair("client_reference_id", &request.subject)
        .append_pair("metadata[lenso_scope_kind]", &request.scope_kind)
        .append_pair("metadata[lenso_scope_id]", &request.scope_id)
        .append_pair("metadata[lenso_subject]", &request.subject)
        .append_pair("metadata[lenso_price_alias]", &request.price_alias)
        .append_pair(
            "subscription_data[metadata][lenso_scope_kind]",
            &request.scope_kind,
        )
        .append_pair(
            "subscription_data[metadata][lenso_scope_id]",
            &request.scope_id,
        )
        .append_pair(
            "subscription_data[metadata][lenso_subject]",
            &request.subject,
        )
        .append_pair(
            "subscription_data[metadata][lenso_price_alias]",
            &request.price_alias,
        );
    serializer.finish()
}

fn portal_form(customer_id: &str, return_url: &str) -> String {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    serializer
        .append_pair("customer", customer_id)
        .append_pair("return_url", return_url);
    serializer.finish()
}

pub(crate) fn stripe_headers(
    api_key: &str,
    idempotency_key: Option<&str>,
    form_body: bool,
) -> Vec<SendRequestHeadersItem> {
    let mut headers = vec![
        SendRequestHeadersItem {
            name: "Authorization".to_owned(),
            value: format!("Bearer {api_key}"),
        },
        SendRequestHeadersItem {
            name: "Stripe-Version".to_owned(),
            value: STRIPE_API_VERSION.to_owned(),
        },
    ];
    if form_body {
        headers.push(SendRequestHeadersItem {
            name: "Content-Type".to_owned(),
            value: "application/x-www-form-urlencoded".to_owned(),
        });
    }
    if let Some(value) = idempotency_key {
        headers.push(SendRequestHeadersItem {
            name: "Idempotency-Key".to_owned(),
            value: value.to_owned(),
        });
    }
    headers
}

fn request_hash<T: Serialize>(value: &T) -> Result<Vec<u8>, RuntimeFailure> {
    let bytes = serde_json::to_vec(value).map_err(|error| failure(error.to_string()))?;
    Ok(Sha256::digest(bytes).to_vec())
}

fn stable_effect_id(caller: &str, operation: EffectOperation, key: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(caller.as_bytes());
    digest.update([0]);
    digest.update(operation.as_str().as_bytes());
    digest.update([0]);
    digest.update(key.as_bytes());
    format!("stripe_effect_{}", encode_hex(&digest.finalize()[..16]))
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn valid_idempotency_key(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDEMPOTENCY_BYTES
        && !value.chars().any(char::is_control)
}

fn valid_effect_id(value: &str) -> bool {
    value.strip_prefix("stripe_effect_").is_some_and(|suffix| {
        suffix.len() == 32 && suffix.bytes().all(|byte| byte.is_ascii_hexdigit())
    })
}

fn valid_subject_request(scope_kind: &str, scope_id: &str, subject: &str) -> bool {
    valid_name(scope_kind) && valid_name(scope_id) && valid_name(subject)
}

fn subscription_response(
    subject: BillingSubject,
) -> Result<GetSubscriptionResponse, RuntimeFailure> {
    let status = match subject.subscription_status.as_str() {
        "none" => GetSubscriptionResponseStatus::None,
        "incomplete" => GetSubscriptionResponseStatus::Incomplete,
        "incomplete_expired" => GetSubscriptionResponseStatus::IncompleteExpired,
        "trialing" => GetSubscriptionResponseStatus::Trialing,
        "active" => GetSubscriptionResponseStatus::Active,
        "past_due" => GetSubscriptionResponseStatus::PastDue,
        "canceled" => GetSubscriptionResponseStatus::Canceled,
        "unpaid" => GetSubscriptionResponseStatus::Unpaid,
        "paused" => GetSubscriptionResponseStatus::Paused,
        "unknown" => GetSubscriptionResponseStatus::Unknown,
        other => {
            return Err(failure(format!(
                "invalid stored subscription status `{other}`"
            )));
        }
    };
    let entitlement_state = match subject.entitlement_state.as_str() {
        "pending" => GetSubscriptionResponseEntitlementState::Pending,
        "granted" => GetSubscriptionResponseEntitlementState::Granted,
        "revoked" => GetSubscriptionResponseEntitlementState::Revoked,
        "failed" => GetSubscriptionResponseEntitlementState::Failed,
        other => {
            return Err(failure(format!(
                "invalid stored entitlement state `{other}`"
            )));
        }
    };
    Ok(GetSubscriptionResponse {
        cancel_at_period_end: subject.cancel_at_period_end,
        current_period_end: subject
            .current_period_end
            .map(|value| value.format(&Rfc3339))
            .transpose()
            .map_err(|error| failure(error.to_string()))?,
        customer_id: subject.customer_id,
        entitlement_state,
        price_alias: subject.price_alias,
        revision: subject.revision,
        scope_id: subject.scope_id,
        scope_kind: subject.scope_kind,
        status,
        subject: subject.subject,
        subscription_id: subject.subscription_id,
    })
}

fn webhook_domain(error: WebhookError) -> IngestWebhookError {
    match error {
        WebhookError::BodyTooLarge => IngestWebhookError::BodyTooLarge,
        WebhookError::InvalidSignature | WebhookError::ModeMismatch => {
            IngestWebhookError::InvalidSignature
        }
        WebhookError::StaleSignature => IngestWebhookError::StaleSignature,
        WebhookError::InvalidEvent => IngestWebhookError::InvalidEvent,
    }
}

fn store_runtime<T>(error: &StoreError) -> T
where
    T: FromRuntime,
{
    T::from_runtime(store_failure(error))
}

trait FromRuntime {
    fn from_runtime(error: RuntimeFailure) -> Self;
}

impl FromRuntime for CheckoutFlowError {
    fn from_runtime(error: RuntimeFailure) -> Self {
        Self::Runtime(error)
    }
}

impl FromRuntime for PortalFlowError {
    fn from_runtime(error: RuntimeFailure) -> Self {
        Self::Runtime(error)
    }
}

impl FromRuntime for SubscriptionFlowError {
    fn from_runtime(error: RuntimeFailure) -> Self {
        Self::Runtime(error)
    }
}

fn store_failure(error: &StoreError) -> RuntimeFailure {
    failure(error.to_string())
}

pub(crate) fn failure(detail: impl Into<String>) -> RuntimeFailure {
    RuntimeFailure::PluginFailure {
        detail: detail.into(),
    }
}

#[cfg(test)]
mod tests {
    use lenso_capability_stripe_subscription::CreateCheckoutSessionRequest;

    use super::*;

    #[test]
    fn checkout_form_carries_both_session_and_subscription_metadata() {
        let request = CreateCheckoutSessionRequest {
            cancel_url: "https://app.example.test/cancel".to_owned(),
            idempotency_key: "checkout-1".to_owned(),
            price_alias: "pro".to_owned(),
            scope_id: "org_1".to_owned(),
            scope_kind: "organization".to_owned(),
            subject: "org_1".to_owned(),
            success_url: "https://app.example.test/success".to_owned(),
        };
        let form = checkout_form(&request, "price_1");
        let values = url::form_urlencoded::parse(form.as_bytes()).collect::<Vec<_>>();
        assert!(values.contains(&("mode".into(), "subscription".into())));
        assert!(values.contains(&("metadata[lenso_subject]".into(), "org_1".into())));
        assert!(values.contains(&(
            "subscription_data[metadata][lenso_subject]".into(),
            "org_1".into()
        )));
    }

    #[test]
    fn receipt_encryption_binds_ciphertext_to_effect() {
        let cipher = ReceiptCipher::derive(b"a sufficiently long test encryption secret");
        let receipt = EffectReceipt {
            url: "https://checkout.stripe.com/c/pay/cs_test".to_owned(),
            expires_at: None,
        };
        let (nonce, encrypted) = cipher.encrypt(&receipt, b"effect-a").unwrap();
        let decoded: EffectReceipt = cipher.decrypt(&nonce, &encrypted, b"effect-a").unwrap();
        assert_eq!(decoded.url, receipt.url);
        assert!(
            cipher
                .decrypt::<EffectReceipt>(&nonce, &encrypted, b"effect-b")
                .is_err()
        );
    }

    #[test]
    fn subscription_parser_requires_one_price_and_known_ids() {
        let value = br#"{"id":"sub_1","customer":"cus_1","status":"active","cancel_at_period_end":false,"current_period_end":2000000000,"items":{"data":[{"price":{"id":"price_1"},"current_period_end":2000000000}]}}"#;
        let parsed = parse_canonical_subscription(value).unwrap();
        assert_eq!(parsed.price_id, "price_1");
        assert_eq!(parsed.status, "active");
    }
}
