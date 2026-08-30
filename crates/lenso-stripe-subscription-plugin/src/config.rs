use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use url::Url;

use crate::schema::schema_plan;

pub(crate) const STRIPE_API_VERSION: &str = "2026-02-25.clover";
const MAX_REFERENCE_BYTES: usize = 256;
const MAX_WEBHOOK_BODY_BYTES: usize = 1_048_576;

/// One configured Stripe Price and the product facts it grants.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PriceMapping {
    pub alias: String,
    pub price_id: String,
    pub entitlements: Vec<EntitlementMapping>,
}

/// One Entitlements feature projection for a paid Price.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EntitlementMapping {
    pub feature: String,
    pub limit: Option<String>,
}

/// Immutable authority, Stripe endpoint, and product mapping for one Instance.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StripeSubscriptionConfig {
    schema: String,
    database_url_secret: String,
    stripe_api_key_secret: String,
    webhook_signing_secret: String,
    receipt_encryption_secret: String,
    api_base_url: String,
    livemode: bool,
    signature_tolerance_seconds: i64,
    max_webhook_body_bytes: usize,
    reconciliation_lease_seconds: i64,
    redirect_origins: Vec<String>,
    prices: Vec<PriceMapping>,
    product_instances: Vec<String>,
    webhook_instances: Vec<String>,
    worker_instances: Vec<String>,
    operator_instances: Vec<String>,
}

impl StripeSubscriptionConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        schema: impl Into<String>,
        database_url_secret: impl Into<String>,
        stripe_api_key_secret: impl Into<String>,
        webhook_signing_secret: impl Into<String>,
        receipt_encryption_secret: impl Into<String>,
        api_base_url: impl Into<String>,
        livemode: bool,
        signature_tolerance_seconds: i64,
        max_webhook_body_bytes: usize,
        reconciliation_lease_seconds: i64,
        redirect_origins: Vec<String>,
        prices: Vec<PriceMapping>,
        product_instances: Vec<String>,
        webhook_instances: Vec<String>,
        worker_instances: Vec<String>,
        operator_instances: Vec<String>,
    ) -> Result<Self, String> {
        let config = Self {
            schema: schema.into(),
            database_url_secret: database_url_secret.into(),
            stripe_api_key_secret: stripe_api_key_secret.into(),
            webhook_signing_secret: webhook_signing_secret.into(),
            receipt_encryption_secret: receipt_encryption_secret.into(),
            api_base_url: api_base_url.into(),
            livemode,
            signature_tolerance_seconds,
            max_webhook_body_bytes,
            reconciliation_lease_seconds,
            redirect_origins,
            prices,
            product_instances,
            webhook_instances,
            worker_instances,
            operator_instances,
        };
        config.validate()?;
        Ok(config)
    }

    pub(crate) fn validate(&self) -> Result<(), String> {
        schema_plan(self.schema.clone())
            .map_err(|error| format!("invalid owned PostgreSQL schema: {error}"))?;
        let secret_references = [
            &self.database_url_secret,
            &self.stripe_api_key_secret,
            &self.webhook_signing_secret,
            &self.receipt_encryption_secret,
        ];
        if secret_references
            .iter()
            .any(|reference| !valid_secret_reference(reference))
            || secret_references.iter().collect::<BTreeSet<_>>().len() != secret_references.len()
        {
            return Err("all four secret references must be valid and distinct".to_owned());
        }
        fixed_api_base(&self.api_base_url)?;
        if !(60..=900).contains(&self.signature_tolerance_seconds) {
            return Err("signature_tolerance_seconds must be between 60 and 900".to_owned());
        }
        if !(1_024..=MAX_WEBHOOK_BODY_BYTES).contains(&self.max_webhook_body_bytes) {
            return Err(format!(
                "max_webhook_body_bytes must be between 1024 and {MAX_WEBHOOK_BODY_BYTES}"
            ));
        }
        if !(5..=3_600).contains(&self.reconciliation_lease_seconds) {
            return Err("reconciliation_lease_seconds must be between 5 and 3600".to_owned());
        }
        validate_origins(&self.redirect_origins)?;
        validate_prices(&self.prices)?;
        validate_callers(&self.product_instances, "product")?;
        validate_callers(&self.webhook_instances, "webhook")?;
        validate_callers(&self.worker_instances, "worker")?;
        validate_callers(&self.operator_instances, "operator")?;
        let all_callers = self
            .product_instances
            .iter()
            .chain(&self.webhook_instances)
            .chain(&self.worker_instances)
            .chain(&self.operator_instances)
            .collect::<Vec<_>>();
        if all_callers.iter().collect::<BTreeSet<_>>().len() != all_callers.len() {
            return Err("caller role lists must be pairwise disjoint".to_owned());
        }
        Ok(())
    }

    pub(crate) fn price(&self, alias: &str) -> Option<&PriceMapping> {
        self.prices.iter().find(|price| price.alias == alias)
    }

    pub(crate) fn redirect_allowed(&self, value: &str) -> bool {
        redirect_origin(value).is_ok_and(|origin| self.redirect_origins.contains(&origin))
    }

    pub(crate) fn product_allowed(&self, caller: Option<&str>) -> bool {
        allowed(&self.product_instances, caller)
    }

    pub(crate) fn webhook_allowed(&self, caller: Option<&str>) -> bool {
        allowed(&self.webhook_instances, caller)
    }

    pub(crate) fn worker_allowed(&self, caller: Option<&str>) -> bool {
        allowed(&self.worker_instances, caller)
    }

    pub(crate) fn operator_allowed(&self, caller: Option<&str>) -> bool {
        allowed(&self.operator_instances, caller)
    }

    pub(crate) fn schema(&self) -> &str {
        &self.schema
    }

    pub(crate) fn database_url_secret(&self) -> &str {
        &self.database_url_secret
    }

    pub(crate) fn stripe_api_key_secret(&self) -> &str {
        &self.stripe_api_key_secret
    }

    pub(crate) fn webhook_signing_secret(&self) -> &str {
        &self.webhook_signing_secret
    }

    pub(crate) fn receipt_encryption_secret(&self) -> &str {
        &self.receipt_encryption_secret
    }

    pub(crate) fn api_base(&self) -> Url {
        fixed_api_base(&self.api_base_url).expect("validated Stripe API base")
    }

    pub(crate) const fn livemode(&self) -> bool {
        self.livemode
    }

    pub(crate) const fn signature_tolerance_seconds(&self) -> i64 {
        self.signature_tolerance_seconds
    }

    pub(crate) const fn max_webhook_body_bytes(&self) -> usize {
        self.max_webhook_body_bytes
    }

    pub(crate) const fn reconciliation_lease_seconds(&self) -> i64 {
        self.reconciliation_lease_seconds
    }
}

fn allowed(values: &[String], caller: Option<&str>) -> bool {
    caller.is_some_and(|caller| values.iter().any(|value| value == caller))
}

fn validate_callers(values: &[String], role: &str) -> Result<(), String> {
    if values.is_empty() || values.iter().any(|value| !valid_name(value)) {
        return Err(format!("at least one valid {role} caller is required"));
    }
    if values.iter().collect::<BTreeSet<_>>().len() != values.len() {
        return Err(format!("{role} caller list contains duplicates"));
    }
    Ok(())
}

fn validate_origins(values: &[String]) -> Result<(), String> {
    if values.is_empty() || values.len() > 64 {
        return Err("between one and 64 redirect origins are required".to_owned());
    }
    let normalized = values
        .iter()
        .map(|value| redirect_origin(value))
        .collect::<Result<Vec<_>, _>>()?;
    if normalized != values {
        return Err("redirect origins must already use their canonical origin form".to_owned());
    }
    if normalized.iter().collect::<BTreeSet<_>>().len() != normalized.len() {
        return Err("redirect origins contain duplicates".to_owned());
    }
    Ok(())
}

fn validate_prices(values: &[PriceMapping]) -> Result<(), String> {
    if values.is_empty() || values.len() > 256 {
        return Err("between one and 256 price mappings are required".to_owned());
    }
    if values.iter().any(|price| {
        !valid_name(&price.alias)
            || !valid_stripe_id(&price.price_id, "price_")
            || price.entitlements.is_empty()
            || price.entitlements.len() > 256
            || price.entitlements.iter().any(|entitlement| {
                !valid_name(&entitlement.feature)
                    || entitlement
                        .limit
                        .as_deref()
                        .is_some_and(|limit| limit.parse::<i64>().map_or(true, |value| value <= 0))
            })
            || price
                .entitlements
                .iter()
                .map(|entitlement| &entitlement.feature)
                .collect::<BTreeSet<_>>()
                .len()
                != price.entitlements.len()
    }) {
        return Err("price and entitlement mappings are invalid".to_owned());
    }
    if values
        .iter()
        .map(|price| &price.alias)
        .collect::<BTreeSet<_>>()
        .len()
        != values.len()
        || values
            .iter()
            .map(|price| &price.price_id)
            .collect::<BTreeSet<_>>()
            .len()
            != values.len()
    {
        return Err("price aliases and Stripe Price IDs must be unique".to_owned());
    }
    Ok(())
}

fn fixed_api_base(value: &str) -> Result<Url, String> {
    let url = Url::parse(value).map_err(|_| "api_base_url is invalid".to_owned())?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err("api_base_url must be one HTTPS origin without credentials".to_owned());
    }
    Ok(url)
}

fn redirect_origin(value: &str) -> Result<String, String> {
    let url = Url::parse(value).map_err(|_| "redirect URL is invalid".to_owned())?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err("redirect URLs must use HTTPS without credentials".to_owned());
    }
    Ok(url.origin().ascii_serialization())
}

fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_REFERENCE_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
}

fn valid_stripe_id(value: &str, prefix: &str) -> bool {
    value.starts_with(prefix)
        && value.len() <= MAX_REFERENCE_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn valid_secret_reference(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_REFERENCE_BYTES
        && !value.starts_with('/')
        && !value.ends_with('/')
        && !value.contains("//")
        && value
            .split('/')
            .all(|segment| segment != "." && segment != "..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'/'))
}

#[cfg(test)]
mod tests {
    use super::{EntitlementMapping, PriceMapping, STRIPE_API_VERSION, StripeSubscriptionConfig};

    fn config() -> StripeSubscriptionConfig {
        StripeSubscriptionConfig::new(
            "stripe_billing",
            "stripe/database-url",
            "stripe/api-key",
            "stripe/webhook-secret",
            "stripe/receipt-key",
            "https://api.stripe.com",
            false,
            300,
            262_144,
            30,
            vec!["https://app.example.test".to_owned()],
            vec![PriceMapping {
                alias: "pro".to_owned(),
                price_id: "price_test123".to_owned(),
                entitlements: vec![EntitlementMapping {
                    feature: "projects.unlimited".to_owned(),
                    limit: None,
                }],
            }],
            vec!["billing-ui".to_owned()],
            vec!["stripe-ingress".to_owned()],
            vec!["stripe-worker".to_owned()],
            vec!["billing-operator".to_owned()],
        )
        .unwrap()
    }

    #[test]
    fn immutable_policy_uses_current_api_and_exact_origins() {
        let policy = config();
        assert_eq!(STRIPE_API_VERSION, "2026-02-25.clover");
        assert!(policy.redirect_allowed("https://app.example.test/billing/success?session=1"));
        assert!(!policy.redirect_allowed("https://evil.example.test/return"));
        assert_eq!(policy.price("pro").unwrap().price_id, "price_test123");
    }

    #[test]
    fn authority_and_secret_roles_are_separate() {
        let policy = config();
        assert!(policy.product_allowed(Some("billing-ui")));
        assert!(policy.webhook_allowed(Some("stripe-ingress")));
        assert!(policy.worker_allowed(Some("stripe-worker")));
        assert!(policy.operator_allowed(Some("billing-operator")));
        assert!(!policy.operator_allowed(Some("billing-ui")));

        let mut invalid = policy.clone();
        invalid.operator_instances = vec!["billing-ui".to_owned()];
        assert!(invalid.validate().is_err());

        let mut invalid = policy;
        invalid.stripe_api_key_secret = invalid.webhook_signing_secret.clone();
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn price_and_endpoint_policy_fail_closed() {
        let mut invalid = config();
        invalid.api_base_url = "http://api.stripe.com".to_owned();
        assert!(invalid.validate().is_err());

        let mut invalid = config();
        invalid.prices[0].entitlements[0].limit = Some("0".to_owned());
        assert!(invalid.validate().is_err());

        let mut invalid = config();
        invalid.redirect_origins = vec!["https://app.example.test/path".to_owned()];
        assert!(invalid.validate().is_err());
    }
}
