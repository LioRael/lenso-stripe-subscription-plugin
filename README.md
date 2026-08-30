# Lenso Stripe Subscription Plugin

Removable Stripe Billing integration for Lenso. It creates subscription-mode
Checkout Sessions, creates Customer Portal sessions, ingests verified Stripe
webhooks, projects durable subscription state, and reconciles product
entitlements without putting billing policy in the Runtime or Kernel.

It keeps Stripe mutations behind a durable effect ledger, treats webhooks as
unordered hints, and changes Lenso entitlements only after fetching the
canonical Subscription from Stripe.

See [the Plugin card](docs/plugin-card.md) for the exact authority, effect,
webhook, entitlement, and deletion boundaries.

## Operator workflow

1. Run the explicit `StripeSubscriptionOperator::setup` or `upgrade` path for
   the Plugin-owned PostgreSQL schema.
2. Store four distinct secret references for PostgreSQL, the Stripe API key,
   the webhook signing secret, and receipt encryption.
3. Configure immutable product, webhook, worker, and effect-operator caller
   allowlists, canonical HTTPS redirect origins, and Price-to-entitlement
   mappings.
4. Bind an allowlisted HTTP Client that permits only the configured Stripe API
   origin and bind Entitlements Admin only to this Plugin's worker path.
5. Route the exact raw webhook body and full `Stripe-Signature` header to
   `ingest_webhook`; invoke `reconcile_next` until it reports `idle`.

Runtime activation verifies an already-managed schema. It never creates or
upgrades database objects implicitly.

## Release safety

The release workflow is manually gated. A live run requires `live=true` and
`confirm=publish` on `main`, and publishes through crates.io Trusted Publishing
with GitHub OIDC. A new crate name must first be allocated on crates.io before
its Trusted Publisher can be configured for `release-plz.yml`.
