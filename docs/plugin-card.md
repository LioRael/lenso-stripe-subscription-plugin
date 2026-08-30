# Stripe Subscription Plugin card

## Job and first observable result

An authorized product surface creates a Stripe-hosted subscription Checkout
Session from a configured price alias and receives its short-lived redirect
URL. After Stripe sends a verified webhook, an authorized worker reconciles the
canonical Subscription and converges the matching Lenso entitlements.

## Identity and capabilities

- Repository: `lenso-stripe-subscription-plugin`
- Plugin ID: `lenso.stripe-subscription`
- Plugin Root slot: `billing`
- Provides `lenso.stripe-subscription@1`
  - `create_checkout_session`
  - `create_portal_session`
  - `get_subscription`
- Provides `lenso.stripe-subscription-admin@1`
  - `ingest_webhook`
  - `reconcile_next`
  - `inspect_effect`
  - `resolve_unknown_effect`
- Requires `lenso.secrets@1`, `lenso.http.client@1`, and
  `lenso.entitlements-admin@1`.

The webhook ingress adapter is outside this Plugin and receives no billing
authority beyond the exact `ingest_webhook` binding. Reconciliation workers and
effect operators use separate immutable caller allowlists.

## Billing boundary

Checkout always uses `mode=subscription` and configured Stripe Price IDs.
Customer Portal sessions are the only v1 mutation surface for upgrades,
downgrades, cancellation, and payment-method changes. The Plugin does not
implement a renewal loop, accept raw payment details, or expose arbitrary
Stripe API parameters.

The product supplies a stable scope kind/ID and subject. Checkout metadata
contains only opaque Lenso identifiers and the configured price alias. Email,
name, card data, webhook bodies, API keys, endpoint secrets, and Stripe response
bodies are never retained as operational evidence.

## Durable external effects

Checkout and Portal requests are fingerprinted under
`(caller_instance, operation, idempotency_key)`. The effect ledger moves only
through:

`prepared -> in_flight -> accepted | known_failure | effect_unknown`

`accepted` requires both a successful Stripe response and a durable local
receipt containing the safe Stripe object ID and redirect expiry. A timeout,
transport failure, malformed success response, or process loss after dispatch
is ambiguous and becomes `effect_unknown`. Exact retries return the durable
state; they never silently choose a new key. Only a separately authorized
operator can resolve an unknown effect after correlating Stripe's request log.
The configured uncertainty window must exceed the bound HTTP Client timeout;
only an `in_flight` row older than that window is recovered after a process
loss, so rolling activation cannot invalidate another live dispatch.

## Webhook and reconciliation boundary

`ingest_webhook` accepts the exact raw UTF-8 body and the complete
`Stripe-Signature` header. It enforces timestamp tolerance, verifies at least
one v1 HMAC-SHA256 signature in constant time, rejects over-sized bodies, and
stores each Stripe Event ID once. Duplicate delivery returns the original
receipt.

Stripe does not guarantee delivery order. Subscription-related events enqueue a
deduplicated reconciliation key instead of directly granting access from the
event snapshot. `reconcile_next` fetches the current Stripe Subscription,
persists its canonical status, and applies configured entitlement mappings.
`active` and `trialing` grant configured features; every other status revokes
them. An unknown Price mapping also revokes existing bindings and records a
failed entitlement projection. Entitlement put/revoke operations are naturally
repeatable, and the reconciliation row is terminal only after the remote
Capability call and fenced PostgreSQL update succeed.

Each reconciliation uses a PostgreSQL lease token. Expired work may be claimed
by another worker, while a stale worker cannot mark the row converged. Partial
Entitlements failures return the row to `pending` with a bounded failure code;
they never publish a false converged state.

## Deletion boundary

Removing the Plugin removes Stripe session creation, webhook receipts, billing
projection, and entitlement reconciliation without changing Kernel or Runtime.
The operator removes the private PostgreSQL schema only after the application's
billing-retention policy permits it. Existing Stripe subscriptions remain
external resources and require an explicit business migration or cancellation
plan.
