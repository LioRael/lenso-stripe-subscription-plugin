# Agent instructions

This repository contains the first-party Stripe Subscription Plugin for Lenso.

- Use Stripe Billing with subscription-mode Checkout Sessions and the Customer
  Portal. Do not implement renewals with Payment Intents or legacy Plans.
- Pin outbound requests to Stripe API version `2026-02-25.clover` until a
  separately reviewed upgrade changes the stored webhook/API projections.
- Verify `Stripe-Signature` over the exact, unmodified UTF-8 webhook body before
  parsing JSON. Secrets and raw payloads must never appear in logs or Debug.
- Stripe webhooks are hints, not ordered canonical state. Persist each verified
  event once, then reconcile the current Subscription from Stripe before
  changing entitlements.
- Every outbound Stripe mutation needs a caller-scoped idempotency key, immutable
  request fingerprint, and durable effect state. Transport ambiguity is
  `effect_unknown`; do not claim success or create a fresh Stripe effect.
- Product price selection uses configured price aliases. Callers cannot provide
  arbitrary Stripe Price IDs or expand configured redirect origins.
- PostgreSQL and Stripe resources remain behind this Plugin boundary. Runtime
  startup only verifies operator-managed storage.
- Registry publication, immutable tags, GitHub Releases, and remote repository
  creation require the explicitly approved release workflow.

