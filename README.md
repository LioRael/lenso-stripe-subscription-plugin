# Lenso Stripe Subscription Plugin

Removable Stripe Billing integration for Lenso. It creates subscription-mode
Checkout Sessions, creates Customer Portal sessions, ingests verified Stripe
webhooks, projects durable subscription state, and reconciles product
entitlements without putting billing policy in the Runtime or Kernel.

The implementation lives on a feature branch until its contracts, external
effect ledger, webhook verification, and PostgreSQL behavior pass all gates.

