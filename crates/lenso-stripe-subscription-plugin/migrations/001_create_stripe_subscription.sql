CREATE TABLE stripe_billing_subjects (
    scope_kind text NOT NULL,
    scope_id text NOT NULL,
    subject text NOT NULL,
    stripe_customer_id text NOT NULL,
    stripe_subscription_id text,
    price_alias text,
    subscription_status text NOT NULL DEFAULT 'none',
    cancel_at_period_end boolean NOT NULL DEFAULT false,
    current_period_end timestamptz,
    entitlement_state text NOT NULL DEFAULT 'pending',
    revision bigint NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (scope_kind, scope_id, subject),
    CONSTRAINT stripe_billing_customer_unique UNIQUE (stripe_customer_id),
    CONSTRAINT stripe_billing_subscription_unique UNIQUE (stripe_subscription_id),
    CONSTRAINT stripe_billing_status_valid CHECK (
        subscription_status IN (
            'none', 'incomplete', 'incomplete_expired', 'trialing', 'active',
            'past_due', 'canceled', 'unpaid', 'paused', 'unknown'
        )
    ),
    CONSTRAINT stripe_billing_entitlement_state_valid CHECK (
        entitlement_state IN ('pending', 'granted', 'revoked', 'failed')
    ),
    CONSTRAINT stripe_billing_revision_valid CHECK (revision >= 0)
);

CREATE TABLE stripe_effects (
    effect_id text PRIMARY KEY,
    caller_instance text NOT NULL,
    operation text NOT NULL,
    idempotency_key text NOT NULL,
    request_hash bytea NOT NULL,
    scope_kind text NOT NULL,
    scope_id text NOT NULL,
    subject text NOT NULL,
    price_alias text,
    status text NOT NULL,
    stripe_object_id text,
    response_nonce bytea,
    response_ciphertext bytea,
    failure_code text,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    completed_at timestamptz,
    CONSTRAINT stripe_effect_identity_unique UNIQUE (caller_instance, operation, idempotency_key),
    CONSTRAINT stripe_effect_operation_valid CHECK (operation IN ('checkout', 'portal')),
    CONSTRAINT stripe_effect_status_valid CHECK (
        status IN ('prepared', 'in_flight', 'accepted', 'known_failure', 'effect_unknown')
    ),
    CONSTRAINT stripe_effect_response_shape_valid CHECK (
        (status = 'accepted' AND stripe_object_id IS NOT NULL AND response_nonce IS NOT NULL AND response_ciphertext IS NOT NULL AND failure_code IS NULL)
        OR (status = 'known_failure' AND response_nonce IS NULL AND response_ciphertext IS NULL AND failure_code IS NOT NULL)
        OR (status IN ('prepared', 'in_flight', 'effect_unknown') AND response_nonce IS NULL AND response_ciphertext IS NULL)
    )
);

CREATE TABLE stripe_webhook_events (
    event_id text PRIMARY KEY,
    event_type text NOT NULL,
    stripe_created bigint NOT NULL,
    livemode boolean NOT NULL,
    payload_sha256 bytea NOT NULL,
    customer_id text,
    subscription_id text,
    outcome text NOT NULL,
    received_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    CONSTRAINT stripe_webhook_outcome_valid CHECK (outcome IN ('accepted', 'ignored'))
);

CREATE TABLE stripe_reconciliations (
    subscription_id text PRIMARY KEY,
    customer_id text NOT NULL,
    state text NOT NULL DEFAULT 'pending',
    attempts integer NOT NULL DEFAULT 0,
    lease_generation bigint NOT NULL DEFAULT 0,
    lease_owner text,
    lease_token_hash bytea,
    lease_expires_at timestamptz,
    last_failure_code text,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    CONSTRAINT stripe_reconciliation_state_valid CHECK (state IN ('pending', 'running', 'converged')),
    CONSTRAINT stripe_reconciliation_attempts_valid CHECK (attempts >= 0),
    CONSTRAINT stripe_reconciliation_lease_shape_valid CHECK (
        (state = 'running' AND lease_owner IS NOT NULL AND lease_token_hash IS NOT NULL AND lease_expires_at IS NOT NULL)
        OR (state <> 'running' AND lease_owner IS NULL AND lease_token_hash IS NULL AND lease_expires_at IS NULL)
    )
);

CREATE INDEX stripe_reconciliations_claim_order
    ON stripe_reconciliations (state, updated_at, subscription_id)
    WHERE state IN ('pending', 'running');

CREATE TABLE stripe_entitlement_bindings (
    subscription_id text NOT NULL,
    feature text NOT NULL,
    grant_id text NOT NULL,
    applied_revision bigint NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (subscription_id, feature),
    CONSTRAINT stripe_entitlement_binding_revision_valid CHECK (applied_revision >= 0)
);
