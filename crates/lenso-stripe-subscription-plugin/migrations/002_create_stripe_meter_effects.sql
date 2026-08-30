CREATE TABLE stripe_meter_effects (
    delivery_id text PRIMARY KEY,
    caller_instance text NOT NULL,
    request_hash bytea NOT NULL,
    scope_kind text NOT NULL,
    scope_id text NOT NULL,
    subject text NOT NULL,
    meter_alias text NOT NULL,
    stripe_event_name text NOT NULL,
    quantity text NOT NULL,
    occurred_at timestamptz NOT NULL,
    status text NOT NULL,
    provider_reference text,
    failure_code text,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    completed_at timestamptz,
    CONSTRAINT stripe_meter_quantity_valid CHECK (quantity ~ '^(0|[1-9][0-9]*)$'),
    CONSTRAINT stripe_meter_effect_status_valid CHECK (
        status IN ('prepared', 'in_flight', 'accepted', 'known_failure', 'effect_unknown')
    ),
    CONSTRAINT stripe_meter_effect_result_shape_valid CHECK (
        (status = 'accepted' AND provider_reference IS NOT NULL AND failure_code IS NULL)
        OR (status = 'known_failure' AND provider_reference IS NULL AND failure_code IS NOT NULL)
        OR (status IN ('prepared', 'in_flight', 'effect_unknown') AND provider_reference IS NULL AND failure_code IS NULL)
    )
);

