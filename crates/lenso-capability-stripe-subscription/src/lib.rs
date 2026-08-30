include!("generated.rs");

#[cfg(test)]
mod tests {
    use super::{CreateCheckoutSessionResponse, CreateCheckoutSessionResponseStatus};

    #[test]
    fn checkout_redirect_url_is_redacted_from_debug_evidence() {
        let response = CreateCheckoutSessionResponse {
            effect_id: "effect_1".to_owned(),
            expires_at: None,
            session_id: Some("cs_test_1".to_owned()),
            status: CreateCheckoutSessionResponseStatus::Accepted,
            url: Some("https://checkout.stripe.com/secret".to_owned()),
        };
        let debug = format!("{response:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("checkout.stripe.com/secret"));
    }
}
