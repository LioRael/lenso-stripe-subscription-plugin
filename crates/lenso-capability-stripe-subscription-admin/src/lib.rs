include!("generated.rs");

#[cfg(test)]
mod tests {
    use super::IngestWebhookRequest;

    #[test]
    fn webhook_material_is_redacted_from_debug_evidence() {
        let request = IngestWebhookRequest {
            raw_body: "{\"id\":\"evt_secret\"}".to_owned(),
            signature_header: "t=1,v1=secret".to_owned(),
        };
        let debug = format!("{request:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("evt_secret"));
        assert!(!debug.contains("v1=secret"));
    }
}
