use reqwest;
use serde_json;

#[derive(Debug, Clone)]
pub struct ProviderConfig {
    pub url: String,
    pub schema_url: String,
}

impl ProviderConfig {
    pub async fn new(url: String, schema_url: String) -> Self {
        // Fetch schema content from schema_url
        let schema_response = reqwest::get(&schema_url)
            .await
            .expect("Failed to fetch schema_url");

        let schema_json = schema_response.json::<serde_json::Value>()
            .await
            .expect("Failed to parse schema content as JSON");

        // Fetch data content from url
        let data_response = reqwest::get(&url)
            .await
            .expect("Failed to fetch url");

        let data_json = data_response.json::<serde_json::Value>()
            .await
            .expect("Failed to parse data content as JSON");

        // Validate data_json against schema_json
        let compiled_schema = jsonschema::Validator::new(&schema_json)
            .expect("Invalid JSON schema");

        if let Err(errors) = compiled_schema.validate(&data_json) {
            panic!(
                "JSON validation failed: {:?}",
                errors.map(|e| e.to_string()).collect::<Vec<_>>()
            );
        }
        Self { url, schema_url }
    }
}
