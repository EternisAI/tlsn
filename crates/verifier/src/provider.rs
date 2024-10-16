//! Provider configuration for the verifier

use boa_engine::{js_str, property::Attribute, Context, JsValue, Source};
use jmespath::{self};
use regex::Regex;
use reqwest;
use serde_json::{self, Value};

/// Processor is the processor configuration for the verifier
#[derive(Debug, Clone)]
pub struct Processor {
    /// Url is the url that the verifier will use to fetch the config
    pub url: String,
    /// Schema url is the url that the verifier will use to fetch the schema
    pub schema_url: String,
    /// Config is the provider configuration for the verifier
    pub config: Config,
}

impl Processor {
    /// Create a new processor
    pub async fn new(url: String, schema_url: String) -> Self {
        // Fetch schema content from schema_url
        let schema_response = reqwest::get(&schema_url)
            .await
            .expect("Failed to fetch schema_url");

        let schema_json = schema_response
            .json::<serde_json::Value>()
            .await
            .expect("Failed to parse schema content as JSON");

        // Fetch data content from url
        let data_response = reqwest::get(&url).await.expect("Failed to fetch url");

        let data_json = data_response
            .json::<Value>()
            .await
            .expect("Failed to parse data content as JSON");

        let config_json: Config = serde_json::from_value(data_json.clone())
            .expect("Failed to parse data content as JSON");

        // Validate data_json against schema_json
        let compiled_schema =
            jsonschema::Validator::new(&schema_json).expect("Invalid JSON schema");

        if let Err(errors) = compiled_schema.validate(&data_json) {
            panic!(
                "JSON validation failed: {:?}",
                errors.map(|e| e.to_string()).collect::<Vec<_>>()
            );
        }

        for provider in config_json.providers.clone() {
            Provider::new(
                provider.id,
                provider.host,
                provider.url_regex,
                provider.target_url,
                provider.method,
                provider.title,
                provider.description,
                provider.icon,
                provider.response_type,
                provider.attributes.clone(),
                provider.preprocess,
            );
        }
        Self {
            url,
            schema_url,
            config: config_json,
        }
    }

    /// Process the response using the providers
    pub fn process(&self, url: &str, method: &str, response: &str) -> Vec<String> {
        let mut result: Vec<String> = Vec::new();
        for provider in self.config.providers.clone() {
            if provider.check_url_method(url, method) {
                let attributes = if provider.response_type != "json" {
                    let processed_response = provider
                        .preprocess_response(response)
                        .expect("Failed to preprocess response");
                    provider.get_attributes(&processed_response)
                } else {
                    let response_json =
                        serde_json::from_str(response).expect("Failed to parse response as JSON");
                    provider.get_attributes(&response_json)
                };
                for attribute in attributes {
                    let attribute_str = attribute.to_string();
                    result.push(attribute_str);
                }
            }
        }
        return result;
    }
}

use serde::{Deserialize, Serialize};

/// Provider is the provider configuration for the verifier
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Provider {
    /// Id is the id of the provider
    pub id: u32,
    /// Host is the host of the provider
    pub host: String,
    /// Url regex is the regex that the url must match
    #[serde(rename = "urlRegex")]
    pub url_regex: String,
    /// Target url is the url that the provider will use
    #[serde(rename = "targetUrl")]
    pub target_url: String,
    /// Method is the HTTP method that the provider will use
    pub method: String,
    /// Title is the title of the provider
    pub title: String,
    /// Description is the description of the provider
    pub description: String,
    /// Icon is the icon of the provider
    pub icon: String,
    /// Response type is the type of the response that the provider will process
    #[serde(rename = "responseType")]
    pub response_type: String,
    /// Attributes is a list of JMESPath expressions that are applied to the response to extract the attributes
    pub attributes: Option<Vec<String>>,
    /// Preprocess is a JMESPath expression that is applied to the response before the attributes are extracted
    pub preprocess: Option<String>,
}

impl Provider {
    /// Create a new provider
    pub fn new(
        id: u32,
        host: String,
        url_regex: String,
        target_url: String,
        method: String,
        title: String,
        description: String,
        icon: String,
        response_type: String,
        attributes: Option<Vec<String>>,
        preprocess: Option<String>,
    ) -> Self {
        // let mut compiled_attributes: Vec<jmespath::Expression> = Vec::new();
        if let Some(attributes) = attributes.clone() {
            for attribute in attributes {
                if attribute != "" {
                    jmespath::compile(&attribute).expect("Invalid JMESPath expression");
                }
            }
        }
        Self {
            id,
            host,
            url_regex,
            target_url,
            method,
            title,
            description,
            icon,
            response_type,
            attributes,
            preprocess,
        }
    }

    /// Preprocess the response using the preprocess JMESPath expression
    pub fn preprocess_response(&self, response: &str) -> Result<Value, Box<dyn std::error::Error>> {
        if let Some(preprocess) = self.preprocess.clone() {
            let mut context = Context::default();
            context
                .eval(Source::from_bytes(preprocess.as_bytes()))
                .expect("Failed to compile preprocess");

            let js_string = JsValue::String(response.to_string().into());
            context
                .register_global_property(js_str!("response"), js_string, Attribute::all())
                .expect("Failed to register global property");

            let value = context
                .eval(Source::from_bytes("convertToJson(response)"))
                .expect("Failed to execute preprocess");
            let json = value
                .to_json(&mut context)
                .expect("Failed to convert to json");
            println!("preprocess result: {:?}", json);
            return Ok(json);
        }
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            "No preprocess",
        )));
    }

    /// Get the attributes from the response using the JMESPath expressions
    pub fn get_attributes(&self, response: &serde_json::Value) -> Vec<String> {
        let mut result: Vec<String> = Vec::new();
        if let Some(attributes) = self.attributes.clone() {
            for attribute in attributes {
                let compiled_jmespath =
                    jmespath::compile(&attribute).expect("Invalid JMESPath expression");
                let search_result = compiled_jmespath
                    .search(&response)
                    .expect("Failed to execute jmespath search");
                if let Some(result_map) = search_result.as_object() {
                    // Iterate over the dynamic keys and values in the result
                    for (key, value) in result_map {
                        result.push(format!("{}: {}", key, value.to_string()));
                    }
                }
            }
        }
        return result;
    }

    /// Check if the url and method match the provider's url_regex and method
    pub fn check_url_method(&self, url: &str, method: &str) -> bool {
        let regex = Regex::new(&self.url_regex).expect("Invalid regex");
        return regex.is_match(url) && self.method == method;
    }
}

/// Config is the provider configuration for the verifier
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Version is the version of the config
    pub version: String,
    /// Expected PCRs is a map of PCR banks and the expected value for each bank
    #[serde(rename = "EXPECTED_PCRS")]
    pub expected_pcrs: std::collections::HashMap<String, String>,
    /// Providers is a list of providers that the verifier will use to process the response
    #[serde(rename = "PROVIDERS")]
    pub providers: Vec<Provider>,
}

#[cfg(test)]
mod tests {
    use super::*;

    const JSON_PROVIDER_TEXT: &str = r#"{
      "id": 7,
      "host": "github.com",
      "urlRegex": "^https:\\/\\/api\\.github\\.com\\/users\\/[a-zA-Z0-9]+(\\?.*)?$",
      "targetUrl": "https://github.com",
      "method": "GET",
      "title": "Github profile",
      "description": "Go to your profile",
      "icon": "https://github.githubassets.com/images/modules/logos_page/GitHub-Mark.png",  
      "responseType": "json",
      "attributes": ["{followers: followers, following: following}", "{public_repos: public_repos}", "{is_active: sum([followers, following]) > public_repos}"]
    }"#;

    const TEXT_PROVIDER_TEXT: &str = r#"{
        "id": 7,
        "host": "chase.com",
        "urlRegex": "^https:\\/\\/api\\.chase\\.com\\/users\\/[a-zA-Z0-9]+(\\?.*)?$",
        "targetUrl": "https://github.com",
        "method": "GET",
        "title": "Github profile",
        "description": "Go to your profile",
        "icon": "https://github.githubassets.com/images/modules/logos_page/GitHub-Mark.png",  
        "responseType": "text",
        "preprocess": "function convertToJson(htmlString) { const getValueById = (id) => { const regex = new RegExp(`<h1 id=\"${id}\">(.*?)</h1>`, 'i'); const match = htmlString.match(regex); return match ? parseInt(match[1], 10) : null; }; return { followers: getValueById('followers'), following: getValueById('following'), public_repos: getValueById('public_repos') }; }",
        "attributes": ["{followers: followers, following: following, public_repos: public_repos}"]
    }"#;

    #[test]
    fn test_check_url_method() {
        let provider: Provider =
            serde_json::from_str(JSON_PROVIDER_TEXT).expect("Failed to parse provider");
        let provider = Provider::new(
            provider.id,
            provider.host,
            provider.url_regex,
            provider.target_url,
            provider.method,
            provider.title,
            provider.description,
            provider.icon,
            provider.response_type,
            provider.attributes,
            provider.preprocess,
        );
        assert!(provider.check_url_method("https://api.github.com/users/saberistic", "GET"));
        assert!(
            !provider.check_url_method("https://api.github.com/users/saberistic/followers", "GET")
        );
    }

    #[test]
    fn test_provider_json() {
        let provider: Provider =
            serde_json::from_str(JSON_PROVIDER_TEXT).expect("Failed to parse provider");
        let provider = Provider::new(
            provider.id,
            provider.host,
            provider.url_regex,
            provider.target_url,
            provider.method,
            provider.title,
            provider.description,
            provider.icon,
            provider.response_type,
            provider.attributes,
            provider.preprocess,
        );
        println!("provider: {:?}", provider);

        let response_text = r#"{
            "login": "saberistic",
            "id": 4715448,    
            "public_repos": 47,
            "public_gists": 0,
            "followers": 94,
            "following": 80,
            "created_at": "2013-06-17T06:21:04Z",
            "updated_at": "2024-08-30T16:35:36Z"
        }"#;
        let parsed_response: serde_json::Value =
            serde_json::from_str(response_text).expect("Failed to parse response text");
        let result = provider.get_attributes(&parsed_response);
        println!("result: {:?}", result);
    }

    #[test]
    fn test_provider_text() {
        let provider: Provider =
            serde_json::from_str(TEXT_PROVIDER_TEXT).expect("Failed to parse provider");
        let provider = Provider::new(
            provider.id,
            provider.host,
            provider.url_regex,
            provider.target_url,
            provider.method,
            provider.title,
            provider.description,
            provider.icon,
            provider.response_type,
            provider.attributes,
            provider.preprocess,
        );
        let response_text = r#"<html>
            <body>
                <h1 id="followers">94</h1>
                <h1 id="following">80</h1>
                <h1 id="public_repos">47</h1>
            </body>
        </html>"#;
        let result = provider
            .preprocess_response(response_text)
            .expect("Failed to preprocess response");
        let result = provider.get_attributes(&result);
        println!("result: {:?}", result);
    }
}
