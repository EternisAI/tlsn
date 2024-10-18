//! Provider configuration for the verifier

use boa_engine::{js_str, property::Attribute, Context, JsValue, Source};
use jmespath;
use regex::Regex;
use reqwest;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::cell::RefCell;
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error)]
/// ProviderError is the error that is returned when the provider is invalid
pub enum ProviderError {
    /// InvalidRegex is the error that is returned when the regex is invalid
    #[error("Invalid regex '{0}': {1}")]
    InvalidRegex(String, regex::Error),
    /// InvalidJmespath is the error that is returned when the JMESPath expression is invalid
    #[error("Invalid JMESPath expression '{0}': {1}")]
    InvalidJmespath(String, jmespath::JmespathError),
    /// JmespathError is the error that is returned when the JMESPath search fails
    #[error("JMESPath search error: {0}")]
    JmespathError(String),
    /// JsonParseError is the error that is returned when the JSON is invalid
    #[error("Failed to parse JSON: {0}")]
    JsonParseError(serde_json::Error),
    /// PreprocessError is the error that is returned when the preprocess script is invalid
    #[error("Preprocess script error: {0}")]
    PreprocessError(String),
    /// PreProcessScriptError is the error that is returned when the preprocess script is invalid
    #[error("Preprocess script error: {0}")]
    PreProcessScriptError(String),
    /// ProcessError is the error that is returned when the process script is invalid
    #[error("Process script error: {0}")]
    ProcessError(String),
    /// RequestError is the error that is returned when the request to the provider fails
    #[error("Failed to make request to provider: {0}")]
    RequestError(reqwest::Error),
    /// ResponseParseError is the error that is returned when the response is invalid
    #[error("Failed to parse response: {0}")]
    ResponseParseError(reqwest::Error),
    /// SchemaError is the error that is returned when the schema is invalid
    #[error("Invalid schema: {0}")]
    SchemaError(String),
    /// ValidationError is the error that is returned when the JSON does not match the schema
    #[error("JSON validation failed: {0}")]
    ValidationError(String),
    /// CacheError is the error that is returned when the cache is invalid
    #[error("Cache error: {0}")]
    CacheError(String),
}

thread_local! {
    static COMPILED_ATTRIBUTES_CACHE: RefCell<HashMap<u32, Vec<jmespath::Expression<'static>>>> = RefCell::new(HashMap::new());
    static COMPILED_REGEX_CACHE: RefCell<HashMap<u32, Regex>> = RefCell::new(HashMap::new());
    static COMPILED_PREPROCESS_CACHE: RefCell<HashMap<u32, Context>> = RefCell::new(HashMap::new());
}

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
    pub async fn new(url: String, schema_url: String) -> Result<Self, ProviderError> {
        // Fetch schema content from schema_url
        let schema_response = reqwest::get(&schema_url)
            .await
            .map_err(|e| ProviderError::RequestError(e))?;

        let schema_json = schema_response
            .json::<serde_json::Value>()
            .await
            .map_err(|e| ProviderError::ResponseParseError(e))?;

        // Fetch data content from url
        let data_response = reqwest::get(&url)
            .await
            .map_err(|e| ProviderError::RequestError(e))?;

        let data_json = data_response
            .json::<Value>()
            .await
            .map_err(|e| ProviderError::ResponseParseError(e))?;

        // Validate data_json against schema_json
        let compiled_schema = jsonschema::Validator::new(&schema_json)
            .map_err(|e| ProviderError::SchemaError(e.to_string()))?;

        if let Err(errors) = compiled_schema.validate(&data_json) {
            return Err(ProviderError::ValidationError(
                errors.map(|e| e.to_string()).collect::<Vec<_>>().join(", "),
            )
            .into());
        }

        let config_json: Config =
            serde_json::from_value(data_json).map_err(|e| ProviderError::JsonParseError(e))?;

        Ok(Self {
            url,
            schema_url,
            config: config_json,
        })
    }

    /// Process the response using the providers
    pub fn process(
        &self,
        url: &str,
        method: &str,
        response: &str,
    ) -> Result<Vec<String>, ProviderError> {
        let mut result: Vec<String> = Vec::new();
        for provider in &self.config.providers {
            match provider.check_url_method(url, method) {
                Ok(true) => {
                    let processed_response = provider
                        .preprocess_response(response)
                        .map_err(|e| ProviderError::ProcessError(e.to_string()))?;
                    match provider.get_attributes(&processed_response) {
                        Ok(attributes) => {
                            for attribute in attributes {
                                let attribute_str = attribute.to_string();
                                result.push(attribute_str);
                            }
                        }
                        Err(e) => {
                            tracing::error!("Failed to get attributes: {}", e);
                            return Err(ProviderError::ProcessError(e.to_string()));
                        }
                    }
                    break;
                }
                Ok(false) => {
                    tracing::debug!("Skipping provider: {}", provider.id);
                }
                Err(e) => {
                    tracing::error!("Failed to check url method: {}", e);
                    return Err(ProviderError::ProcessError(e.to_string()));
                }
            }
        }
        Ok(result)
    }
}

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
    /// Get the compiled attributes from the JMESPath expressions
    fn get_compiled_attributes<F>(&self, f: F) -> Result<Vec<String>, ProviderError>
    where
        F: FnOnce(&Vec<jmespath::Expression<'static>>) -> Result<Vec<String>, ProviderError>,
    {
        // Use the thread-local cache
        COMPILED_ATTRIBUTES_CACHE.with(|cache| {
            let mut cache = cache.borrow_mut();
            if let Some(compiled_exprs) = cache.get(&self.id) {
                // Return the cached compiled expressions
                return f(compiled_exprs);
            } else {
                // Compile the expressions and store them in the cache
                let compiled_exprs = self
                    .attributes
                    .as_deref()
                    .unwrap_or(&[])
                    .iter()
                    .filter(|attr| !attr.is_empty())
                    .map(|attr| {
                        jmespath::compile(attr)
                            .map_err(|e| ProviderError::InvalidJmespath(attr.to_string(), e))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                // Cache the compiled expressions
                cache.insert(self.id, compiled_exprs);
                if let Some(compiled_exprs) = cache.get(&self.id) {
                    return f(compiled_exprs);
                }
                return Err(ProviderError::CacheError(
                    "Failed to get compiled attributes".to_string(),
                ));
            }
        })
    }

    /// Get the compiled regex from the thread-local cache
    fn get_compiled_regex<F>(&self, f: F) -> Result<bool, ProviderError>
    where
        F: FnOnce(&Regex) -> Result<bool, ProviderError>,
    {
        COMPILED_REGEX_CACHE.with(|cache| {
            let mut cache = cache.borrow_mut();
            if let Some(compiled_regex) = cache.get(&self.id) {
                return f(compiled_regex);
            } else {
                let regex = Regex::new(&self.url_regex)
                    .map_err(|e| ProviderError::InvalidRegex(self.url_regex.to_string(), e))?;
                cache.insert(self.id, regex);
                if let Some(compiled_regex) = cache.get(&self.id) {
                    return f(compiled_regex);
                }
                return Err(ProviderError::CacheError(
                    "Failed to get compiled regex".to_string(),
                ));
            }
        })
    }

    /// Get the compiled preprocess from the thread-local cache
    fn get_compiled_preprocess<F>(&self, f: F) -> Result<Value, ProviderError>
    where
        F: FnOnce(&mut Context) -> Result<Value, ProviderError>,
    {
        COMPILED_PREPROCESS_CACHE.with(|cache| {
            let mut cache = cache.borrow_mut();
            if let Some(context) = cache.get_mut(&self.id) {
                return f(context);
            }
            let mut context = Context::default();
            if let Some(preprocess) = &self.preprocess {
                context
                    .eval(Source::from_bytes(preprocess))
                    .map_err(|e| ProviderError::PreProcessScriptError(e.to_string()))?;
            }
            cache.insert(self.id, context);
            if let Some(context) = cache.get_mut(&self.id) {
                return f(context);
            }
            Err(ProviderError::CacheError(
                "Failed to get compiled preprocess".to_string(),
            ))
        })
    }

    /// Preprocess the response using the preprocess JMESPath expression
    pub fn preprocess_response(&self, response: &str) -> Result<Value, ProviderError> {
        if let Some(_preprocess) = &self.preprocess {
            return self.get_compiled_preprocess(|context| {
                let js_string = JsValue::String(response.to_string().into());
                context
                    .register_global_property(js_str!("response"), js_string, Attribute::all())
                    .map_err(|e| ProviderError::PreprocessError(e.to_string()))?;

                let value = context
                    .eval(Source::from_bytes("process(response)"))
                    .map_err(|e| ProviderError::PreprocessError(e.to_string()))?;
                let json = value
                    .to_json(context)
                    .map_err(|e| ProviderError::PreProcessScriptError(e.to_string()))?;
                tracing::debug!("preprocess result: {:?}", json);
                Ok(json)
            });
        }
        Ok(serde_json::from_str(response).map_err(|e| ProviderError::JsonParseError(e))?)
    }

    /// Get the attributes from the response using the JMESPath expressions
    pub fn get_attributes(
        &self,
        response: &serde_json::Value,
    ) -> Result<Vec<String>, ProviderError> {
        let mut result: Vec<String> = Vec::new();
        self.get_compiled_attributes(|compiled_jmespaths| {
            for compiled_jmespath in compiled_jmespaths {
                let search_result = compiled_jmespath
                    .search(response)
                    .map_err(|e| ProviderError::JmespathError(e.to_string()))?;
                if let Some(result_map) = search_result.as_object() {
                    for (key, value) in result_map {
                        result.push(format!("{}: {}", key, value.to_string()));
                    }
                }
            }
            Ok(result)
        })
    }

    /// Check if the url and method match the provider's url_regex and method
    pub fn check_url_method(&self, url: &str, method: &str) -> Result<bool, ProviderError> {
        self.get_compiled_regex(|regex| Ok(regex.is_match(url) && self.method == method))
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
    use tokio;

    const MISSING_ATTRIBUTES_PROVIDER_TEXT: &str = r#"{
        "id": 7,
        "host": "github.com",
        "urlRegex": "^https:\\/\\/api\\.github\\.com\\/users\\/[a-zA-Z0-9]+(\\?.*)?$",
        "targetUrl": "https://github.com",
        "method": "GET",
        "title": "Github profile",
        "description": "Go to your profile",
        "icon": "https://github.githubassets.com/images/modules/logos_page/GitHub-Mark.png",  
        "responseType": "json"
    }"#;

    #[test]
    fn test_missing_attributes_provider() {
        let provider: Provider = serde_json::from_str(MISSING_ATTRIBUTES_PROVIDER_TEXT)
            .expect("Failed to parse provider");
        let response_text = r#"{
            "login": "saberistic",
            "id": 4715448,    
            "public_repos": 47,
            "public_gists": 0
    }"#;
        let parsed_response: serde_json::Value =
            serde_json::from_str(response_text).expect("Failed to parse response text");
        let processed_response = provider
            .preprocess_response(&parsed_response.to_string())
            .expect("Failed to preprocess response");
        let result = provider
            .get_attributes(&processed_response)
            .expect("Failed to get attributes");
        assert_eq!(result.len(), 0);
    }

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

    #[test]
    fn test_check_url_method() {
        let provider: Provider =
            serde_json::from_str(JSON_PROVIDER_TEXT).expect("Failed to parse provider");
        assert!(provider
            .check_url_method("https://api.github.com/users/saberistic", "GET")
            .expect("Failed to check url method"));
        assert!(!provider
            .check_url_method("https://api.github.com/users/saberistic/followers", "GET")
            .expect("Failed to check url method"));
    }

    #[test]
    fn test_provider_json() {
        let provider: Provider =
            serde_json::from_str(JSON_PROVIDER_TEXT).expect("Failed to parse provider");
        tracing::info!("provider: {:?}", provider);

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
        let processed_response = provider
            .preprocess_response(&parsed_response.to_string())
            .expect("Failed to preprocess response");
        let result = provider
            .get_attributes(&processed_response)
            .expect("Failed to get attributes");
        assert_eq!(result.len(), 4);
        assert!(result.contains(&"followers: 94".to_string()));
        assert!(result.contains(&"following: 80".to_string()));
        assert!(result.contains(&"public_repos: 47".to_string()));
        assert!(result.contains(&"is_active: true".to_string()));
    }

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
        "preprocess": "function process(htmlString) { const getValueById = (id) => { const regex = new RegExp(`<h1 id=\"${id}\">(.*?)</h1>`, 'i'); const match = htmlString.match(regex); return match ? parseInt(match[1], 10) : null; }; return { followers: getValueById('followers'), following: getValueById('following'), public_repos: getValueById('public_repos') }; }",
        "attributes": ["{total: sum([followers, following])}"]
    }"#;

    #[test]
    fn test_provider_text() {
        let provider: Provider =
            serde_json::from_str(TEXT_PROVIDER_TEXT).expect("Failed to parse provider");
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
        let result = provider
            .get_attributes(&result)
            .expect("Failed to get attributes");
        assert_eq!(result.len(), 1);
        assert!(result.contains(&"total: 174.0".to_string()));
    }

    const SSA_PROVIDER_TEXT: &str = r#"{
        "id": 4,
        "host": "secure.ssa.gov",
        "urlRegex": "https://secure.ssa.gov/myssa/myprofile-api/profileInfo",
        "targetUrl": "https://secure.ssa.gov/myssa/myprofile-ui/main",
        "method": "GET",
        "transport": "xmlhttprequest",
        "title": "US SSA",
        "description": "Go to your profile",
        "icon": "https://brandslogos.com/wp-content/uploads/images/large/us-social-security-administration-logo-black-and-white.png",
        "responseType": "json",
        "attributes": ["{age: age, isValid: length(loggedInUserInfo.cossn) == `11` } "],
        "preprocess": "function process(jsonString) { const startIndex = jsonString.indexOf('{'); const endIndex = jsonString.lastIndexOf('}') + 1; if (startIndex === -1 || endIndex === 0) { return {}; } try { const cleanedResponse = jsonString.slice(startIndex, endIndex); const s = JSON.parse(cleanedResponse); const currentDate = new Date(); const currentYear = currentDate.getFullYear(); let age = currentYear - s.loggedInUserInfo.dobYear; const currentMonth = currentDate.getMonth(); const currentDay = currentDate.getDate(); if (currentMonth === 0 && currentDay < 1) { age--; } s.age = age; return s; } catch (e) { return {}; }  }"
      }"#;

    const SSA_RESPONSE_TEXT: &str = r#"
          1e0
          {
              "responseStatus": {
                "returnCode": "0000",
                "reasonCode": "0000",
                "reasonDescription": "Successfully obtained the profile info"
              },
              "urlPath": "/myssa/bec-plan-prep-ui/",
              "loggedInUserInfo": {
                  "cossn": "***-**-9999",
                  "name": {
                    "firstName": "JOHN",
                    "middleName": "",
                    "lastName": "DOE",
                    "suffix": ""
                  },
                  "formattedName": "John Doe",
                  "otherServicesInd": "N",
                  "messageCount": "",
                  "dobYear": "1999",
                  "dobMonth": "09",
                  "dobDay": "09",
                  "contactDisplayInd": "N",
                  "bankingDisplayInd": "N"
              }
          }
          0"#;

    #[test]
    fn test_ssa_provider() {
        let provider: Provider =
            serde_json::from_str(SSA_PROVIDER_TEXT).expect("Failed to parse provider");
        let processed_response = provider
            .preprocess_response(&SSA_RESPONSE_TEXT)
            .expect("Failed to preprocess response");
        let result = provider
            .get_attributes(&processed_response)
            .expect("Failed to get attributes");
        assert_eq!(result.len(), 2);
        assert!(result.contains(&"age: 25.0".to_string()));
        assert!(result.contains(&"isValid: true".to_string()));
    }

    #[tokio::test]
    async fn test_processor() {
        let processor = Processor::new("https://eternis-extension-providers.s3.us-east-1.amazonaws.com/test/provider-example.json".to_string(), "https://eternis-extension-providers.s3.us-east-1.amazonaws.com/test/provider-schema.json".to_string()).await.expect("Failed to initialize processor");
        let result = processor
            .process(
                "https://secure.ssa.gov/myssa/myprofile-api/profileInfo",
                "GET",
                SSA_RESPONSE_TEXT,
            )
            .expect("Failed to process");
        assert_eq!(result.len(), 2);
        assert!(result.contains(&"age: 25.0".to_string()));
        assert!(result.contains(&"isValid: true".to_string()));
    }
}
