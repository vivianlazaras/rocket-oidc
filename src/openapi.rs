use crate::auth::ApiKeyGuard;
use okapi::map;
use okapi::openapi3::Responses;
use okapi::openapi3::SecurityScheme;
use okapi::openapi3::SecuritySchemeData;
use rocket_okapi::OpenApiError;
use rocket_okapi::r#gen::OpenApiGenerator;
use rocket_okapi::okapi::schemars;
use rocket_okapi::okapi::schemars::JsonSchema;
use rocket_okapi::request::{OpenApiFromRequest, RequestHeaderInput};
use rocket_okapi::util::add_schema_response;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

#[derive(Debug, Serialize, Clone, Deserialize, JsonSchema)]
pub struct ErrorResponse {
    pub message: String,
    pub code: u16,
}

impl<'a, T: crate::CoreClaims + Serialize + DeserializeOwned + Send + Sync + std::fmt::Debug>
    OpenApiFromRequest<'a> for ApiKeyGuard<T>
{
    // Required method
    fn from_request_input(
        _generator: &mut OpenApiGenerator,
        _name: String,
        _required: bool,
    ) -> Result<RequestHeaderInput, OpenApiError> {
        Ok(RequestHeaderInput::Security(
            "Bearer".into(),
            SecurityScheme {
                description: Some("API Key for authentication".into()),
                data: SecuritySchemeData::Http {
                    scheme: "Bearer".into(),
                    bearer_format: Some("JWT".into()),
                },
                extensions: map![],
            },
            map!["Bearer".into() => vec![]],
        ))
    }

    // Provided method
    fn get_responses(generator: &mut OpenApiGenerator) -> Result<Responses, OpenApiError> {
        let mut responses = Responses::default();
        let schema = generator.json_schema::<ErrorResponse>();
        add_schema_response(&mut responses, 403, "application/json", schema.clone())?;
        add_schema_response(&mut responses, 401, "application/json", schema.clone())?;
        Ok(responses)
    }
}
