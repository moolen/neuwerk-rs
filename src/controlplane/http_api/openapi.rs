use std::path::Path;

use axum::body::Body;
use axum::http::header::CONTENT_TYPE;
use axum::http::HeaderValue;
use axum::response::Response;
use serde::{Deserialize, Serialize};
use utoipa::openapi::security::{ApiKey, ApiKeyValue, HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{Modify, OpenApi, ToSchema};

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ErrorBody {
    pub error: String,
}

struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi
            .components
            .get_or_insert_with(utoipa::openapi::Components::new);
        components.add_security_scheme(
            "bearerAuth",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .bearer_format("JWT")
                    .build(),
            ),
        );
        components.add_security_scheme(
            "sessionCookie",
            SecurityScheme::ApiKey(ApiKey::Cookie(ApiKeyValue::new("neuwerk_auth"))),
        );
    }
}

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Neuwerk HTTP API",
        description = "OpenAPI document for the Neuwerk control-plane management API.",
        version = "0.1.0"
    ),
    paths(
        super::auth_routes::auth_token_login,
        super::auth_routes::auth_logout,
        super::auth_routes::auth_whoami,
        super::sso_auth_routes::auth_sso_supported_providers,
        super::policy::get_policy_singleton,
        super::policy::put_policy_singleton,
        super::integrations::list_integrations,
        super::integrations::get_integration,
        super::integrations::create_integration,
        super::integrations::update_integration,
        super::integrations::delete_integration,
        super::service_accounts_api::list_service_accounts,
        super::service_accounts_api::create_service_account,
        super::service_accounts_api::update_service_account,
        super::service_accounts_api::delete_service_account,
        super::service_accounts_api::list_service_account_tokens,
        super::service_accounts_api::create_service_account_token,
        super::service_accounts_api::revoke_service_account_token,
        super::performance_mode::get_performance_mode,
        super::performance_mode::put_performance_mode,
        super::threats::get_threat_settings,
        super::threats::put_threat_settings,
        super::threats::list_threat_silences,
        super::threats::post_threat_silences,
        super::threats::delete_threat_silence,
        super::threats::threat_findings,
        super::threats::threat_feed_status,
        super::tls_intercept::get_tls_intercept_ca,
        super::tls_intercept::get_tls_intercept_ca_cert,
        super::tls_intercept::put_tls_intercept_ca,
        super::tls_intercept::generate_tls_intercept_ca,
        super::tls_intercept::delete_tls_intercept_ca,
        super::app_routes::list_dns_cache,
        super::app_routes::stats_handler
    ),
    components(
        schemas(
            ErrorBody,
            crate::controlplane::policy_config::RuleMode,
            crate::controlplane::policy_config::PolicyConfig,
            crate::controlplane::policy_config::MatchModeValue,
            crate::controlplane::policy_config::SourceGroupConfig,
            crate::controlplane::policy_config::SourcesConfig,
            crate::controlplane::policy_config::KubernetesSourceConfig,
            crate::controlplane::policy_config::KubernetesPodSelectorConfig,
            crate::controlplane::policy_config::KubernetesNodeSelectorConfig,
            crate::controlplane::policy_config::RuleConfig,
            crate::controlplane::policy_config::RuleMatchConfig,
            crate::controlplane::policy_config::PolicyValue,
            crate::controlplane::policy_config::ProtoValue,
            crate::controlplane::policy_config::PortSpec,
            crate::controlplane::policy_config::TlsMatchConfig,
            crate::controlplane::policy_config::TlsModeValue,
            crate::controlplane::policy_config::Tls13UninspectableValue,
            crate::controlplane::policy_config::TlsNameMatchConfig,
            crate::controlplane::policy_config::HttpPolicyConfig,
            crate::controlplane::policy_config::HttpRequestPolicyConfig,
            crate::controlplane::policy_config::HttpResponsePolicyConfig,
            crate::controlplane::policy_config::HttpStringMatcherConfig,
            crate::controlplane::policy_config::HttpPathMatcherConfig,
            crate::controlplane::policy_config::HttpQueryMatcherConfig,
            crate::controlplane::policy_config::HttpHeadersMatcherConfig,
            crate::controlplane::integrations::IntegrationKind,
            crate::controlplane::integrations::IntegrationView,
            crate::controlplane::service_accounts::ServiceAccountStatus,
            crate::controlplane::service_accounts::ServiceAccountRole,
            crate::controlplane::service_accounts::ServiceAccount,
            crate::controlplane::service_accounts::TokenStatus,
            crate::controlplane::service_accounts::TokenMeta,
            crate::controlplane::threat_intel::settings::ThreatIntelSettings,
            crate::controlplane::threat_intel::settings::ThreatBaselineFeeds,
            crate::controlplane::threat_intel::settings::ThreatFeedToggle,
            crate::controlplane::threat_intel::settings::ThreatRemoteEnrichmentSettings,
            crate::controlplane::threat_intel::silences::ThreatSilenceKind,
            crate::controlplane::threat_intel::silences::ThreatSilenceEntry,
            crate::controlplane::threat_intel::silences::ThreatSilenceList,
            crate::controlplane::threat_intel::types::ThreatSeverity,
            crate::controlplane::threat_intel::types::ThreatIndicatorType,
            crate::controlplane::threat_intel::types::ThreatObservationLayer,
            crate::controlplane::threat_intel::store::ThreatMatchSource,
            crate::controlplane::threat_intel::store::ThreatEnrichmentStatus,
            crate::controlplane::threat_intel::store::ThreatFeedHit,
            crate::controlplane::threat_intel::store::ThreatFinding,
            crate::controlplane::threat_intel::store::ThreatFindingQuery,
            crate::controlplane::threat_intel::store::ThreatFindingQueryResponse,
            crate::controlplane::threat_intel::store::ThreatNodeQueryError,
            crate::controlplane::threat_intel::manager::ThreatRefreshOutcome,
            crate::controlplane::threat_intel::manager::ThreatFeedIndicatorCounts,
            crate::controlplane::threat_intel::manager::ThreatFeedStatusItem,
            crate::controlplane::threat_intel::manager::ThreatFeedRefreshState,
            super::threats::ThreatIntelSettingsStatus,
            super::threats::ThreatIntelSettingsUpdateRequest,
            super::threats::ThreatSilenceCreateRequest,
            crate::controlplane::metrics::StatsSnapshot,
            crate::controlplane::metrics::DataplaneStats,
            crate::controlplane::metrics::DecisionCounters,
            crate::controlplane::metrics::DnsStats,
            crate::controlplane::metrics::TlsStats,
            crate::controlplane::metrics::DhcpStats,
            crate::controlplane::metrics::ClusterStats,
            crate::controlplane::metrics::ClusterNodeCatchup,
            crate::controlplane::wiretap::DnsCacheEntry,
            crate::controlplane::sso::SsoProviderKind
        )
    ),
    tags(
        (name = "Auth", description = "Session and identity endpoints"),
        (name = "Policies", description = "Policy management endpoints"),
        (name = "Integrations", description = "External integration management"),
        (name = "Service Accounts", description = "Service account and token lifecycle"),
        (name = "Settings", description = "Mutable runtime and certificate settings"),
        (name = "Threats", description = "Threat-intelligence findings and feed status"),
        (name = "Diagnostics", description = "Operational state and runtime statistics")
    ),
    modifiers(&SecurityAddon)
)]
struct HttpApiDoc;

pub fn openapi_document() -> utoipa::openapi::OpenApi {
    HttpApiDoc::openapi()
}

pub fn openapi_json_pretty() -> Result<String, String> {
    serde_json::to_string_pretty(&openapi_document()).map_err(|err| err.to_string())
}

pub fn write_openapi_json(path: impl AsRef<Path>) -> Result<(), String> {
    let path = path.as_ref();
    let json = openapi_json_pretty()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|err| err.to_string())?;
    }
    std::fs::write(path, json).map_err(|err| err.to_string())
}

pub async fn openapi_json() -> Response {
    match openapi_json_pretty() {
        Ok(json) => {
            let mut response = Response::new(Body::from(json));
            response
                .headers_mut()
                .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
            response
        }
        Err(err) => super::extractors::error_response(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("openapi generation failed: {err}"),
        ),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn openapi_contains_core_paths() {
        let json = super::openapi_json_pretty().expect("openapi json");
        let value: serde_json::Value = serde_json::from_str(&json).expect("json parse");
        let paths = value
            .get("paths")
            .and_then(|value| value.as_object())
            .expect("paths object");
        assert!(paths.contains_key("/api/v1/policy"));
        assert!(paths.contains_key("/api/v1/service-accounts"));
        assert!(paths.contains_key("/api/v1/settings/performance-mode"));
        assert!(paths.contains_key("/api/v1/settings/threat-intel"));
    }
}
