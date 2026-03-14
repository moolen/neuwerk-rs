#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TlsMatchConfig {
    #[serde(default)]
    pub mode: Option<TlsModeValue>,
    pub sni: Option<TlsNameMatchConfig>,
    pub server_dn: Option<String>,
    pub server_san: Option<TlsNameMatchConfig>,
    pub server_cn: Option<TlsNameMatchConfig>,
    #[serde(default)]
    pub fingerprint_sha256: Vec<String>,
    #[serde(default)]
    pub trust_anchors_pem: Vec<String>,
    #[serde(default)]
    pub tls13_uninspectable: Option<Tls13UninspectableValue>,
    #[serde(default)]
    pub http: Option<HttpPolicyConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum TlsModeValue {
    Metadata,
    Intercept,
}

impl From<TlsModeValue> for TlsMode {
    fn from(value: TlsModeValue) -> Self {
        match value {
            TlsModeValue::Metadata => TlsMode::Metadata,
            TlsModeValue::Intercept => TlsMode::Intercept,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum Tls13UninspectableValue {
    Allow,
    Deny,
}

impl From<Tls13UninspectableValue> for Tls13Uninspectable {
    fn from(value: Tls13UninspectableValue) -> Self {
        match value {
            Tls13UninspectableValue::Allow => Tls13Uninspectable::Allow,
            Tls13UninspectableValue::Deny => Tls13Uninspectable::Deny,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(untagged)]
pub enum TlsNameMatchConfig {
    String(String),
    List(Vec<String>),
    Object {
        #[serde(default)]
        exact: Vec<String>,
        regex: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, ToSchema)]
pub struct HttpPolicyConfig {
    #[serde(default)]
    pub request: Option<HttpRequestPolicyConfig>,
    #[serde(default)]
    pub response: Option<HttpResponsePolicyConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, ToSchema)]
pub struct HttpRequestPolicyConfig {
    #[serde(default)]
    pub host: Option<HttpStringMatcherConfig>,
    #[serde(default)]
    pub methods: Vec<String>,
    #[serde(default)]
    pub path: Option<HttpPathMatcherConfig>,
    #[serde(default)]
    pub query: Option<HttpQueryMatcherConfig>,
    #[serde(default)]
    pub headers: Option<HttpHeadersMatcherConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, ToSchema)]
pub struct HttpResponsePolicyConfig {
    #[serde(default)]
    pub headers: Option<HttpHeadersMatcherConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, ToSchema)]
pub struct HttpStringMatcherConfig {
    #[serde(default)]
    pub exact: Vec<String>,
    #[serde(default)]
    pub regex: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, ToSchema)]
pub struct HttpPathMatcherConfig {
    #[serde(default)]
    pub exact: Vec<String>,
    #[serde(default)]
    pub prefix: Vec<String>,
    #[serde(default)]
    pub regex: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, ToSchema)]
pub struct HttpQueryMatcherConfig {
    #[serde(default)]
    pub keys_present: Vec<String>,
    #[serde(default)]
    pub key_values_exact: std::collections::BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub key_values_regex: std::collections::BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, ToSchema)]
pub struct HttpHeadersMatcherConfig {
    #[serde(default)]
    pub require_present: Vec<String>,
    #[serde(default)]
    pub deny_present: Vec<String>,
    #[serde(default)]
    pub exact: std::collections::BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub regex: std::collections::BTreeMap<String, String>,
}

impl TlsNameMatchConfig {
    fn compile(self, rule_id: &str, field: &str) -> Result<TlsNameMatch, String> {
        let (mut exact, regex) = match self {
            TlsNameMatchConfig::String(value) => (Vec::new(), Some(value)),
            TlsNameMatchConfig::List(values) => (values, None),
            TlsNameMatchConfig::Object { exact, regex } => (exact, regex),
        };

        for value in &mut exact {
            *value = normalize_hostname(value);
        }
        exact.retain(|value| !value.is_empty());

        let regex = match regex {
            Some(pattern) => {
                let pattern = pattern.trim();
                if pattern.is_empty() {
                    return Err(format!("rule {rule_id}: {field} regex cannot be empty"));
                }
                Some(
                    RegexBuilder::new(pattern)
                        .case_insensitive(true)
                        .build()
                        .map_err(|err| format!("rule {rule_id}: invalid {field} regex: {err}"))?,
                )
            }
            None => None,
        };

        let matcher = TlsNameMatch { exact, regex };
        if matcher.is_empty() {
            return Err(format!("rule {rule_id}: {field} matcher cannot be empty"));
        }
        Ok(matcher)
    }
}

impl HttpPolicyConfig {
    fn compile(self, rule_id: &str) -> Result<TlsInterceptHttpPolicy, String> {
        let request = match self.request {
            Some(request) => Some(request.compile(rule_id)?),
            None => None,
        };
        let response = match self.response {
            Some(response) => Some(response.compile(rule_id)?),
            None => None,
        };

        if request.is_none() && response.is_none() {
            return Err(format!(
                "rule {rule_id}: tls.http requires request and/or response constraints"
            ));
        }

        Ok(TlsInterceptHttpPolicy { request, response })
    }
}

impl HttpRequestPolicyConfig {
    fn compile(self, rule_id: &str) -> Result<HttpRequestPolicy, String> {
        let host = match self.host {
            Some(host) => Some(host.compile(rule_id, "tls.http.request.host")?),
            None => None,
        };
        let mut methods = Vec::new();
        for method in self.methods {
            let method = method.trim().to_ascii_uppercase();
            if method.is_empty() {
                return Err(format!(
                    "rule {rule_id}: tls.http.request.methods entries cannot be empty"
                ));
            }
            methods.push(method);
        }
        let path = match self.path {
            Some(path) => Some(path.compile(rule_id)?),
            None => None,
        };
        let query = match self.query {
            Some(query) => Some(query.compile(rule_id)?),
            None => None,
        };
        let headers = match self.headers {
            Some(headers) => Some(headers.compile(rule_id, "tls.http.request.headers")?),
            None => None,
        };

        Ok(HttpRequestPolicy {
            host,
            methods,
            path,
            query,
            headers,
        })
    }
}

impl HttpResponsePolicyConfig {
    fn compile(self, rule_id: &str) -> Result<HttpResponsePolicy, String> {
        let headers = match self.headers {
            Some(headers) => Some(headers.compile(rule_id, "tls.http.response.headers")?),
            None => None,
        };
        Ok(HttpResponsePolicy { headers })
    }
}

impl HttpStringMatcherConfig {
    fn compile(self, rule_id: &str, field: &str) -> Result<HttpStringMatcher, String> {
        let mut exact = Vec::new();
        for value in self.exact {
            let value = value.trim().to_ascii_lowercase();
            if !value.is_empty() {
                exact.push(value);
            }
        }
        let regex = compile_optional_regex(self.regex, rule_id, field, true)?;
        if exact.is_empty() && regex.is_none() {
            return Err(format!("rule {rule_id}: {field} matcher cannot be empty"));
        }
        Ok(HttpStringMatcher { exact, regex })
    }
}

impl HttpPathMatcherConfig {
    fn compile(self, rule_id: &str) -> Result<HttpPathMatcher, String> {
        let exact = self
            .exact
            .into_iter()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .collect::<Vec<_>>();
        let prefix = self
            .prefix
            .into_iter()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .collect::<Vec<_>>();
        let regex = compile_optional_regex(self.regex, rule_id, "tls.http.request.path", false)?;
        if exact.is_empty() && prefix.is_empty() && regex.is_none() {
            return Err(format!(
                "rule {rule_id}: tls.http.request.path matcher cannot be empty"
            ));
        }
        Ok(HttpPathMatcher {
            exact,
            prefix,
            regex,
        })
    }
}

impl HttpQueryMatcherConfig {
    fn compile(self, rule_id: &str) -> Result<HttpQueryMatcher, String> {
        let keys_present = self
            .keys_present
            .into_iter()
            .map(|key| key.trim().to_string())
            .filter(|key| !key.is_empty())
            .collect::<Vec<_>>();

        let mut key_values_exact = std::collections::BTreeMap::new();
        for (key, values) in self.key_values_exact {
            let key = key.trim().to_string();
            if key.is_empty() {
                return Err(format!(
                    "rule {rule_id}: tls.http.request.query.key_values_exact has empty key"
                ));
            }
            let values = values
                .into_iter()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
                .collect::<Vec<_>>();
            if values.is_empty() {
                return Err(format!(
                    "rule {rule_id}: tls.http.request.query.key_values_exact[{key}] cannot be empty"
                ));
            }
            key_values_exact.insert(key, values);
        }

        let mut key_values_regex = std::collections::BTreeMap::new();
        for (key, regex) in self.key_values_regex {
            let key = key.trim().to_string();
            if key.is_empty() {
                return Err(format!(
                    "rule {rule_id}: tls.http.request.query.key_values_regex has empty key"
                ));
            }
            let compiled = compile_regex(
                &regex,
                rule_id,
                &format!("tls.http.request.query.key_values_regex[{key}]"),
                false,
            )?;
            key_values_regex.insert(key, compiled);
        }

        if keys_present.is_empty() && key_values_exact.is_empty() && key_values_regex.is_empty() {
            return Err(format!(
                "rule {rule_id}: tls.http.request.query matcher cannot be empty"
            ));
        }
        Ok(HttpQueryMatcher {
            keys_present,
            key_values_exact,
            key_values_regex,
        })
    }
}

impl HttpHeadersMatcherConfig {
    fn compile(self, rule_id: &str, field: &str) -> Result<HttpHeadersMatcher, String> {
        let require_present = self
            .require_present
            .into_iter()
            .map(|key| normalize_header_name(&key))
            .filter(|key| !key.is_empty())
            .collect::<Vec<_>>();
        let deny_present = self
            .deny_present
            .into_iter()
            .map(|key| normalize_header_name(&key))
            .filter(|key| !key.is_empty())
            .collect::<Vec<_>>();

        let mut exact = std::collections::BTreeMap::new();
        for (key, values) in self.exact {
            let key = normalize_header_name(&key);
            if key.is_empty() {
                return Err(format!(
                    "rule {rule_id}: {field}.exact has empty header name"
                ));
            }
            let values = values
                .into_iter()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
                .collect::<Vec<_>>();
            if values.is_empty() {
                return Err(format!(
                    "rule {rule_id}: {field}.exact[{key}] cannot be empty"
                ));
            }
            exact.insert(key, values);
        }

        let mut regex = std::collections::BTreeMap::new();
        for (key, pattern) in self.regex {
            let key = normalize_header_name(&key);
            if key.is_empty() {
                return Err(format!(
                    "rule {rule_id}: {field}.regex has empty header name"
                ));
            }
            let compiled =
                compile_regex(&pattern, rule_id, &format!("{field}.regex[{key}]"), false)?;
            regex.insert(key, compiled);
        }

        if require_present.is_empty()
            && deny_present.is_empty()
            && exact.is_empty()
            && regex.is_empty()
        {
            return Err(format!("rule {rule_id}: {field} matcher cannot be empty"));
        }
        Ok(HttpHeadersMatcher {
            require_present,
            deny_present,
            exact,
            regex,
        })
    }
}

impl TlsMatchConfig {
    fn compile(self, rule_id: &str) -> Result<TlsMatch, String> {
        let mode = self.mode.unwrap_or(TlsModeValue::Metadata).into();

        let sni = match self.sni {
            Some(config) => Some(config.compile(rule_id, "tls.sni")?),
            None => None,
        };

        let server_cn = match (self.server_cn, self.server_dn) {
            (Some(config), _) => Some(config.compile(rule_id, "tls.server_cn")?),
            (None, Some(legacy)) => {
                Some(TlsNameMatchConfig::String(legacy).compile(rule_id, "tls.server_dn")?)
            }
            _ => None,
        };

        let server_san = match self.server_san {
            Some(config) => Some(config.compile(rule_id, "tls.server_san")?),
            None => None,
        };

        let mut fingerprints_sha256 = Vec::with_capacity(self.fingerprint_sha256.len());
        for fp in self.fingerprint_sha256 {
            fingerprints_sha256.push(
                parse_sha256_fingerprint(&fp).map_err(|err| format!("rule {rule_id}: {err}"))?,
            );
        }

        let mut trust_anchors = Vec::new();
        for pem in self.trust_anchors_pem {
            trust_anchors.extend(
                parse_pem_cert_chain(&pem).map_err(|err| format!("rule {rule_id}: {err}"))?,
            );
        }

        let tls13_uninspectable = self
            .tls13_uninspectable
            .unwrap_or(Tls13UninspectableValue::Deny)
            .into();

        let intercept_http = match self.http {
            Some(http) => Some(http.compile(rule_id)?),
            None => None,
        };

        match mode {
            TlsMode::Metadata => {
                if intercept_http.is_some() {
                    return Err(format!(
                        "rule {rule_id}: tls.http is only valid when tls.mode is intercept"
                    ));
                }
            }
            TlsMode::Intercept => {
                if sni.is_some()
                    || server_cn.is_some()
                    || server_san.is_some()
                    || !fingerprints_sha256.is_empty()
                    || !trust_anchors.is_empty()
                {
                    return Err(format!(
                        "rule {rule_id}: tls.mode intercept cannot be combined with metadata matchers"
                    ));
                }
                if intercept_http.is_none() {
                    return Err(format!(
                        "rule {rule_id}: tls.mode intercept requires tls.http constraints"
                    ));
                }
            }
        }

        Ok(TlsMatch {
            mode,
            sni,
            server_san,
            server_cn,
            fingerprints_sha256,
            trust_anchors,
            tls13_uninspectable,
            intercept_http,
        })
    }
}
