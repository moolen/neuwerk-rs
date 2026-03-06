impl AzureProvider {
    fn deserialize_zones<'de, D>(deserializer: D) -> Result<Option<Vec<String>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let zones = Option::<Vec<Option<String>>>::deserialize(deserializer)?;
        let Some(zones) = zones else {
            return Ok(None);
        };
        let filtered: Vec<String> = zones.into_iter().filter_map(|zone| zone).collect();
        if filtered.is_empty() {
            Ok(None)
        } else {
            Ok(Some(filtered))
        }
    }

    fn parse_tags(
        tag_string: Option<&str>,
        tag_map: Option<&HashMap<String, String>>,
    ) -> HashMap<String, String> {
        if let Some(tags) = tag_map {
            return tags.clone();
        }
        let mut parsed = HashMap::new();
        let Some(raw) = tag_string else {
            return parsed;
        };
        for entry in raw.split(';') {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            if let Some((key, value)) = entry.split_once(':').or_else(|| entry.split_once('=')) {
                parsed.insert(key.trim().to_string(), value.trim().to_string());
            }
        }
        parsed
    }

    fn parse_time(value: Option<&str>) -> i64 {
        let Some(raw) = value else {
            return 0;
        };
        OffsetDateTime::parse(raw, &Rfc3339)
            .map(|dt| dt.unix_timestamp())
            .unwrap_or(0)
    }

    fn is_management_subnet(name: &str, tags: &HashMap<String, String>) -> bool {
        let lowered = name.to_ascii_lowercase();
        if lowered.contains("mgmt") || lowered.contains("management") {
            return true;
        }
        if TAG_NIC_MANAGEMENT.iter().any(|key| tags.contains_key(*key)) {
            return true;
        }
        TAG_ROLE
            .iter()
            .filter_map(|key| tags.get(*key))
            .map(|value| value.to_ascii_lowercase())
            .any(|value| {
                value == "management"
                    || value == "mgmt"
                    || value == "controlplane"
                    || value == "control-plane"
            })
    }
}
