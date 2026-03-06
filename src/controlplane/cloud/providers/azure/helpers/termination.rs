impl AzureProvider {
    async fn ensure_termination_notifications_enabled(
        &self,
        subscription_id: &str,
        resource_group: &str,
        vmss_name: &str,
    ) -> Result<(), CloudError> {
        let url = format!(
            "{ARM_BASE}/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.Compute/virtualMachineScaleSets/{vmss_name}?api-version={COMPUTE_API_VERSION}",
        );
        let value: serde_json::Value = self.get_json(url).await?;
        let enabled = value
            .get("properties")
            .and_then(|value| value.get("virtualMachineProfile"))
            .and_then(|value| value.get("scheduledEventsProfile"))
            .and_then(|value| value.get("terminateNotificationProfile"))
            .and_then(|value| value.get("enable").or_else(|| value.get("enabled")))
            .and_then(|value| value.as_bool())
            .unwrap_or(false);
        if enabled {
            Ok(())
        } else {
            Err(CloudError::InvalidResponse(
                "vmss termination notifications disabled (terminateNotificationProfile.enable != true)"
                    .to_string(),
            ))
        }
    }
}
