impl AzureProvider {
    async fn set_instance_protection_provider(
        &self,
        instance: &InstanceRef,
        enabled: bool,
    ) -> Result<CapabilityResult, CloudError> {
        let url = format!(
            "{ARM_BASE}/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Compute/virtualMachineScaleSets/{}/virtualMachines/{}?api-version={COMPUTE_API_VERSION}",
            self.subscription_id, self.resource_group, self.vmss_name, instance.id
        );
        let body = VmssVmUpdateRequest {
            properties: VmssVmUpdateProperties {
                protection_policy: VmssVmProtectionPolicy {
                    protect_from_scale_in: enabled,
                    protect_from_scale_set_actions: enabled,
                },
            },
        };
        let response = self
            .client
            .patch(url)
            .bearer_auth(self.token().await?)
            .json(&body)
            .send()
            .await
            .map_err(|err| CloudError::RequestFailed(err.to_string()))?;
        let status = response.status();
        if !status.is_success() {
            return Err(CloudError::RequestFailed(format!(
                "instance protection update failed: {status}"
            )));
        }
        Ok(CapabilityResult::Applied)
    }

    async fn poll_termination_notice_provider(
        &self,
        instance: &InstanceRef,
    ) -> Result<Option<TerminationEvent>, CloudError> {
        let url = format!(
            "{}/scheduledevents?api-version={}",
            IMDS_BASE, IMDS_SCHEDULED_EVENTS_VERSION
        );
        let response = self
            .client
            .get(url)
            .header("Metadata", "true")
            .send()
            .await
            .map_err(|err| CloudError::RequestFailed(err.to_string()))?;
        let status = response.status();
        if !status.is_success() {
            return Err(CloudError::RequestFailed(format!(
                "scheduled events request failed: {status}"
            )));
        }
        let payload: ScheduledEventsResponse = response
            .json()
            .await
            .map_err(|err| CloudError::InvalidResponse(err.to_string()))?;
        let now = OffsetDateTime::now_utc().unix_timestamp();
        for event in payload.events {
            if !event.is_termination() {
                continue;
            }
            if !event.applies_to(instance) {
                continue;
            }
            let deadline_epoch = event
                .not_before
                .as_deref()
                .and_then(|raw| OffsetDateTime::parse(raw, &Rfc2822).ok())
                .map(|dt| dt.unix_timestamp())
                .or_else(|| event.duration_in_seconds.map(|secs| now + secs))
                .unwrap_or(now);
            return Ok(Some(TerminationEvent {
                id: event.event_id.clone(),
                instance_id: instance.id.clone(),
                deadline_epoch,
            }));
        }
        Ok(None)
    }

    async fn complete_termination_action_provider(
        &self,
        event: &TerminationEvent,
    ) -> Result<CapabilityResult, CloudError> {
        let url = format!(
            "{}/scheduledevents?api-version={}",
            IMDS_BASE, IMDS_SCHEDULED_EVENTS_VERSION
        );
        let body = ScheduledEventAck {
            start_requests: vec![ScheduledEventStartRequest {
                event_id: event.id.clone(),
            }],
        };
        let response = self
            .client
            .post(url)
            .header("Metadata", "true")
            .json(&body)
            .send()
            .await
            .map_err(|err| CloudError::RequestFailed(err.to_string()))?;
        let status = response.status();
        if !status.is_success() {
            return Err(CloudError::RequestFailed(format!(
                "scheduled events acknowledge failed: {status}"
            )));
        }
        Ok(CapabilityResult::Applied)
    }

    fn capabilities_provider(&self) -> IntegrationCapabilities {
        IntegrationCapabilities {
            instance_protection: true,
            termination_notice: true,
            lifecycle_hook: false,
        }
    }
}
