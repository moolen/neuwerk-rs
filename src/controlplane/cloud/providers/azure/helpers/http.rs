impl AzureProvider {
    async fn token(&self) -> Result<String, CloudError> {
        let url = format!(
            "{}/identity/oauth2/token?api-version={}&resource=https%3A%2F%2Fmanagement.azure.com%2F",
            IMDS_BASE, IMDS_TOKEN_VERSION
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
                "token request failed: {status}"
            )));
        }
        let payload: ImdsToken = response
            .json()
            .await
            .map_err(|err| CloudError::InvalidResponse(err.to_string()))?;
        Ok(payload.access_token)
    }

    async fn get_json<T: for<'de> Deserialize<'de>>(&self, url: String) -> Result<T, CloudError> {
        let token = self.token().await?;
        let response = self
            .client
            .get(url)
            .bearer_auth(token)
            .send()
            .await
            .map_err(|err| CloudError::RequestFailed(err.to_string()))?;
        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|err| CloudError::RequestFailed(err.to_string()))?;
        if !status.is_success() {
            let snippet = body.chars().take(4096).collect::<String>();
            return Err(CloudError::RequestFailed(format!(
                "request failed: {status}, body={snippet}"
            )));
        }
        serde_json::from_str::<T>(&body).map_err(|err| {
            let snippet = body.chars().take(4096).collect::<String>();
            CloudError::InvalidResponse(format!(
                "error decoding response body: {err}, body={snippet}"
            ))
        })
    }

    async fn fetch_nic(&self, nic_id: &str) -> Result<NicResource, CloudError> {
        let url = format!("{nic_id}?api-version={NETWORK_API_VERSION}");
        self.get_json(url).await
    }
}
