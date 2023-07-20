use surf::utils::async_trait;

#[async_trait]
pub trait StatusUpdaterCallback {
    fn update_status(
        &mut self,
        current_action: u16,
        max_action: u16,
        min_global_ratio: f32,
        max_global_ratio: f32,
    );
    async fn complete_action(&mut self);
}

pub struct StatusUpdater {
    request_id: String,
    token: String,
    last_updated: std::time::Instant,
    http_client: surf::Client,
    current_action: u16,
    max_action: u16,
    min_global_ratio: f32,
    max_global_ratio: f32,
}

impl StatusUpdater {
    pub fn new(address: surf::Url, request_id: &str, token: &str, room_id: &str) -> Self {
        StatusUpdater {
            request_id: request_id.to_string(),
            token: token.to_string(),
            last_updated: std::time::Instant::now(),
            http_client: surf::Config::new()
                .set_base_url(address.join(&format!("rooms/{}/", room_id)).unwrap())
                .set_timeout(None)
                .try_into()
                .unwrap(),
            current_action: 0,
            max_action: 0,
            min_global_ratio: 0.0,
            max_global_ratio: 0.0,
        }
    }
}

#[async_trait]
impl StatusUpdaterCallback for StatusUpdater {
    fn update_status(
        &mut self,
        current_action: u16,
        max_action: u16,
        min_global_ratio: f32,
        max_global_ratio: f32,
    ) {
        self.current_action = current_action;
        self.max_action = max_action;
        self.min_global_ratio = min_global_ratio;
        self.max_global_ratio = max_global_ratio;
    }
    async fn complete_action(&mut self) {
        if self.last_updated.elapsed().as_secs() > 2 {
            self.last_updated = std::time::Instant::now();
            let progress_percentage: f32 = (self.min_global_ratio as f32) * 100 as f32
                + (self.current_action as f32 / self.max_action as f32)
                    * 100.0 as f32
                    * (self.max_global_ratio - self.min_global_ratio);
            println!("report progress: {}% ", progress_percentage as u16);
            let _ = self
                .http_client
                .post("status")
                .header("X-Request-ID", self.request_id.to_string())
                .header("X-Token", self.token.to_string())
                .body(format!("{}", progress_percentage as u16))
                .await;
        }
    }
}
