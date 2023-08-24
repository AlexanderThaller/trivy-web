use axum::{
    self,
    response::IntoResponse,
};

#[tracing::instrument]
#[axum_macros::debug_handler]
pub(super) async fn root() -> impl IntoResponse {
    include_str!("../resources/index.html")
}
