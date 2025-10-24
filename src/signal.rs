use tokio::signal;
use tracing::{
    Level,
    event,
};

pub(super) async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    let signal = tokio::select! {
        () = ctrl_c => {
            "SIGINT (CTRL+C)"
        },
        () = terminate => {
            "SIGTERM"
        },
    };

    event!(
        Level::INFO,
        signal = signal,
        "Signal received, shutting down"
    );
}
