use eyre::{
    Result,
    WrapErr,
};
use opentelemetry::KeyValue;
use opentelemetry_sdk::{
    runtime,
    trace::{
        BatchConfig,
        RandomIdGenerator,
        Sampler,
        Tracer,
    },
    Resource,
};
use opentelemetry_semantic_conventions::{
    resource::{
        DEPLOYMENT_ENVIRONMENT,
        SERVICE_NAME,
        SERVICE_VERSION,
    },
    SCHEMA_URL,
};
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::{
    layer::SubscriberExt,
    util::SubscriberInitExt,
    Registry,
};

pub(super) fn setup(log_level: tracing::Level) -> Result<()> {
    Registry::default()
        .with(tracing_subscriber::EnvFilter::new(format!("{log_level}")))
        .with(tracing_subscriber::fmt::layer())
        .with(OpenTelemetryLayer::new(
            init_tracer().context("Failed to initialize tracer")?,
        ))
        .init();

    Ok(())
}

pub(super) fn resource() -> Resource {
    Resource::from_schema_url(
        [
            KeyValue::new(SERVICE_NAME, env!("CARGO_PKG_NAME")),
            KeyValue::new(SERVICE_VERSION, env!("CARGO_PKG_VERSION")),
            #[cfg(debug_assertions)]
            KeyValue::new(DEPLOYMENT_ENVIRONMENT, "develop"),
            #[cfg(not(debug_assertions))]
            KeyValue::new(DEPLOYMENT_ENVIRONMENT, "release"),
        ],
        SCHEMA_URL,
    )
}

pub(super) fn init_tracer() -> Result<Tracer, opentelemetry::trace::TraceError> {
    opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_trace_config(
            opentelemetry_sdk::trace::Config::default()
                // Customize sampling strategy
                .with_sampler(Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(
                    1.0,
                ))))
                // If export trace to AWS X-Ray, you can use XrayIdGenerator
                .with_id_generator(RandomIdGenerator::default())
                .with_resource(resource()),
        )
        .with_batch_config(BatchConfig::default())
        .with_exporter(opentelemetry_otlp::new_exporter().tonic())
        .install_batch(runtime::Tokio)
}
