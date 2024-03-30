use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use opentelemetry::metrics::MeterProvider;
use opentelemetry_sdk::runtime;
use opentelemetry_otlp::{ExportConfig, WithExportConfig};
use opentelemetry_sdk::metrics::SdkMeterProvider;


static GLOBAL_METRICS_REPORTER_STATE: AtomicUsize = AtomicUsize::new(UN_SET);

const UN_SET: usize = 0;
const SETTING: usize = 1;
const SET: usize = 2;

static mut GLOBAL_METRICS_REPORTER: Option<TestMetricsReporter> = None;

type TestMetricsReporter = Arc<SdkMeterProvider>;

pub fn init_metrics_reporter() {
    let export_config = ExportConfig {
        endpoint: "http://localhost:4317".to_string(),
        ..ExportConfig::default()
    };
    let provider = opentelemetry_otlp::new_pipeline()
        .metrics(runtime::Tokio)
        .with_exporter(
            opentelemetry_otlp::new_exporter()
                .tonic()
                .with_export_config(export_config),
        )
        .build().unwrap();
    set_metrics_reporter(provider);
}

pub fn increment_metrics(key: String) {
    if let Some(provider) = metrics_reporter() {
        provider.meter("forge-tests")
            .u64_counter(key)
            .init().add(1, &[],);
    }
}

pub fn shutdown_metrics_reporter() {
    if let Some(reporter) = metrics_reporter() {
        reporter.shutdown().unwrap();
    }
}

fn set_metrics_reporter(provider: SdkMeterProvider) {
    if GLOBAL_METRICS_REPORTER_STATE
        .compare_exchange(UN_SET, SETTING, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok()
    {
        unsafe {
            GLOBAL_METRICS_REPORTER = Some(Arc::new(provider));
        }
        GLOBAL_METRICS_REPORTER_STATE.store(SET, Ordering::SeqCst);
    }
}

fn metrics_reporter() -> Option<&'static Arc<SdkMeterProvider>> {
    if GLOBAL_METRICS_REPORTER_STATE.load(Ordering::SeqCst) != SET {
        return None;
    }
    unsafe {
        Some(GLOBAL_METRICS_REPORTER.as_ref().expect(
            "Reporter invariant violated: GLOBAL_METRICS_REPORTER must be initialized before GLOBAL_METRICS_REPORTER_STATE is set",
        ))
    }
}