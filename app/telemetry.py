"""OpenTelemetry bootstrap — call ``configure_telemetry()`` once at startup."""

import logging
import os

from opentelemetry import metrics, trace
from opentelemetry._logs import set_logger_provider
from opentelemetry.exporter.otlp.proto.grpc._log_exporter import OTLPLogExporter
from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor


def configure_telemetry(app):
    """Set up the OpenTelemetry SDK (Traces, Metrics, Logs) and instrument FastAPI.

    Resource attributes are driven by environment variables:
    * ``OTEL_SERVICE_NAME``    – logical service name (default: ``order-tracker``)
    * ``OTEL_ENV``             – deployment environment (default: ``development``)
    * ``OTEL_SERVICE_VERSION`` – deployed version (default: ``0.0.0``)
    """
    resource = Resource.create(
        {
            "service.name": os.getenv("OTEL_SERVICE_NAME", "order-tracker"),
            "deployment.environment": os.getenv("OTEL_ENV", "development"),
            "service.version": os.getenv("OTEL_SERVICE_VERSION", "0.0.0"),
        }
    )

    # 1. Traces
    tracer_provider = TracerProvider(resource=resource)
    tracer_provider.add_span_processor(
        BatchSpanProcessor(
            OTLPSpanExporter(),
            schedule_delay_millis=1000,
        )
    )
    trace.set_tracer_provider(tracer_provider)

    # 2. Metrics
    metric_reader = PeriodicExportingMetricReader(
        OTLPMetricExporter(),
        export_interval_millis=2000,
    )
    meter_provider = MeterProvider(resource=resource, metric_readers=[metric_reader])
    metrics.set_meter_provider(meter_provider)

    # 3. Logs
    logger_provider = LoggerProvider(resource=resource)
    logger_provider.add_log_record_processor(
        BatchLogRecordProcessor(
            OTLPLogExporter(),
            schedule_delay_millis=1000,
        )
    )
    set_logger_provider(logger_provider)

    handler = LoggingHandler(level=logging.NOTSET, logger_provider=logger_provider)
    logging.getLogger().addHandler(handler)
    logging.getLogger("uvicorn").addHandler(handler)
    logging.getLogger("uvicorn.access").addHandler(handler)

    # 4. Instrument FastAPI
    FastAPIInstrumentor.instrument_app(app)
