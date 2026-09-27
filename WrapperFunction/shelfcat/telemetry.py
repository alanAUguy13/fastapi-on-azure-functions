"""
OpenTelemetry wiring.

When APPLICATIONINSIGHTS_CONNECTION_STRING is set (Azure Functions sets it when
Application Insights is linked), traces, metrics and logs are exported to Azure
Monitor. Otherwise the no-op OTel API is used, so local runs and tests need no
configuration.
"""

from __future__ import annotations

import logging
import os

from opentelemetry import metrics, trace

log = logging.getLogger(__name__)
_configured = False


def configure(app) -> None:
    global _configured
    if _configured:
        return
    _configured = True
    if not os.getenv("APPLICATIONINSIGHTS_CONNECTION_STRING"):
        log.info("Azure Monitor export disabled: APPLICATIONINSIGHTS_CONNECTION_STRING not set")
        return
    try:
        from azure.monitor.opentelemetry import configure_azure_monitor
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
    except ImportError:  # pragma: no cover - optional dependency
        log.warning("azure-monitor-opentelemetry not installed; telemetry export disabled")
        return
    configure_azure_monitor(logger_name="shelfcat")
    FastAPIInstrumentor.instrument_app(app, excluded_urls="health")


tracer = trace.get_tracer("shelfcat.truth_api")
_meter = metrics.get_meter("shelfcat.truth_api")

truth_decisions = _meter.create_counter(
    "shelfcat.truth.decisions",
    description="Truth write attempts by outcome (accepted / blocked / unauthorized)",
)
ledger_verifications = _meter.create_counter(
    "shelfcat.ledger.verifications",
    description="Ledger verification runs by result",
)
