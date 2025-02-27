from prometheus_client import Counter, Gauge, Histogram
import time

# Metrics
SCAN_COUNTER = Counter('llm_scans_total', 'Total number of scans')
SCAN_DURATION = Histogram('llm_scan_duration_seconds', 'Scan duration in seconds')
VULNERABILITY_COUNTER = Counter('llm_vulnerabilities_total', 'Total vulnerabilities found', ['type'])
ERROR_COUNTER = Counter('llm_errors_total', 'Total errors', ['type'])

class MetricsMiddleware:
    async def __call__(self, request, call_next):
        start_time = time.time()
        response = await call_next(request)
        duration = time.time() - start_time
        
        # Record request duration
        SCAN_DURATION.observe(duration)
        return response 