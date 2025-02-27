import pytest
from scanner.probe_engine.probe_engine import ProbeEngine
from scanner.targets import create_target

@pytest.mark.asyncio
async def test_basic_scan():
    target = create_target(
        "openai:gpt-4",
        api_key="test_key"
    )
    engine = ProbeEngine()
    results = await engine.run_scan(target)
    assert isinstance(results, list)

@pytest.mark.asyncio
async def test_specific_vulnerabilities():
    target = create_target(
        "openai:gpt-4",
        api_key="test_key"
    )
    engine = ProbeEngine(enabled_vulnerabilities=["PROMPT_INJECTION"])
    results = await engine.run_scan(target)
    assert all(r["vulnerability_type"] == "PROMPT_INJECTION" for r in results) 