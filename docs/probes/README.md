# OWASP Top 10 LLM Probes

## LLM01: Prompt Injection
- DirectInjectionProbe: Tests for direct prompt injection attempts
- IndirectInjectionProbe: Tests for indirect/subtle injection techniques

## LLM02: Data Disclosure
...

## Implementation Guide
To create a new probe:
1. Inherit from BaseProbe
2. Define test cases and patterns
3. Implement run() method
4. Add appropriate findings 