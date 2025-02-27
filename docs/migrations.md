# Migration Guide

## Version Compatibility Notes

### FastAPI 0.110.0
- Response validation now uses Pydantic v2
- Changes required:
  ```python
  # Old way
  from pydantic import BaseModel
  
  # New way
  from fastapi.responses import JSONResponse
  from pydantic.v1 import BaseModel  # If using v1 models
  ```

### Streamlit 1.31.1
- Session state behavior changes:
  ```python
  # Old way
  st.session_state['key'] = value
  
  # New way (preferred)
  st.session_state.key = value
  ```
- Widget keys must be unique across entire app

### Anthropic 0.18.1
- New client initialization:
  ```python
  # Old way
  client = anthropic.Client(api_key="your_key")
  
  # New way
  client = anthropic.Anthropic(api_key="your_key")
  ```
- Response format changes:
  ```python
  # Old way
  response = client.completion(...)
  text = response.completion
  
  # New way
  message = client.messages.create(...)
  text = message.content
  ```

### Pandas 2.2.1
- DataFrame operations:
  ```python
  # Old way
  df.append(other_df)
  
  # New way
  pd.concat([df, other_df])
  ```
- Type system changes:
  ```python
  # Old way
  df['column'].astype(str)
  
  # New way
  df['column'].convert_dtypes()
  ```

## Troubleshooting Common Issues

### OpenAI API Changes
- API response format changes
- New authentication methods
- Rate limiting behavior changes

### Streamlit UI Issues
- Widget rendering problems
- Session state persistence
- Layout system changes

### FastAPI Endpoint Issues
- Response validation errors
- Dependency injection changes
- CORS configuration updates

## Testing for Compatibility

Run the compatibility test suite:
```bash
pytest tests/compatibility/
```

## Reporting Compatibility Issues

When reporting compatibility issues:
1. Include package versions (`pip freeze`)
2. Provide minimal reproduction code
3. Describe expected vs actual behavior
4. Include error messages and stack traces 