import pytest
from scanner.ui.auth import create_access_token, get_current_user
from starlette.requests import Request

@pytest.mark.asyncio
async def test_create_access_token():
    token = create_access_token({"sub": "test_user"})
    assert isinstance(token, str)

@pytest.mark.asyncio
async def test_get_current_user_no_token():
    request = Request({"type": "http"})
    with pytest.raises(HTTPException) as exc:
        await get_current_user(request)
    assert exc.value.status_code == 401 