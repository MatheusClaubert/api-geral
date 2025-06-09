from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import RedirectResponse
from fastapi.openapi.docs import get_swagger_ui_html
from jose import jwt, JWTError
from datetime import datetime, timezone

from app.auth import SECRET_KEY, ALGORITHM  # Suas configs de segurança

app = FastAPI()

@app.get("/docs", include_in_schema=False)
def custom_swagger_ui_html(request: Request):
    token = request.cookies.get("access_token")
    if not token:
        return RedirectResponse("/", status_code=302)

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        exp_timestamp = payload.get("exp")
        expire = datetime.fromtimestamp(exp_timestamp, tz=timezone.utc)
        if expire < datetime.now(timezone.utc):
            raise JWTError()  # Token expirado
    except JWTError:
        return RedirectResponse("/", status_code=302)

    response = get_swagger_ui_html(
        openapi_url=request.app.openapi_url,
        title="Documentação API",
        swagger_favicon_url="/static/favicon.ico"
    )
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

@app.get("/openapi.json", include_in_schema=False)
def get_open_api_endpoint(request: Request):
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=401)

    try:
        jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(status_code=401)

    return app.openapi()
