from fastapi import FastAPI, Request, Form, Depends, HTTPException
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from jose import JWTError, jwt
from datetime import datetime, timedelta, timezone
from starlette.status import HTTP_302_FOUND
from fastapi.openapi.utils import get_openapi

app = FastAPI(docs_url=None, redoc_url=None) 
# Dados e config
SECRET_KEY = "IES_SECRET_KEY"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1





# Verificador de autenticação com timezone-aware
def get_current_user(request: Request):
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=401, detail="Token não encontrado")

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        exp_timestamp = payload.get("exp")
        if username is None or exp_timestamp is None:
            raise HTTPException(status_code=401, detail="Token inválido")
        expire = datetime.fromtimestamp(exp_timestamp, tz=timezone.utc)
        if expire < datetime.now(timezone.utc):
            raise HTTPException(status_code=401, detail="Token expirado")
    except JWTError:
        raise HTTPException(status_code=401, detail="Token inválido")

    return username




@app.get("/openapi.json", include_in_schema=False)
def openapi(request: Request, user: str = Depends(get_current_user)):
    return app.openapi()

# Função para criar token com datetime timezone-aware
def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

app = FastAPI()

app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")


# Página de login
@app.get("/")
def home(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

# Rota de login
@app.post("/login", response_class=HTMLResponse)
def login(request: Request, username: str = Form(...), password: str = Form(...)):
    if username == fake_user["username"] and password == fake_user["password"]:
        token = create_access_token({"sub": username})
        response = RedirectResponse(url="/docs", status_code=HTTP_302_FOUND)
        response.set_cookie(key="access_token", value=token, httponly=True)
        return response

    return templates.TemplateResponse("login.html", {
        "request": request,
        "error": "Usuário ou senha inválidos"
    })

# Dependência para proteger as rotas (exemplo proteção /docs)
from fastapi.openapi.docs import get_swagger_ui_html

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
        # Redireciona e remove o cookie
        response = RedirectResponse("/", status_code=302)
        response.delete_cookie("access_token")
        return response

    # Token válido: retorna docs normalmente
    response = get_swagger_ui_html(
        openapi_url=request.app.openapi_url,
        title="Documentação API",
        swagger_favicon_url="/static/favicon.ico"
    )
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response