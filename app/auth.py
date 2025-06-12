from datetime import datetime, timedelta, timezone
from jose import jwt

SECRET_KEY = "IES_SECRET_KEY"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 0.01

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

if __name__ == "__main__":
    payload = {"sub": "usuario123"}
    token = create_access_token(payload)
    print("Token JWT gerado:")
    print(token)
    