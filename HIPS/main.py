from typing import Optional
from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.responses import JSONResponse
from fastapi_jwt_auth import AuthJWT
from fastapi_jwt_auth.exceptions import AuthJWTException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware

import os
import hashlib
import psutil
import subprocess

app = FastAPI()


origins = [ 
    "http://localhost", 
    "http://localhost:4200" 
]
app.add_middleware(
    CORSMiddleware, 
    allow_origins=origins, 
    allow_credentials=True, 
    allow_methods=["*"], 
    allow_headers=["*"]
)
#rutas
passwd_file = "/etc/passwd"
shadow_file = "/etc/shadow"
#variables
passwd_hash = None
shadow_hash = None


def calculate_file_hash(file_path):
    try:
        with open(file_path, "rb") as file:
            data = file.read()
            file_hash = hashlib.sha256(data).hexdigest()
            return file_hash
    except FileNotFoundError as e:
        print("FileNotFoundError:", e)
        return None
    except Exception as e:
        print("Exception:", e)
        return None

#uvicorn main:app --reload para iniciar




class User(BaseModel):
    username: str
    password: str


# in production you can use Settings management
# from pydantic to get secret key from .env
class Settings(BaseModel):
    authjwt_secret_key: str = "secret"



@AuthJWT.load_config
def get_config():
    return Settings()

@app.on_event("startup")
async def startup_event():
    global passwd_hash, shadow_hash
    passwd_hash = calculate_file_hash(passwd_file)
    shadow_hash = calculate_file_hash(shadow_file)

# exception handler for authjwt
# in production, you can tweak performance using orjson response
@app.exception_handler(AuthJWTException)
def authjwt_exception_handler(request: Request, exc: AuthJWTException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.message}
    )



@app.get("/")
def read_root():
    return {"Hello": "Admin"}


# Proporcionar un método para crear tokens de acceso. El create_access_token () 
# la función se usa para generar realmente el token para usar la autorización más tarde en el punto final protegido
@app.post('/login')
def login(user: User, Authorize: AuthJWT = Depends()):
    if user.username != "test" or user.password != "test":
        raise HTTPException(status_code=401, detail="Bad username or password")
    access_token = Authorize.create_access_token(subject=user.username)
    return {"access_token": access_token}

@app.get("/archivos/")
async def check_file_modifications():
    global passwd_hash, shadow_hash

    # Ver el Hash
    current_passwd_hash = calculate_file_hash(passwd_file)
    current_shadow_hash = calculate_file_hash(shadow_file)

    # VVer si Existen o tira error
    if current_passwd_hash is None:
        return {"message": "El archivo /etc/passwd no existe."}
    if current_shadow_hash is None:
        return {"message": "El archivo /etc/shadow no existe."}

    response = {"message": "Todo bien por ahora"}
    
    print("passwd_hash:", passwd_hash)
    print("current_passwd_hash:", current_passwd_hash)

    # Check if the hashes changed
    if passwd_hash != current_passwd_hash:
        response["passwd"] = "El archivo /etc/passwd se modificó. ¡Alerta!"
    else:
        response["passwd"] = "El archivo /etc/passwd no ha sido modificado."

    if shadow_hash != current_shadow_hash:
        response["shadow"] = "El archivo /etc/shadow se modificó. ¡Alerta!"
    else:
        response["shadow"] = "El archivo /etc/shadow no ha sido modificado."

    return response

@app.get('/user')
def user(Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()
    current_user = Authorize.get_jwt_subject()
    return {"user": current_user, 'data': 'jwt test works'}

    # return {"user": 123124124, 'data': 'jwt test works'}

@app.get("/active_users/")
async def active_users():
    active_users = []

    for user in psutil.users():
        user_info = {
            "username": user.name,
            "terminal": user.terminal,
            "host": user.host,
            "started_at": user.started,
        }
        active_users.append(user_info)

    return {"active_users": active_users}

def get_all_interfaces():
    try:
        output = subprocess.check_output(["ip", "link", "show"]).decode()
        interfaces = []
        for line in output.splitlines():
            if "UP" in line and "LOOPBACK" not in line:
                interface = line.split(":")[1].strip()
                interfaces.append(interface)
        return interfaces
    except subprocess.CalledProcessError:
        return []

def is_promiscuous_mode(interface):
    try:
        output = subprocess.check_output(["ip", "link", "show", interface]).decode()
        return "PROMISC" in output
    except subprocess.CalledProcessError:
        return False

#Falta ver si hay sniffers
@app.get("/sniffer")
def check_sniffer_mode():
    all_interfaces = get_all_interfaces()

    results = {}
    for interface in all_interfaces:
        promiscuous_mode = is_promiscuous_mode(interface)
        results[interface] = promiscuous_mode

    return results