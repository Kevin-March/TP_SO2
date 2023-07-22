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
import socket
import smtplib
from datetime import datetime, timedelta
import stat
import shutil
from typing import List



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

#A donde van los archivos sospechosos
QUARANTINE_FOLDER = "/tmp/cuarentena"

#IPS Sospechosas
suspicious_ips = ["192.168.1.100", "10.0.0.2", "127.0.0.1"]

#ajustar este para el maximo de emails enviados por un usuario
max_emails_per_user = 50

#ajustar este para el porcentaje de memoria
memory_percentage =50.0 
# ajustar este para el maximo de horas de un proceso que utilize mucha memoria
max_hours_memory=1


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


def is_suspicious(ip_address):
    return ip_address in suspicious_ips

def get_user_ip():
    try:
        hostname = socket.gethostname()
        user_ip = socket.gethostbyname(hostname)
        return user_ip
    except socket.gaierror:
        return None

def block_ip(ip_address):
    try:
        subprocess.run(["sudo", "ipset", "add", "blocked_ips", ip_address])
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"])
    except subprocess.CalledProcessError:
        pass

@app.on_event("startup")
def startup_event():
    # Create an IP set named "blocked_ips" if it doesn't exist
    subprocess.run(["sudo", "ipset", "-N", "blocked_ips", "iphash"])

@app.get("/active_users/")
async def active_users():
    active_users = []
    user_sessions = {}

    user_ip = get_user_ip()

    for user in psutil.users():
        user_ip_address = user_ip or "Unknown"
        username = user.name
        session_info = {
            "terminal": user.terminal,
            "ip_address": user_ip_address,
            "started_at": user.started,
        }

        if username in user_sessions:
            user_sessions[username]["sessions"].append(session_info)
        else:
            user_sessions[username] = {
                "sessions": [session_info],
                "change_password": False,  # Flag to indicate if the user needs to change their password
            }

        # Check if the user has multiple active sessions
        if len(user_sessions[username]["sessions"]) > 1:
            user_sessions[username]["change_password"] = True

        active_users.append(session_info)

    response = {"message": "Buscando Todos los usuarios"}

    # If any user has multiple active sessions, add an alert to change password
    if any(session_data["change_password"] for session_data in user_sessions.values()):
        response["alert_change_password"] = f"Usuario {username}, cambie su contraseña debido a múltiples sesiones activas. O te hackearon papu O deja de conectarte por todos lados"

    response["active_users"] = active_users

    # Check if the user's IP address is suspicious, block access, and add an alert
    if user_ip and is_suspicious(user_ip):
        response["alert_block_ip"] = "IP AmongUs BLOQUEADO PAPU"
        # block_ip(user_ip)  

    return response

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

@app.get("/mail")
async def check_mail_queue():
    user_ip = get_user_ip()

    response = {"message": "Verificando tamaño de cola de correos"}

    # Check mail queue size
    try:
        output = subprocess.check_output(["mailq"])
        queue_size = len(output.splitlines())
        response["mail_queue_size"] = queue_size
    except subprocess.CalledProcessError as e:
        response["error"] = f"Error checking mail queue: {e}"

    # Check if the user's IP address is suspicious, block access, and add an alert
    if user_ip and is_suspicious(user_ip):
        response["alert_block_ip"] = "IP sospechosa bloqueada"
        # block_ip(user_ip)  # Uncomment this line to block the suspicious IP address

    # Check if a user generates many emails, and send an alert to change password
    user_email_count = get_user_email_count()
    if user_email_count > max_emails_per_user:
        username = psutil.Process().username()
        response["alert_change_password"] = f"Usuario {username}, cambie su contraseña debido a muchos correos enviados. Por razones de seguridad, se recomienda cambiar la contraseña regularmente."

    return response

def get_user_email_count():
    try:
        output = subprocess.check_output(["grep", "^From:", "/var/log/mail.log"])
        email_count = len(output.splitlines())
        return email_count
    except subprocess.CalledProcessError as e:
        print(f"Error counting emails: {e}")
        return 0

@app.get("/memoria")
async def check_memory_usage():
    response = {"message": "Verificando procesos con alto consumo de memoria"}

    # Get the processes consuming a high percentage of memory
    high_memory_processes = []
    for process in psutil.process_iter(["pid", "name", "memory_percent", "create_time"]):
        if process.info["memory_percent"] > memory_percentage:  
            high_memory_processes.append(process.info)

    response["high_memory_processes"] = high_memory_processes

    # Terminate processes that have been running for more than 1 hour
    now = datetime.now()
    for process_info in high_memory_processes:
        create_time = datetime.fromtimestamp(process_info["create_time"])
        if (now - create_time) > timedelta(max_hours_memory):
            try:
                process = psutil.Process(process_info["pid"])
                process.terminate()
                response["message"] = f"Proceso {process_info['name']} (PID: {process_info['pid']}) terminado por alto consumo de memoria y tiempo de ejecución."
            except psutil.NoSuchProcess:
                response["message"] = "Error al terminar el proceso: proceso no encontrado."

    return response

def move_files_to_quarantine():
    extensions_to_quarantine = [".cpp", ".c", ".exe", ".sh", ".php", ".py"]

    if not os.path.exists(QUARANTINE_FOLDER):
        os.makedirs(QUARANTINE_FOLDER)

    files_in_tmp = os.listdir("/tmp")
    alerts = []  # Lista para almacenar alertas
    for file_name in files_in_tmp:
        for extension in extensions_to_quarantine:
            if file_name.endswith(extension):
                file_path = os.path.join("/tmp", file_name)
                quarantine_path = os.path.join(QUARANTINE_FOLDER, file_name)

                try:
                    shutil.move(file_path, quarantine_path)
                    os.chmod(quarantine_path, stat.S_IWUSR)
                    alerts.append(f"Archivo {file_name} movido a cuarentena.")
                except Exception as e:
                    raise HTTPException(status_code=500, detail=str(e))

    return alerts


def terminate_processes_in_tmp():
    alerts = []  # Lista para almacenar alertas
    for process in psutil.process_iter(['pid', 'cmdline']):
        try:
            # Get the full command line of the process
            cmdline = process.info['cmdline']
            if not cmdline:
                continue

            # Check if the process is running in /tmp directory
            if any("/tmp" in arg for arg in cmdline):
                process.terminate()
                alerts.append(f"Proceso {process.info['pid']} terminado.")
        except psutil.NoSuchProcess:
            continue
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    return alerts


def check_for_scripts_in_files():
    extensions_to_check = [".cpp", ".c", ".exe", ".sh", ".php", ".py"]

    files_in_tmp = os.listdir("/tmp")
    suspicious_files = []
    for file_name in files_in_tmp:
        for extension in extensions_to_check:
            if file_name.endswith(extension):
                file_path = os.path.join("/tmp", file_name)
                with open(file_path, "r") as file:
                    content = file.read()
                    if "import os" in content or "import subprocess" in content:
                        suspicious_files.append(file_name)

    return suspicious_files


@app.get("/temp")
def check_tmp_directory():
    response = {"message": "Checking /tmp directory for suspicious files and processes"}

    # Move suspicious files to quarantine and get alerts
    quarantine_alerts = move_files_to_quarantine()
    if quarantine_alerts:
        response["quarantine_alerts"] = quarantine_alerts
    else:
        response["quarantine_alerts"] = "No quarentine alerts found in /tmp directory"
        

    # Terminate processes in /tmp directory and get alerts
    terminate_alerts = terminate_processes_in_tmp()
    if terminate_alerts:
        response["terminate_alerts"] = terminate_alerts
    else:
        response["terminate_alerts"] = "No terminate alerts found in /tmp directory"

    # Check for scripts in files
    suspicious_files = check_for_scripts_in_files()
    if suspicious_files:
        response["suspicious_files"] = suspicious_files
    else:
        response["suspicious_files"] = "No suspicious files found in /tmp directory"

    return response


@app.get("/test-jwt")
def test_jwt():
    return {"message": "Test JWT route works!"}


def execute_process(command: str) -> List[str]:
    try:
        output = subprocess.check_output(command, shell=True, text=True)
        return output.splitlines()
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {e}")
        return []

def check_user_cron() -> List[str]:
    alerts = []

    try:
        command_getuser = "cat /etc/passwd | awk -F : '{print $1}'"
        list_user = execute_process(command_getuser)
        list_user.pop(0)

        if list_user:
            for user in list_user:
                command_crontab = f"crontab -u {user} -l"
                list_cron = execute_process(command_crontab)

                if "no crontab for" in "".join(list_cron):
                    alerts.append(f"No cron job found for user {user}")
                else:
                    for cron in list_cron:
                        cron = cron.split()
                        alerts.append(f"User {user} is executing the file {cron[-1]} as cron")

    except Exception as error:
        print('An exception occurred', error)
    
    return alerts

@app.get("/cron")
def examine_user_cron():
    response = {"message": "Checking user cron jobs"}

    # Check user cron jobs
    cron_alerts = check_user_cron()
    if cron_alerts:
        response["cron_alerts"] = cron_alerts
    else:
        response["cron_alerts"] = "No user cron jobs found"

    return response