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
from collections import defaultdict
from typing import Dict
from collections import defaultdict
import re
import datetime


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

# Diccionario para mantener un registro de IPs con intentos de acceso no válidos
invalid_attempts: defaultdict = defaultdict(int)

#donde se encuentran los logs
logs_directory = "/var/log/hips"


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

    # Ver si Existen o tira error
    if current_passwd_hash is None:
        return {"message": "El archivo /etc/passwd no existe."}
    if current_shadow_hash is None:
        return {"message": "El archivo /etc/shadow no existe."}

    response = {"message": "Todo bien por ahora"}
    

    # Ver si el Hash se cambio desde el incio
    if passwd_hash != current_passwd_hash:
        response["passwd"] = "El archivo /etc/passwd se modificó. ¡Alerta!"
        write_alarm_log("Modificación en /etc/passwd")
    else:
        response["passwd"] = "El archivo /etc/passwd no ha sido modificado."

    if shadow_hash != current_shadow_hash:
        response["shadow"] = "El archivo /etc/shadow se modificó. ¡Alerta!"
        write_alarm_log("Modificación en /etc/shadow")
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

def write_prevention_log(alert_type, ip=None):
    log_path = "/var/log/hips/prevencion.log"
    timestamp = datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")

    with open(log_path, "a") as log_file:
        if ip:
            log_file.write(f"{timestamp} :: {alert_type} :: {ip}\n")
        else:
            log_file.write(f"{timestamp} :: {alert_type}\n")

@app.get("/active_users/")
async def active_users():
    active_users = []
    user_sessions = {}

    user_ip = get_user_ip()

    for user in psutil.users():
        user_ip_address = user_ip or "Unknown"
        username = user.name
        session_info = {
            "username": username,
            "terminal": user.terminal,
            "ip_address": user_ip_address,
            "started_at": user.started,
        }

        if username in user_sessions:
            user_sessions[username]["sessions"].append(session_info)
        else:
            user_sessions[username] = {
                "sessions": [session_info],
                "change_password": False,  # te avisa si debe cambiar la contrasenha
            }

        # Chequea si el usuario debe tiene multiples sesiones
        if len(user_sessions[username]["sessions"]) > 1:
            user_sessions[username]["change_password"] = True

        active_users.append(session_info)

    response = {"message": "Buscando Todos los usuarios"}

    # Si tiene multiples sesiones entonces que cambie la passwd
    if any(session_data["change_password"] for session_data in user_sessions.values()):
        response["alert_change_password"] = f"Usuario {username}, cambie su contraseña debido a múltiples sesiones activas. O te hackearon papu O deja de conectarte por todos lados"

    response["active_users"] = active_users

    # Ve si la ip de inicio es rara
    if user_ip and is_suspicious(user_ip):
        response["alert_block_ip"] = "IP AmongUs BLOQUEADO PAPU"
        # block_ip(user_ip)
        write_prevention_log("Bloqueo de IP AmongUs", ip=user_ip)  

    return response

def check_sniffers():
    sniffers = ["tcpdump", "ethereal", "wireshark"]
    blocked_sniffers = []
    
    for sniffer in sniffers:
        try:
            command_check_sniffer = f"ps -ef | grep {sniffer} | grep -v grep"
            output = subprocess.check_output(command_check_sniffer, shell=True, text=True)
            if output:
                blocked_sniffers.append(sniffer)
                os.system(f"sudo killall {sniffer}")
        except subprocess.CalledProcessError as e:
            pass
    
    return blocked_sniffers

def check_promiscuous_mode():
    try:
        command_check_promiscuous = "ip link show"
        output = subprocess.check_output(command_check_promiscuous, shell=True, text=True)
        interfaces_info = output.strip().split("\n\n")
        promiscuous_interfaces = []

        for interface_info in interfaces_info:
            if "PROMISC" in interface_info:
                interface_name = interface_info.split(":")[1].strip()
                promiscuous_interfaces.append(interface_name)

        return promiscuous_interfaces
    except subprocess.CalledProcessError as e:
        pass

    return []

@app.get("/sniffer")
def check_sniffer_and_promiscuous_mode():
    blocked_sniffers = check_sniffers()
    promiscuous_interfaces = check_promiscuous_mode()
    
    response = {"message": "Sniffer and promiscuous mode check completed"}
    
    if blocked_sniffers:
        response["blocked_sniffers"] = blocked_sniffers
        response["alarm_blocked_sniffers"] = "Se bloqueo Algun sniffer, chales ya te la metieron"
        write_prevention_log("Bloqueo de Snifers") 
    else:
        response["blocked_sniffers"] = []
        response["alarm_blocked_sniffers"] = "NO se detecto sniffers, bien ahi rey"
    
    if promiscuous_interfaces:
        response["promiscuous_interfaces"] = promiscuous_interfaces
        response["alarm_promiscuous_mode"] = "Estan en modo promiscuo"
        write_prevention_log("Modo Promiscuo") 
    else:
        response["promiscuous_interfaces"] = []
        response["alarm_promiscuous_mode"] = "No estan en modo promiscuo"
    
    return response

@app.get("/mail")
async def check_mail_queue():
    user_ip = get_user_ip()

    response = {"message": "Verificando tamaño de cola de correos"}

    try:
        output = subprocess.check_output(["mailq"])
        queue_size = len(output.splitlines())
        response["mail_queue_size"] = queue_size
    except subprocess.CalledProcessError as e:
        response["error"] = f"Error checking mail queue: {e}"

    # Ve la ip del usuario, si es sospechosa la bloquea y manda alerta
    if user_ip and is_suspicious(user_ip):
        response["alert_block_ip"] = "IP sospechosa bloqueada"
        # block_ip(user_ip)  #descomentar
        write_prevention_log("Bloqueo de IP SUSSY BAKA",ip=user_ip) 

    # Ve si eun usuario esta mandadno muchos mails, manda una alerta
    user_email_count = get_user_email_count()
    if user_email_count > max_emails_per_user:
        username = psutil.Process().username()
        response["alert_change_password"] = f"Usuario {username}, cambie su contraseña debido a muchos correos enviados."

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

    # Ve que poceso consume mucha memoria
    high_memory_processes = []
    for process in psutil.process_iter(["pid", "name", "memory_percent", "create_time"]):
        if process.info["memory_percent"] > memory_percentage:  
            high_memory_processes.append(process.info)

    response["high_memory_processes"] = high_memory_processes

    # MAta el proceso si tiene mas de N tiempo activo
    now = datetime.datetime.now()
    for process_info in high_memory_processes:
        create_time = datetime.fromtimestamp(process_info["create_time"])
        if (now - create_time) > timedelta(max_hours_memory):
            try:
                process = psutil.Process(process_info["pid"])
                process.terminate()
                response["message"] = f"Proceso {process_info['name']} (PID: {process_info['pid']}) terminado por alto consumo de memoria y tiempo de ejecución."
                write_prevention_log("Proceso UnAlive", ip= process_info)
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
    response = {"message": "Verificando directorio /tmp"}

    # Mueve archivos sussy baka a cuarentena
    quarantine_alerts = move_files_to_quarantine()
    if quarantine_alerts:
        response["quarantine_alerts"] = quarantine_alerts
        write_prevention_log("Archivo a Cuarentena por COVID 20",ip = quarantine_alerts)
    else:
        response["quarantine_alerts"] = "No quarentine alerts found in /tmp directory"
        

    # Mata procesos en tmp
    terminate_alerts = terminate_processes_in_tmp()
    if terminate_alerts:
        response["terminate_alerts"] = terminate_alerts
    else:
        response["terminate_alerts"] = "No terminate alerts found in /tmp directory"

    # Verifica si existen scripts en los archivos
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
                    alerts.append(f"No se encontro cron para {user}")
                else:
                    for cron in list_cron:
                        cron = cron.split()
                        alerts.append(f"{user} esta ejecutando {cron[-1]} como cron, CRUSIFIQUENLO!!!")

    except Exception as error:
        print('An exception occurred', error)
    
    return alerts

@app.get("/cron")
def examine_user_cron():
    response = {"message": "Verificando cron "}

    # Verifica crons
    cron_alerts = check_user_cron()
    if cron_alerts:
        response["cron_alerts"] = cron_alerts
    else:
        response["cron_alerts"] = "No cron encontrados"

    return response

def check_authentication_failure():
    suspicious_users = set()
    suspicious_ips = set()
    command_auth = "cat /var/log/auth.log | grep 'authentication failure'"

    try:
        output = subprocess.check_output(command_auth, shell=True, text=True)
        lines = output.splitlines()

        for line in lines:
            ip_match = re.search(r'rhost=(\S+)', line)
            if ip_match:
                ip = ip_match.group(1)
                suspicious_ips.add(ip)

    except subprocess.CalledProcessError as e:
        print("Error while checking authentication failure logs:", e)

    return suspicious_users, suspicious_ips

@app.get("/invalid")
def check_invalid_login_attempts():
    suspicious_users, suspicious_ips = check_authentication_failure()

    response = {
        "message": "Verifricando los logs  por inicios de sesion fallidos.",
        "suspicious_users": list(suspicious_users),
        "suspicious_ips": list(suspicious_ips),
    }

    if suspicious_users or suspicious_ips:
        response["alarm"] = "Actividad AMONGUS DETECTADA! Verifique los logs."

        # Writing the alarm log
        for user in suspicious_users:
            write_alarm_log("Invalid login attempt (user)", user)
        
        for ip in suspicious_ips:
            write_alarm_log("Invalid login attempt (IP)", ip)

    return response

def create_hips_directory():
    hips_directory = "/var/log/hips"
    if not os.path.exists(hips_directory):
        os.makedirs(hips_directory)


def write_alarm_log(alarm_type, ip=None):
    hips_log_path = "/var/log/hips/alarmas.log"
    now = datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    log_entry = f"{now} :: {alarm_type} :: {ip}\n" if ip else f"{now} :: {alarm_type}\n"
    
    with open(hips_log_path, "a") as file:
        file.write(log_entry)

def process_secure_log():
    try:
        command_auth_log = "grep 'Failed password' /var/log/secure"
        output = subprocess.check_output(command_auth_log, shell=True, text=True)
        if output:
            ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
            ips = re.findall(ip_pattern, output)
            if ips:
                for ip in ips:
                    write_alarm_log("Failed password", ip)
            return True
    except subprocess.CalledProcessError as e:
        pass
    return False

def process_message_log():
    try:
        command_message_log = "grep 'Authentication failure' /var/log/messages"
        output = subprocess.check_output(command_message_log, shell=True, text=True)
        if output:
            ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
            ips = re.findall(ip_pattern, output)
            if ips:
                for ip in ips:
                    write_alarm_log("Authentication failure", ip)
            return True
    except subprocess.CalledProcessError as e:
        pass
    return False

def process_access_log():
    try:
        command_access_log = "grep 'Error' /var/log/httpd/access.log"
        output = subprocess.check_output(command_access_log, shell=True, text=True)
        if output:
            ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
            ips = re.findall(ip_pattern, output)
            if ips:
                for ip in ips:
                    write_alarm_log("Access log error", ip)
            return True
    except subprocess.CalledProcessError as e:
        pass
    return False

def process_mail_log():
    try:
        command_mail_log = "grep 'from=<.*>, size=' /var/log/maillog"
        output = subprocess.check_output(command_mail_log, shell=True, text=True)
        if output:
            ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
            ips = re.findall(ip_pattern, output)
            if ips:
                for ip in ips:
                    write_alarm_log("Mail log", ip)
            return True
    except subprocess.CalledProcessError as e:
        pass
    return False

@app.get("/logs")
def check_logs():
    alarms_found = False
    
    if process_secure_log():
        alarms_found = True
    
    if process_message_log():
        alarms_found = True
    
    if process_access_log():
        alarms_found = True
    
    if process_mail_log():
        alarms_found = True
    
    response = {"message": "Se comprobaron los Logs"}
    
    if alarms_found:
        response["alarm"] = "Se ENcontro algo. Mira /var/log/hips/alarmas.log."
    else:
        response["alarm"] = "No se encontro nada papu."
    
    return response

@app.get('/verlogs')
async def read_logs():
    logs = {}
    alarmas_log_path = os.path.join(logs_directory, "alarmas.log")
    prevencion_log_path = os.path.join(logs_directory, "prevencion.log")

    if os.path.exists(alarmas_log_path):
        with open(alarmas_log_path, "r") as alarmas_file:
            logs["alarmas.log"] = alarmas_file.read()

    if os.path.exists(prevencion_log_path):
        with open(prevencion_log_path, "r") as prevencion_file:
            logs["prevencion.log"] = prevencion_file.read()

    return logs