# TP_SO2
Trabajo Final Sistemas Operativos 2

# Requisitos
Docker
Angular

# Instalacion
Para El HIPS

0 - descargar el codigo fuente `https://gitlab.com/kevin-march/hips` 

1 - dependencias: `sudo apt-get install binutils python3-dev libproj-dev gdal-bin libpq-dev`

2- `docker-compose up -d web_server`

3- `python -m venv .venv`

4- `source ./.venv/bin/activate`

5- `pip install -r requeriments.txt`

6 - `uvicorn main:app –reload` o `sudo /usr/local/bin/uvicorn main:app --reload`

7- `Interfaz web: localhost:8000/docs`

Para La Web

0 - descargar el codigo fuente

1 - Descargar e instalar angular @cli

2 - `sudo npm install` para que se instalen las dependencias

3 - `sudo npm start`

4 - `Inferfaz web: localhost:4200`
