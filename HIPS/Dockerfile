FROM python:3.8-slim-buster as base
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update \
  # El infaltable
  && apt-get install -y tcpdump zip \
  && apt-get install build-essential gcc python3-dev -y \
  && apt-get install pkg-config zlib1g-dev -y \
  # psycopg2 dependencies
  && apt-get install -y libpq-dev \
  # cleaning up unused files
  && apt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false \
  && rm -rf /var/lib/apt/lists/*

COPY ./requeriments.txt /

RUN pip install setuptools --upgrade

RUN pip install -r /requeriments.txt

COPY . /app

WORKDIR /app

CMD gunicorn -w 3 -k uvicorn.workers.UvicornWorker web_server:app --bind 0.0.0.0:8000