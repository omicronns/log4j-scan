# Ref: https://devguide.python.org/#branchstatus
FROM python:3.10-slim-bullseye

RUN useradd -ms /bin/bash appuser && apt update && DEBIAN_FRONTEND="noninteractive" apt install -y git openjdk-17-jdk maven && \
    mkdir /app && chown appuser:appuser /app
USER appuser
WORKDIR /app

COPY --chown=appuser:appuser requirements.txt requirements.txt

RUN pip3 install -r requirements.txt

ENV PATH="/home/appuser/.local/bin:${PATH}"

COPY --chown=appuser:appuser setup.sh setup.sh

RUN ./setup.sh

COPY --chown=appuser:appuser ./ ./

ENTRYPOINT ["./run.sh"]
