FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir requests authlib

COPY oidc_whoami.py /app/oidc_whoami.py

RUN chmod +x /app/oidc_whoami.py

EXPOSE 8765

CMD ["python3", "/app/oidc_whoami.py"]

