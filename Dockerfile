FROM python:3.12-slim

LABEL org.opencontainers.image.authors="RayanErfan <https://github.com/RayanErfan>"
LABEL org.opencontainers.image.source="https://github.com/RayanErfan/vpn-decryptor"

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
