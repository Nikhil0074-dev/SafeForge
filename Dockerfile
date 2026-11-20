# UNTESTED in the build environment (no Docker available there) - review before production use.
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends qpdf ffmpeg poppler-utils \
        libreoffice-core libreoffice-writer libreoffice-calc libreoffice-impress \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 10001 sf
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn
COPY safeforge ./safeforge
USER sf
ENV SAFEFORGE_DATA=/data HOME=/tmp
EXPOSE 8080
CMD ["gunicorn", "-w", "2", "--timeout", "300", "-b", "0.0.0.0:8080", "safeforge.server:create_app()"]
