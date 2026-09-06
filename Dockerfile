FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl unzip ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Pin a tested Xray-core version (overridable with --build-arg XRAY_VERSION=...).
# Direct release download + retries: the GitHub API endpoint used before is
# rate-limited on CI runners and randomly broke builds (=> "no xray => no ping").
ARG XRAY_VERSION=v25.8.29
RUN ARCH=$(dpkg --print-architecture) \
    && case "$ARCH" in \
         amd64) XARCH="64" ;; \
         arm64) XARCH="arm64-v8a" ;; \
         *) XARCH="64" ;; \
       esac \
    && echo "Installing Xray-core ${XRAY_VERSION} (linux-${XARCH})" \
    && for i in 1 2 3 4 5; do \
         curl -fsSL --retry 3 --retry-delay 2 \
           "https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/Xray-linux-${XARCH}.zip" \
           -o /tmp/xray.zip && break || { echo "download retry $i"; sleep 5; }; \
       done \
    && test -s /tmp/xray.zip \
    && unzip -o /tmp/xray.zip -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/xray \
    && rm -f /tmp/xray.zip \
    && /usr/local/bin/xray version

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py templates_data.py entrypoint.sh ./
RUN chmod +x entrypoint.sh && mkdir -p /app/data

ENV PORT=8080
ENV PYTHONUNBUFFERED=1
EXPOSE 8080

CMD ["./entrypoint.sh"]
