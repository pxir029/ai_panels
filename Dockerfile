FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl unzip ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install latest Xray-core
RUN XRAY_VERSION=$(curl -sL https://api.github.com/repos/XTLS/Xray-core/releases/latest | grep -oP '"tag_name": "\K[^"]+' | head -1) \
    && echo "Xray ${XRAY_VERSION}" \
    && curl -sL "https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/Xray-linux-64.zip" -o /tmp/xray.zip \
    && unzip -o /tmp/xray.zip -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/xray \
    && rm -f /tmp/xray.zip \
    && xray version

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py templates_data.py entrypoint.sh ./
RUN chmod +x entrypoint.sh && mkdir -p /app/data

ENV PORT=8080
ENV PYTHONUNBUFFERED=1
EXPOSE 8080

CMD ["./entrypoint.sh"]
