# ===========================================================================
# Stage 1 — builder
# ---------------------------------------------------------------------------
# Compila wheels Python (incl. extensões nativas como curl_cffi) num
# ambiente com toolchain completa. Apenas o resultado do `pip install` é
# copiado para a imagem final, evitando ~300MB de build deps em runtime.
# ===========================================================================
FROM python:3.10-slim AS builder

RUN DEBIAN_FRONTEND="noninteractive" apt-get update && \
    apt-get install -y --no-install-recommends \
      build-essential \
      curl \
      libssl-dev \
      libffi-dev \
      libcurl4-openssl-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Instala dependências num prefix isolado que será copiado para a imagem final.
COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install --prefix=/install --no-cache-dir -r requirements.txt


# ===========================================================================
# Stage 2 — runtime
# ---------------------------------------------------------------------------
# Imagem final: só Tor + libcurl4 runtime + as wheels Python compiladas.
# Sem build-essential, sem -dev packages.
# ===========================================================================
FROM python:3.10-slim AS runtime

RUN DEBIAN_FRONTEND="noninteractive" apt-get update && \
    apt-get install -y --no-install-recommends \
      tor \
      libcurl4 \
      ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Copia o site-packages compilado do builder
COPY --from=builder /install /usr/local

WORKDIR /app
COPY . .

RUN chmod +x /app/entrypoint.sh

EXPOSE 8501

ENTRYPOINT ["/app/entrypoint.sh"]
