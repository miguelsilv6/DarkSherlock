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
      cmake \
      curl \
      git \
      libssl-dev \
      libffi-dev \
      libcurl4-openssl-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Instala dependências num prefix isolado que será copiado para a imagem final.
# llama-cpp-python normalmente resolve uma wheel CPU pré-compilada; cmake/git
# acima são a rede de segurança caso seja preciso compilar a partir do source.
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

# libgomp1: runtime OpenMP de que o llama-cpp-python precisa (sem ele o modelo
# embutido falha com "libgomp.so.1: cannot open shared object file").
# curl: usado pelo healthcheck do docker-compose (README).
RUN DEBIAN_FRONTEND="noninteractive" apt-get update && \
    apt-get install -y --no-install-recommends \
      tor \
      libcurl4 \
      libgomp1 \
      curl \
      ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Copia o site-packages compilado do builder
COPY --from=builder /install /usr/local

WORKDIR /app
COPY . .

RUN chmod +x /app/entrypoint.sh

# Dados que têm de sobreviver à recriação do contentor: modelos GGUF (centenas
# de MB), investigações (evidência + hashes), logs/audit trail, configuração
# dos motores e o registo de denúncias da salvaguarda ética. O .dockerignore
# impede que as cópias locais destas pastas (e o .env) entrem na imagem.
ENV DARKSHERLOCK_MODELS_DIR=/app/models
RUN mkdir -p /app/models /app/investigations /app/logs /app/config /app/referrals && \
    chmod 700 /app/investigations /app/referrals
VOLUME ["/app/models", "/app/investigations", "/app/logs", "/app/config", "/app/referrals"]

EXPOSE 8501

ENTRYPOINT ["/app/entrypoint.sh"]
