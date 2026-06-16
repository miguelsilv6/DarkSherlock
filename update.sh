#!/usr/bin/env bash
#
# update.sh — Atualiza o DarkSherlock a partir do Git e corre localmente.
#
# Uso:
#   ./update.sh                      # atualiza main, instala deps e corre a app
#   ./update.sh <branch>             # idem, mas a partir de <branch> (ex: testar uma PR)
#   ./update.sh <branch> --no-run    # só atualiza + instala (não arranca a app)
#
# Faz:
#   1. git fetch + checkout + pull (fast-forward) da branch escolhida
#   2. cria/atualiza um virtualenv (.venv) com Python 3.10+
#   3. instala/atualiza as dependências de requirements.txt
#   4. cria .env a partir de .env.example se ainda não existir
#   5. avisa se o Tor não estiver acessível (pesquisa .onion precisa dele)
#   6. arranca o Streamlit (a menos que --no-run)
#
# O modelo LLM leve embutido é descarregado automaticamente na 1ª investigação;
# não é preciso configurar nada para a app funcionar.

set -euo pipefail
cd "$(dirname "$0")"

BRANCH="${1:-main}"
NO_RUN="${2:-}"
VENV=".venv"

# ---------------------------------------------------------------------------
# 1. Atualizar código
# ---------------------------------------------------------------------------
echo "==> A atualizar código (branch: ${BRANCH})"
git fetch origin
git checkout "${BRANCH}"
# --ff-only evita merges acidentais; falha de forma clara se houver divergência
git pull --ff-only origin "${BRANCH}"

# ---------------------------------------------------------------------------
# 2. Escolher interpretador Python 3.10+
# ---------------------------------------------------------------------------
PY=""
for c in python3.13 python3.12 python3.11 python3.10 python3; do
  if command -v "${c}" >/dev/null 2>&1; then PY="${c}"; break; fi
done
if [ -z "${PY}" ]; then
  echo "ERRO: Python 3.10+ não encontrado no PATH." >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# 3. Criar venv se necessário
# ---------------------------------------------------------------------------
if [ ! -d "${VENV}" ]; then
  echo "==> A criar virtualenv (${PY}) em ${VENV}"
  "${PY}" -m venv "${VENV}"
fi
VENV_PY="${VENV}/bin/python"

# ---------------------------------------------------------------------------
# 4. Instalar / atualizar dependências
# ---------------------------------------------------------------------------
echo "==> A instalar/atualizar dependências (pode demorar na 1ª vez)"
"${VENV_PY}" -m pip install --upgrade pip >/dev/null
"${VENV_PY}" -m pip install -r requirements.txt

# ---------------------------------------------------------------------------
# 5. .env a partir do template
# ---------------------------------------------------------------------------
if [ ! -f .env ]; then
  echo "==> A criar .env a partir de .env.example"
  cp .env.example .env
fi

# ---------------------------------------------------------------------------
# 6. Aviso de Tor (não bloqueante — a pesquisa .onion precisa do Tor em 9050)
# ---------------------------------------------------------------------------
if ! (exec 3<>/dev/tcp/127.0.0.1/9050) 2>/dev/null; then
  echo "AVISO: Tor não detectado em 127.0.0.1:9050 — a pesquisa .onion não funcionará."
  echo "       macOS:  brew services start tor"
  echo "       Linux:  sudo systemctl start tor"
fi

# ---------------------------------------------------------------------------
# 7. Arrancar a app (a menos que --no-run)
# ---------------------------------------------------------------------------
if [ "${NO_RUN}" = "--no-run" ]; then
  echo "==> Setup concluído. Para correr:  ${VENV}/bin/streamlit run Home.py"
  exit 0
fi

echo "==> A iniciar DarkSherlock em http://localhost:8501  (Ctrl+C para parar)"
exec "${VENV}/bin/streamlit" run Home.py
