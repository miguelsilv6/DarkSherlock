#!/usr/bin/env bash
#
# evaluation/run_battery.sh — Lança a bateria de avaliação (run_battery.py) em
# segundo plano, de forma a sobreviver ao fecho do terminal (ou da sessão SSH)
# e a impedir que a máquina suspenda enquanto corre.
#
# Uso:
#   ./evaluation/run_battery.sh [opções do run_battery.py]   # lança em segundo plano
#   ./evaluation/run_battery.sh --dry-run                    # só o plano, em primeiro plano
#   ./evaluation/run_battery.sh status                       # está a correr? últimas linhas
#   ./evaluation/run_battery.sh log                          # acompanha o log (Ctrl+C só sai do log)
#   ./evaluation/run_battery.sh stop                         # para a bateria (e as etapas em curso)
#
# Como:
#   - usa sempre o Python do .venv (as dependências da app estão lá);
#   - setsid + nohup: a bateria corre numa sessão própria, sem terminal, por isso
#     fechar o terminal ou cair o SSH não a mata (SIGHUP não lhe chega);
#   - systemd-inhibit: enquanto corre, bloqueia a suspensão, a hibernação, a
#     suspensão por inatividade e a de fechar a tampa. O bloqueio acaba sozinho
#     quando a bateria termina. Num contentor (LXC/Docker) só vale dentro dele:
#     a suspensão do anfitrião configura-se no anfitrião.

set -euo pipefail
cd "$(dirname "$0")/.."

PY=".venv/bin/python"
RESULTS="evaluation/results"
PIDFILE="${RESULTS}/battery.pid"
LOGLINK="${RESULTS}/battery_console.latest"

running_pid() {
  [ -f "${PIDFILE}" ] || return 1
  local pid
  pid="$(cat "${PIDFILE}")"
  kill -0 "${pid}" 2>/dev/null && echo "${pid}"
}

case "${1:-}" in
  status)
    if pid="$(running_pid)"; then
      echo "A bateria está a correr (PID ${pid}). Log: $(readlink -f "${LOGLINK}" 2>/dev/null || echo '?')"
    else
      echo "A bateria não está a correr."
    fi
    [ -e "${LOGLINK}" ] && { echo "--- últimas linhas ---"; tail -n 15 "${LOGLINK}"; }
    exit 0 ;;
  log)
    [ -e "${LOGLINK}" ] || { echo "Ainda não há log de nenhuma bateria."; exit 1; }
    exec tail -n 40 -F "${LOGLINK}" ;;
  stop)
    if pid="$(running_pid)"; then
      # A sessão criada pelo setsid tem o PID da bateria como grupo: para tudo o que ela lançou.
      kill -TERM -- "-${pid}" 2>/dev/null || kill -TERM "${pid}"
      echo "Pedido de paragem enviado à bateria (PID ${pid})."
      rm -f "${PIDFILE}"
    else
      echo "A bateria não está a correr."
    fi
    exit 0 ;;
esac

if [ ! -x "${PY}" ]; then
  echo "ERRO: não existe ${PY}. Corre primeiro ./update.sh (cria o virtualenv com as dependências)." >&2
  exit 1
fi

# --dry-run e --help não demoram: correm em primeiro plano, no terminal.
for arg in "$@"; do
  case "${arg}" in
    --dry-run|-h|--help) exec "${PY}" evaluation/run_battery.py "$@" ;;
  esac
done

if pid="$(running_pid)"; then
  echo "ERRO: já há uma bateria a correr (PID ${pid}). Vê-a com: $0 status   (ou para-a com: $0 stop)" >&2
  exit 1
fi

mkdir -p "${RESULTS}"
LOG="${RESULTS}/battery_console_$(date +%Y%m%d_%H%M%S).out"
CMD=("${PY}" evaluation/run_battery.py --yes "$@")

if command -v systemd-inhibit >/dev/null 2>&1 && systemd-inhibit --list >/dev/null 2>&1; then
  CMD=(systemd-inhibit --what=sleep:idle:handle-lid-switch --mode=block
       --who="DarkSherlock" --why="Bateria de avaliação em curso" "${CMD[@]}")
  INHIBIT="sim (systemd-inhibit)"
else
  INHIBIT="não (systemd-inhibit indisponível: desliga a suspensão automática à mão)"
fi

setsid nohup "${CMD[@]}" > "${LOG}" 2>&1 < /dev/null &
echo $! > "${PIDFILE}"
ln -sfn "$(basename "${LOG}")" "${LOGLINK}"

sleep 2
if ! running_pid >/dev/null; then
  echo "ERRO: a bateria terminou logo ao arrancar. Últimas linhas de ${LOG}:" >&2
  tail -n 20 "${LOG}" >&2
  exit 1
fi

cat <<EOF
Bateria lançada em segundo plano (PID $(cat "${PIDFILE}")).
  - Podes fechar o terminal ou sair do SSH: continua a correr.
  - Suspensão bloqueada: ${INHIBIT}.
  - Log:     ${LOG}
  - Seguir:  $0 log
  - Estado:  $0 status
  - Parar:   $0 stop
No fim, o resumo fica em ${RESULTS}/battery_<data>/README.md.
EOF
