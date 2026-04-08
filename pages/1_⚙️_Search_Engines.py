"""
Página de Gestão de Search Engines — DarkSherlock.

Esta página permite ao utilizador gerir os motores de pesquisa da dark web
utilizados pelo pipeline de investigação. As funcionalidades incluem:

  - Verificação automática de conectividade ao arrancar a página (auto-health-check)
  - Teste manual de todos os engines via proxy Tor
  - Ativação e desativação individual de engines
  - Edição inline de nome e URL de cada engine
  - Remoção com diálogo de confirmação
  - Adição de novos engines (URL deve conter o placeholder {query})
  - Reset para a lista de engines originais (defaults)

Os resultados de saúde dos engines são armazenados em st.session_state para
que possam ser consultados noutras páginas da aplicação (ex: banner de aviso
na página de Investigação).
"""

import streamlit as st
from datetime import datetime

# Funções CRUD para gerir a lista persistente de search engines
from engine_manager import (
    get_all_engines,    # Lê todos os engines (ativos e desativados)
    add_engine,         # Adiciona um novo engine à lista
    update_engine,      # Atualiza nome, URL e estado de um engine existente
    remove_engine,      # Remove um engine pelo índice
    toggle_engine,      # Alterna o estado ativo/inativo de um engine
    reset_to_defaults,  # Repõe a lista de engines para os valores originais
)

# Funções de verificação de conectividade via Tor
from health import check_engines_list, check_tor_proxy

# Configuração da página Streamlit: título, ícone e estado inicial da sidebar
st.set_page_config(
    page_title="DarkSherlock — Search Engines",
    page_icon="⚙️",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&display=swap');
    html, body, [class*="css"] {
        font-family: 'JetBrains Mono', 'Fira Code', 'Cascadia Code', ui-monospace, monospace !important;
    }
    h1 {
        font-size: 1.55rem !important; font-weight: 700 !important;
        letter-spacing: 0.12em !important; text-transform: uppercase !important;
        color: #00ff9f !important; border-bottom: 1px solid #00ff9f33 !important;
        padding-bottom: 0.4rem !important; margin-bottom: 1.4rem !important;
    }
    h2, h3 { letter-spacing: 0.06em; color: #a0f0c8; }
    input[type="text"] {
        background-color: #0d0d14 !important; border: 1px solid #00ff9f55 !important;
        border-radius: 4px !important; color: #e2e8f0 !important;
        caret-color: #00ff9f !important; font-family: inherit !important;
        transition: border-color 0.25s ease, box-shadow 0.25s ease !important;
    }
    input[type="text"]:focus {
        border-color: #00ff9f !important;
        box-shadow: 0 0 0 1px #00ff9f, 0 0 14px #00ff9f55 !important;
        outline: none !important;
    }
    .stButton > button, .stDownloadButton > button {
        background-color: transparent !important; color: #a0f0c8 !important;
        border: 1px solid #a0f0c833 !important; border-radius: 4px !important;
        transition: border-color 0.2s ease !important;
    }
    .stButton > button:hover, .stDownloadButton > button:hover {
        border-color: #00ff9f !important; color: #00ff9f !important;
    }
    button[kind="primaryFormSubmit"],
    button[data-testid="baseButton-primary"],
    .stButton > button[kind="primary"] {
        background-color: #00ff9f14 !important; color: #00ff9f !important;
        border: 1px solid #00ff9f !important; border-radius: 4px !important;
        font-weight: 600 !important;
    }
    [data-testid="stStatusWidget"], div[data-testid="stExpander"] {
        border: 1px solid #00ff9f22 !important; border-radius: 6px !important;
        background-color: #0d0d18 !important;
    }
    [data-testid="stSidebar"] { border-right: 1px solid #00ff9f1a !important; }
    [data-testid="stAlertContainer"][kind="success"] {
        border-left: 3px solid #00ff9f !important; background-color: #00ff9f0d !important;
    }
    [data-testid="stAlertContainer"][kind="warning"] { border-left: 3px solid #ffcc00 !important; }
    [data-testid="stAlertContainer"][kind="error"]   { border-left: 3px solid #ff4444 !important; }
    </style>""",
    unsafe_allow_html=True,
)

st.title("Search Engine Management")

# Carrega todos os engines configurados (ativos + desativados)
engines = get_all_engines()

# Conta quantos engines estão ativos para mostrar o resumo no topo da página
active_count = sum(1 for e in engines if e.get("enabled", True))
disabled_count = len(engines) - active_count
st.caption(
    f"{active_count} engines activos · {disabled_count} desactivados · {len(engines)} total  "
    f"— Fonte adicional: [fastfire/deepdarkCTI](https://github.com/fastfire/deepdarkCTI)"
)

# Nota informativa sobre os engines provenientes do deepdarkCTI
deepdarkCTI_engines = [e for e in engines if not e.get("enabled", True) and e.get("is_default", False)]
if deepdarkCTI_engines:
    with st.expander(f"ℹ️ {len(deepdarkCTI_engines)} engines do deepdarkCTI disponíveis (desactivados)", expanded=False):
        st.markdown(
            "Estes engines foram adicionados a partir do repositório "
            "[fastfire/deepdarkCTI](https://github.com/fastfire/deepdarkCTI), "
            "que mantém uma lista actualizada de recursos da dark web verificados como ONLINE.\n\n"
            "Estão **desactivados por omissão** porque o formato exacto dos seus parâmetros de "
            "pesquisa não foi testado neste contexto. Activa-os individualmente e usa o botão "
            "**Test All Engines** para verificar a conectividade antes de usar no pipeline.\n\n"
            "**Engines disponíveis:** " +
            ", ".join(f"`{e['name']}`" for e in deepdarkCTI_engines)
        )


# ---------------------------------------------------------------------------
# AUTO-HEALTH-CHECK — Executado automaticamente na primeira carga da página
# ---------------------------------------------------------------------------
# Verifica se já existe informação de saúde no session_state. Se não existir,
# significa que a página está a ser carregada pela primeira vez nesta sessão,
# pelo que se realiza um teste automático de conectividade a todos os engines.
# Desta forma, o utilizador vê imediatamente o estado dos engines sem precisar
# de clicar no botão de teste manual.
if "engine_health" not in st.session_state:
    with st.spinner("Testing engines via Tor..."):
        # Passo 1: Verifica se o proxy Tor está acessível na porta 9050
        tor_result = check_tor_proxy()

        if tor_result["status"] == "up":
            # Passo 2: Constrói a lista de engines para testar (nome + URL)
            test_engines = [{"name": e["name"], "url": e["url"]} for e in engines]

            # Passo 3: Testa todos os engines em paralelo (até 8 workers simultâneos)
            # O parâmetro max_workers controla a concorrência dos pedidos HTTP via Tor
            results = check_engines_list(test_engines, max_workers=8)

            # Armazena os resultados de saúde no session_state, indexados pelo nome
            # do engine, para uso imediato na listagem abaixo e persistência entre reruns
            st.session_state["engine_health"] = {r["name"]: r for r in results}

            # Guarda também os resultados com timestamp para o banner de notificação
            # que aparece na página de Investigação (partilha de estado entre páginas)
            st.session_state["last_engine_check"] = {
                "results": results,
                "timestamp": datetime.now().isoformat(),
            }

            # Força o re-render da página para que a listagem mostre os ícones de saúde
            st.rerun()


# ---------------------------------------------------------------------------
# SECÇÃO: TESTE DE CONECTIVIDADE MANUAL
# ---------------------------------------------------------------------------
st.subheader("Connection Test")

# Botão que desencadeia o teste manual de todos os engines
if st.button("Test All Engines", type="primary", use_container_width=True):
    # Passo 1: Verifica primeiro se o proxy Tor está operacional
    # Sem Tor, os sites .onion não são alcançáveis, pelo que não faz sentido
    # testar os engines
    with st.spinner("Checking Tor proxy..."):
        tor_result = check_tor_proxy()

    if tor_result["status"] == "down":
        # Mostra uma mensagem de erro clara com instruções de arranque do Tor
        st.error(
            f"**Tor Proxy** — Not reachable\n\n{tor_result['error']}\n\n"
            "Ensure Tor is running: `brew services start tor`"
        )
    else:
        # Tor está acessível — mostra latência e avança para o teste dos engines
        st.success(f"**Tor Proxy** — Connected ({tor_result['latency_ms']}ms)")

        # Constrói a lista com TODOS os engines (ativos e desativados),
        # pois o utilizador pode querer saber o estado de engines desativados
        test_engines = [{"name": e["name"], "url": e["url"]} for e in engines]

        with st.spinner(f"Testing {len(test_engines)} engines via Tor..."):
            # Testa todos os engines em paralelo com 8 workers
            results = check_engines_list(test_engines, max_workers=8)

        # Atualiza o session_state com os novos resultados, substituindo o auto-check
        # Os resultados são um dicionário {nome_engine: resultado} para acesso rápido
        st.session_state["engine_health"] = {r["name"]: r for r in results}

        # Persiste também o timestamp e resultados completos para o banner na página
        # de Investigação (permite ao utilizador saber quando foi o último teste)
        st.session_state["last_engine_check"] = {
            "results": results,
            "timestamp": datetime.now().isoformat(),
        }

        # Mostra um resumo do resultado: todos online, alguns online, ou nenhum
        up_count = sum(1 for r in results if r["status"] == "up")
        if up_count == len(results):
            st.success(f"All {len(results)} engines reachable")
        elif up_count > 0:
            st.warning(f"{up_count}/{len(results)} engines reachable")
        else:
            st.error(f"0/{len(results)} engines reachable")

st.divider()


# ---------------------------------------------------------------------------
# SECÇÃO: LISTAGEM DE ENGINES
# ---------------------------------------------------------------------------
st.subheader("Engines")

# Caso não existam engines configurados, mostra instrução para adicionar
if not engines:
    st.info("Nenhum engine configurado. Adiciona um abaixo ou repoe os defaults.")

# Lê os dados de saúde do session_state (pode estar vazio se o Tor falhou no auto-check)
health_data = st.session_state.get("engine_health", {})

# Itera sobre todos os engines para renderizar cada linha da listagem
for i, eng in enumerate(engines):
    # Determina o estado atual de ativação do engine (default: True)
    enabled = eng.get("enabled", True)

    # Obtém os dados de saúde para este engine específico (pode ser None)
    health = health_data.get(eng["name"])

    # Determina o ícone de estado a apresentar:
    # - Se existem dados de saúde, o ícone reflete o resultado do teste (verde/vermelho)
    # - Se não há dados de saúde, o ícone reflete apenas se está ativo (verde) ou
    #   desativado (cinzento), sem informação de conectividade
    if health:
        icon = "🟢" if health["status"] == "up" else "🔴"
    else:
        icon = "🟢" if enabled else "⚪"

    with st.container():
        # Layout em 4 colunas: [ícone | nome+saúde | URL | botões de ação]
        cols = st.columns([0.3, 2.5, 5, 2.5])

        # Coluna 0: Ícone de estado (online/offline/desativado)
        cols[0].markdown(icon)

        # Coluna 1: Nome do engine com informação de saúde inline
        name_text = f"**{eng['name']}**"
        if health and health["status"] == "up":
            # Mostra a latência em milissegundos se o engine está online
            name_text += f" `{health['latency_ms']}ms`"
        elif health and health["status"] == "down":
            # Mostra os primeiros 35 caracteres da mensagem de erro se está offline
            name_text += f" _{health['error'][:35]}_"
        if not enabled:
            # Indica visualmente que o engine está desativado
            name_text += " *(off)*"
        cols[1].markdown(name_text)

        # Coluna 2: URL do engine, truncado a 60 caracteres para não quebrar o layout
        url_display = eng["url"][:60] + "..." if len(eng["url"]) > 60 else eng["url"]
        cols[2].code(url_display, language=None)

        # Coluna 3: Botões de ação (Ativar/Desativar, Editar, Eliminar)
        with cols[3]:
            # Sub-colunas para os três botões de ação ficarem na mesma linha
            btn_cols = st.columns(3)

            # Botão Toggle: alterna entre "Off" (desativar) e "On" (ativar)
            # O tipo muda para dar feedback visual: secondary=ativo, primary=inativo
            if btn_cols[0].button("Off" if enabled else "On", key=f"toggle_{i}",
                                  type="secondary" if enabled else "primary"):
                toggle_engine(i)   # Persiste a alteração no ficheiro de configuração
                st.rerun()         # Re-renderiza a página para refletir a mudança

            # Botão Editar: guarda o índice do engine a editar no session_state
            # O formulário de edição é renderizado inline abaixo desta linha
            if btn_cols[1].button("Edit", key=f"edit_{i}"):
                st.session_state["editing_engine"] = i
                st.rerun()

            # Botão Eliminar: em vez de eliminar imediatamente, guarda o índice
            # no session_state para mostrar um diálogo de confirmação
            if btn_cols[2].button("Del", key=f"del_{i}", type="secondary"):
                st.session_state["confirm_delete"] = i
                st.rerun()

    # -----------------------------------------------------------------------
    # DIÁLOGO DE CONFIRMAÇÃO DE ELIMINAÇÃO
    # -----------------------------------------------------------------------
    # Só é renderizado para o engine cujo índice coincide com o armazenado em
    # session_state["confirm_delete"]. Esta abordagem garante que apenas um
    # diálogo de confirmação está ativo de cada vez.
    if st.session_state.get("confirm_delete") == i:
        st.warning(f"Tens a certeza que queres remover **{eng['name']}**?")
        col_yes, col_no, _ = st.columns([1, 1, 6])

        # Confirmação: remove o engine e limpa o estado de confirmação
        if col_yes.button("Sim, remover", key=f"confirm_del_yes_{i}", type="primary"):
            remove_engine(i)
            st.session_state.pop("confirm_delete", None)
            st.rerun()

        # Cancelamento: limpa apenas o estado de confirmação sem alterar dados
        if col_no.button("Cancelar", key=f"confirm_del_no_{i}"):
            st.session_state.pop("confirm_delete", None)
            st.rerun()

    # -----------------------------------------------------------------------
    # FORMULÁRIO DE EDIÇÃO INLINE
    # -----------------------------------------------------------------------
    # Renderizado apenas para o engine cujo índice coincide com
    # session_state["editing_engine"]. O formulário é mostrado imediatamente
    # abaixo da linha do engine que está a ser editado.
    if st.session_state.get("editing_engine") == i:
        with st.form(key=f"edit_form_{i}"):
            # Campos pré-preenchidos com os valores atuais do engine
            new_name = st.text_input("Nome", value=eng["name"])
            new_url = st.text_input("URL", value=eng["url"])
            new_enabled = st.checkbox("Ativo", value=enabled)

            col_save, col_cancel, _ = st.columns([1, 1, 6])
            save_btn = col_save.form_submit_button("Guardar")
            cancel_btn = col_cancel.form_submit_button("Cancelar")

            if save_btn:
                # Tenta persistir as alterações; update_engine devolve uma
                # mensagem de erro se a validação falhar (ex: URL sem {query})
                err = update_engine(i, new_name, new_url, new_enabled)
                if err:
                    st.error(err)
                else:
                    # Guarda com sucesso: fecha o formulário e re-renderiza
                    st.session_state.pop("editing_engine", None)
                    st.rerun()

            if cancel_btn:
                # Descarta as alterações e fecha o formulário
                st.session_state.pop("editing_engine", None)
                st.rerun()

    # Separador visual entre cada engine da lista
    st.divider()


# ---------------------------------------------------------------------------
# SECÇÃO: LEGENDA DOS ÍCONES DE ESTADO
# ---------------------------------------------------------------------------
# Expander colapsável para não ocupar espaço desnecessário na página
with st.expander("Legenda"):
    st.markdown("""
| Simbolo | Significado |
|---------|-------------|
| 🟢 | Engine online / ativo |
| 🔴 | Engine offline (teste falhou) |
| ⚪ | Engine desativado (sem teste) |
""")


# ---------------------------------------------------------------------------
# SECÇÃO: ADICIONAR NOVO ENGINE
# ---------------------------------------------------------------------------
st.subheader("Adicionar Engine")

# Formulário com clear_on_submit=True para limpar os campos após submissão
with st.form("add_engine_form", clear_on_submit=True):
    new_name = st.text_input("Nome", placeholder="My Search Engine")
    new_url = st.text_input(
        "URL",
        placeholder="http://xxxx.onion/search?q={query}",
        # Instrução ao utilizador: o URL deve incluir {query} como placeholder
        # que será substituído pelo termo de pesquisa em cada consulta
        help="O URL deve conter {query} como placeholder para o termo de pesquisa.",
    )
    submitted = st.form_submit_button("Adicionar", type="primary")

    if submitted:
        # add_engine valida o nome (não vazio, não duplicado) e o URL (contém {query})
        # e devolve uma mensagem de erro se a validação falhar
        err = add_engine(new_name, new_url)
        if err:
            st.error(err)
        else:
            st.success(f"Engine **{new_name.strip()}** adicionado com sucesso!")
            st.rerun()  # Re-renderiza para mostrar o novo engine na lista


# ---------------------------------------------------------------------------
# SECÇÃO: RESET PARA DEFAULTS
# ---------------------------------------------------------------------------
st.divider()
st.subheader("Reset")

# Checkbox de confirmação explícita para evitar resets acidentais.
# O botão de reset fica desativado até o utilizador marcar a checkbox.
confirm_reset = st.checkbox("Confirmo que quero repor os engines originais", key="confirm_reset")

if st.button("Repor Defaults", disabled=not confirm_reset, type="secondary"):
    # Repõe a lista de engines para os 16 engines originais definidos no código
    reset_to_defaults()

    # Invalida o cache de saúde para que o auto-check seja executado novamente
    # na próxima carga da página com a lista restaurada
    st.session_state.pop("engine_health", None)

    st.success("Engines repostos para os valores originais!")
    st.rerun()
