import streamlit as st

st.set_page_config(
    page_title="DarkSherlock — Help",
    page_icon="❓",
    initial_sidebar_state="expanded",
)

st.title("Help & Documentation")
st.caption("DarkSherlock — AI-Powered Dark Web OSINT Tool")

# --- Quick Start ---
st.header("Quick Start")
st.markdown("""
1. **Seleciona um modelo LLM** na sidebar (ex: `llama3.2:latest` para uso local via Ollama)
2. **Escreve uma query** na barra de pesquisa da Home (ex: `Akira ransomware`)
3. **Clica em Run** — o DarkSherlock executa automaticamente o pipeline de 6 etapas
4. **Analisa os resultados** — o summary e gerado pelo LLM com base nos dados recolhidos
5. **Descarrega o relatorio** em Markdown para referencia futura
""")

st.divider()

# --- Pipeline ---
st.header("Pipeline de Investigacao")
st.markdown("""
O DarkSherlock executa 6 etapas sequenciais quando fazes uma pesquisa:
""")

stages = [
    ("Stage 1 — Load LLM", "Carrega o modelo de linguagem selecionado. "
     "Se usas Ollama, o modelo corre localmente. Se usas OpenAI/Claude/Gemini, e feita uma chamada API."),
    ("Stage 2 — Refine Query", "O LLM analisa a tua query e optimiza-a para obter melhores resultados "
     "nos motores de pesquisa. Exemplo: `Akira` pode ser refinado para `Akira ransomware group leak`."),
    ("Stage 3 — Search Dark Web", "A query refinada e enviada a todos os search engines ativos via Tor. "
     "Cada engine e consultado em paralelo. Os resultados (titulo + link .onion) sao agregados e deduplicados."),
    ("Stage 4 — Filter Results", "O LLM recebe todos os resultados e seleciona os Top 20 mais relevantes "
     "para a query. Isto filtra ruido e foca a investigacao nos resultados mais promissores."),
    ("Stage 5 — Scrape Content", "Os links filtrados sao acedidos via Tor e o conteudo textual e extraido "
     "com BeautifulSoup. O numero de paginas scrapeadas depende do slider 'Max Pages to Scrape'."),
    ("Stage 6 — Generate Summary", "O LLM analisa todo o conteudo recolhido e gera um relatorio de "
     "inteligencia estruturado, com artefactos, insights e proximos passos de investigacao."),
]

for title, desc in stages:
    with st.expander(f"**{title}**"):
        st.markdown(desc)

st.divider()

# --- Pages ---
st.header("Paginas")

st.subheader("Home")
st.markdown("""
Pagina principal com barra de pesquisa. Quando executa uma investigacao, mostra o progresso
de cada etapa do pipeline em tempo real com tempos de execucao. Inclui:
- **Barra de pesquisa** — escreve a query e clica Run
- **Pipeline visual** — cada etapa mostra estado (running/complete/error) e detalhes expandiveis
- **Findings** — summary final em streaming
- **Notes** — detalhes da investigacao (query refinada, modelo, contagens)
- **Sources** — lista de links .onion filtrados
- **Download** — exporta o summary em Markdown
""")

st.subheader("Search Engines")
st.markdown("""
Gestao dos motores de pesquisa da dark web. Funcionalidades:
- **Test All Engines** — testa a conectividade de todos os engines via Tor, mostrando latencia ou erro
- **Ativar/Desativar** — engines desativados sao completamente ignorados nas pesquisas e health checks
- **Editar** — altera nome e URL de um engine existente
- **Remover** — remove permanentemente um engine (com confirmacao)
- **Adicionar** — regista um novo engine (URL deve conter `{query}`)
- **Reset** — repoe a lista original de 16 engines
""")

st.subheader("Investigation (Pipeline Detalhado)")
st.markdown("""
Versao alternativa da Home com pipeline identico mas sidebar completa partilhada.
Util para ter a mesma experiencia de investigacao com acesso a todas as configuracoes.
""")

st.divider()

# --- Sidebar Settings ---
st.header("Settings (Sidebar)")

st.subheader("Select LLM Model")
st.markdown("""
Escolhe o modelo de linguagem para processar as queries. Opcoes disponiveis dependem
das API keys configuradas no ficheiro `.env`:

| Provider | Modelos | Requisito |
|----------|---------|-----------|
| **Ollama** (local) | Qualquer modelo instalado (`ollama pull <nome>`) | `OLLAMA_BASE_URL` no .env |
| **OpenAI** | GPT-4.1, GPT-5.x | `OPENAI_API_KEY` |
| **Anthropic** | Claude Sonnet 4.0, 4.5 | `ANTHROPIC_API_KEY` |
| **Google** | Gemini 2.5 Flash/Pro | `GOOGLE_API_KEY` |
| **OpenRouter** | Qwen, Grok, e outros | `OPENROUTER_API_KEY` |
| **llama.cpp** | Qualquer modelo servido localmente | `LLAMA_CPP_BASE_URL` |

Modelos locais (Ollama, llama.cpp) sao automaticamente detetados e adicionados a lista.
Para instalar um novo modelo Ollama: `ollama pull <nome>` (ex: `ollama pull mistral`).
""")

st.subheader("Scraping Threads")
st.markdown("""
Numero de threads paralelos usados para scraping de paginas .onion (1-16, default: 4).
Mais threads = mais rapido, mas pode sobrecarregar o Tor proxy.
Recomendado: 4-8 para uso normal.
""")

st.subheader("Max Results to Filter")
st.markdown("""
Limite maximo de resultados brutos enviados ao LLM para filtragem (10-100, default: 50).
Valores mais altos dao mais cobertura mas aumentam o uso de tokens do LLM.
""")

st.subheader("Max Pages to Scrape")
st.markdown("""
Limite maximo de paginas .onion a scrape depois da filtragem (3-20, default: 10).
Valores mais altos fornecem mais dados ao LLM para a analise final,
mas aumentam o tempo de execucao.
""")

st.divider()

# --- Prompt Settings ---
st.header("Prompt Settings")
st.markdown("""
Os Prompt Settings definem o **dominio de investigacao** — o tipo de analise que o LLM
vai produzir no relatorio final. Cada preset configura um system prompt especializado
que orienta o LLM para extrair artefactos e insights relevantes ao dominio.
""")

presets = {
    "Dark Web Threat Intel": {
        "icon": "🔍",
        "desc": "Analise generalista de ameacas ciberneticas. O LLM procura e destaca:",
        "focus": [
            "Indicadores de ameaca: nomes, emails, telefones, enderecos crypto, dominios",
            "Mercados e foruns darkweb mencionados",
            "Informacao sobre threat actors (nomes, aliases, TTPs)",
            "Nomes de malware e ferramentas",
            "3-5 insights chave com proximos passos de investigacao",
        ],
        "use_when": "Investigacao generica sem foco especifico, reconhecimento inicial de ameacas.",
    },
    "Ransomware / Malware Focus": {
        "icon": "🦠",
        "desc": "Analise focada em ransomware e malware. O LLM procura:",
        "focus": [
            "Grupos de ransomware e familias de malware",
            "Indicadores: hashes, dominios C2, IPs, URLs de staging, nomes de payload",
            "Mapeamento de TTPs para MITRE ATT&CK",
            "Organizacoes vitimas, setores e geografias",
            "Evolucao do threat actor e comportamento",
        ],
        "use_when": "Investigacao de incidentes de ransomware, analise de malware, threat hunting.",
    },
    "Personal / Identity Investigation": {
        "icon": "👤",
        "desc": "Investigacao de exposicao de dados pessoais (PII). O LLM procura:",
        "focus": [
            "PII exposto: nomes, emails, telefones, moradas, SSN, passaportes, dados financeiros",
            "Fontes de breach e data brokers",
            "Mercados que vendem dados pessoais",
            "Avaliacao de severidade de exposicao",
            "Acoes protetivas recomendadas",
        ],
        "use_when": "Verificacao de exposicao de identidade, investigacao de breach, protecao de executivos.",
    },
    "Corporate Espionage / Data Leaks": {
        "icon": "🏢",
        "desc": "Analise de leaks corporativos e espionagem. O LLM procura:",
        "focus": [
            "Dados corporativos leaked: credenciais, codigo-fonte, documentos internos",
            "Registos financeiros, dados de empregados, bases de dados de clientes",
            "Threat actors e insider threats",
            "Atividade de data brokers focada na organizacao",
            "Avaliacao de impacto empresarial",
        ],
        "use_when": "Investigacao de data leaks empresariais, resposta a incidentes, due diligence.",
    },
}

for name, info in presets.items():
    with st.expander(f"{info['icon']} **{name}**"):
        st.markdown(info["desc"])
        for item in info["focus"]:
            st.markdown(f"- {item}")
        st.info(f"**Quando usar:** {info['use_when']}")

st.subheader("Custom Instructions")
st.markdown("""
Campo opcional que permite adicionar instrucoes extra ao LLM para a analise final.
As instrucoes sao anexadas ao system prompt do preset selecionado.

**Exemplos por dominio:**
- **Threat Intel:** _"Pay extra attention to cryptocurrency wallet addresses and exchange names"_
- **Ransomware:** _"Highlight any references to double-extortion tactics"_
- **Identity:** _"Flag any passport or government ID numbers"_
- **Corporate:** _"Prioritize mentions of source code repositories and API keys"_
""")

st.divider()

# --- Provider Configuration ---
st.header("Provider Configuration")
st.markdown("""
O DarkSherlock suporta multiplos providers de LLM. Configura-os no ficheiro `.env`
na raiz do projeto:

```
OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=sk-ant-...
GOOGLE_API_KEY=AI...
OLLAMA_BASE_URL=http://localhost:11434
OPENROUTER_BASE_URL=https://openrouter.ai/api/v1
OPENROUTER_API_KEY=sk-or-...
LLAMA_CPP_BASE_URL=http://localhost:8080
```

Apenas os providers com chaves configuradas aparecem na lista de modelos.
O Ollama e o llama.cpp sao opcionais — usam modelos locais sem necessidade de API key.
""")

st.divider()

# --- Health Checks ---
st.header("Health Checks")
st.markdown("""
Na sidebar, os botoes de Health Check permitem verificar:

- **Check LLM Connection** — envia um prompt minimo ("Say OK") ao modelo selecionado
  para verificar conectividade e medir latencia
- **Check Search Engines** — verifica primeiro se o Tor proxy esta acessivel (porta 9050),
  depois faz ping a todos os engines ativos via Tor e reporta latencia ou erro

Na pagina **Search Engines**, o botao **Test All Engines** testa todos os engines
(incluindo desativados) e mostra o estado de cada um com indicadores visuais.
""")

st.divider()

# --- Tor ---
st.header("Tor Proxy")
st.markdown("""
O DarkSherlock necessita do Tor para aceder a sites .onion. O Tor deve estar a correr
na porta 9050 (SOCKS5 proxy).

**Instalacao e arranque (macOS):**
```bash
brew install tor
brew services start tor
```

**Verificar se esta a correr:**
```bash
curl --socks5 127.0.0.1:9050 https://check.torproject.org
```

**Docker:** O Dockerfile inclui o Tor automaticamente. O `entrypoint.sh` arranca
o Tor antes do Streamlit.
""")

st.divider()

# --- Investigations ---
st.header("Investigacoes Guardadas")
st.markdown("""
Cada investigacao completada e automaticamente guardada em `investigations/` como JSON.
Na sidebar, podes carregar investigacoes passadas para rever os resultados.

Cada ficheiro contem:
- Query original e refinada
- Modelo usado e preset
- Lista de sources filtradas
- Summary completo gerado pelo LLM
""")

st.divider()

# --- Keyboard ---
st.header("Dicas")
st.markdown("""
- **Modelos locais sao mais lentos** mas nao tem custos e mantem os dados privados
- **Mais search engines = mais resultados** mas tambem mais tempo de execucao
- **Desativa engines offline** na pagina Search Engines para acelerar pesquisas
- **Usa Custom Instructions** para focar a analise em artefactos especificos
- **O pipeline e idempotente** — resultados de pesquisa e scraping sao cached por 200 segundos
- **Ficheiros .env nunca devem ser comitados** — ja esta no .gitignore
""")
