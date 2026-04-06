"""
3_❓_Help.py — Documentacao completa do DarkSherlock.

Pagina de referencia com guia de utilizacao, descricao do pipeline,
configuracao de providers, gestao de engines, logs/debug e dicas.

Contexto academico: Dissertacao de Mestrado em Ciberseguranca.
"""

import streamlit as st

st.set_page_config(
    page_title="DarkSherlock — Help",
    page_icon="❓",
    initial_sidebar_state="expanded",
)

st.title("Help & Documentation")
st.caption("DarkSherlock — AI-Powered Dark Web OSINT Tool")

# ---------------------------------------------------------------------------
# Quick Start
# ---------------------------------------------------------------------------
st.header("Quick Start")
st.markdown("""
1. **Garante que o Tor esta a correr** na porta 9050 (`brew services start tor` no macOS)
2. **Seleciona um modelo LLM** na sidebar (ex: `llama3.2:latest` para uso local via Ollama)
3. **Escolhe o dominio de investigacao** no Prompt Settings (Threat Intel, Ransomware, PII, Corporate)
4. **Escreve uma query** na barra de pesquisa (ex: `Akira ransomware leak site`)
5. **Clica em Run** — o pipeline de 6 etapas executa automaticamente
6. **Analisa os resultados** — o LLM produz uma analise por fonte com citacoes directas
7. **Descarrega o relatorio** em PDF forense ou Markdown
""")

st.divider()

# ---------------------------------------------------------------------------
# Pipeline de Investigacao
# ---------------------------------------------------------------------------
st.header("Pipeline de Investigacao")
st.markdown("""
O DarkSherlock executa um pipeline de **6 etapas sequenciais** quando fazes uma pesquisa.
Cada etapa mostra o estado (running/complete/error), detalhes expandiveis e tempo de execucao.
""")

stages = [
    ("Stage 1 — Load LLM", """
Carrega o modelo de linguagem selecionado na sidebar.

- **Ollama (local):** O modelo corre na tua maquina — sem custos, dados privados
- **Cloud (OpenAI, Claude, Gemini, OpenRouter):** Chamada API — mais rapido, melhor qualidade
- O modelo e reutilizado para as etapas 2, 4 e 6
"""),
    ("Stage 2 — Refine Query", """
O LLM analisa a tua query e optimiza-a para motores de pesquisa da dark web.

- A query e adaptada ao **dominio de investigacao** selecionado (preset)
- Exemplo: `lockbit` → `lockbit ransomware group leak site`
- O refinamento e limitado a **5 palavras** para maximizar a relevancia
- O LLM opera como um "algoritmo de keywords" — sem acesso a conteudo externo
"""),
    ("Stage 3 — Search Dark Web", """
A query refinada e enviada a **todos os search engines ativos** em paralelo via proxy Tor.

- Cada engine e consultado numa thread separada (configuraveis na sidebar)
- Os resultados (titulo + link .onion) sao agregados e **deduplicados por URL**
- A sessao Tor e **partilhada entre todos os workers** para minimizar o overhead de circuito
- Os resultados sao limitados ao valor de "Max Results to Filter"
- Cada resultado recebe um **timestamp UTC de recolha** para auditoria
"""),
    ("Stage 4 — Filter Results", """
O LLM recebe todos os resultados (indice, link truncado, titulo) e seleciona os **Top 20 mais relevantes**.

- O LLM opera como um "algoritmo de ranking" — devolve apenas indices numericos
- Filtra ruido e foca a investigacao nos resultados mais promissores
- Em caso de **rate limit da API**, tenta automaticamente com titulos truncados
- Se o LLM falhar, usa os primeiros 20 resultados como fallback
"""),
    ("Stage 5 — Scrape Content", """
Os links filtrados sao acedidos via Tor e o conteudo textual e extraido com BeautifulSoup.

- A sessao Tor e **partilhada** entre todos os workers de scraping (optimizacao de performance)
- Paginas inacessiveis sao removidas automaticamente (timeout, 404, etc.)
- O conteudo e **truncado por paragrafo** — corta no ultimo paragrafo completo antes do limite, em vez de cortar a meio de frases
- Sao calculados **hashes SHA-256 de integridade** para cada pagina e para o conjunto global
- Cada pagina recebe um **timestamp UTC de scraping**
- Um expander mostra o **conteudo recolhido por fonte** (primeiros 500 chars de cada) para transparencia

**Novo:** O conteudo recolhido e agora visivel antes da analise do LLM, permitindo ao investigador verificar exactamente o que foi extraido de cada URL.
"""),
    ("Stage 6 — Generate Summary", """
O LLM analisa todo o conteudo recolhido e gera um **relatorio de inteligencia estruturado** em Portugues.

- O conteudo e formatado como **[FONTE N]** com URL explicito para cada pagina
- O LLM produz uma **analise por fonte**: cita excertos directos do texto e explica a relevancia
- Cada insight referencia a(s) fonte(s) de onde deriva
- O output segue o formato do preset selecionado (Threat Intel, Ransomware, PII, Corporate)
- O summary e gerado em **modo streaming** — aparece em tempo real na interface

**Formato de output (por preset):**
- Artefactos de investigacao (IOCs, nomes, emails, hashes, IPs, dominios)
- Analise por fonte com citacoes directas
- Insights chave com referencia a fontes
- Proximos passos de investigacao
"""),
]

for title, desc in stages:
    with st.expander(f"**{title}**"):
        st.markdown(desc)

st.divider()

# ---------------------------------------------------------------------------
# Paginas
# ---------------------------------------------------------------------------
st.header("Paginas")

st.subheader("Home")
st.markdown("""
Pagina principal com barra de pesquisa e pipeline completo de investigacao.

- **Pipeline visual** — cada etapa mostra estado (running/complete/error) com tempos de execucao
- **Conteudo por fonte** — expander com o texto extraido de cada URL antes da analise LLM
- **Findings** — relatorio final em streaming com analise per-source
- **Notes** — detalhes da investigacao (query refinada, modelo, contagens)
- **Download PDF** — relatorio forense com metadados, hashes de integridade e cadeia de custodia
- **Download MD** — summary em Markdown para referencia rapida
- **Past Investigations** — sidebar com historico de investigacoes anteriores (JSON)
""")

st.subheader("Search Engines")
st.markdown("""
Gestao dos motores de pesquisa da dark web utilizados pelo pipeline.

- **Auto-health-check** — testa automaticamente todos os engines na primeira carga da pagina
- **Test All Engines** — teste manual de conectividade via Tor com latencia por engine
- **Ativar/Desativar** — engines desativados sao ignorados nas pesquisas
- **Editar** — altera nome e URL de um engine (URL deve conter `{query}`)
- **Remover** — remove permanentemente um engine (com dialogo de confirmacao)
- **Adicionar** — regista um novo engine customizado
- **Reset** — repoe a lista original de engines (inclui defaults + deepdarkCTI)

**Integracao deepdarkCTI:** Alem dos engines originais, o DarkSherlock inclui **18 engines
adicionais** do repositorio [fastfire/deepdarkCTI](https://github.com/fastfire/deepdarkCTI),
que mantem uma lista actualizada de recursos .onion verificados como ONLINE.
Estes engines vem **desactivados por omissao** — activa-os individualmente e testa com
"Test All Engines" antes de usar no pipeline.
""")

st.subheader("Investigation (Pipeline Detalhado)")
st.markdown("""
Pipeline identico a Home mas com a sidebar completa e opcoes de configuracao
acessiveis durante a investigacao. Inclui:

- Mesmo pipeline de 6 etapas com progresso visual
- Sidebar com modelo, threads, limites, preset e custom instructions
- Historico de investigacoes carregavel
- Download de PDF forense e Markdown
""")

st.subheader("Debug & Logs")
st.markdown("""
Pagina de diagnostico que centraliza toda a informacao de logs e auditoria.

- **Audit Log** — tabela com todas as investigacoes executadas: query, modelo, preset,
  engines, resultados encontrados/filtrados/scraped, duracao e timestamp
- **Detalhes por entrada** — expander JSON com todos os campos de cada investigacao
- **App Log** — log aplicacional em texto livre com todos os eventos da aplicacao
  (scraping timeouts, erros de rede, debug messages)
- **Filtro por nivel** — filtra por DEBUG, INFO, WARNING, ERROR
- **Metricas** — contagem de warnings e errors no log actual
- **Limpar logs** — botoes para limpar Audit Log, App Log ou ambos
""")

st.divider()

# ---------------------------------------------------------------------------
# Settings (Sidebar)
# ---------------------------------------------------------------------------
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
Numero de threads paralelos usados para pesquisa e scraping de paginas .onion (1-16, default: 4).

- Mais threads = mais rapido, mas pode sobrecarregar o Tor proxy
- A sessao Tor e **partilhada** entre todos os threads (sem overhead por thread)
- Recomendado: **4-8** para uso normal
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
mas aumentam o tempo de execucao do Stage 5.
""")

st.divider()

# ---------------------------------------------------------------------------
# Prompt Settings
# ---------------------------------------------------------------------------
st.header("Prompt Settings")
st.markdown("""
Os Prompt Settings definem o **dominio de investigacao** — o tipo de analise que o LLM
vai produzir no relatorio final. Cada preset configura um system prompt especializado
que orienta o LLM para:

- Analisar o conteudo de **cada fonte individualmente** (analise per-source)
- Citar **excertos directos** do texto de cada fonte
- Extrair **artefactos e IOCs** relevantes ao dominio
- Gerar **insights accionaveis** com referencia as fontes de onde derivam
""")

presets = {
    "Dark Web Threat Intel": {
        "icon": "🔍",
        "desc": "Analise generalista de ameacas ciberneticas. O LLM procura e destaca:",
        "focus": [
            "Indicadores de ameaca: nomes, emails, telefones, enderecos crypto, dominios",
            "Mercados e foruns darkweb mencionados",
            "Informacao sobre threat actors (nomes, aliases, TTPs)",
            "Nomes de malware e ferramentas de ataque",
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
            "Perfil do threat actor e evolucao comportamental",
        ],
        "use_when": "Investigacao de incidentes de ransomware, analise de malware, threat hunting.",
    },
    "Personal / Identity Investigation": {
        "icon": "👤",
        "desc": "Investigacao de exposicao de dados pessoais (PII). O LLM procura:",
        "focus": [
            "PII exposto: nomes, emails, telefones, moradas, SSN, passaportes, dados financeiros",
            "Fontes de breach e data brokers identificados",
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
            "Threat actors, insider threats e data brokers",
            "Avaliacao de impacto empresarial e dano competitivo",
            "Passos de resposta a incidentes e consideracoes legais",
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

**Exemplos:**
- **Threat Intel:** _"Pay extra attention to cryptocurrency wallet addresses and exchange names"_
- **Ransomware:** _"Highlight any references to double-extortion tactics and MITRE T1486"_
- **Identity:** _"Flag any passport or government ID numbers found in breach data"_
- **Corporate:** _"Prioritize mentions of source code repositories, API keys and internal wikis"_
""")

st.divider()

# ---------------------------------------------------------------------------
# Provider Configuration
# ---------------------------------------------------------------------------
st.header("Configuracao de Providers")
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

# ---------------------------------------------------------------------------
# Reports & Forensics
# ---------------------------------------------------------------------------
st.header("Relatorios e Forense")
st.markdown("""
Cada investigacao completa gera dois tipos de relatorio:

**Relatorio PDF Forense:**
- Metadados completos: audit ID, timestamps UTC, modelo, preset, engines utilizados
- Lista de fontes com URLs e timestamps de recolha/scraping
- **Hashes SHA-256 de integridade** — por pagina e global — para verificacao de cadeia de custodia
- Summary completo gerado pelo LLM
- Adequado para anexar a relatorios formais de investigacao ou processos legais

**Summary Markdown:**
- Analise completa em formato texto
- Ideal para referencia rapida, partilha ou inclusao em documentacao
""")

st.divider()

# ---------------------------------------------------------------------------
# Health Checks
# ---------------------------------------------------------------------------
st.header("Health Checks")
st.markdown("""
Na sidebar, os botoes de Health Check permitem verificar:

- **Check LLM Connection** — envia um prompt minimo ("Say OK") ao modelo selecionado
  para verificar conectividade e medir latencia
- **Check Search Engines** — verifica primeiro se o Tor proxy esta acessivel (porta 9050),
  depois faz ping a todos os engines ativos via Tor e reporta latencia ou erro

Na pagina **Search Engines**, o **auto-health-check** testa automaticamente todos os engines
na primeira carga. O botao **Test All Engines** permite re-testar a qualquer momento.

O resultado do ultimo teste e mostrado como **banner de notificacao** na pagina de Investigacao.
""")

st.divider()

# ---------------------------------------------------------------------------
# Tor Proxy
# ---------------------------------------------------------------------------
st.header("Tor Proxy")
st.markdown("""
O DarkSherlock necessita do Tor para aceder a sites .onion. O Tor deve estar a correr
na porta 9050 (SOCKS5 proxy).

**macOS:**
```bash
brew install tor
brew services start tor
```

**Linux (Debian/Ubuntu):**
```bash
sudo apt install tor
sudo systemctl start tor
```

**Verificar se esta a correr:**
```bash
curl --socks5 127.0.0.1:9050 https://check.torproject.org
```

**Docker:** O Dockerfile inclui o Tor automaticamente. O `entrypoint.sh` arranca
o Tor antes do Streamlit.
""")

st.divider()

# ---------------------------------------------------------------------------
# Investigacoes Guardadas
# ---------------------------------------------------------------------------
st.header("Investigacoes Guardadas")
st.markdown("""
Cada investigacao completada e automaticamente guardada em `investigations/` como JSON.
Na sidebar da pagina Investigation, podes carregar investigacoes passadas.

Cada ficheiro contem:
- **audit_id** — identificador unico da investigacao (UUID)
- **Timestamps UTC** — momento exacto de inicio e conclusao
- **Query original e refinada**
- **Modelo usado e preset**
- **Engines activos** durante a investigacao
- **Lista de sources filtradas** com timestamps de recolha e scraping
- **Hashes de integridade** — SHA-256 por fonte e global
- **Summary completo** gerado pelo LLM

O **Audit Log** (consultavel na pagina Debug) regista tambem metricas de performance:
resultados encontrados, filtrados, scraped, duracao total do pipeline e erros.
""")

st.divider()

# ---------------------------------------------------------------------------
# Dicas
# ---------------------------------------------------------------------------
st.header("Dicas")
st.markdown("""
- **Modelos locais sao mais lentos** mas nao tem custos e mantem os dados completamente privados
- **O pipeline reutiliza sessoes Tor** — nao cria novas conexoes por cada URL, o que acelera significativamente o Stage 3 e 5
- **Resultados de pesquisa sao cached** por 200 segundos na Home — re-executar a mesma query e instantaneo
- **Mais search engines = mais resultados** mas tambem mais tempo — desactiva engines offline na pagina Search Engines
- **Engines do deepdarkCTI** estao desactivados por omissao — activa-os e testa antes de usar
- **Usa Custom Instructions** para focar a analise em artefactos especificos
- **O conteudo por fonte** (expander no Stage 5) permite verificar o que o LLM vai analisar antes de ver o summary
- **Consulta os logs** na pagina Debug para diagnosticar problemas de scraping (timeouts, erros de rede)
- **Ficheiros .env nunca devem ser comitados** — ja estao no .gitignore
- **O relatorio PDF** inclui hashes de integridade para cadeia de custodia forense
""")
