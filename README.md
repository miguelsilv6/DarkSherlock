<div align="center">
   <h1>DarkSherlock</h1>
   <strong>AI-Powered Dark Web OSINT Investigation Tool</strong>
   <br><br>
   <p>
      DarkSherlock is an AI-powered tool for conducting dark web OSINT investigations.<br>
      It leverages LLMs to refine queries, search multiple dark web engines via Tor,<br>
      scrape and analyze content per-source, and generate structured intelligence reports in Portuguese.
   </p>
   <p>
      <a href="#features">Features</a> &bull;
      <a href="#architecture">Architecture</a> &bull;
      <a href="#installation">Installation</a> &bull;
      <a href="#usage">Usage</a> &bull;
      <a href="#configuration">Configuration</a> &bull;
      <a href="#academic-context">Academic Context</a>
   </p>
</div>

---

## Features

- **6-Stage Investigation Pipeline** — Automated workflow: LLM load → query refinement → multi-engine Tor search → LLM relevance filtering → content scraping → intelligence report generation
- **Per-Source Analysis** — The LLM analyzes each scraped page individually, citing direct quotes and explaining relevance, rather than producing a generic summary
- **Multi-Model Support** — OpenAI, Anthropic Claude, Google Gemini, OpenRouter, Ollama (local), and llama.cpp — switch models from the sidebar
- **34+ Dark Web Search Engines** — 16 built-in engines + 18 from [fastfire/deepdarkCTI](https://github.com/fastfire/deepdarkCTI), all configurable and testable via the UI
- **Forensic PDF Reports** — Download reports with audit ID, UTC timestamps, SHA-256 integrity hashes (per-page and global), source list, and full analysis
- **Real-Time Streaming** — Intelligence reports are generated token-by-token with live display
- **Investigation Presets** — 4 specialized analysis domains: Threat Intel, Ransomware/Malware, Personal Identity (PII), Corporate Espionage
- **Shared Tor Sessions** — Single Tor session reused across all concurrent workers, minimizing circuit establishment overhead
- **Debug & Audit Logging** — Structured audit log (JSONL) + application log with level filtering, metrics, and cleanup tools
- **Auto Health Checks** — Automatic engine connectivity testing on page load, with manual re-test available
- **Integrity Hashes** — SHA-256 hashes computed for every scraped page, ensuring forensic chain of custody
- **Docker-Ready** — Dockerfile with Tor included for isolated, reproducible deployments

---

## Architecture

```
                    ┌─────────────┐
                    │   User      │
                    │   Query     │
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │  Stage 1    │
                    │  Load LLM   │
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │  Stage 2    │
                    │ Refine Query│ ◄── LLM + Preset Context
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │  Stage 3    │
                    │ Search Tor  │ ◄── N engines in parallel (shared session)
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │  Stage 4    │
                    │ Filter LLM  │ ◄── Top 20 most relevant
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │  Stage 5    │
                    │ Scrape Tor  │ ◄── Parallel scraping (shared session)
                    └──────┬──────┘     + SHA-256 hashes + timestamps
                           │
                    ┌──────▼──────┐
                    │  Stage 6    │
                    │ LLM Report  │ ◄── Per-source analysis, streaming output
                    └──────┬──────┘
                           │
               ┌───────────┼───────────┐
               ▼           ▼           ▼
          ┌─────────┐ ┌─────────┐ ┌─────────┐
          │  PDF    │ │Markdown │ │  JSON   │
          │ Report  │ │ Summary │ │ Archive │
          └─────────┘ └─────────┘ └─────────┘
```

---

## Pages

| Page | Description |
|------|-------------|
| **Home** | Main investigation interface with full pipeline, streaming results, PDF/MD download |
| **Search Engines** | Manage, test, enable/disable, edit, add, and reset dark web search engines |
| **Investigation** | Alternative pipeline view with full sidebar settings accessible during execution |
| **Help** | Complete documentation, pipeline explanation, configuration guide, and tips |
| **Debug** | Audit log table, application log viewer with level filter, metrics, and log cleanup |

---

## Installation

### Prerequisites

- **Python 3.10+**
- **Tor** running on port 9050 (SOCKS5 proxy)

Install Tor:
```bash
# macOS
brew install tor
brew services start tor

# Linux (Debian/Ubuntu)
sudo apt install tor
sudo systemctl start tor
```

### Python (Development)

```bash
# Clone the repository
git clone https://github.com/miguelsilv6/DarkSherlock.git
cd DarkSherlock

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
# venv\Scripts\activate   # Windows

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your API keys (see Configuration section)

# Run
streamlit run Home.py
```

Open your browser at `http://localhost:8501`

### Docker

```bash
docker build -t darksherlock .

docker run --rm \
   -v "$(pwd)/.env:/app/.env" \
   --add-host=host.docker.internal:host-gateway \
   -p 8501:8501 \
   darksherlock
```

> **Tip:** To persist investigations across Docker restarts:
> ```bash
> docker run --rm \
>    -v "$(pwd)/.env:/app/.env" \
>    -v "$(pwd)/investigations:/app/investigations" \
>    -v "$(pwd)/logs:/app/logs" \
>    --add-host=host.docker.internal:host-gateway \
>    -p 8501:8501 \
>    darksherlock
> ```

---

## Usage

### Basic Investigation

1. Select an LLM model in the sidebar (e.g., `llama3.2:latest` for local Ollama)
2. Choose an investigation domain in Prompt Settings
3. Type a query (e.g., `Akira ransomware leak site`) and click **Run**
4. Review the per-source analysis and download the forensic PDF report

### Investigation Presets

| Preset | Focus | Example Queries |
|--------|-------|-----------------|
| **Threat Intel** | General OSINT — threat actors, forums, IOCs, marketplaces | `lockbit leak site`, `credential dump forum` |
| **Ransomware/Malware** | Ransomware groups, C2 infrastructure, MITRE ATT&CK mapping | `Akira ransomware`, `cobalt strike beacon` |
| **Personal Identity** | PII exposure, breach databases, data brokers | `john.doe@company.com breach`, `SSN dark web` |
| **Corporate Espionage** | Leaked credentials, source code, internal documents | `company.com leaked credentials`, `internal wiki dump` |

### Search Engine Management

- Navigate to the **Search Engines** page to manage dark web engines
- **18 engines from deepdarkCTI** are included but disabled by default — enable and test before using
- Use **Test All Engines** to verify connectivity via Tor before running investigations
- Add custom engines with URLs containing `{query}` as a placeholder

---

## Configuration

### Environment Variables (`.env`)

```env
# LLM Providers (add keys for providers you want to use)
OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=sk-ant-...
GOOGLE_API_KEY=AI...
OPENROUTER_BASE_URL=https://openrouter.ai/api/v1
OPENROUTER_API_KEY=sk-or-...

# Local Models (optional)
OLLAMA_BASE_URL=http://localhost:11434
LLAMA_CPP_BASE_URL=http://localhost:8080
```

Only providers with configured keys appear in the model selection dropdown.
Ollama models are auto-detected from the running Ollama instance.

### Ollama Setup (Local Models)

```bash
# Install Ollama (macOS)
brew install ollama
ollama serve

# Pull a model
ollama pull llama3.2
ollama pull mistral
```

> **Docker note:** Use `OLLAMA_BASE_URL=http://host.docker.internal:11434` in `.env`
> and serve Ollama on `0.0.0.0`: `OLLAMA_HOST=0.0.0.0 ollama serve`

---

## Project Structure

```
DarkSherlock/
├── Home.py                    # Main page — investigation pipeline
├── pages/
│   ├── 1_⚙️_Search_Engines.py  # Engine management & health checks
│   ├── 2_🔍_Investigation.py   # Alternative pipeline with full sidebar
│   ├── 3_❓_Help.py            # Documentation & help
│   └── 4_🐛_Debug.py           # Audit log, app log, diagnostics
├── llm.py                     # LLM integration, prompts, presets
├── llm_utils.py               # Model registry, streaming handler
├── search.py                  # Multi-engine Tor search (shared sessions)
├── scrape.py                  # Tor scraping with paragraph-aware truncation
├── engine_manager.py          # Engine CRUD + deepdarkCTI sync
├── health.py                  # Tor & engine connectivity checks
├── report.py                  # Forensic PDF generation & integrity hashes
├── audit.py                   # JSONL audit log & file logging setup
├── sidebar.py                 # Shared sidebar across all pages
├── config.py                  # Environment variable loading
├── Dockerfile                 # Docker image with Tor included
├── entrypoint.sh              # Docker entrypoint (starts Tor + Streamlit)
├── requirements.txt           # Python dependencies
├── .env.example               # Template for environment variables
└── .streamlit/config.toml     # Streamlit theme configuration
```

---

## Key Technical Details

### Performance Optimizations

- **Shared Tor Sessions** — A single `requests.Session` with SOCKS5h proxy is created once and shared across all concurrent workers in ThreadPoolExecutor, eliminating per-request Tor circuit establishment overhead (~300-500ms saved per URL)
- **Search Result Caching** — `@st.cache_data(ttl=200)` caches search results by query only (thread count excluded from cache key to avoid unnecessary invalidation)
- **Single-Pass Deduplication** — Results are deduplicated once in `search.py` instead of redundantly in each page
- **Pre-compiled Regex** — Regex patterns for URL/title normalization are compiled once at module level
- **Paragraph-Aware Truncation** — Content is truncated at the last complete paragraph before the character limit, preserving context for the LLM

### Forensic Features

- **SHA-256 Integrity Hashes** — Computed for every scraped page and globally, enabling chain of custody verification
- **UTC Timestamps** — Every result and scraped page receives ISO 8601 UTC timestamps
- **Audit Trail** — Structured JSONL log records all investigation parameters, metrics, and durations
- **Forensic PDF** — Downloadable report with audit ID, timestamps, hashes, sources, and full analysis

### LLM Prompt Engineering

- **Per-Source Analysis** — Content is structured as `[FONTE N]\nURL: ...\n\ncontent` blocks so the LLM can reference and cite each source individually
- **DFIR Framing** — System prompts use concrete academic/forensic personas and authorization chains to prevent local model safety filter refusals on dark web content
- **Domain-Specific Presets** — 4 specialized prompt templates with tailored extraction rules and output formats
- **Minimal-Surface Prompts** — `refine_query` and `filter_results` use deliberately simplified roles ("keyword analyst", "ranking algorithm") to minimize safety filter triggers

---

## Disclaimer

> This tool is developed as part of a Master's thesis in Cybersecurity and is intended
> exclusively for **educational and authorized research purposes**.
>
> Accessing or interacting with certain dark web content may be illegal depending on
> your jurisdiction. The authors are not responsible for any misuse of this tool.
>
> Use responsibly and ensure compliance with all applicable laws and institutional
> policies before conducting OSINT investigations.
>
> This tool leverages third-party LLM APIs. Review the terms of service for any
> API provider you use before sending potentially sensitive queries.

---

## Academic Context

This project was developed as part of a **Master's thesis in Cybersecurity** at the
University of Lisbon, focusing on defensive OSINT capabilities for dark web monitoring
and threat intelligence gathering.

The tool is designed for:
- **Digital Forensics & Incident Response (DFIR)** — evidence collection and analysis
- **Threat Intelligence** — monitoring dark web forums, markets, and leak sites
- **Risk Assessment** — evaluating organizational exposure on the dark web
- **Academic Research** — studying dark web ecosystems and threat actor behavior

---

## Acknowledgements

- Originally forked from [Robin](https://github.com/apurvsinghgautam/robin) by [Apurv Singh Gautam](https://github.com/apurvsinghgautam)
- Dark web engine list extended with [fastfire/deepdarkCTI](https://github.com/fastfire/deepdarkCTI)
- Idea inspiration from [Thomas Roccia](https://x.com/fr0gger_) and [Perplexity of the Dark Web](https://x.com/fr0gger_/status/1908051083068645558)
- LLM prompt patterns inspired by [OSINT-Assistant](https://github.com/AXRoux/OSINT-Assistant)

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
