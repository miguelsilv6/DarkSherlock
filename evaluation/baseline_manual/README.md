# Baseline Manual — Protocolo de Execução (Capítulo 6, secção 6.5)

Este diretório contém o instrumento de apoio à execução do **baseline manual**
exigido por EQ-01 (e usado depois em EQ-02, EQ-03 e EQ-04): a mesma
investigação que o DarkSherlock faz automaticamente, mas conduzida à mão,
para servir de termo de comparação (`Baseline (s)` na Tabela 13, e as fontes
recolhidas manualmente como metade do *ground truth* pooling de EQ-02/EQ-03).

## Regras do protocolo (secção 6.5.2) — leitura obrigatória antes de começar

**Permitido:**
- Tor Browser para navegar em `.onion`.
- Pesquisa manual em três motores: **Ahmia**, **Tor66**, **The Deep Searches**.
- Um editor de texto para anotar fontes, citações e escrever o relatório.
- `baseline_helper.py` (esta pasta) — só cronometra e calcula SHA-256, não pesquisa nem analisa.

**Não permitido:**
- Qualquer LLM, mesmo offline (ChatGPT, Claude, um modelo local — nenhum).
- Outras ferramentas de automação OSINT (Maltego, SpiderFoot, etc.).
- O próprio DarkSherlock, obviamente.

Cada cenário é executado **uma única vez** no baseline (ao contrário do
DarkSherlock, que corre 3× por cenário e reporta a média).

## As 5 etapas cronometradas (secção 6.5.3)

| # | Etapa | O que fazer |
|---|---|---|
| 1 | Refinamento manual da query | Decide as palavras-chave que vais efetivamente pesquisar (equivalente à Etapa 2 do pipeline automático). |
| 2 | Pesquisa manual | Executa a pesquisa nos três motores permitidos. |
| 3 | Triagem manual | Lê títulos/URLs dos resultados e seleciona até 20 para investigar. |
| 4 | Recolha manual | Abre cada resultado selecionado no Tor Browser, copia o texto relevante para um ficheiro, calcula o SHA-256. |
| 5 | Redação do relatório | Escreve o relatório final no formato de `templates/report_template.md`. |

## Passo a passo prático

1. **Antes de começares um cenário**, cria a pasta de fontes:
   ```bash
   mkdir -p sources/A1
   ```

2. **Para cada etapa**, cronometra com `start`/`stop` (não faças contas de cabeça —
   a duração é calculada automaticamente e gravada em `timing_log.csv`):
   ```bash
   python baseline_helper.py start A1 1
   # ... fazes o trabalho da etapa 1 ...
   python baseline_helper.py stop A1 1
   ```
   Repete para as etapas 2 a 5. Se te esqueceres de um `stop` e começares outra
   etapa, a ferramenta avisa-te (`AVISO: já havia um cronómetro ativo...`) mas
   substitui — confirma sempre com `summary` no final.

3. **Na Etapa 4 (Recolha)**, por cada fonte que abrires no Tor Browser, guarda o
   texto relevante num ficheiro `.txt` dentro de `sources/<ID>/` (um ficheiro
   por fonte) e calcula o hash individual:
   ```bash
   python baseline_helper.py hash sources/A1/fonte1.txt
   ```
   Cola o hash no relatório (secção "Análise por Fonte" do template).

4. **No fim da Etapa 4**, calcula o hash global da investigação (mesmo
   algoritmo que `report.compute_integrity_hashes()` usa no DarkSherlock —
   hash da concatenação ordenada de todas as fontes):
   ```bash
   python baseline_helper.py hash-global sources/A1/
   ```
   Cola o resultado no cabeçalho de metadados do relatório.

5. **Escreve o relatório** em `reports/report_A1.md` (copia de
   `templates/report_A1.md`, que já vem com a query e o domínio preenchidos),
   seguindo exatamente a estrutura de 5 secções — é a mesma estrutura que o
   DarkSherlock produz, exigida pelos critérios de equivalência de output
   (secção 6.5.4).

6. **No final de cada cenário**, confirma que as 5 etapas foram registadas:
   ```bash
   python baseline_helper.py summary A1
   ```

7. Quando tiveres os 12 cenários completos:
   ```bash
   python baseline_helper.py summary
   ```
   Isto dá-te a soma por cenário (a coluna `Baseline (s)` da Tabela 13). O
   detalhe por etapa fica em `timing_log.csv` para a métrica "tempo por etapa"
   de EQ-01.

## Mitigação de ameaças à validade (o que já está tratado, e o que ainda precisas de garantir tu)

- **Volatilidade dos motores .onion** (secção 6.6, "Validade Interna"): o
  protocolo pede execução das duas condições (DarkSherlock e manual) "no
  mesmo dia, com não mais de uma hora de intervalo". Isto não é automatizável
  — faz o baseline manual do cenário X o mais próximo possível no tempo de
  uma corrida automática desse mesmo cenário.
- **Critérios de equivalência de output** (secção 6.5.4): os templates já
  espelham a estrutura de 5 secções do DarkSherlock. Garante URLs explícitos,
  hashes SHA-256 (por fonte e global) e timestamps UTC em todas as fontes —
  são os quatro requisitos formais listados.

## Ficheiros gerados (não versionados em git — ver `.gitignore`)

- `timing_log.csv` — log de todas as etapas cronometradas.
- `.timer_state.json` — estado interno dos cronómetros ativos.
- `sources/<ID>/*.txt` — texto bruto recolhido de cada fonte (pode conter
  conteúdo sensível/dark web — não deve ir para o repositório).
- `reports/report_<ID>.md` — os relatórios finais preenchidos.

Isto segue o mesmo princípio de `investigations/` e `logs/` no resto do
projeto: dados gerados por uma execução real não são versionados; só a
ferramenta e os templates em branco (`templates/`) o são.
