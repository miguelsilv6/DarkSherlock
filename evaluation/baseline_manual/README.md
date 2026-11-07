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

## Fontes recolhidas (EQ-02 e EQ-03)

Além do relatório, regista-se, por cenário, **todas as fontes que o investigador viu** nas
Etapas 2–3 (não só as escolhidas) em `reports/manual_sources_<ID>.csv`, com as colunas
`url,title,engine,selected` (modelo em `templates/manual_sources_template.csv`).
`selected = 1` marca as (até 20) fontes escolhidas na triagem, que formam o Top-20 manual.
Estas listas alimentam `evaluation/eq02_eq03.py` (ver o cabeçalho desse ficheiro).

## Antes de começar: ensaio técnico (dados fictícios)

Antes de investires horas no baseline, confirma que todo o circuito de análise funciona
com as tuas investigações reais:

```bash
python evaluation/ensaio_tecnico.py --model "Phi-3.5-mini (embutido, médio)" --since 20261009
```

O script gera um baseline e folhas de revisores **aleatórios** em
`evaluation/ensaio/ENSAIO_FICTICIO_<data>/` e corre `tabela13.py`, `eq02_eq03.py` e
`eq04_review.py` de ponta a ponta. O `LEIA-ME.md` dessa pasta lista os passos e os
problemas encontrados (cenários sem execuções, relatórios "Sem dados suficientes",
mistura de versões do pipeline...). Todos os `.md` e `.csv` levam a marca
`⚠️ ENSAIO TÉCNICO — DADOS FICTÍCIOS. NÃO USAR NA TESE.`; a pasta está no `.gitignore`
e é recusada pelo hook de rasura. **Nenhum número do ensaio pode entrar na tese.**

## Cenários sem evidência (EQ-04 e verdadeiros negativos)

Quando a execução do DarkSherlock escolhida para um cenário termina num relatório sem
evidência, não há afirmações nem citações para a rubric Likert. Esses cenários saem da
EQ-04 (as duas condições, para a comparação continuar emparelhada), e a exclusão fica
registada em `private/key.json` e no resumo:

```bash
python evaluation/eq04_review.py build --investigations "investigations/eval_*.json" --model "Phi-3.5-mini (embutido, médio)" --since 20261110 --pipeline-version 2.3 --manual-dir evaluation/baseline_manual --exclude-no-evidence
```

Esses cenários entram depois na tabela de verdadeiros/falsos negativos, que compara a
ausência de evidência do DarkSherlock com o baseline manual e com os rótulos do pool:

```bash
python evaluation/true_negatives.py --investigations "investigations/eval_*.json" --model "Phi-3.5-mini (embutido, médio)" --since 20261110 --pipeline-version 2.3
```

Usa em `--since` o primeiro dia do baseline manual: assim as execuções do DarkSherlock
usadas são as emparelhadas com o trabalho manual (mesmo dia, ≤ 1 hora de intervalo).

## Revisor LLM complementar (opcional, além dos revisores humanos)

Depois de os revisores humanos terminarem, `evaluation/llm_judge.py` pode repetir as
mesmas tarefas com um modelo local e medir a concordância LLM–humano:

```bash
python evaluation/llm_judge.py eq0203 --ground-truth evaluation/ground_truth --investigations "investigations/eval_*.json" --model "<outro modelo>"
python evaluation/llm_judge.py eq04 --out evaluation/ground_truth/eq04 --model "<outro modelo>"
python evaluation/llm_judge.py compare --ground-truth evaluation/ground_truth --eq04-out evaluation/ground_truth/eq04
```

- O juiz lê só o que os revisores leem (URL, título e texto da fonte; relatório e
  evidência anonimizados) e nunca os rótulos humanos nem `private/key.json`.
- Usa um modelo **diferente** do que gerou os relatórios (viés de auto-preferência);
  o script avisa quando é o mesmo.
- As saídas ficam em `llm_judge/` e nunca são lidas por `eq02_eq03.py` nem por
  `eq04_review.py`: não substituem os revisores humanos.

Texto sugerido para a metodologia: *"Como análise complementar, as tarefas de
rotulagem do pool (EQ-02/EQ-03) e de pontuação dos relatórios (EQ-04) foram repetidas
por um modelo de linguagem local (temperatura 0, prompt fixo, cego à condição), diferente
do que gerou os relatórios. Reporta-se a concordância com os revisores humanos (κ de
Cohen e κ ponderado), que não substitui a avaliação humana."*
