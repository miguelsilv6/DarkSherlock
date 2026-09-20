<!--
Template genérico do relatório de baseline manual (secção 6.5.4 — Critérios
de Equivalência de Output). Estrutura idêntica à que o DarkSherlock gera
(ver _OUTPUT_FORMAT em llm.py): mesmas 5 secções, para que os relatórios
sejam comparáveis na revisão cega (EQ-04) e no ground truth pooling
(EQ-02/EQ-03). NÃO copies estas instruções entre parênteses para o
relatório final — substitui-as pelo conteúdo real.
-->

# Baseline Manual — Investigação {{ID}}

## Metadados

- **Cenário:** {{ID}} — {{DOMAIN}}
- **Query original:** `{{QUERY}}`
- **Investigador:** (o teu nome)
- **Início (Etapa 1, UTC):**
- **Fim (Etapa 5, UTC):**
- **Motores usados:** Ahmia ⬜ · Tor66 ⬜ · The Deep Searches ⬜ (assinala os que produziram resultados)
- **Hash global SHA-256** (`baseline_helper.py hash-global sources/{{ID}}/`):

## 1. Query: {{QUERY}}

## 2. Análise por Fonte

(Uma subsecção `###` por fonte consultada. Cita excertos diretos do texto e
explica em 1-2 frases a relevância para a query.)

### Fonte 1

- **URL:**
- **SHA-256** (`baseline_helper.py hash sources/{{ID}}/fonte1.txt`):
- **Timestamp de recolha (UTC):**
- **Excerto citado:**
- **Relevância:**

## 3. Artefactos / IOCs

(Lista os indicadores técnicos — IPs, domínios, hashes, wallets, emails —
cada um com a fonte de origem. Se não houver, escreve "Nenhum identificado".)

## 4. Insights Chave

(3-5 observações acionáveis.)

## 5. Próximos Passos

(Queries e ações de investigação sugeridas.)
