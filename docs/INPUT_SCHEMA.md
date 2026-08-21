# Esquema de entrada

Todos os CSVs usam cabeçalho UTF-8. Datas usam `AAAA-MM-DD`. Timestamps usam ISO 8601 com
indicador de fuso horário, como `2026-08-21T10:30:00-03:00` ou o sufixo `Z`.

## users.csv

| Campo | Uso |
|---|---|
| `user_id` | Identificador do usuário |
| `status` | `active`, `enabled`, `locked` ou outro estado normalizado |
| `user_type` | `dialog`, `shared`, `generic`, `service`, `system` ou `communication` |
| `last_logon` | Data do último logon, quando disponível |

## assignments.csv

| Campo | Uso |
|---|---|
| `user_id` | Usuário que recebeu a função |
| `role` | Identificador da função |
| `valid_from` | Início da validade, opcional |
| `valid_to` | Fim da validade, opcional |

## permissions.csv

| Campo | Uso |
|---|---|
| `role` | Função que concede a ação |
| `action` | Ação de negócio normalizada |
| `activity` | Atividade normalizada, como `display`, `change`, `execute` ou `approve` |
| `org_unit` | Escopo organizacional ou `*` |
| `active` | Indicador booleano |

## events.csv, opcional

| Campo | Uso |
|---|---|
| `user_id` | Usuário atribuído ao evento |
| `action` | Ação normalizada |
| `activity` | Atividade observada |
| `timestamp` | Data e hora do evento |
| `org_unit` | Escopo organizacional |
| `document_ref` | Referência usada somente para correlação, nunca gravada no relatório |
| `event_source` | Fonte declarada, por exemplo `SM20` |

## mitigations.csv, opcional

| Campo | Uso |
|---|---|
| `user_id` | Usuário coberto pelo controle |
| `risk_id` | Regra de risco aplicável |
| `control_id` | Identificador do controle |
| `valid_from` | Início da validade |
| `valid_to` | Fim da validade |
| `approved` | Aprovação formal normalizada |

## coverage.json, opcional

```json
{
  "source": "SM20-normalized-export",
  "period_start": "2026-07-01",
  "period_end": "2026-08-21",
  "completeness": 0.9
}
```

`completeness` é uma declaração de 0 a 1 fornecida pelo responsável pela extração. A ferramenta não
consegue comprovar sozinha a completude do log.
