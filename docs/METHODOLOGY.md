# Metodologia

## Versões

- ruleset: `sap-sod-core-1.0.0`;
- score: `sap-sod-risk-1.0.0`;
- relatório: `sap-sod-report-1.0`.

O score é uma regra de priorização criada por este projeto. Ele não é o resultado oficial do SAP
Access Control e não conclui fraude, desenho inadequado de função, efetividade de controle ou
conformidade com SOX.

## Conflito efetivo

Uma ocorrência somente é criada quando:

1. o usuário está ativo na data de análise;
2. as duas atribuições de função estão válidas;
3. as permissões estão ativas;
4. cada atividade corresponde ao requisito da regra;
5. os escopos organizacionais são iguais ou um deles contém `*`.

Acesso somente de consulta não atende a uma regra que exige criar, alterar, executar, liberar,
lançar ou aprovar.

## Risco inerente

| Fator | Pontos |
|---|---:|
| Severidade baixa | 20 |
| Severidade média | 35 |
| Severidade alta | 50 |
| Severidade crítica | 65 |
| Escopo organizacional sobreposto | +5 |
| Duas ações observadas | +15 |
| Mesmo fluxo documental | +10 |
| Usuário compartilhado ou genérico | +10 |
| Usuário técnico | +5 |
| Mitigação aprovada, mas vencida | +5 |

O resultado é limitado a 100.

## Risco residual

Um controle mitigatório aprovado e válido na data de análise reduz 20 pontos do risco residual. O
risco inerente é preservado. Controles não aprovados, vencidos ou fora do período não reduzem o
score.

## Faixas

- 0: informativo;
- 1 a 29: baixo;
- 30 a 49: médio;
- 50 a 69: alto;
- 70 a 100: crítico.

## Score do ambiente

```text
environment_score = 50% maior risco residual
                  + 35% média dos 10 maiores riscos residuais
                  + 15% proporção de ocorrências críticas
```

## Confiança

A confiança é separada do risco:

| Evidência | Pontos |
|---|---:|
| Regra versionada | 15 |
| Registro do usuário | 15 |
| Atribuição de função | 15 |
| Permissão efetiva | 20 |
| Escopo organizacional específico | 10 |
| Completude declarada do log | até 20 |
| Dataset de mitigações fornecido | 5 |
| Usuário compartilhado ou genérico | -20 |

A completude do log altera a confiança, não o risco de acesso concedido. Ausência de evento não
significa ausência de utilização quando a cobertura é incompleta.
