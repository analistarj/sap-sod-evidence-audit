# SAP SoD Evidence Audit

MVP offline, determinístico e explicável para correlacionar acessos concedidos, utilização
observada, escopo organizacional e controles mitigatórios em testes de segregação de funções SAP.

Versão: `0.1.0`. Ruleset sintético: `sap-sod-core-1.0.0`. Score:
`sap-sod-risk-1.0.0`.

O projeto não solicita credenciais, não acessa sistemas SAP e não reproduz um ruleset proprietário
do SAP Access Control. Ele processa exportações normalizadas dentro de uma pasta local.

## Perguntas de auditoria

- O usuário possui capacidade efetiva para executar duas ações conflitantes?
- As permissões se sobrepõem no mesmo escopo organizacional?
- Existem eventos que indiquem utilização das duas ações?
- Os eventos pertencem ao mesmo fluxo documental?
- Existe controle mitigatório aprovado e válido?
- A evidência disponível possui completude suficiente?

## Resultados

Cada ocorrência contém:

- `risk_score`, risco inerente de 0 a 100;
- `residual_risk_score`, risco depois do controle mitigatório;
- `confidence_score`, completude da evidência, separado do risco;
- conflito potencial e utilização observada;
- fatores de pontuação;
- linhas dos arquivos que sustentaram a conclusão;
- identificadores pseudonimizados no relatório.

O score prioriza revisão de auditoria. Ele não comprova fraude, falha de controle ou conformidade.

## Riscos sintéticos incluídos

| Processo | Conflito | Severidade |
|---|---|---|
| P2P | Manter fornecedor e executar pagamento | Crítica |
| P2P | Alterar dados bancários do fornecedor e executar pagamento | Crítica |
| P2P | Criar e liberar pedido de compra | Alta |
| R2R | Lançar e aprovar lançamento contábil | Alta |
| O2C | Manter cliente e registrar recebimento | Crítica |

Essas regras demonstram o mecanismo. Antes de utilização corporativa, devem ser revisadas e
adaptadas por especialistas SAP Security, responsáveis de processo e Auditoria Interna.

## Instalação

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install .
```

No PowerShell:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install .
```

## Execução do exemplo

```bash
sap-sod-evidence-audit examples/synthetic \
  --rules rules/sap-sod-core-1.0.0.json \
  --analysis-date 2026-08-21 \
  --output report-synthetic.json
```

No PowerShell:

```powershell
sap-sod-evidence-audit examples/synthetic `
  --rules rules/sap-sod-core-1.0.0.json `
  --analysis-date 2026-08-21 `
  --output report-synthetic.json
```

Sem segredo configurado, cada relatório usa uma chave aleatória efêmera e suas referências não
podem ser correlacionadas com outro relatório. Para referências pseudonimizadas estáveis, forneça
um segredo obtido de cofre somente ao processo:

```bash
export SAP_SOD_HMAC_SECRET="valor-obtido-de-cofre"
```

Nunca grave o segredo no repositório ou o passe pela linha de comando.

## Formato de entrada

A pasta contém `users.csv`, `assignments.csv` e `permissions.csv`. `events.csv`,
`mitigations.csv` e `coverage.json` são opcionais. O esquema está documentado em
[INPUT_SCHEMA.md](docs/INPUT_SCHEMA.md).

A extração de dados reais não faz parte deste MVP. Os arquivos devem ser preparados e revisados por
uma equipe autorizada.

## Metodologia

A fórmula, as faixas, o tratamento de escopo e as limitações estão em
[METHODOLOGY.md](docs/METHODOLOGY.md). A arquitetura está em
[BLUEPRINT.md](docs/BLUEPRINT.md).

## Desenvolvimento

```bash
python -m pip install -e '.[dev]'
ruff check .
coverage run -m unittest discover -v
coverage report
python -m build
```

Todos os dados dos exemplos e testes são artificiais.

## English summary

SAP SoD Evidence Audit is an offline, deterministic and explainable MVP that correlates normalized
user, role, permission, event, organizational scope and mitigation exports. It separates inherent
risk, residual risk and evidence confidence, while pseudonymizing identifiers and avoiding direct
SAP connectivity. The included rules are synthetic and do not claim compliance or reproduce a
proprietary SAP Access Control ruleset.

## Licença

Distribuído sob a [MIT License](LICENSE).
