# Segurança

## Modelo operacional

A versão `0.1.0` processa somente arquivos locais normalizados. Ela não solicita credenciais, não
chama RFC, OData ou APIs SAP e não executa remediações.

Use apenas exportações obtidas com autorização formal. Dados de usuários, funções, permissões,
eventos e controles mitigatórios podem revelar a estrutura de segurança da organização.

## Proteção do relatório

- usuários, funções, organizações e controles são pseudonimizados;
- referências documentais e textos originais dos eventos são omitidos;
- somente arquivo e número da linha são preservados como rastreabilidade;
- o relatório é publicado atomicamente;
- em sistemas POSIX, o arquivo recebe modo `0600`;
- sem segredo configurado, uma chave aleatória efêmera impede correlação entre relatórios;
- um segredo HMAC pode ser fornecido por `SAP_SOD_HMAC_SECRET` quando referências estáveis forem
  necessárias.

Pseudonimização não torna o relatório público. O arquivo permanece confidencial.

## Limites de segurança

- cada arquivo pode ter no máximo 20 MiB e 200 mil linhas;
- links simbólicos são rejeitados;
- a pasta de evidências deve conter arquivos regulares em seu nível raiz;
- o destino do relatório não pode ser um link simbólico;
- não há coleta ou correção automática;
- regras, scores e resultados exigem revisão humana.

Não publique exportações reais, relatórios, segredos ou identificadores em commits, issues ou pull
requests.

## Comunicação responsável

Não abra uma issue pública com detalhes exploráveis ou dados do ambiente. Use um canal privado
previamente acordado com o mantenedor.
