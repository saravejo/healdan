# Check de integração da sprint

`sprint/b00` é o check consolidado dos lotes da sprint em `saravejo/healdan`. A publicação ocorre no HEAD da PR. O registro também vincula o número da PR, a base, o commit de merge de teste, a tentativa de CI e o hash da atestação. A integração exige um preflight do coordenador com esses mesmos dados.

## Proteção e configuração

- Proteja `main` com PR obrigatória, zero aprovações obrigatórias no GitHub, conversas resolvidas, checks estritos e proteção aplicada aos administradores. Desabilite force-push, exclusão e exceções para PRs. Exija `test`, `package` e `sprint/b00` com a fonte GitHub Actions, `app_id` 15368.
- Mantenha um ruleset ativo para `main` com a regra `Restrict updates`. Configure apenas o papel de administrador do repositório, ID 5, com bypass `pull_request` nesse ruleset. O coordenador é o único administrador e integra através da PR. A proteção clássica permanece aplicada aos administradores.
- Em Actions, configure as variáveis `SPRINT_B00_COORDINATOR_ID`, `SPRINT_B00_QODO_BOT_ID` e `SPRINT_B00_QODO_APP_ID` com os IDs numéricos verificados. A instalação observada do Qodo usa bot `151058649` e App `484649`. Confirme a instalação antes de alterar esses IDs.

O workflow `.github/workflows/sprint-b00.yml` é disparado de `main` protegida. Os jobs de teste nativo e empacotamento obtêm o código público por `refs/pull/<n>/head`, verificam o SHA recebido do job de preparação e executam com permissões vazias e ambiente reduzido. Cada job usa um runner separado. O job `sprint-b00 gate` mantém `checks: write` e só executa o verificador do ref protegido. O verificador lê comentários e critérios como dados, usa metadados oficiais da execução e exige sucesso real dos jobs `sprint-b00 test` e `sprint-b00 package` na mesma tentativa.

A proteção do GitHub identifica o App GitHub Actions, compartilhado por workflows do repositório. A fonte da aprovação é confirmada no preflight pelo caminho, identidade, SHA e tentativa do workflow protegido e pelo ID de check no log oficial do job. A regra que restringe atualizações de `main` reserva a integração ao coordenador, que verifica esse vínculo antes do merge. [Proteção de branches](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches), [fonte de checks](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets)

## Atestação GitHub

Use a branch `sprint/bNN-descricao` no próprio repositório e atualize o HEAD com a `main` corrente. Registre o número da PR e os SHAs completos. A matriz e o contrato B00 vêm do commit que executa a política. Os IDs numéricos da matriz aparecem como chaves de texto na atestação. O inventário do B00 usa as linhas de aceite de `B00.md`.

Em um checkout confiável que contém `scripts/sprint_gate.py`, carregue as variáveis de configuração locais e obtenha o inventário. `$PR`, `$HEAD`, `$BASE`, `$RUN` e `$ATTEMPT` nos comandos são os valores registrados pelo coordenador. O token vem da sessão autenticada do GitHub CLI.

```bash
export GH_TOKEN="$(gh auth token)"
export SPRINT_COORDINATOR_ID=138138496
export SPRINT_QODO_BOT_ID=151058649
export SPRINT_QODO_APP_ID=484649
python scripts/sprint_gate.py snapshot --pull "$PR" --head "$HEAD" --base "$BASE" > inventario.json
python scripts/sprint_gate.py snapshot --pull "$PR" --head "$HEAD" --base "$BASE" --template > atestacao.json
```

O inventário contém os corpos e hashes de comentários de conversa, revisões, comentários inline e edições disponíveis. Ele ainda guarda revisões de SHAs anteriores e comentários incrementais. Uma revisão completa do App observado tem `Code Review by Qodo`, os contadores de achados e o marcador de commit no corpo autenticado com o HEAD inteiro. O `PR Summary` entra no inventário. Uma revisão incremental ou um resumo descritivo deixa a condição de revisão completa pendente. Se o Qodo estiver ausente, se falhar a coleta ou se houver histórico indisponível, a execução bloqueia.

Preencha o modelo a partir das verificações registradas pelo auditor e pelo coordenador.

- Liste os identificadores de sessão dos implementadores em `implementers`. Registre em `audit.agent` uma sessão de auditoria independente, com `result` igual a `pass`, `history_complete` igual a `true` e evidências do parecer para o SHA revisado.
- Em `items`, mantenha os hashes do modelo e registre `result` igual a `pass` e evidência de cada aceite. Uma evidência é um objeto com `url` do repositório no GitHub e `detail` com a verificação e seu resultado. Use o mesmo formato de evidência para auditoria e achados.
- Em `qodo.completion`, selecione o ID da revisão completa do inventário. Cubra todas as chaves em `qodo.records`, inclusive as versões anteriores. Para cada achado registre `quote` com trecho literal da origem, `resolution` igual a `fixed` ou `dismissed-with-reason` e `evidence` com a prova. Use `no_findings` com justificativa para os registros sem achados. A contagem do Qodo exige cobertura mínima. A atribuição dos achados a cada trecho e a validade da resolução são parte do parecer independente atestado pelo coordenador.

O coordenador publica a atestação como um comentário da própria PR, com um único bloco cercado `json` e o conteúdo de `atestacao.json`. Registre o número após `issuecomment-` no URL, aqui chamado `$COMMENT`. A API verifica o autor do comentário pelo ID. O verificador confronta o comentário e o inventário com o estado atual da PR.

## Execução e retomada

Dispare a verificação pelo workflow em `main` protegida.

```bash
gh workflow run sprint-b00.yml --repo saravejo/healdan --ref main \
  -f pull="$PR" -f head="$HEAD" -f attestation="$COMMENT"
```

Use `publish=false` para ensaiar sem publicar. Registre o ID da execução e a tentativa. Se um job for cancelado, dispare de novo ou reexecute todos os jobs da tentativa. O verificador reconstrói o estado por metadados oficiais. Uma repetição equivalente reaproveita o check existente e uma nova tentativa para o mesmo escopo atualiza seu resultado, preservando seu ID. Mudança no HEAD, na base ou no histórico do Qodo exige revalidar a evidência afetada.

Depois de obter a conclusão do workflow, execute o preflight com as credenciais autenticadas do coordenador. Ele verifica a proteção, a execução, a evidência atual, os jobs e o log oficial de publicação. Use o HEAD verificado também no comando de merge e acompanhe os checks da nova `main` antes de iniciar outra integração.

```bash
python scripts/sprint_gate.py preflight --pull "$PR" --head "$HEAD" --base "$BASE" \
  --attestation "$COMMENT" --run "$RUN" --attempt "$ATTEMPT"
gh pr merge "$PR" --repo saravejo/healdan --match-head-commit "$HEAD" --merge
```

O resultado corresponde ao momento do preflight. Faça o merge imediatamente após a validação. Se houver nova mensagem do Qodo, mudança na atestação, reabertura, atualização de branch ou alteração da proteção, execute a validação de novo. As regras do GitHub avaliam checks por commit.

## Bootstrap da PR 1

O workflow definitivo ainda não está disponível em `main` no primeiro B00. A entrada existente `.github/workflows/ci.yml` já aceita `workflow_dispatch`. Para a PR 1 do B00, publique um ref próprio a partir da `main` corrente com a política, matriz, scripts e testes auditados, usando a cópia do novo workflow em `.github/workflows/ci.yml`. Proteja `sprint-gate-bootstrap` contra atualizações, force-push e exclusão antes de usar o ref. Configure `SPRINT_B00_BOOTSTRAP_SHA` com o SHA completo da lógica auditada e confira o valor pela API. A PR continua com base em `main` e executa os mesmos jobs em seu próprio HEAD. [Eventos do GitHub Actions](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#workflow_dispatch)

Para inventário e preflight use os mesmos comandos com `--bootstrap` e `SPRINT_BOOTSTRAP_SHA` local igual ao valor da variável do repositório. No disparo informe a base da PR explicitamente.

```bash
gh workflow run ci.yml --repo saravejo/healdan --ref sprint-gate-bootstrap \
  -f base="$BASE" -f pull="$PR" -f head="$HEAD" -f attestation="$COMMENT"
```

O verificador bloqueia se o ref protegido ou seu SHA divergir, se a PR for outra, se a PR mudar de base ou se `main` já contiver o workflow definitivo. Confirme a proteção clássica e o ruleset de `main` antes de disparar. A prova da ativação é uma execução real, o check publicado vinculado ao HEAD e o preflight aprovado. Quando o workflow definitivo chegar a `main`, remova a variável de bootstrap para encerrar a transição.
