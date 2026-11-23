# Check de integração da sprint

`sprint/b00` é o check consolidado dos lotes da sprint em `saravejo/healdan`. A publicação ocorre no HEAD da PR. O registro também vincula o número da PR, a base, o commit de merge de teste, a tentativa de CI e o hash da atestação. A integração exige um preflight do coordenador com esses mesmos dados.

## Proteção e configuração

- Proteja `main` com PR obrigatória, zero aprovações obrigatórias no GitHub, conversas resolvidas, checks estritos e proteção aplicada aos administradores. Desabilite force-push, exclusão e exceções para PRs. Exija `test`, `package` e `sprint/b00` com a fonte GitHub Actions, `app_id` 15368.
- Mantenha um ruleset ativo para `main` com a regra `Restrict updates`. Configure apenas o papel de administrador do repositório, ID 5, com bypass `pull_request` nesse ruleset. O coordenador é o único administrador e integra através da PR. A proteção clássica permanece aplicada aos administradores.
- Em Actions, configure as variáveis `SPRINT_B00_COORDINATOR_ID`, `SPRINT_B00_QODO_BOT_ID` e `SPRINT_B00_QODO_APP_ID` com os IDs numéricos verificados. A instalação observada do Qodo usa bot `151058649` e App `484649`. Confirme a instalação antes de alterar esses IDs.

O workflow `.github/workflows/sprint-b00.yml` é disparado de `main` protegida. Os jobs obtêm o código público por `refs/pull/<n>/head` e verificam o SHA recebido da preparação. O teste nativo audita a árvore com o script do ref protegido antes de executar o código candidato em ambiente reduzido e com permissões vazias. O job de pacote compila com Python 3.12 em um contêiner sem rede, montagens do host ou tokens de repositório, sob UID não privilegiado. O runner guarda a saída e o log de compilação localmente. O auditor protegido lê o tar de saída sem extraí-lo, exige o wheel e o sdist esperados e rejeita entradas de link, dispositivo ou travessia nos cabeçalhos. O job `sprint-b00 gate` mantém `checks: write`, executa o verificador do ref protegido e exige sucesso real dos jobs `sprint-b00 test` e `sprint-b00 package` na mesma tentativa.

A proteção do GitHub identifica o App GitHub Actions, compartilhado por workflows do repositório. O preflight confirma o caminho, a identidade, o SHA e o ID da execução protegida, além da tentativa. O resumo do check vincula o ID e a tentativa da execução ao escopo e à atestação. O URL deve corresponder à execução ou à página canônica do próprio check, cujo ID precisa constar no log oficial do job. A regra que restringe atualizações de `main` reserva a integração ao coordenador, que verifica esse vínculo antes do merge. [Proteção de branches](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches), [fonte de checks](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets)

## Atestação GitHub

Use a branch `sprint/bNN-descricao` no próprio repositório e atualize o HEAD com a `main` corrente. Registre o número da PR e os SHAs completos. A matriz e o contrato `BNN.md` vêm do commit que executa a política. O verificador também lê a matriz candidata como dados no HEAD e exige os mesmos IDs, lotes, aceites e dependências. Os IDs numéricos aparecem como chaves de texto na atestação.

Em B00, mantenha os itens da matriz pendentes. Em lotes seguintes, uma linha pode registrar `concluido` com número ou URL da PR já integrada do lote correto, SHAs de commits da PR e links GitHub verificáveis em `testes` e `pareceres`. O merge dessa PR precisa estar no histórico da base protegida. Antes de avaliar o lote corrente, o gate confere a integração de B00 e os itens de cada dependência declarada no contrato da matriz.

O B00 usa cada linha de `B00.md` como um controle de aceite. Para os demais lotes, coloque o contrato detalhado revisado no ref protegido antes da verificação. Preserve na PR o contrato detalhado do lote em execução. Além da descrição humana, use um único bloco `json` de cenários com os mesmos IDs do lote e controles e contraprovas separados.

```json
{"scenarios":{"15":{"positivo":"Exercitar o registro válido","contraprova":"Bloquear o registro inválido"}}}
```

Em um checkout confiável que contém `scripts/sprint_gate.py`, carregue as variáveis de configuração locais e obtenha o inventário. `$PR`, `$HEAD`, `$BASE`, `$RUN` e `$ATTEMPT` nos comandos são os valores registrados pelo coordenador. O token vem da sessão autenticada do GitHub CLI.

```bash
export GH_TOKEN="$(gh auth token)"
export SPRINT_COORDINATOR_ID=138138496
export SPRINT_QODO_BOT_ID=151058649
export SPRINT_QODO_APP_ID=484649
python scripts/sprint_gate.py snapshot --pull "$PR" --head "$HEAD" --base "$BASE" > inventario.json
python scripts/sprint_gate.py snapshot --pull "$PR" --head "$HEAD" --base "$BASE" --template > atestacao.json
```

O inventário contém os corpos e hashes de comentários de conversa, revisões, comentários inline e edições disponíveis. Ele inclui revisões de SHAs anteriores e comentários incrementais. Uma revisão completa tem `Code Review by Qodo`, contadores de achados e o marcador do HEAD inteiro no corpo autenticado. Quando o comentário foi editado, o verificador confere que a última edição veio do bot. Um `PR Summary` ou uma revisão incremental entra no inventário e deixa a revisão completa pendente.

Preserve snapshots contemporâneos dos corpos observados junto com ID da fonte, autor e horário. Se uma publicação desaparecer ou for reescrita, inclua sua versão arquivada no inventário com `--archives snapshots.json`. Cada entrada contém `kind`, `record` com o objeto REST integral da captura e `anchor` com o ID do comentário GitHub do coordenador. O comentário-âncora deve permanecer sem edição, identificar o `bot GitHub <BOT_ID>, App <APP_ID>` e ter uma linha de tabela com ID do registro, descrição e SHA-256 dos bytes UTF-8 do corpo. O gate reconcilia cada versão registrada pelo coordenador com a coleta atual ou com um corpo arquivado. O parecer independente cobre cada versão. Uma exclusão informada pelo GitHub bloqueia a execução porque o evento omite o ID do comentário removido. Ausência do Qodo ou histórico de edições possivelmente truncado também bloqueiam a execução. [Esquema de `CommentDeletedEvent`](https://docs.github.com/en/graphql/reference/issues#commentdeletedevent)

Preencha o modelo a partir das verificações registradas pelo auditor e pelo coordenador. Mantenha `contract_sha256` e os hashes dos aceites e dos cenários do inventário.

- Liste os identificadores de sessão dos implementadores em `implementers`. Em `items`, registre `result` igual a `pass` e evidências do aceite e de cada cenário. Uma evidência contém `url` e `detail` com a verificação e seu resultado. Use um link de comentário ou revisão da PR, execução ou job de Actions, commit, ou arquivo versionado por SHA. A API precisa confirmar que a referência existe no escopo correto.
- Em `qodo.completion`, selecione o ID da revisão completa. Cubra todas as chaves em `qodo.records`, inclusive versões anteriores e snapshots. Para cada achado registre `id` individual dentro da origem, `quote` literal com o título do achado quando ele estiver presente e `resolution` igual a `fixed` ou `dismissed-with-reason`. Uma correção inclui `commit` com SHA novo e ancestral do HEAD. Uma dispensa inclui `reason` com a explicação sustentada pela contraprova. Ambas incluem `test` com `command`, `result` e `evidence`. O comando e o resultado precisam constar no log do job no SHA ou em comentário autenticado do coordenador que nomeia o SHA. Use `no_findings` com justificativa para registros sem achados.
- Gere o modelo do parecer e registre a sessão independente em `agent`, o resultado geral e por ID, `history_complete` e as evidências. Em cada achado, a sessão independente registra `approved` igual a `true` e `detail` com o parecer sobre a correção ou contraprova. Os hashes vinculam o parecer aos cenários, às origens e às resoluções da atestação. O coordenador publica o parecer separado em um único bloco `json` na PR e registra seu ID GitHub.

```bash
python scripts/sprint_gate.py audit-template --manifest atestacao.json > parecer.json
python scripts/sprint_gate.py snapshot --pull "$PR" --head "$HEAD" --base "$BASE" \
  --audit-comment "$AUDIT_COMMENT" > atestacao-vinculos.json
```

Copie `audit` de `atestacao-vinculos.json` para a atestação preenchida. Use as mesmas opções de `--bootstrap` e `--archives` nas coletas vinculadas a essa PR. O coordenador publica a atestação como outro comentário da própria PR, com um único bloco `json` e o conteúdo de `atestacao.json`. Registre o ID após `issuecomment-` no URL como `$COMMENT`. Preserve o parecer e a atestação sem edições. Se precisar corrigi-los, publique uma nova versão e vincule seu novo ID. O verificador autentica os dois comentários, confere o hash do parecer e compara o inventário com o estado atual da PR.

## Execução e retomada

Dispare a verificação pelo workflow em `main` protegida.

```bash
gh workflow run sprint-b00.yml --repo saravejo/healdan --ref main \
  -f pull="$PR" -f head="$HEAD" -f attestation="$COMMENT"
```

Use `publish=false` para ensaiar sem publicar. Registre o ID da execução e a tentativa. Se um job for cancelado, dispare de novo ou reexecute todos os jobs da tentativa. O verificador reconstrói o estado por metadados oficiais. Uma repetição equivalente reaproveita o check existente. Se o GitHub recalcular o merge de teste com a mesma PR, a mesma base e o mesmo HEAD, revalide e publique com o ID existente. Mudança no HEAD, na base ou no histórico do Qodo exige revalidar a evidência afetada.

Depois de obter a conclusão do workflow, execute o preflight com as credenciais autenticadas do coordenador. Ele verifica a proteção, a execução, a evidência atual, os jobs e o log oficial de publicação. Use o HEAD verificado também no comando de merge e acompanhe os checks da nova `main` antes de iniciar outra integração.

```bash
python scripts/sprint_gate.py preflight --pull "$PR" --head "$HEAD" --base "$BASE" \
  --attestation "$COMMENT" --run "$RUN" --attempt "$ATTEMPT"
gh pr merge "$PR" --repo saravejo/healdan --match-head-commit "$HEAD" --merge
```

O resultado corresponde ao momento do preflight. Faça o merge imediatamente após a validação. Se houver nova mensagem do Qodo, mudança na atestação, reabertura, atualização de branch ou alteração da proteção, execute a validação de novo. As regras do GitHub avaliam checks por commit.

## Bootstrap da PR 1

O workflow definitivo ainda não está disponível em `main` no primeiro B00. A entrada existente `.github/workflows/ci.yml` já aceita `workflow_dispatch`. Para a PR 1 do B00, publique o ref `sprint-gate-bootstrap-v2` a partir da `main` corrente com a política, matriz, scripts e testes auditados, usando a cópia do novo workflow em `.github/workflows/ci.yml`. Proteja esse ref contra atualizações, force-push e exclusão antes de usá-lo. Configure `SPRINT_B00_BOOTSTRAP_SHA` com o SHA completo da lógica auditada e confira o valor pela API. A PR continua com base em `main` e executa os mesmos jobs em seu próprio HEAD. [Eventos do GitHub Actions](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#workflow_dispatch)

Para inventário e preflight use os mesmos comandos com `--bootstrap` e `SPRINT_BOOTSTRAP_SHA` local igual ao valor da variável do repositório. No disparo informe a base da PR explicitamente.

```bash
gh workflow run ci.yml --repo saravejo/healdan --ref sprint-gate-bootstrap-v2 \
  -f base="$BASE" -f pull="$PR" -f head="$HEAD" -f attestation="$COMMENT"
```

O verificador bloqueia se o ref protegido ou seu SHA divergir, se a PR for outra, se a PR mudar de base ou se `main` já contiver o workflow definitivo. Confirme a proteção clássica e o ruleset de `main` antes de disparar. A prova da ativação é uma execução real, o check publicado vinculado ao HEAD e o preflight aprovado. Quando o workflow definitivo chegar a `main`, remova a variável de bootstrap para encerrar a transição.
