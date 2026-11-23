
- **1. Recuperação dependente do ambiente perdido**  
    **Descrição:** `restore` depende do catálogo original, exige todas as réplicas disponíveis e reconstrói apenas parte do estado operacional.  
    **Motivo:** perder a máquina ou um destino de backup pode inutilizar o caminho normal de recuperação, mesmo com outra cópia íntegra.  
    **Solução:** gravar um manifesto portátil assinado junto de cada geração; permitir restauração por qualquer réplica verificável; recuperar os registros necessários de tarefas, sessões, aprovações, retenção e holds. Separar o manifesto imutável do estado mutável das réplicas e reconciliar caminhos da máquina antiga.  
    **Validação sem Mac:** restaurar em controlador novo, sem catálogo original e com uma réplica indisponível; comparar arquivos, referências Git e registros operacionais.  
    **Código:** backups.py (src/healdan/backups.py:119), custody.py (src/healdan/custody.py:61).
- **2. Backup não corresponde ao conjunto de bytes verificado**  
    **Descrição:** a verificação examina objetos do histórico Git, mas a geração também lê arquivos atuais, incluindo arquivos ignorados encontrados por `inputs()`.  
    **Motivo:** conteúdo indevido pode entrar no backup longo; alterações durante a captura podem produzir uma geração inconsistente. Criptografar não resolve seleção ou retenção incorretas.  
    **Solução:** definir explicitamente os arquivos elegíveis, capturar um snapshot imutável e verificar exatamente os bytes que serão cifrados. Separar conhecimento canônico, estado operacional e conversas; incluir material não commitado somente por uma regra explícita de preservação.  
    **Validação sem Mac:** inserir arquivo ignorado, alterar arquivo durante a captura e conferir o conteúdo decifrado contra o manifesto.  
    **Código:** backups.py (src/healdan/backups.py:48), core.py (src/healdan/core.py:233).
- **3. Retenção que compromete recuperação e bloqueia manutenção**  
    **Descrição:** a cópia cifrada pode ser apagada antes da verificação exigida para excluir a cópia nativa. Um plano pendente também impede descobrir novos vencimentos e bloqueia backups.  
    **Motivo:** uma operação de limpeza reduz a recuperabilidade e pode paralisar indefinidamente a manutenção.  
    **Solução:** verificar as condições de preservação do material inteiro antes da primeira exclusão; manter as cópias necessárias enquanto a recuperação estiver pendente; processar materiais independentes e novos vencimentos. Reconciliar renomes e cópias conhecidas, preservar prazos e devolver código de saída que diferencie conclusão de pendência. Backups elegíveis devem ter tratamento separado dos corpos bloqueados por retenção.  
    **Validação sem Mac:** combinar ausência de prova, hold, novo vencimento, arquivo renomeado e interrupção entre exclusão e recibo.  
    **Código:** retention.py (src/healdan/retention.py:19), maintenance.py (src/healdan/maintenance.py:47).
- **4. Integração pode divergir do pacote aprovado**  
    **Descrição:** o journal não vincula suficientemente o destino da recuperação; o commit final lê arquivos da árvore de trabalho, sujeitos a alterações por editores externos.  
    **Motivo:** compromete a garantia central de aplicar exatamente o conteúdo assinado, na referência correta. A trava do controlador não impede um editor externo de salvar arquivos.  
    **Solução:** vincular journal a repositório, worktree, referência, commit-base e pacote; conferir seu conteúdo contra o pacote assinado em cada recuperação. Construir a árvore Git com os blobs congelados, atualizar a referência somente se a base continuar igual e verificar o resultado antes de registrar conclusão. Preservar alterações externas para reconciliação.  
    **Validação sem Mac:** dois worktrees, edição concorrente e interrupções em cada etapa; nenhum byte não aprovado deve entrar no commit.  
    **Código:** transactions.py (src/healdan/transactions.py:201).
- **5. Dados incompletos e páginas obsoletas podem parecer válidos**  
    **Descrição:** registro obrigatório ausente é tratado como vazio; existem lacunas em números, timestamps e identidades. Páginas antigas também podem permanecer publicadas quando deixam de ter seletores.  
    **Motivo:** o sistema pode retornar uma abstenção aparentemente normal sobre dados perdidos ou continuar exibindo uma afirmação retirada.  
    **Solução:** distinguir arquivos obrigatórios de opcionais; validar esquemas, números finitos, datas obrigatórias, prefixos e colisões entre registros. Reconciliar o conjunto completo de páginas geradas, inclusive páginas retiradas e índice vazio, preservando histórico com identificação explícita.  
    **Validação sem Mac:** remover registros, fornecer `1e400` e `captured_at=null`, criar colisões e revogar a última afirmação publicada.  
    **Código:** core.py (src/healdan/core.py:59), knowledge.py (src/healdan/knowledge.py:31), pages.py (src/healdan/pages.py:122).
- **6. Revisão independente sem encadeamento completo dos artefatos**  
    **Descrição:** o recibo do lançamento não fixa os arquivos de extração produzidos. O validador aceita declarações de conformidade sem conferir a correspondência estrutural com as unidades extraídas.  
    **Motivo:** um dos principais controles do projeto depende de uma declaração que o código não verifica suficientemente.  
    **Solução:** gerar um manifesto de saídas ao concluir cada execução, vinculando hashes à sessão, ao lançamento e às fontes. Validar esquemas das extrações, correspondência das unidades, proveniência, cobertura e divergências. Tornar o congelamento e a entrega dos insumos de comparação idempotentes. Isso fortalece rastreabilidade; não transforma concordância entre modelos em prova de verdade.  
    **Validação sem Mac:** extrações vazias, unidade ausente, saída trocada, comparação divergente e falha de entrega seguida de nova tentativa.  
    **Código:** launcher.py (src/healdan/launcher.py:207), review.py (src/healdan/review.py:11).
- **7. Ciclo de tarefas frágil e relógios incompatíveis**  
    **Descrição:** falhas intermediárias podem deixar sessões órfãs ou capacidade ocupada; repetir fechamento pode alterar seu prazo. A tarefa expira em 24 horas, embora a revisão humana tenha lembretes posteriores. Casos `at_execution` podem usar o corte antigo do pacote.  
    **Motivo:** o fluxo fica dependente de intervenção manual e pode validar expectativas temporais já vencidas.  
    **Solução:** definir transições de estado recuperáveis e comandos idempotentes, com reconciliação após falhas. Separar prazo do processo/worktree, espera humana e validade do pacote congelado. Revalidar base e evidências antes da integração; casos `at_execution` devem usar o instante efetivo, enquanto casos históricos preservam seu corte explícito.  
    **Validação sem Mac:** relógio controlado, falhas simuladas de criação de processo e escrita, repetição de comandos e aprovação após D+3 com base intacta ou alterada.  
    **Código:** tasks.py (src/healdan/tasks.py:83), regression.py (src/healdan/regression.py:39).
- **8. Prontidão vinculada à identidade e às evidências erradas**  
    **Descrição:** ensaios vencem quando o conteúdo do vault muda, mas suas dependências atuais não são comparadas às atestadas. O verificador de release aceita sucesso geral do CI sem conferir individualmente a execução dos testes obrigatórios.  
    **Motivo:** a prontidão pode ser invalidada por mudança irrelevante ou sustentada por evidência incompleta.  
    **Solução:** identificar o controlador instalado por versão/digest e registrar dependências e configuração relevantes. Produzir resultados estruturados por teste, diferenciando aprovado, falhou e pulado. Executar o núcleo em CI Windows/Linux com Git, OpenSSH e age reais; auditar o alvo correto e seu histórico completo. Manter os requisitos macOS explicitamente pendentes.  
    **Validação sem Mac:** mudança apenas de conteúdo, troca de controlador/dependência, teste obrigatório pulado, clone raso e auditoria apontando para outro vault.  
    **Código:** maintenance.py (src/healdan/maintenance.py:14), release_check.py (scripts/release_check.py), ci.yml (.github/workflows/ci.yml).
- **9. Construção de propostas exige trabalho estrutural demais do agente**  
    **Descrição:** o editor não recebe automaticamente o estado canônico relevante e precisa propor arquivos completos quando altera registros como `claims.jsonl`.  
    **Motivo:** conforme a base cresce, aumenta o contexto necessário, o risco de omitir registros e o trabalho manual para montar uma proposta válida.  
    **Solução:** implementar um construtor determinístico de candidatos. O agente recebe um snapshot limitado ao escopo e propõe operações como adicionar, corrigir ou superseder uma afirmação. O controlador compõe os registros, reserva IDs, calcula localizadores e hashes, preserva conteúdo existente e apresenta o diff. Citações com múltiplas ocorrências devem exigir desambiguação.  
    **Validação sem Mac:** numa base com milhares de afirmações, adicionar três e corrigir uma sem reescrever manualmente o registro inteiro; confirmar preservação das demais.  
    **Código:** tasks.py (src/healdan/tasks.py:56), transactions.py (src/healdan/transactions.py:27).
- **10. Consultas e manutenção repetem trabalho sobre a base inteira**  
    **Descrição:** consultas recalculam fingerprints e conferem fontes; conflitos são comparados em pares; páginas repetem resoluções; reservas de IDs percorrem o histórico.  
    **Motivo:** uma base pequena pode funcionar bem e tornar-se lenta com milhares de afirmações, históricos extensos e fontes grandes. Isso afeta consultas, duração das travas e memória utilizada.  
    **Solução:** medir primeiro e reduzir trabalho repetido: compartilhar um snapshot validado por operação, agrupar conflitos por chave, reutilizar resultados na geração de páginas e criar índices reconstruíveis para IDs. Processar backups em fluxo quando possível. Qualquer cache deve estar vinculado a conteúdo ou versões imutáveis; tamanho e data de modificação não bastam para preservar integridade.  
    **Validação sem Mac:** comparar tempo, memória e resultados em bases crescentes, incluindo adulterações de arquivos e invalidação dos índices. Otimizar sem perder detecção de alterações.  
    **Código:** knowledge.py (src/healdan/knowledge.py:148), pages.py (src/healdan/pages.py:17), ids.py (src/healdan/ids.py:38).
- **11. Evidências multimodais sem extração e localização auditáveis**  
    **Descrição:** hoje o Healdan consegue **preservar arquivos binários classificados como `common`**, incluindo PDFs ou imagens. Entretanto, não possui pipeline próprio de extração documental, OCR, análise visual ou localizadores específicos desses formatos. A validação trabalha com intervalos de bytes e hashes.  
    **Motivo:** guardar e verificar o hash de um PDF não permite demonstrar, de forma útil ao revisor, qual tabela, página ou imagem sustenta uma afirmação. Um intervalo de bytes dentro de um arquivo comprimido também pode não corresponder a um trecho visual compreensível.  
    **Solução:** implementar uma cadeia explícita de **original preservado → extração derivada versionada → evidência localizada → afirmação revisada**. Registrar ferramenta/modelo, versão, configuração, hashes, falhas e completude da extração. Usar localizadores adequados: página/região em PDF; região em imagem; seção/parágrafo em DOCX; folha/células em planilha; intervalo temporal em áudio/vídeo. O revisor deve conseguir abrir o original no ponto citado, além de consultar o derivado.  
    PDFs com texto podem usar extração estrutural; digitalizações exigem OCR; gráficos e diagramas podem exigir análise visual. **OCR ou descrição por modelo continuam sendo interpretações falíveis**, e duas revisões baseadas no mesmo OCR podem repetir o mesmo erro. Para originais sensíveis, integrar custódia externa e derivados minimizados exigirá também evoluir o schema e o resolvedor atual.  
    **Validação sem Mac:** fixtures com PDF textual e escaneado, imagem, planilha e documento parcialmente ilegível; conferir localização, vínculo ao original, versionamento e sinalização de extração incompleta.  
    **Código:** cli.py (src/healdan/cli.py:198), knowledge.py (src/healdan/knowledge.py:82), pages.py (src/healdan/pages.py:29).
- **12. Backup e retenção configuráveis, incluindo preservação permanente**  
    **Descrição:** o código impõe prazos de retenção e exige configuração de backup para considerar o ambiente pronto. Não existe um modo explícito para operar sem backup ou preservar os materiais indefinidamente.  
    **Motivo:** o usuário deve poder escolher entre manter um acervo permanente, aplicar prazos por categoria ou usar backup manual/agendado. Essas escolhas não deveriam impedir consultas, aprovações ou manutenção das demais funções.
    
    **Solução:** implementar uma política versionada com opções independentes:
    
    **Backup:** `off`, `manual` ou `scheduled`. Desativar a criação de backups não deve apagar gerações existentes nem impedir sua restauração.
    
    **Retenção:** `keep_forever` ou `by_class`, com prazos configuráveis por categoria. “Permanente” deve ser um estado explícito, diferente de configuração ausente ou prazo desconhecido.
    
    Um exemplo **proposto, ainda não implementado**, seria:
    
    ```
    {
      "backup": {
        "mode": "off"
      },
      "retention": {
        "mode": "keep_forever"
      }
    }
    ```
    
    A implementação precisa ajustar `doctor`, `lint` e manutenção para reconhecer **“desativado por política”**, sem tratar isso como falha. Antes de cada exclusão, o executor deve conferir a política vigente: ativar preservação permanente precisa bloquear também exclusões de planos anteriormente preparados.
    
    Mudanças devem registrar versão, responsável e alcance sobre materiais existentes. Prazos de backups já assinados não podem ser reescritos silenciosamente; precisam de uma decisão de preservação vinculada ao registro original. Novas gerações poderiam admitir ausência explícita de expiração, desde que compatível com a política dos materiais incluídos.
    
    **Desativar backup também não deve desativar a custódia necessária para encerrar tarefas.** Processos e worktrees podem terminar após preservação verificada do conteúdo. A limpeza própria do Claude é outro mecanismo: preservar conversas permanentemente exige mantê-las no armazenamento controlado pelo Healdan, sem presumir que essa configuração desligue a limpeza do fornecedor.
    
    **Validação sem Mac:** avançar o relógio por anos e verificar preservação; mudar a política com exclusões pendentes; executar manutenção sem destinos de backup; testar os três modos e confirmar que hashes, assinaturas e históricos continuam válidos.
    
    **Código:** custody.py (src/healdan/custody.py:103), maintenance.py (src/healdan/maintenance.py:47), setup.py (src/healdan/setup.py:96), linting.py (src/healdan/linting.py), backups.py (src/healdan/backups.py:37).
- **13. Arquivamento de arquivo vazio sobrescreve conteúdo existente**  
    **Descrição:** reproduzimos a perda da anotação: o arquivo arquivado voltou a zero bytes e o novo arquivo do Inbox foi removido.  
    **Motivo:** arquivos vazios compartilham o mesmo hash; com o mesmo nome, chegam ao mesmo destino. `atomic()` substitui o arquivo existente sem verificar seu conteúdo.  
    **Solução:** criar destinos de forma exclusiva. Se já existirem, reutilizá-los somente quando o conteúdo for idêntico; caso contrário, preservar origem e destino e informar conflito. A proteção precisa impedir sobrescrita também entre a verificação e a gravação.  
    **Validação da correção:** arquivar, editar o destino e repetir com arquivo vazio de mesmo nome; ambos devem sobreviver ao conflito.  
    **Código:** inbox.py (src/healdan/inbox.py:105).
- **14. Retratação mantém afirmação publicada como vigente**  
    **Descrição:** dois pacotes aplicados com assinaturas reais confirmaram o problema: a consulta passou a se abster, mas a página continuou exibindo `[accepted]` e o índice manteve o link.  
    **Motivo:** a preparação e a validação consideram apenas os seletores atuais. Destinos retirados ficam sem reconciliação; com seletores vazios, o índice nem é regenerado.  
    **Solução:** comparar os destinos anteriores e propostos, atualizar as seções vigentes dos tópicos retirados e regenerar o índice mesmo vazio. Preservar âncoras e histórico, identificando claramente o conteúdo que deixou de valer.  
    **Validação da correção:** publicar e depois retratar a última afirmação; reabrir o vault commitado e conferir consulta, página e índice.  
    **Código:** transactions.py (src/healdan/transactions.py:125), pages.py (src/healdan/pages.py:122).
- **15. Separador Unicode no histórico bloqueia reserva de IDs**  
    **Descrição:** um registro com U+2028 foi aceito no arquivo atual, mas passou a bloquear reservas depois de commitado. Corrigir o registro atual não resolveu, porque o conteúdo permaneceu no histórico.  
    **Motivo:** `str.splitlines()` interpreta U+2028 dentro da string JSON como separação de registros, produzindo JSON truncado.  
    **Solução:** compartilhar um parser JSONL entre leitura atual e histórica, delimitado por LF e compatível com CRLF, sem dividir registros por separadores Unicode internos. Trocar por `split("\\n")` resolve a causa imediata; unificar o parser evita divergências futuras.  
    **Validação da correção:** manter U+2028 e U+2029 em commits anteriores e reservar novos IDs, preservando a reserva dos identificadores históricos.  
    **Código:** ids.py (src/healdan/ids.py:38), core.py (src/healdan/core.py:72).
- **16. Caso “no momento da execução” usa data antiga do pacote**  
    **Descrição:** reproduzimos um caso `at_execution` que falha hoje, mas passa quando a suíte recebe um corte de 2020, anterior ao vencimento da afirmação.  
    **Motivo:** a expressão `case["cutoff"] or cutoff or stamp()` permite que o corte do pacote substitua o significado de `at_execution`. Aprovação e aplicação repassam esse corte.  
    **Solução:** separar o corte histórico do relógio de execução. Casos históricos usam o instante assinado; casos `at_execution` usam uma única leitura do relógio por execução da suíte. Testes controlam esse relógio por parâmetro próprio.  
    **Validação da correção:** preparar antes do vencimento e aprovar depois; o caso histórico continua válido, enquanto o caso atual que espera o fato vencido falha.  
    **Código:** regression.py (src/healdan/regression.py:39).
- **17. Um item em preservação impede processar novos vencimentos**  
    **Descrição:** reproduzimos o plano contendo somente A: depois do vencimento de B, a manutenção reutilizou o mesmo plano e deixou B no disco.  
    **Motivo:** enquanto existe plano pendente, `daily()` não descobre novos materiais vencidos. Um hold pode bloquear indefinidamente itens independentes.  
    **Solução:** retomar os planos existentes e descobrir novos vencimentos em cada rodada, deduplicando por identidade estável de material e cópia. Manter A preservado e processar B conforme sua política.  
    **Ajuste à recomendação original:** não manter automaticamente um bloqueio global de backup. A relação deve considerar os materiais incluídos e a política configurada; em `keep_forever`, ausência de exclusão é comportamento esperado.  
    **Validação da correção:** A permanece em hold; B é removido quando elegível; a pendência de A continua visível sem impedir o progresso de B.  
    **Código:** maintenance.py (src/healdan/maintenance.py:63), retention.py (src/healdan/retention.py:41).
- **18. Repetição da criação devolve sessão sem vínculo com a tarefa**  
    **Descrição:** após falha injetada na gravação da tarefa, duas novas tentativas devolveram `S-0001`, mas `task.sessions` permaneceu vazio.  
    **Motivo:** a sessão é persistida primeiro; ao encontrá-la numa repetição, o código retorna imediatamente sem reparar a associação com a tarefa.  
    **Solução:** sob a mesma trava, validar os argumentos e reconciliar o vínculo antes de retornar sucesso, garantindo exatamente uma ocorrência da operação.  
    **Validação da correção:** falhar uma vez depois de salvar a sessão, repetir duas vezes e exigir um arquivo de sessão, um vínculo e inclusão no processamento de fechamento.  
    **Limite do impacto:** pode faltar a preservação individual da sessão; isso não demonstra perda total, pois existe também captura agregada da tarefa.  
    **Código:** tasks.py (src/healdan/tasks.py:83).
- **19. Timestamp inválido da fonte passa ou quebra o contrato de erro**  
    **Descrição:** confirmamos três comportamentos: `null` permitiu resposta factual; número provocou `AttributeError`; string sem fuso retornou código 2.  
    **Motivo:** um campo persistido obrigatório usa o mesmo helper que interpreta `None` como “agora”. Além disso, dado armazenado inválido é confundido com argumento inválido da consulta.  
    **Solução:** validar `captured_at` como string obrigatória com fuso antes de chamar o conversor. Valores inválidos devem produzir erro de integridade, código 4, identificando a fonte. Manter o comportamento “agora” apenas nos usos explícitos do relógio.  
    **Validação da correção:** testar `null`, número, string sem fuso e timestamp válido; somente o último deve sustentar uma resposta factual.  
    **Código:** knowledge.py (src/healdan/knowledge.py:41), core.py (src/healdan/core.py:29).
- **20. Mesmo identificador aceito em registros incompatíveis**  
    **Descrição:** confirmamos que `D-0001` em decisões e lições passou pela validação e foi aplicado em pacote assinado. Depois, novas reservas de `D` falharam por colisão.  
    **Motivo:** a validação examina cada registro separadamente e usa um conjunto compartilhado de reservas, sem exigir o prefixo correspondente à categoria.  
    **Solução:** definir prefixos permitidos por registro — `D` para decisões, `L` para lições etc. — e verificar colisões numéricas no conjunto completo do candidato antes de congelar ou assinar o pacote. Revalidar na integração.  
    **Validação da correção:** decisão `D-0001` e lição `L-0001` passam; `D-0001` nos dois registros falha antes da publicação, sem deixar a base bloqueada.  
    **Código:** transactions.py (src/healdan/transactions.py:73), ids.py (src/healdan/ids.py:38).
 *  **21. Restauração sobrescreve alterações concorrentes da custódia** **Descrição:** reproduzimos três efeitos: um hold desapareceu; cópias excluídas voltaram ao estado `present`, embora seus arquivos continuassem ausentes; uma restauração interrompida deixou arquivo em texto claro sem registro da nova cópia. **Motivo:** `restore_capture` trabalha fora da trava comum e salva uma versão antiga do material depois da reconstrução. As cópias novas só são registradas ao final. **Solução:** registrar previamente a intenção e o destino da restauração; reconstruir em área intermediária inventariada; reler o material sob trava antes de incorporar as novas cópias. Preservar holds, dependências e estados de exclusão atuais. Tornar a conclusão e a recuperação dessa operação idempotentes. **Validação da correção:** inserir hold ou executar exclusão durante a restauração; interromper a escrita do segundo arquivo; verificar que nenhum estado recente desaparece e nenhum arquivo criado fica sem rastreamento.
 * **22. Manutenção diária sobrescreve resposta humana ou registro de processo**  
    **Descrição:** uma intercalação controlada confirmou que a manutenção apagou do registro uma resposta assinada e, em outro teste, um PID recém-registrado.  
    **Motivo:** `daily()` lê as tarefas antes de adquirir a trava. Depois, `reconcile_clock()` grava o dicionário antigo inteiro, mesmo sem mudança de relógio. Adquirir a trava depois da leitura não atualiza esse snapshot.  
    **Solução:** enumerar identificadores e reler cada tarefa dentro da trava; calcular as transições sobre o estado atualizado e persistir somente quando houver alteração. As decisões posteriores de fechamento ou reconciliação também precisam verificar o estado vigente.  
    **Validação da correção:** intercalar resposta, registro de processo e fechamento entre enumeração e processamento; preservar resposta, PID e capacidade já liberada.  
    **Código:** maintenance.py (src/healdan/maintenance.py:47), tasks.py (src/healdan/tasks.py:162).
- **23. Falha ao iniciar processo deixa sessão permanentemente “em execução”**  
    **Descrição:** uma falha injetada em `Popen` deixou `state=running`, nenhum PID registrado e a capacidade ocupada. Novo lançamento e fechamento foram recusados; reconciliar a lista vazia de processos não corrigiu a sessão.  
    **Motivo:** o estado `running` é persistido antes da abertura dos arquivos e da criação do processo, sem tratamento recuperável dessas falhas.  
    **Solução:** introduzir uma transição de inicialização persistida. Quando for comprovado que nenhum processo nasceu, registrar falha e permitir nova tentativa controlada. Se houver interrupção entre criação do processo e registro do PID, manter estado indeterminado e reconciliar por identidade do lançamento antes de liberar capacidade. Não basta redefinir automaticamente para “parado”.  
    **Validação da correção:** falhas na abertura dos arquivos, criação do processo e persistência do PID; verificar recuperação sem processos duplicados ou capacidade liberada indevidamente.  
    **Código:** launcher.py (src/healdan/launcher.py:163), tasks.py (src/healdan/tasks.py:214).
* **24. Registro obrigatório ausente é tratado como ausência legítima de conhecimento**  
    **Descrição:** reconfirmamos: uma consulta que respondia normalmente passou a retornar `20/abstention`, com `research=complete`, após retirar `claims.jsonl`. Um arquivo vazio produziu o mesmo resultado; JSON corrompido retornou erro de integridade.  
    **Motivo:** `read_jsonl()` transforma arquivo ausente em lista vazia. O fingerprint não resolve uma ausência que já existia antes da consulta.  
    **Solução:** definir explicitamente quais registros são obrigatórios e exigir sua presença ao abrir um vault operacional. Manter arquivos inicializados com zero bytes como válidos e preservar a distinção entre ausência, corrupção e falha de leitura.  
    **Validação da correção:** consultar com registro preenchido, vazio, ausente e corrompido; somente o vazio válido deve produzir abstenção por falta de afirmações.  
    **Código:** core.py (src/healdan/core.py:72), knowledge.py (src/healdan/knowledge.py:31)
- **25. Repetir a preparação permite sortear novamente a inspeção**  
    **Descrição:** duas preparações sem corte explícito, sobre os mesmos arquivos e unidades, geraram timestamps, IDs de pacote e sementes diferentes. Com corte fixo, reutilizaram pacote e semente.  
    **Motivo:** o instante atual participa da identidade do pacote; cada nova identidade recebe outra semente. Isso permite alterar a seleção apenas repetindo a preparação.  
    **Solução:** persistir a identidade lógica da preparação, vinculada à base, fontes, proposta, revisão, política e estado CSP. Repetições devem recuperar a mesma preparação; mudanças reais exigem substituição explícita com histórico. Trocar apenas o identificador da operação não deve permitir novo sorteio das mesmas unidades. Manter separado o relógio efetivo dos casos `at_execution`.  
    **Validação da correção:** repetir a preparação no regime amostral e exigir estabilidade de pacote, semente, seleção e inspeções registradas.  
    **Ressalva:** a seleção não necessariamente muda em cada tentativa. Os registros antigos permanecem; o problema é criar outro plano que não reaproveita as inspeções.  
    **Código:** transactions.py (src/healdan/transactions.py:119), review.py (src/healdan/review.py:67
	
-**26. Página confunde modalidade ausente com qualquer modalidade**  
    **Descrição:** numa fixture com duas afirmações aceitas, uma sem modalidade e outra `simulated`, a primeira apareceu em `Pending: invalid`, enquanto a segunda apareceu em `Knowledge`.  
    **Motivo:** modalidade faz parte da chave, mas o renderer omite o filtro quando ela está ausente. A consulta se amplia para várias chaves e exige refinamento. O estado armazenado continua `accepted`; a classificação incorreta ocorre na apresentação.  
    **Solução:** criar resolução interna pela chave completa, capaz de representar explicitamente modalidade ausente. Preservar a semântica pública em que omitir um filtro significa consultar qualquer modalidade. Passar `None` ao método atual não basta: ele exige filtros textuais.  
    **Validação da correção:** publicar ambas corretamente e verificar que divergências reais dentro da mesma modalidade continuam gerando conflito.  
    **Código:** pages.py (src/healdan/pages.py:17), knowledge.py (src/healdan/knowledge.py:27).
- **27. Geração de páginas repete comparação de conflitos com custo elevado**  
    **Descrição:** reproduzimos os números apresentados: **8.448 chamadas** a `claim_key` para 16 afirmações da mesma chave e **66.560** para 32 — aproximadamente 7,88 vezes mais trabalho ao dobrar a entrada.  
    **Motivo:** o resolvedor compara candidatos em pares, e o renderer repete essa resolução para cada afirmação. O preview acrescenta novas avaliações de grupos sobrepostos. Nesse cenário, o trabalho se aproxima de crescimento cúbico; isso não descreve universalmente qualquer distribuição de dados.  
    **Solução:** agrupar candidatos por chave e vigência uma vez, calcular conflitos por grupos de valores/polaridades e reutilizar os resultados durante renderização e preview. Preservar as regras atuais de igualdade, estados e filtros; agrupar apenas por hash JSON pode introduzir diferenças indevidas, como entre números equivalentes.  
    **Validação da correção:** combinar testes de resultados com contagem de operações e medição de tempo/memória, cobrindo mesma chave, chaves distintas, modalidades e conflitos.  
    **Código:** knowledge.py (src/healdan/knowledge.py:143), pages.py (src/healdan/pages.py:17).
- **28. — Tornar os comentários essenciais, objetivos e compatíveis com as garantias reais do código.**
    - **Descrição:** revisar comentários e docstrings para remover redundâncias, informações desatualizadas e afirmações mais abrangentes que a implementação. Em `src/healdan`, encontrei apenas **19 linhas de comentários e 24 docstrings em 3.039 linhas Python**. Portanto, não há evidência de excesso que justifique eliminar 90%.
    - **Razão/motivo:** comentários imprecisos podem orientar pessoas e LLMs a presumir garantias inexistentes ou perpetuar decisões inadequadas. Entretanto, apagar explicações essenciais também remove contexto necessário. O comentário em core.py:152 (src/healdan/core.py:152) explica o risco de expor conversas ou chaves nos erros; em test_transactions.py:26 (tests/test_transactions.py:26), outro esclarece que as sessões são simuladas e não comprovam execução nativa. **Ambos devem permanecer. Remover comentários não garante impedir alucinações nem corrige dívida técnica.**
    - **Solução:** eliminar comentários que apenas repetem a sintaxe; preservar explicações breves sobre motivos, invariantes, limitações e condições de recuperação. Reformular promessas amplas como operações verificáveis: em review.py:41 (src/healdan/review.py:41), por exemplo, descrever que a extração congelada é disponibilizada para comparação, sem sugerir que essa linha comprova toda a independência da revisão. Garantias críticas devem existir em validações e testes, acompanhadas por comentários quando o motivo não for evidente. Preservar shebangs, diretivas de ferramentas e marcadores `healdan:current/history`, que têm função operacional. **O critério de conclusão deve ser precisão e utilidade; o percentual removido será uma consequência da revisão.**
- 29.  — Montagem verificável do contexto necessário a cada papel.**
    - **Descrição:** mantenho a melhoria, agora identificada como concretização de partes de P1/P2 já selecionadas na avaliação. O controlador recebe contexto arbitrário, mas não monta obrigatoriamente o pacote de instruções e evidências correspondente ao papel.
    - **Razão/motivo:** a avaliação pede contexto sob demanda e, para extração cega, pergunta neutra sem exposição da proposta. Acrescentar todos os documentos ao prompt contrariaria essa redução de contexto.
    - **Solução:** montar pacotes mínimos por operação, com objetivo, instruções aplicáveis, referências autorizadas, contrato de saída e versão. Separar o pacote de extração cega daquele usado na comparação posterior. Medir o contexto final montado e preservar qualificadores necessários. Os limites devem ser definidos para o Claude utilizado; os tetos do modelo local da v15 não são automaticamente adequados.
    - **Teste/evidência:** o ensaio anterior aceitou uma sessão de extração com contexto vazio e entregou exatamente esse conteúdo ao processo simulado. O aceite da correção deve inspecionar os pacotes efetivamente enviados. Referências: avaliação, P1/P2 (avaliacao-v15-para-wiki.md:108), tasks.py:83 (src/healdan/tasks.py:83).
- 30 — Linhagem explícita para impedir confirmação pela própria saída da wiki.**
    - **Descrição:** mantenho o problema, mas restrinjo a solução a referências explícitas entre fontes, revisões e derivados, verificadas no estado atual.
    - **Razão/motivo:** a v15 determina que fontes derivadas registrem sua origem e que cópias da mesma observação não contem como corroboração independente. Também rejeita usar um mapa persistido como autorização de uso.
    - **Solução:** registrar a origem dos derivados e percorrer suas referências quando necessário. Um índice reconstruível pode ajudar a localizar relações; a validação deve conferir os registros atuais. Começar pela distinção entre evidência original e derivada, sem incorporar automaticamente todo o sistema de supressões e investigação transitiva que a avaliação adiou.
    - **Teste/evidência:** permanece a reprodução anterior: uma página interna reingerida sustentou uma nova afirmação aceita após a rejeição da original. Houve aprovação de teste; o problema demonstrado foi a ausência de controle da dependência. Referências: v15, fontes (Arquitetura-Harness-Local-v15.md:93), dependentes (Arquitetura-Harness-Local-v15.md:269).
* **31. — Evolução de formatos sem alterar o significado das aprovações antigas.**
    - **Descrição:** mantenho o versionamento e a compatibilidade, acrescentando uma exigência: migração deve preservar também o significado dos registros.
    - **Razão/motivo:** a v15 explicita que converter formato não cria leitura humana individual, autoridade, modalidade ou continuidade estatística. Uma migração estruturalmente válida pode corromper essas distinções.
    - **Solução:** definir leitores por versão, transformações explícitas e prévia das pendências. Preservar payloads assinados e relacionar as novas representações aos originais. Campos desconhecidos permanecem pendentes; conversão não promove relato a fato nem aprovação amostral a revisão integral.
    - **Teste/evidência:** o teste anterior mostrou que uma assinatura válida não torna um formato novo compatível com o leitor atual. O aceite adicional deve demonstrar que a migração conserva IDs, assinaturas e regime de revisão. Referências: v15, migração (Arquitetura-Harness-Local-v15.md:392), regression.py:11 (src/healdan/regression.py:11). 
* 32 — Definir o alcance da pesquisa antes de permitir isolamento de falhas.**
    - **Descrição:** este é o ponto que mais reformulo. Retiro a recomendação inicial de criar coleções como solução imediata. Primeiro, o Healdan precisa distinguir pesquisa em afirmações aprovadas de pesquisa nas fontes preservadas.
    - **Razão/motivo:** chaves diferentes nas afirmações existentes não demonstram que uma fonte seja irrelevante: ela pode conter contraevidência ainda não extraída. A v15 exige alcance explícito e mantém pendência quando a independência não foi demonstrada.
    - **Solução:** informar escopo pesquisado, cobertura e motivo de parada. Recomendo um piloto de busca textual nas fontes, apresentando trechos não revisados separadamente dos fatos aprovados. Só permitir continuidade diante de falha independente quando as dependências e a pesquisa obrigatória estiverem suficientemente verificadas. A curadoria completa por uso continua sendo uma proposta adicional — a avaliação a havia adiado.
    - **Teste novo:** uma fonte sem afirmações retornou `20`, sem apresentar seu trecho. Depois, uma afirmação aprovada com valor **42**, acompanhada de outra fonte íntegra contendo uma possível correção para **43**, continuou retornando `42`, sem conflitos e com `research=complete`. Isso não prova que 43 seja verdadeiro; demonstra o alcance limitado da pesquisa atual. Referências: v15, busca (Arquitetura-Harness-Local-v15.md:198), knowledge.py:127 (src/healdan/knowledge.py:127). 
- **33.— Orçamento de execução integrado às tarefas e sessões existentes.**
    - **Descrição:** mantenho os limites por execução, mas retiro a necessidade de criar outro registro paralelo de tarefa, como um `ResearchRun` independente.
    - **Razão/motivo:** a v15 favorece uma fonte de estado por responsabilidade e listas derivadas. Duplicar objetivo, consumo e pendências criaria novos problemas de reconciliação.
    - **Solução:** acrescentar às tarefas/sessões atuais limites de duração, tentativas, chamadas e saída, preservados nas retomadas. Registrar cobertura e motivo de parada; reservar capacidade para investigar conflitos. Distinguir limites efetivamente impostos de estimativas e separar bytes disponíveis de leituras observadas.
    - **Teste/evidência:** o processo simulado anterior pôde declarar consumo elevado e concluir, enquanto `evidence_bytes` contabilizou arquivos não lidos. A correção deve demonstrar que retomadas não renovam o orçamento e ausência de telemetria não significa consumo zero. Referências: v15, limites (Arquitetura-Harness-Local-v15.md:317), launcher.py:202 (src/healdan/launcher.py:202).
- **34 — Separar aprovação de conteúdo de comprovação operacional.**
    - **Descrição:** hoje, `accepted` habilita a resposta, enquanto `modality` participa da chave e dos filtros, mas não impõe requisitos distintos de comprovação. O JSON retornado também não preserva modalidade, enunciado e atribuição. Assim, um conteúdo aprovado como relato pode chegar ao consumidor apenas como um valor aparentemente conclusivo.
    - **Razão/motivo:** aprovar “Ana relatou que a restauração passou” confirma a aceitação daquele relato; não demonstra que o teste aconteceu. Essa distinção é central para uma wiki usada para decisões, procedimentos e evidências de controles. **A prioridade está em evitar que uma resposta tecnicamente íntegra seja utilizada para sustentar uma conclusão que sua evidência não permite.**
    - **Solução:** tornar explícitas as categorias fato operacional, relato, plano, decisão e regra declarada, preservando natureza, atribuição, condições e referências no retorno estruturado e nas páginas. Consultas que exigem comprovação de execução devem exigir evidência operacional apropriada e revisão correspondente. Quando houver somente relato ou plano, apresentar esse conteúdo identificado e informar insuficiência para comprovar execução. A migração deve manter casos ambíguos pendentes. Isso concretiza a distinção da v15 (Arquitetura-Harness-Local-v15.md:105), preservando a exigência de registro operacional indicada na avaliação (avaliacao-v15-para-wiki.md:59).
    - **Teste realizado:** em um vault temporário com assinatura SSH real de teste, registrei uma afirmação corretamente atribuída: “Ana relatou que o teste de restauração passou; execução não confirmada”, com modalidade `relato_operacional`. A consulta retornou **`code=0`, `outcome=answer` e `value=passed`**, omitindo modalidade, atribuição e ressalva. A página preservou a frase original; portanto, o teste demonstra perda de significado no contrato de saída, não invenção automática de uma execução. Código: knowledge.py:146 (src/healdan/knowledge.py:146).
    - **Critério de aceite:** a mesma evidência deve permitir responder corretamente **“o que Ana relatou?”**, mas permanecer insuficiente para **“a restauração foi comprovadamente executada?”**. Essa diferença precisa sobreviver ao JSON, à renderização e aos testes de regressão.
- **35. Relatório legível das mudanças, vinculado ao pacote que será assinado.
    - **O que existe:** `relatorio`, `avaliar` e `imprimir_relatorio` identificam arquivos alterados, IDs novos, mudanças de estado, reescritas de afirmações, fontes modificadas e bloqueios. pr.py:629 (pr.py:629)
    - **Por que aproveitar:** o Healdan congela um pacote verificável, mas falta uma apresentação consolidada que ajude a pessoa a entender exatamente o que está aprovando.
    - **Como adaptar:** gerar o relatório a partir dos bytes do **pacote congelado**, incluindo diferenças nas afirmações, fontes, páginas, inspeções e pendências. Vinculá-lo ao digest do pacote.
    - **O que descartar:** a implementação antiga lê o worktree e monta um índice temporário. Esse estado mutável não deve ser a referência da aprovação de um pacote já preparado. A ideia de apresentação combina com a assinatura informada da v15, §9.1 (Arquitetura-Harness-Local-v15.md:291).
- **36. Conferência da entrega declarada contra os artefatos realmente produzidos.**
    - **O que existe:** `conferir_ingest` compara os IDs e páginas declarados pela sessão com as alterações observadas. pr.py:723 (pr.py:723)
    - **Teste:** uma declaração compatível passou; declarar `C-0003` quando somente `C-0002` havia sido registrada produziu os diagnósticos esperados.
    - **Como adaptar:** conferir o resumo de entrega contra os objetos efetivamente incluídos no candidato: afirmações propostas, páginas alteradas, evidências e pendências.
    - **Limite:** aparecer numa linha modificada não comprova uma entrega semanticamente correta. Tampouco devemos exigir que toda tarefa produza conhecimento: a v15 admite registrar que não houve aprendizado reutilizável. Este mecanismo ajudaria a concretizar melhorias de rastreabilidade já discutidas.
- **37. Verificações editoriais de navegação dentro do lint atual.**
    - **O que existe:** checagem de wikilinks, páginas fora do índice, referências a IDs e exclusão de exemplos de código da análise de links. wiki_check.py:150 (wiki_check.py:150)
    - **Teste comparativo:** o Healdan atual aceitou `[[ghost]]` sem diagnóstico e rejeitou o exemplo literal `` `[x](missing.md)` `` como link quebrado. São lacunas concretas em pages.py:156 (src/healdan/pages.py:156).
    - **Como adaptar:** incorporar essas verificações ao `linting.collect`, preservando a validação atual de caminhos e âncoras. Classificar páginas órfãs como diagnóstico editorial quando sua ausência no índice não violar um contrato obrigatório.
    - **O que descartar:** o resolvedor antigo de wikilinks usa apenas nomes de arquivos e não resolve ambiguidades adequadamente. Também não devemos reintroduzir as pastas antigas ou exigir `memory.md` em todo tópico.
- **38. Merge por identidade — aproveitamento condicional, fora da publicação.**
    - **O que funciona:** o algoritmo combina inclusões em IDs diferentes e produz conflito quando os dois lados alteram o mesmo registro de maneiras incompatíveis. Reproduzi ambos. pr.py:1865 (pr.py:1865)
    - **Onde poderia ajudar:** preparação de uma proposta atualizada ou importação assistida de acervo.
    - **Por que não priorizar agora:** o Healdan tem um escritor ativo por padrão; o benefício imediato é menor. Além disso, o legado aceitou `C-0001` e `C-1` simultaneamente, permite remoções e pode retornar merge limpo contendo JSONL malformado pelo fallback.
    - **Condição para aproveitar:** parsing estrito, identidade numérica do Healdan, preservação de registros e nova validação/revisão/assinatura após recomposição. Nunca fundir automaticamente pacotes já assinados
- **39.  — Preservar os bytes originais durante o armazenamento no Git.**
    
    **Breve descrição:** a ingestão calcula corretamente o hash do arquivo recebido, mas o `.gitattributes` atual (.gitattributes:1) aplica `text=auto eol=lf` sem excluir os originais. Assim, um documento textual, histórico, JSON ou código com quebras CRLF pode ser armazenado no Git com bytes diferentes daqueles registrados no manifesto.
    
    **Razão/motivo:** isso compromete a recuperação exata da evidência e seus localizadores. **Reproduzi:** uma fonte de 13 bytes passou na validação inicial; após commit e criação de outro worktree, tinha 11 bytes, e a consulta retornou código **4**, com `Source hash/size mismatch`. Não houve concorrência. O bloqueio de integridade funciona, mas o Git deixou de preservar o original. A v15 exige expressamente `-text` para os brutos (Arquitetura-Harness-Local-v15.md:95).
    
    **Solução:** aplicar `-text` aos originais, verificar atributos e filtros efetivos e conferir o hash do conteúdo realmente armazenado no Git. Incorporar essa proteção ao `setup`, que atualmente não cria `.gitattributes`, e verificar a configuração no `doctor`. Normalizações devem gerar derivados identificados. O comportamento de `-text` está documentado pelo [Git](https://git-scm.com/docs/gitattributes#_text). 
- **42.  — Impedir reclassificação implícita de material sensível na entrada.**
    
    **Breve descrição:** a triagem registra classificação por hash (src/healdan/inbox.py:61), mas o comando de ingestão (src/healdan/cli.py:198) não consulta essa decisão. Informar `--classification common` permite importar os mesmos bytes anteriormente classificados como pessoais ou sensíveis.
    
    **Razão/motivo:** não depende de descobrir automaticamente conteúdo sensível: o sistema **já conhece a restrição e a ignora nessa passagem**. Reproduzi ambos os casos, `personal` e `sensitive`: a nova fonte ficou como `common`, enquanto a triagem conservou a classificação anterior. A custódia acompanhava somente a cópia do Inbox, não a nova cópia canônica. Isso cria políticas contraditórias de finalidade e retenção. A v15 determina a preservação das restrições das fontes (Arquitetura-Harness-Local-v15.md:99).
    
    **Solução:** centralizar a admissão de fontes, reconciliando hash/revisão, classificação, finalidade e vínculos de custódia antes de publicar a cópia. Uma divergência deve exigir reclassificação explícita, autorizada e auditável. O operador continua podendo corrigir uma classificação; essa mudança precisa ser uma decisão identificável. Aplicar a mesma verificação às propostas e aos futuros adaptadores.
    
    **Validação:** testar bloqueio da passagem implícita `sensitive → common`, sucesso de uma reclassificação autorizada e registro das cópias sob a política correspondente. Os ensaios realizados comprovaram a inconsistência local; não envolveram transmissão a provedores.
- **43.— Avaliação independente da qualidade dos agentes e prompts**
    
    **Breve descrição:** Avaliar se o agente compreendeu a tarefa, encontrou evidência suficiente e entregou uma resposta ou alteração correta.
    
    **Razão/motivo:** A regressão atual testa o resolvedor usando filtros estruturados. Em uma contraprova, dois casos assinados — um perguntando o valor de um instrumento e outro a população de Paris — passaram com os mesmos filtros e resultado `42`. **Nenhum agente respondeu sobre Paris:** o teste demonstra que o campo da pergunta não participa da execução da regressão. Assim, uma suíte verde não avalia compreensão da tarefa. Código (src/healdan/regression.py:50)
    
    **Solução:** Criar um pequeno conjunto de tarefas representativas, com critérios e respostas de referência definidos antes da execução. Comparar versões de prompts ou do fluxo nas mesmas condições, preservando fontes, configuração e resultados. Avaliar saídas sem revelar a variante quando possível; separar casos usados no desenvolvimento de casos reservados. Medir erros materiais, omissões, abstenções corretas e bloqueios indevidos. Um avaliador LLM pode auxiliar, mas sua nota não deve ser a única referência. A v15 fornece um desenho aproveitável de comparação pareada; não é necessário adicionar outro modelo para começar. v15 (Arquitetura-Harness-Local-v15.md:647)
- **44. — Produtividade medida por resultado útil e esforço total**
    
    **Breve descrição:** Relacionar cada tarefa ao resultado efetivamente aceito e ao custo completo para produzi-lo.
    
    **Razão/motivo:** Atualmente, `success` significa término técnico sem erro declarado e com UUID esperado. Não significa cumprimento do objetivo. Além disso, tokens ausentes viram zero e `evidence_bytes` soma todo o diretório de evidências por execução, sem demonstrar leitura efetiva. Esses registros não permitem concluir economia de tempo ou qualidade do trabalho. Código (src/healdan/launcher.py:199)
    
    **Solução:** Acrescentar ao registro existente da tarefa critérios breves de aceite, evidências da entrega e desfecho confirmado pelo responsável. Contabilizar preparação, revisão, correções e tentativas fracassadas; separar tempo humano, execução e espera. Consumo desconhecido deve continuar desconhecido. Comparar tarefas semelhantes e mostrar esforço sem resultado quando o denominador for zero. Uma abstenção correta pode ser útil; quantidade de arquivos, tokens ou afirmações não deve virar pontuação de produtividade. Isso aproveita diretamente a disciplina da v15, sem exigir avaliação burocrática de cada sessão. v15 (Arquitetura-Harness-Local-v15.md:343)
**45. — Amostragem vinculada ao processo avaliado e aos erros posteriores**
    
    **Breve descrição:** Impedir que uma configuração nova herde automaticamente a sequência de acertos de outro processo.
    
    **Razão/motivo:** O CSP utiliza um estado global de sequência limpa. No teste, uma preparação com template e contextos diferentes herdou `streak=111`; a unidade não foi selecionada para inspeção, e aprovação e integração passaram. Foram usados Git e assinaturas reais, com sessões sintéticas. Isso demonstra ausência de segmentação, não desempenho de um modelo novo. Código (src/healdan/transactions.py:146)
    
    **Solução:** Vincular a sequência ao escopo elegível e à configuração relevante: versão do prompt, modelo identificado pelo provedor, conversor e regras de revisão. Mudanças materiais reiniciam a sequência afetada, conservando o histórico. Não reiniciar por qualquer pergunta diferente. Criar também um registro separado para erro material descoberto após publicação, capaz de retornar o escopo à revisão integral sem editar inspeções já assinadas. Distinguir erros da proposta inicial, erros que escaparam ao revisor e erros encontrados em uso. A v15 descreve essa separação; importar todos os cálculos estatísticos dos apêndices não é necessário agora. v15 (Arquitetura-Harness-Local-v15.md:466)

- **46. Aprendizados vinculados a falhas reproduzíveis e correções verificadas**
    
    **Breve descrição:** Transformar erros relevantes em melhorias demonstráveis de código, prompt ou procedimento.
    
    **Razão/motivo:** Existem registros de lições e acompanhamento de achados, mas não encontrei um ciclo implementado que conecte ocorrência, diagnóstico, contramedida e verificação posterior. Na contraprova, a validação de candidato aceitou uma lição contendo apenas `{"id":"L-0001"}`. Preservar esse registro não demonstra aprendizado nem prevenção de recorrência. Validação atual (src/healdan/transactions.py:73)
    
    **Solução:** Para falhas materiais ou recorrentes, registrar evidência do problema, causa confirmada ou hipótese explicitamente identificada, correção proposta e teste que reproduza o defeito. Verificar a correção e possíveis efeitos negativos em outros casos. Uma lição reutilizável deve indicar quando se aplica, suas limitações e o resultado observado; somente depois deve orientar contextos futuros. Permitir “nenhuma lição necessária” e revisar regras que perderam utilidade. O agente não deve modificar sozinho o gabarito para transformar sua falha em acerto. Esse aproveitamento da v15 reduz o risco de acumular instruções sem eficácia demonstrada. v15 (Arquitetura-Harness-Local-v15.md:329)
- **47. — Auditoria rastreável de alucinações e qualidade da wiki, incluindo a avaliação do próprio auditor**
    
    **Breve descrição:** Criar uma auditoria semântica do acervo e das respostas que identifique o trecho problemático, confronte sua evidência, localize onde a distorção apareceu e permita contestar o diagnóstico. Cada achado deve separar **defeito observado, origem identificável e hipótese sobre a causa**.
    
    **Razão/motivo:** Os controles atuais verificam fontes, localizadores, hashes e aprovações, mas não determinam se a evidência sustenta integralmente a conclusão. Em uma contraprova, uma fonte sobre medição em laboratório sustentou mecanicamente uma afirmação assinada sobre **todos os ambientes de produção**: a consulta retornou resposta e a validação das páginas passou. Outro teste aceitou um título que acrescentava uma conclusão não sustentada pela fonte. O conteúdo foi inserido nas fixtures; não foi produzido por um agente real. Isso demonstra o limite dos controles, sem provar uma causa interna do modelo. Validação atual (src/healdan/knowledge.py:81)
    
    **Solução:** Implementar um registro de auditoria com os seguintes componentes:
    
    1. **Diagnóstico por afirmação e contexto.** Examinar também títulos, tabelas e sínteses, preservando qualificadores. Classificar separadamente contradição, extrapolação, suporte parcial, atribuição incorreta, desatualização e impossibilidade de verificar. Uma inferência explicitamente apresentada, com premissas e derivação válidas, não deve ser automaticamente rotulada como alucinação. Uma conclusão plausível, porém, continua inadequada se apresentada como fato sem suporte. A v15 já fornece distinções aproveitáveis. Revisão semântica na v15 (Arquitetura-Harness-Local-v15.md:219)
    2. **Dossiê reproduzível de cada achado.** Relacionar página/afirmação e versão, fonte original e trecho contextualizado, corte temporal, extrações, contexto registrado, revisão e pacote publicado. Reutilizar IDs, hashes e recibos existentes. Separar o que estava disponível na ocasião do que foi descoberto depois: uma atualização posterior não transforma automaticamente uma resposta histórica em alucinação. Artefatos ausentes devem aparecer como lacuna de rastreabilidade.
    3. **Investigação do “por quê” com limites explícitos.** Comparar as etapas `original → conversão → recuperação → extração → revisão → publicação` para localizar a primeira divergência observável. Por exemplo, demonstrar que uma condição existia no documento e desapareceu na conversão. Já “o modelo se confundiu” ou “o prompt causou o erro” devem permanecer hipóteses até haver evidência adicional. Reexecuções controladas podem testar essas hipóteses; a explicação retrospectiva do próprio agente não comprova causalidade.
    4. **Revisão do diagnóstico do auditor.** O avaliador deve apresentar trecho, evidência e justificativa verificável. Preservar decisões iniciais, discordâncias e resolução humana dos casos relevantes. Permitir os resultados **procedente, parcialmente procedente, refutado e inconclusivo**. Conferir também itens que o auditor não sinalizou, para descobrir falhas de detecção. A proposta se aproxima da avaliação por unidades de informação do FActScore, cujo próprio estudo reconhece limitações nos julgamentos individuais e na medição de cobertura. [FActScore](https://aclanthology.org/2023.emnlp-main.741/)
    5. **Meta-análise com denominadores honestos.** Produzir um relatório derivado por período, domínio e configuração, mostrando defeitos confirmados, gravidade, etapa de origem, recorrência, alcance e causas ainda desconhecidas. Separar amostras do acervo, investigações por suspeita e testes artificiais. Não transformar quantidade de alertas em “taxa de alucinação”, nem contar a reprodução do mesmo erro em várias páginas como observações independentes. Qualidade deve incluir suporte, atualidade, rastreabilidade e cobertura das perguntas definidas, sem reduzir tudo a uma nota única.
    6. **Validação necessária:** Antes de confiar no avaliador, testá-lo contra casos revisados por humanos: fonte errada reproduzida fielmente como relato; número alterado; condição omitida; inferência válida e inválida; fonte atualizada depois; evidência indisponível; e acusação de erro sem fundamento. Medir tanto acusações indevidas quanto defeitos não detectados. Esses são testes de aceite propostos; a eficácia desse avaliador ainda não foi demonstrada no Healdan.
    7. **Implicações:** Começar com lotes pequenos e relatório derivado dos registros existentes. O auditor propõe achados; correções seguem a aprovação normal. Evidências sensíveis continuam sob sua política de acesso e retenção, sem duplicar conversas inteiras no Git. O benefício específico deste ponto é permitir responder, com evidência: **“o que está errado, por que o diagnóstico procede, onde o problema surgiu e o que ainda não sabemos sobre sua causa?”**
    
 **48. — Inventário externo com cobertura explícita e captura reproduzível**
    
    **Breve descrição:** identificar o patrimônio realmente disponível para migração: páginas, anexos, registros, referências, configurações e histórico acessível.
    
    **Razão/motivo:** o inventário atual não serve para uma árvore arbitrária de arquivos. No Notion, a própria documentação informa que a busca não garante inventário completo; exportações também podem omitir páginas sem acesso. Portanto, “encontrei 200 páginas” não demonstra “a wiki tem 200 páginas”. [Limitações da busca](https://developers.notion.com/reference/search-optimizations-and-limitations), [limitações da exportação](https://www.notion.com/help/export-your-content).
    
    **Solução e onde:** ampliar `migration.py` e sua interface em `cli.py` com um **`migration analyze` proposto**, usando adaptadores para pastas, exportações e, posteriormente, API do Notion. Produzir um manifesto com identidade da origem, escopo solicitado, arquivos/objetos encontrados, hashes, janela de captura, formatos e falhas. Distinguir `examinado`, `inacessível`, `não suportado`, `fora do escopo` e `não avaliado`. No conector, percorrer paginação e blocos filhos; no leitor local, resolver os dialetos encontrados, incluindo wikilinks. A API exige consultas adicionais para recuperar filhos aninhados. [Documentação de blocos](https://developers.notion.com/reference/get-block-children).
    
    **Validação necessária:** simular página inacessível, paginação interrompida, anexo ausente e alteração durante a leitura. O resultado deve continuar permitindo um plano parcial, com bloqueios nas operações afetadas. Congelar os arquivos recebidos não autoriza afirmar que toda a wiki remota foi capturada no mesmo instante.


- **49. — Meta-análise das regras e mecanismos da wiki de origem**
    
    **Breve descrição:** compreender como a wiki organiza, revisa e aprova informações, incluindo `CLAUDE.md`, `AGENTS.md`, templates, scripts e convenções.
    
    **Razão/motivo:** esses arquivos ajudam a interpretar o legado, mas podem estar desatualizados ou contradizer o comportamento implementado. Uma regra dizendo “toda informação é verificada” não comprova que as páginas foram verificadas. Além disso, importar suas instruções para o contexto operacional do analisador permitiria que a origem alterasse as próprias regras da análise.
    
    **Solução e onde:** adicionar uma etapa de diagnóstico ao analisador, produzindo uma matriz **regra declarada → mecanismo encontrado → evidência disponível → compatibilidade com Healdan → decisão proposta**. Cada conclusão precisa apontar para o trecho ou código correspondente. Separar “documentado”, “implementado”, “demonstrado por teste” e “não verificado”. Os arquivos externos entram como evidência, conforme a regra já presente no `CLAUDE.md` (CLAUDE.md:8). O processo deve operar fora da árvore externa, com capacidades fixadas pelo controlador; configurações, hooks e comandos encontrados não são ativados automaticamente.
    
    **Validação necessária:** uma wiki de teste deve conter regras contraditórias e um `AGENTS.md` mandando ignorar validações ou publicar tudo como aprovado. O analisador precisa registrar essas instruções como material examinado, sem executá-las. A LLM pode sugerir interpretações; permissões e operações permitidas precisam ser impostas por código.
- **50— Manifesto tipado para identidade, temporalidade, classificação e perdas de significado**
    
    **Breve descrição:** representar explicitamente como cada informação da origem será preservada ou transformada, antes de convertê-la ao modelo Healdan.
    
    **Razão/motivo:** duas wikis podem usar `C-0001` para coisas diferentes — reproduzi essa colisão. Os aliases existentes só permitem grafias da mesma identidade; não resolvem UUIDs do Notion ou identidades entre wikis. Há também um problema concreto no exemplo da análise antiga: a data de um questionário foi convertida em `valid_from` à meia-noite UTC, sem demonstrar horário, fuso ou início da validade do fato. Exemplo auditado (healdan-analise.md:853).
    
    **Solução e onde:** definir um esquema versionado do manifesto de migração, com validadores determinísticos. A identidade externa deve combinar **origem estável + identificador externo**, mantendo revisão e hash separados; o vínculo com IDs Healdan fica em um mapa próprio. Registrar criação, edição, captura, declaração e validade como conceitos distintos. Preservar valor original, precisão e fuso conhecido: uma data sem horário continua sendo uma data. Também registrar autor quando disponível, classificação declarada, finalidade, retenção, linhagem e perdas da transformação. Classificação desconhecida permanece pendente; acesso público ou permissão de leitura não deve convertê-la automaticamente em `common`.
    
    **Validação necessária:** cobrir datas incompletas, fusos equivalentes, duas origens com IDs iguais, divisão de uma afirmação em várias e classificação ausente. Testei que o corte temporal atual representa validade da afirmação: uma fonte capturada depois pode sustentar uma consulta sobre período anterior. Isso não comprova o que era conhecido naquele momento; reconstrução histórica exige evidência adicional.
- **51. — Auditoria diferencial de qualidade: erro herdado, introduzido ou indeterminado**
    
    **Breve descrição:** comparar fonte original, interpretação proposta e resultado convertido para identificar onde surgem distorções.
    
    **Razão/motivo:** uma migração pode preservar perfeitamente uma afirmação errada ou corromper uma afirmação correta ao perder negação, condição, autoria, unidade ou data. Esses casos exigem tratamentos diferentes. Também seria incorreto considerar uma página importada como prova independente daquilo que ela própria afirma.
    
    **Solução e onde:** aplicar ao fluxo de migração o avaliador rastreável proposto em **QA-avaliação-5**, conectado à revisão existente, sem criar outro sistema paralelo. Cada achado deve mostrar os trechos antes/depois, referências, critério violado, origem observável e julgamento: procedente, parcialmente procedente, refutado ou inconclusivo. Distinguir preservação documental, fidelidade da conversão e suporte factual. Estados como “verificado”, aprovações antigas e histórico de amostragem permanecem registrados, mas não se tornam autorização atual automaticamente — orientação explícita da v15 sobre migração (Arquitetura-Harness-Local-v15.md:392).
- **52. — Plano estruturado com simulação, reconciliação e critérios de aceite**
    
    **Breve descrição:** transformar a análise em um plano que possa ser conferido por código e revisado pelo usuário, com etapas, dependências, impedimentos e resultados esperados.
    
    **Razão/motivo:** um relatório narrativo pode recomendar ações incompatíveis entre si, esquecer anexos ou assumir capacidades inexistentes. O Healdan já possui candidatos temporários, restrição de caminhos, preservação de fontes e validação de propostas em `transactions.py` (src/healdan/transactions.py:22). Convém integrar o planejamento a esses mecanismos.
    
    **Solução e onde:** gerar um `plan.json` com esquema estrito e um relatório Markdown derivado dele. Cada objeto inventariado deve ter tratamento explícito: preservar, converter, propor curadoria, manter na origem ou aguardar informação. Registrar transformações permitidas, dependências, hashes de entrada, versão do conversor, base do destino, perdas conhecidas e verificações exigidas. O modo de análise não reserva IDs nem modifica a origem. Uma execução futura reconfere as entradas e usa o fluxo normal de propostas e aprovação. Começar por um domínio pequeno, escolhido por utilidade e disponibilidade de evidências.
    
    **Validação necessária:** repetir a simulação sobre as mesmas entradas deve preservar os mapeamentos; alterações relevantes devem invalidar o plano afetado; toda entrada precisa de destino ou justificativa; referências e anexos não podem desaparecer silenciosamente. O aceite deve medir preservação, qualidade e capacidade de responder perguntas úteis. “Preservar este conjunto sem convertê-lo agora” e “este domínio ainda não é migrável” são resultados válidos
- **53. — Validação incompleta da configuração e das provas de execução**
    
    **Breve descrição:** o `doctor` verifica a existência do executável Claude, mas não sua compatibilidade efetiva. Além disso, encontramos uma falha concreta: com a resposta do subprocesso simulada, `probe()` aceitou tanto `{}` quanto `{"allowed_write":true}` como prova bem-sucedida, porque usa `all(checks.values())` sem exigir todas as verificações. Código da verificação (src/healdan/launcher.py:99).
    
    **Razão/motivo:** uma prova incompleta pode ser registrada como válida. Separadamente, mudanças de versão podem alterar carregamento de configurações, ferramentas e retomada sem mudar o código do Healdan.
    
    **Solução:** exigir conjunto completo de resultados, tipos booleanos e controles positivos; registrar a versão aprovada do Claude e testar as funcionalidades utilizadas pelo launcher. Complementar os ensaios existentes com configuração carregada, ferramentas disponíveis, autenticação e retomada. O evento `system/init`, quando utilizado, fornece metadados úteis, mas não substitui testes de comportamento. [Execução programática](https://code.claude.com/docs/en/headless).
    
    **Validação:** respostas vazias, parciais ou com tipos incorretos devem falhar. Depois, executar os testes reais no Mac. A contraprova atual demonstra uma falha no verificador, **não uma fuga do sandbox**.
- **54. — Perfil nativo permite configurações adicionais sem verificação**
    
    **Breve descrição:** `profile()` confere apenas o conteúdo de `settings.json`. No teste, adicionar `CLAUDE.md`, arquivos em `agents/` e `rules/`, além de `settings.local.json`, não impediu sua reutilização. O perfil nativo permanece amplamente gravável. Código do perfil (src/healdan/launcher.py:110).
    
    **Razão/motivo:** verificar um arquivo não demonstra que todos os canais capazes de modificar a execução estão controlados. O teste comprova que o controlador aceita esses arquivos adicionais; seu carregamento depende do Claude e da versão.
    
    **Solução:** separar configurações confiáveis dos dados que o Claude precisa escrever. Proteger instruções, definições de agentes, skills e hooks autorizados; permitir escrita apenas nos dados nativos necessários. Definir explicitamente a política de memória automática e extensões. Inventariar configurações gerenciadas e bloquear incompatibilidades, preservando a política da organização: configurações locais não têm precedência universal e certas listas são combinadas. [Precedência oficial](https://code.claude.com/docs/en/settings).
55. **Contrato de instruções não é obrigatoriamente entregue à sessão**
    
    **Breve descrição:** existe um template de contexto (templates/context.txt:1), mas `new_session()` recebe texto arbitrário e verifica essencialmente tamanho e identidade. Não exige que objetivo, limites, evidências autorizadas e formato de saída estejam presentes. Criação da sessão (src/healdan/tasks.py:83).
    
    **Razão/motivo:** um bom `CLAUDE.md` na raiz não resolve instruções ausentes na execução real. A v15 (Arquitetura-Harness-Local-v15.md:54) fornece um princípio aproveitável: contrato explícito de entrada e saída, com autorizações mantidas no controlador.
    
    **Solução:** montar o contexto por código usando uma fonte confiável: regras essenciais, tarefa, papel, caminhos autorizados, esquema de saída e condições de parada. Registrar o conteúdo entregue e seu hash. Manter `CLAUDE.local.md` como preferência pessoal, sem conceder autoridade operacional. Não duplicar regras em `CLAUDE.md` e `AGENTS.md`: o suporte atual a este último depende da versão e da presença dos arquivos Claude. [Carregamento de instruções](https://code.claude.com/docs/en/memory#agentsmd).
56. ** Ferramentas não são delimitadas por papel e fase**
    
    **Breve descrição:** o launcher não estabelece uma lista de ferramentas por papel. Um exemplo concreto aparece na recuperação: ele troca o prompt por uma instrução para não usar ferramentas, mas não remove essas ferramentas dos argumentos de execução. Trecho de recuperação (src/healdan/launcher.py:143).
    
    **Razão/motivo:** leitor, editor, extrator, revisor e verificação de recuperação têm necessidades diferentes. Uma proibição textual deixa uma responsabilidade desnecessária com o modelo.
    
    **Solução:** definir uma matriz pequena de capacidades no controlador. Recuperação destinada apenas a confirmar a conversa deve executar sem ferramentas; extração e revisão podem produzir seus próprios artefatos, mantendo os demais destinos protegidos. Autorizar shell somente quando necessário. Utilizar os mecanismos corretos: `--tools` restringe ferramentas disponíveis; `--allowedTools` trata de aprovação e não equivale a essa restrição. [Referência da CLI](https://code.claude.com/docs/en/cli-reference).
    
    **Validação:** testar ações permitidas e proibidas por papel, incluindo ferramentas de arquivo e subprocessos. Preservar o sandbox externo do Healdan: o sandbox interno do Claude cobre comandos de shell e não oferece a mesma abrangência sobre ferramentas, hooks e MCP. [Escopo oficial do sandbox](https://code.claude.com/docs/en/sandboxing).
57. **Delegação nativa sem contrato com as sessões do Healdan**
    
    **Breve descrição:** os papéis registrados pelo Healdan não são definições nativas de subagentes. O launcher não declara uma política explícita de delegação, enquanto a revisão do projeto depende de sessões identificadas e extrações independentes congeladas. Contrato de revisão (src/healdan/review.py:11).
    
    **Razão/motivo:** chamar um subagente “revisor” não estabelece a revisão exigida pelo Healdan. Também não se deve presumir herança uniforme das instruções: a documentação atual informa que Explore e Plan começam sem os arquivos `CLAUDE.md`; outros agentes têm comportamentos diferentes. [Contexto dos subagentes](https://code.claude.com/docs/en/sub-agents#what-loads-at-startup).
    
    **Solução:** manter a revisão formal nas sessões independentes já controladas. Desabilitar delegação nativa onde não há necessidade demonstrada. Se um auxiliar trouxer benefício, delimitar tarefa, evidências, ferramentas, duração e vínculo com a sessão responsável; tratá-lo como auxiliar, sem atribuir-lhe aprovação independente. A restrição precisa considerar também caminhos de criação de processos filhos.
58. ** Política explícita para hooks, sem reproduzir a governança antiga**
    
    **Breve descrição:** não há hooks de projeto configurados no checkout atual. Os hooks antigos exigem seleção cuidadosa: o `hook_guarda` (pr.py:2016) retorna sucesso em exceções, e o `hook_parada` tenta realizar checkpoints automaticamente.
    
    **Razão/motivo:** portar esse comportamento duplicaria responsabilidades do controlador. Além disso, “o hook falhou” não significa necessariamente “a ação foi bloqueada”: a documentação atual prevê continuidade em diversos erros e timeouts. [Comportamento de falhas dos hooks](https://code.claude.com/docs/en/hooks#block-the-action-when-a-hook-fails).
    
    **Solução:** declarar quais hooks podem executar, mantendo desabilitados os não necessários. Quando houver benefício concreto, usar adaptadores pequenos e protegidos para diagnóstico ou validação de artefatos acessíveis da proposta. Hooks não devem assinar, aplicar, fechar tarefas ou fazer commits. Um bloqueio necessário exige resposta apropriada ao evento e tratamento explícito de falhas; não basta repassar qualquer código de saída do controlador. Políticas gerenciadas também precisam ser consideradas: `disableAllHooks` local não desliga universalmente hooks administrados. [Configuração de hooks](https://code.claude.com/docs/en/settings-reference#disableallhooks).
    
    **Validação:** testar script ausente, timeout, JSON inválido, chamada repetida e tentativa de alteração pelo agente. A validação final deve continuar funcionando mesmo sem o hook. Não adotaria automaticamente `--bare`, apesar da recomendação oficial para automação: ele não utiliza o login por assinatura previsto no fluxo atual. Isso exigiria uma decisão de autenticação e novos ensaios, não apenas acrescentar uma flag. [Limitações do modo bare](https://code.claude.com/docs/en/headless#start-faster-with-bare-mode).
59. **Evidências preservadas, mas insuficientemente pesquisáveis .**
    
    **Breve descrição:** implementar pesquisa conjunta em fontes originais e afirmações curadas, recuperando contexto suficiente para interpretar cada trecho.
    
    **Razão/motivo:** o resolvedor atual procura `term` somente no enunciado da afirmação. Em uma contraprova, a fonte continha `CERT-778`, mas consultar esse termo retornou abstenção com pesquisa considerada completa. O documento estava preservado; o caminho de consulta não o pesquisava. Isso é uma limitação do escopo atual, não demonstração de inexistência da evidência. Código atual (src/healdan/knowledge.py:127).
    
    O mecanismo útil do **Linger** é recuperar fatos junto dos trechos originais. O **Hindsight** combina sinais lexicais, semânticos, relacionais e temporais. O **EverOS** agrupa resultados por episódio, reduzindo a ocupação do resultado por várias partes do mesmo episódio. São referências para melhorar seleção e contexto, sem atribuir autoridade ao ranking. [Linger](https://github.com/simplexai-labs/linger/blob/main/apps/node-services/src/memory/session-fact-index.ts#L28), [Hindsight](https://hindsight.vectorize.io/developer/api/recall), [EverOS](https://github.com/EverMind-AI/EverOS/blob/main/CHANGELOG.md).
    
    **Solução:** criar um índice textual reconstruível, vinculado a IDs, revisões, hashes e localizadores. Cada resultado deve permitir abrir seu contexto: seção do documento, falante, data e mensagens adjacentes pertinentes. Exibir separadamente material não revisado e conhecimento aprovado. O índice precisa respeitar classificação, acesso e retirada das fontes; sua cobertura e eventual desatualização devem aparecer na resposta.
    
    Começaria com busca textual e expansão controlada por aliases. Embeddings e reranking entrariam somente se melhorassem perguntas reservadas para avaliação, sob orçamento equivalente. O aceite deve incluir detalhes presentes apenas no original, negações, correções distantes e muitas repetições de uma mesma fonte. **O benefício esperado é encontrar evidências antes invisíveis; o risco é aumentar ruído e custo de contexto.**

- **60. Identidade da entidade depende excessivamente do nome escrito.**
    
    **Breve descrição:** distinguir identidade estável, nome de apresentação e aliases contextualizados.
    
    **Razão/motivo:** reproduzi duas afirmações sobre o mesmo instrumento, identificado na fonte como `Instrument alpha` e `ALPHA-01`. Uma registrava 42; outra, uma leitura disputada de 43. Consultar o primeiro nome retornou 42 sem conflito. Quando os nomes foram unificados, o resolvedor identificou o conflito. A comparação atual de entidade é literal. Os aliases existentes em `ids.py` tratam grafias de IDs, não equivalência entre nomes de entidades. Chave das afirmações (src/healdan/knowledge.py:27), aliases existentes (src/healdan/ids.py:89).
    
    A ligação de entidades utilizada pelo **Mem0** oferece uma referência útil para recuperação. Para o Healdan, porém, a equivalência precisa ter origem e decisão verificáveis: similaridade textual não basta para unir pessoas, serviços ou ambientes. [Mem0](https://github.com/mem0ai/mem0).
    
    **Solução:** acrescentar um cadastro versionado de entidades, com identidade estável, aliases, domínio e evidência da equivalência. Usá-lo tanto na pesquisa quanto na seleção de possíveis conflitos. Mudanças nesse cadastro devem passar pela validação do candidato e pela aprovação, pois uma união de entidades pode alterar respostas anteriormente válidas.
    
    A v15 já prevê `vocab/`; esta melhoria concretiza essa intenção no resolvedor. Não exige banco de grafos. O aceite deve provar que aliases legítimos encontram a mesma entidade, enquanto homônimos e serviços com nomes iguais em projetos diferentes continuam separados. **O benefício é reduzir omissões e conflitos escondidos; o principal risco é uma fusão incorreta contaminar várias respostas.**
- **61. Nome do problema: a mesma regra de conflito é aplicada a propriedades com significados diferentes.**
    
    **Breve descrição:** definir contratos por propriedade, incluindo quantidade de valores permitidos, unidade e dimensões de escopo relevantes.
    
    **Razão/motivo:** duas contraprovas demonstraram o limite atual: um serviço com portas 80 e 443 abertas foi tratado como conflitante; prazos de retenção de 7 e 30 dias, diferenciados por `qualifiers.plan`, também. Individualmente, as afirmações retornaram resposta; juntas, conflito. A chave atual ignora `qualifiers`, e valores distintos na mesma chave são considerados incompatíveis. **Isso segue o contrato atual de um valor por chave; o problema é sua capacidade limitada de representar o domínio.** Implementação (src/healdan/knowledge.py:143).
    
    O **Memobase** permite orientar atualização por campo, e o **MemOS** documenta campos de perfil com controle de atualização. Aproveitaria a ideia de regras específicas por propriedade. Essas fontes não demonstram o contrato determinístico de cardinalidade proposto aqui. [Memobase](https://docs.memobase.io/features/profile/profile_desc), [MemOS](https://memos-docs.openmem.net/memos_cloud/introduction/memory_types/).
    
    **Solução:** começar pelas propriedades realmente usadas, declarando se admitem um valor ou vários, quais unidades aceitam e quais qualificadores distinguem situações. Por exemplo, `open_tcp_port` pode admitir vários membros; `retention_days` pode depender do plano. Somente qualificadores previstos no contrato poderiam separar escopos, evitando que um campo arbitrário esconda uma contradição.
    
    A resposta para conjuntos precisaria de formato próprio. Dois valores escalares incompatíveis no mesmo escopo continuariam conflitantes, assim como afirmar e negar o mesmo membro. O aceite deve cobrir esses controles. **O ganho é representar informação legítima sem falsos conflitos; o custo é versionar o esquema e migrar registros com revisão, preservando os bytes e as aprovações anteriores.**

- **62. O corte temporal não distingue plenamente vigência histórica de conhecimento disponível naquela época.**
    
    **Breve descrição:** oferecer modos explícitos para consultar o que valia em determinada data e o que a wiki havia registrado ou aprovado até outra data.
    
    **Razão/motivo:** na contraprova, uma afirmação válida entre 2020 e 2021, atualmente marcada como `superseded`, não apareceu na consulta de 2020. Alterar somente seu estado para `accepted`, com nova assinatura da fixture, fez o valor antigo reaparecer. Hoje, `active()` combina intervalo temporal com o estado atual; não reconstrói automaticamente o estado histórico. Código (src/healdan/knowledge.py:122).
    
    O mecanismo aproveitável do **Graphiti, associado ao Zep**, é separar tempo de validade da relação e tempo de registro/invalidação no sistema. Isso atende perguntas distintas: “qual regra vigorava?” e “qual informação estava disponível quando a decisão foi tomada?”. [Modelo temporal do Graphiti](https://github.com/getzep/graphiti/blob/main/graphiti_core/edges.py).
    
    **Solução:** definir uma interface temporal explícita, apoiada nas versões do Git e em registros confiáveis de ingresso/publicação. Captura, ocorrência, vigência e aprovação devem continuar separadas. Uma correção recebida hoje sobre um evento antigo pode mudar a interpretação histórica atual, mas não pode aparecer como conhecimento já disponível antes de sua entrada.
    
    Não basta adicionar timestamps: é necessário selecionar a versão adequada das afirmações e aprovações. Histórico continua sujeito às restrições atuais de acesso e expurgo. O aceite deve incluir ingestão tardia, correção retroativa, sucessores e datas desconhecidas. **O benefício é reconstruir decisões com rastreabilidade; o custo é maior complexidade temporal. Eu condicionaria sua implementação às perguntas históricas reais que o Healdan precisa responder.**

- **63. Evidências válidas em etapas diferentes não possuem uma composição verificável.**
    
    **Breve descrição:** permitir consultas compostas limitadas, com resultado e evidência registrados em cada etapa.
    
    **Razão/motivo:** a fixture continha `Atlas.owner = Ana` e `Ana.team = SRE`. As duas consultas individuais responderam corretamente; recuperar ambas em uma consulta retornou código 2, solicitando maior especificidade. Não existe uma operação que componha essas respostas para perguntar “qual é a equipe da pessoa responsável por Atlas?”. Resolvedor (src/healdan/knowledge.py:154).
    
    O **Letta** demonstrou busca iterativa com ferramentas, e o `reflect` do **Hindsight** realiza múltiplas buscas antes de sintetizar. A adaptação útil para o Healdan seria tornar as etapas explícitas e verificáveis. [Experimento do Letta](https://www.letta.com/blog/benchmarking-ai-agent-memory/), [Hindsight Reflect](https://hindsight.vectorize.io/developer/api/reflect).
    
    **Solução:** introduzir planos pequenos com operações permitidas: localizar entidade, consultar propriedade, seguir relação declarada e calcular agregações autorizadas. O controlador executaria cada etapa sobre o mesmo recorte, com limites de chamadas, profundidade e resultados. Um modelo poderia propor o plano; a execução e as condições de parada seriam verificadas em código.
    
    Cada conclusão deve carregar as premissas utilizadas. No exemplo, é possível identificar a equipe de Ana; isso **não autoriza concluir automaticamente que Atlas pertence à equipe SRE**. Ambiguidade, conflito ou ligação ausente devem produzir pendência. Contagens exigem cobertura suficiente, não apenas os primeiros resultados recuperados. **O benefício é responder perguntas compostas sem esconder os passos; o custo é ampliar o contrato de consulta. Implementaria depois dos contratos de identidade e propriedade.**

- **64. Permitir novos esclarecimentos humanos na mesma tarefa.**
    
    **Breve descrição:** hoje, responder à primeira pergunta não libera a apresentação de uma segunda pergunta nessa tarefa.
    
    **Razão/motivo:** reproduzi `criar tarefa → apresentar pergunta → responder com assinatura SSH válida → apresentar outra pergunta`. A última operação retornou código **5**, `"Waiting question already presented"`, mesmo com a tarefa novamente `active`. `present()` exige que `presented_at` não exista, mas `answer()` conserva esse campo. Isso atrapalha trabalhos que exigem esclarecimentos sucessivos e incentiva contornos manuais. Código responsável (src/healdan/tasks.py:120).
    
    **Solução:** representar perguntas como rodadas identificadas, com histórico e uma pergunta aberta por vez. Vincular cada resposta assinada ao ID e ao conteúdo da pergunta. Lembretes e prazo humano acompanham a rodada; idade do worktree e consumo acumulado continuam preservados. **Aceite:** completar duas rodadas, rejeitar resposta destinada à rodada anterior e repetir uma entrega sem duplicá-la. O custo principal é migrar o registro atual de pergunta única.
- **65.  Mostrar pendências e o próximo passo concreto para retomar o trabalho.**
    
    **Breve descrição:** ampliar a consulta operacional para reunir tarefa, sessões, pacote, inspeção, pergunta humana e problemas conhecidos.
    
    **Razão/motivo:** um pacote passou por três situações — aguardando inspeção de `C-0001`, inspeção concluída e aprovação assinada — e o `status` permaneceu **exatamente igual**. Em outra contraprova, o `lint` detectou uma fonte adulterada e criou acompanhamentos, mas o `status` omitiu esses problemas. Ele informa quando o lint ocorreu, sem apresentar suas pendências. O usuário precisa reconstruir manualmente onde parou. Status atual (src/healdan/cli.py:167).
    
    **Solução:** oferecer `task show`/`next` como visão determinística dos registros existentes: título, bloqueio, objeto afetado, pacote congelado, próxima unidade de inspeção e comando aplicável. Pode começar no terminal, mantendo JSON. **Aceite:** distinguir aquelas três etapas, destacar falhas de integridade e identificar pacotes obsoletos. A visão precisa revalidar o estado antes da ação; consultar essa tela não concede aprovação nem executa comandos automaticamente.
- **66. — Vincular explicitamente cada vault ao seu estado externo.**
    
    **Breve descrição:** impedir que uma escolha incorreta de `--state` misture configuração e caminhos operacionais.
    
    **Razão/motivo:** confirmei três comportamentos: dois repositórios diferentes aceitaram o mesmo estado e compartilharam configuração e diretório de autenticação; o mesmo vault, aberto com outro estado, conservou registros antigos e aceitou uma nova sessão, mas depois falhou ao procurar o manifesto de evidências no lugar errado; um worktree legítimo, usando o estado original, funcionou. A causa é que o controle acompanha o Git comum, enquanto o estado externo pode ser escolhido independentemente. Resolução atual (src/healdan/core.py:206).
    
    **Solução:** registrar uma associação verificável entre identidade do repositório comum e estado externo. Reutilizá-la quando `--state` for omitido e rejeitar incompatibilidades antes de alterar arquivos ou criar sessões. Worktrees do mesmo repositório devem continuar permitidos. Mudanças de localização exigem reassociação explícita e conferência dos caminhos. **Aceite:** os dois casos incompatíveis devem ser bloqueados, preservando o controle positivo. Isso exige migração das instalações existentes; a prova demonstrou inconsistência operacional, não vazamento de conversas.
- **67— Instalar e atualizar o controlador sem substituir o utilizado por outras wikis.**
    
    **Breve descrição:** separar a preparação de uma versão do controlador de sua ativação para determinado vault.
    
    **Razão/motivo:** executei o bootstrap instrumentado para duas origens distintas. Ambas direcionaram `pip install --upgrade` ao mesmo ambiente `controller-1.0`. Portanto, instalar outra cópia pode modificar o controlador que a primeira wiki utilizará. O ensaio interceptou os subprocessos: **não executei uma substituição real com pip**. Bootstrap atual (scripts/setup.py:13).
    
    **Solução:** manter instalações imutáveis identificadas pelo conteúdo do build, compartilháveis quando forem idênticas, e registrar qual delas cada vault utiliza. Preparar e verificar a nova instalação antes de ativá-la. Criar o ambiente diretamente no caminho definitivo, pois ambientes `venv` não são considerados portáveis. [Documentação Python](https://docs.python.org/3/library/venv.html). **Aceite:** instalar B deve preservar o controlador de A; falha na preparação deve manter a instalação anterior utilizável. O retorno de versão precisa verificar compatibilidade do estado, pois trocar o executável não desfaz migrações.