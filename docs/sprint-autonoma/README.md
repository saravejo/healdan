# Sprint autônoma do Healdan

[Melhorias-67.md](Melhorias-67.md) contém a especificação original. As linhas da [matriz](matriz.json) mantêm os IDs 1–39 e 42–67. Cada linha associa um requisito ao lote de integração, às dependências e a um aceite resumido. Os detalhes e exemplos da especificação continuam aplicáveis.

O [contrato de preparação](B00.md) precede o [contrato de formatos e identidade](B01.md). Nos lotes seguintes, o leitor especifica interfaces, migração, comportamento legado, controle positivo e contraprovas para cada ID. O coordenador registra a revisão antes da implementação.

O campo `estado` começa em `pendente`. Na integração, registrar por ID o PR, os commits de implementação e as referências de testes e pareceres. As evidências sobre o próprio SHA final ficam na PR, com links para o CI, a auditoria e as versões examinadas do Qodo. O checkpoint operacional guarda a transição de merge e o CI da nova main. A atualização seguinte da matriz incorpora esses identificadores já conhecidos.

O escopo de migração é a análise de pastas e exportações. A busca usa texto e aliases controlados. As validações locais e de CI podem comprovar estrutura, integridade e controles de comportamento. Os ensaios nativos autenticados no Mac pessoal e a eficácia do avaliador semântico dependem de evidência complementar. A publicação estável aguarda as evidências nativas exigidas.
