# Desenvolvimento do controlador Healdan

Trabalhe em um checkout de desenvolvimento isolado do vault em uso. As regras de `CLAUDE.md` regem as sessões do produto. Preserve as aprovações humanas, os bytes assinados e o histórico das instalações existentes.

Na sprint, o coordenador parte da main remota e registra a base e o HEAD completos em cada transição. Use até quatro sessões simultâneas contando o coordenador. Abra contexto novo por lote e por auditoria. Só o coordenador faz push e merge.

1. O leitor prepara um contrato com os IDs originais, aceite, contraprova, interfaces, migração e testes. O coordenador revisa o contrato antes da implementação.
2. O implementador trabalha no lote autorizado e executa os testes. O auditor começa pelo requisito e pelo commit congelado, executa controles positivos e negativos e registra o parecer por ID.
3. O coordenador coleta a revisão completa do Qodo e todas as versões anteriores disponíveis. Registra separadamente cada achado, origem, evidência, correção/teste ou contraprova aprovada pelo auditor. Nova alteração exige revalidar as evidências afetadas.
4. Confira o SHA, os checks e as conversas antes do merge. Acompanhe o CI do novo commit da main antes de integrar outro lote.

Mantenha contratos e cobertura em `docs/sprint-autonoma/` e o diário operacional fora da árvore versionada. Na retomada confira o checkout, os processos, a branch remota, a PR e a tentativa atual de CI. Após três tentativas sem progresso na mesma causa, transfira o diagnóstico para uma sessão nova. Registre dependências externas pendentes. Os ensaios pessoais autenticados no macOS e a validação semântica humana têm evidência própria. A publicação estável requer os ensaios nativos exigidos pelo projeto.
