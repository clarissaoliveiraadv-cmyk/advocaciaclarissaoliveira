# ROADMAP — Módulo Financeiro CO Advocacia App

## Status Atual (v40)
- Formulário de lançamento com split automático (acordo, honorário, alvará)
- Plano de Contas, Centro de Custo, Conta bancária
- Resumo horizontal no topo (Honorários, Repasse, Despesas)
- DRE, Fluxo de Caixa, Inadimplência, Extrato bancário
- Despesas fixas com recorrência
- Notificações push + workflows diários
- Integração DataJud/CNJ

## Bugs Conhecidos
- [x] Receber não funcionava (aspas no onclick — corrigido v40)
- [x] Duplicação ocasional ao salvar acordo (double-click guard — finGuard)
- [ ] Conciliação bancária precisa ser redesenhada

---

## Etapa 1: Estabilização ✅
1. ✅ Resumo financeiro com barra de progresso + alertas contextuais + bug fix
2. ✅ Contrato de honorários inline editável com salvamento direto
3. ✅ Parcelas: accordion por acordo + progresso visual + receber individual
4. ✅ Contas a receber geral: filtros (todos/vencidos/a vencer) + por cliente

## Etapa 2: Despesas + Custódia ✅
1. ✅ Despesas com flag reembolsável/abatível + toggle tipo + cards resumo
2. ✅ Contas a pagar geral (nova aba VF com filtros)
3. ✅ Custódia separada na apuração (bloco visual + aviso "não é receita")
4. ✅ Reembolso: marcar/desmarcar via botão + data de reembolso

## Etapa 3: Repasses ✅
1. ✅ Apuração com blocos de despesas + custódia visual separada
2. ✅ Histórico de repasses com cards (repassado/pendente/líquido) + dados bancários
3. ✅ Prestação de contas com histórico de repasses + dados bancários + WhatsApp detalhado
4. ✅ Gerar repasse com dados bancários + comprovante auto-copiado + andamento na pasta

## Etapa 4: Caixa + DRE + Relatórios
1. Caixa real por conta bancária (Inter, CEF, Dinheiro)
2. DRE gerencial com plano de contas real
3. Relatórios: inadimplência, receita por cliente/área, fluxo
4. Logs de alterações financeiras
5. Automações (despesa recorrente, status automático por vencimento)

---

## Estrutura de Dados Proposta (futuro)
```
lancamento_financeiro {
  id, tipo, subtipo, direcao,
  cliente, processo, contrato,
  desc, valor_bruto, valor_liquido,
  plano_contas, centro_custo, conta_bancaria,
  data_competencia, data_vencimento, data_pagamento,
  forma_pagamento, status,
  parcelas: [{n, valor, venc, pago, dt_baixa}],
  repasse: {valor, pago, venc, conta_destino},
  parceiro: {nome, perc, valor},
  obs, responsavel, log[]
}
```

## Regras de Negócio
- Custódia NÃO é receita operacional
- Repasse só com vínculo a cliente+processo
- Recebimento parcial mantém saldo pendente
- Honorários separados por categoria (contratual, êxito, sucumbência)
- Caixa real = só lançamentos efetivamente compensados
- Toda alteração gera log
- Despesas recorrentes clonadas automaticamente por competência
