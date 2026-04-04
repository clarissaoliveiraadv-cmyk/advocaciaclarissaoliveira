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
- [ ] Duplicação ocasional ao salvar acordo (investigar double-click)
- [ ] Conciliação bancária precisa ser redesenhada

---

## Etapa 1: Estabilização (Próxima sessão)
1. Resumo financeiro do cliente com cards corretos
2. Contrato de honorários integrado ao lançamento
3. Parcelas: accordion funcional, receber por parcela
4. Contas a receber geral: listagem com filtros

## Etapa 2: Despesas + Custódia
1. Despesas do cliente com flag reembolsável/abatível
2. Contas a pagar geral
3. Custódia de clientes (separar de receita operacional)
4. Reembolso: despesa gera receita automática

## Etapa 3: Repasses
1. Apuração de repasse (memória de cálculo)
2. Histórico de repasses por cliente
3. Prestação de contas (modelo copiável WhatsApp)
4. Registro de transferência com conta destino

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
