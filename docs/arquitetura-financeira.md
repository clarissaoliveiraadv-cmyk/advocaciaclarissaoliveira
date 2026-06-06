# Arquitetura Financeira — Premissas Estruturais

Este documento registra as **decisões arquiteturais não-negociáveis** que orientam o desenho do sistema. Toda feature deve respeitar essas três camadas e as regras associadas.

## 1. As três camadas

O sistema separa três coisas que **nunca devem ser misturadas no modelo de dados**:

### Camada 1 — Lançamento financeiro
Movimento real em uma conta bancária. Data, valor, entrada ou saída, conta, categoria.
Esta camada responde: **"O que aconteceu no caixa?"**

**Modelo:** `Lancamento`

### Camada 2 — Recebível
Valor esperado de um cliente/processo, ainda não necessariamente recebido.
Esta camada responde: **"O que está previsto entrar?"**

**Modelo:** `Recebivel` (status: `PREVISTA`, `RECEBIDA`, `REPASSADA`, `CANCELADA`)

### Camada 3 — Distribuição jurídica do valor recebido
Como o valor que entrou (associado a um recebível) se divide entre os beneficiários.
Esta camada responde: **"De quem é esse dinheiro?"**

> **Esta separação evita o erro comum de tratar "valor que entrou na conta" como se fosse "dinheiro do escritório".**

**Beneficiários possíveis em uma distribuição:**
- `CLIENTE` — valor líquido a repassar
- `ESCRITORIO_CONTRATUAL` — honorários contratuais (% do êxito)
- `ESCRITORIO_SUCUMBENCIA` — honorários sucumbenciais (quando houver)
- `PARCEIRO` — advogado parceiro / correspondente
- `PERITO` — perito calculista
- `FGTS` — quando pago fora
- `RESSARCIMENTO` — custas adiantadas pelo escritório a serem reembolsadas
- `CUSTAS` — outras custas processuais
- `OUTRO`

**Modelo (a ser introduzido na Slice 3):** `Distribuicao` (1—N) `ItemDistribuicao`.

Cada `ItemDistribuicao` tem um `status`:
- `PENDENTE_REPASSE` — falta efetuar o lançamento de saída
- `REPASSADO` — gerou o `Lancamento` de saída correspondente
- `RETIDO_CUSTODIA` — fica em custódia até instrução do cliente

## 2. Regra do "sistema sugere, usuário confirma"

**É proibido criar lançamentos automaticamente sem confirmação humana.**

Quando o usuário marca um recebível como "Recebido":
1. O sistema **calcula a distribuição sugerida** com base nos percentuais cadastrados (honorários contratuais, parceria, sucumbência).
2. Exibe uma tela de revisão com cada item da distribuição editável.
3. O usuário **ajusta** se houve exceção (pagamento parcial, custas descontadas na fonte, FGTS pago fora, sucumbência separada, depósito judicial, alvará direto ao cliente etc.).
4. O usuário **confirma**, e só então o sistema persiste a distribuição e gera os `Lancamento`s de entrada/saída necessários.

**Exceções operacionais frequentes que justificam essa regra:**
- Pagamento parcial de parcela
- Custas descontadas direto na fonte
- FGTS pago fora (não passa pela conta do escritório)
- Sucumbência separada do principal
- Acordo parcelado
- Depósito judicial liberado a prazo
- Valor bloqueado / indisponível
- Alvará emitido direto para o cliente (sem passar pela conta do escritório)

## 3. Prestação de contas é cidadão de primeira classe

A `Distribuicao` é a entidade que dá origem à prestação de contas. Para qualquer recebível recebido, deve ser possível gerar um demonstrativo no padrão:

> Processo: [número CNJ]
> Cliente: [nome]
> Valor recebido: R$ X
> Honorários contratuais: R$ X (Y%)
> Honorários sucumbenciais: R$ X
> Perito calculista: R$ X
> Parceiro [nome]: R$ X
> Ressarcimento: R$ X
> **Valor líquido repassado ao cliente: R$ X**

Esta prestação de contas é **módulo próprio** (Slice 4), não um sub-relatório do recebível.

## 4. Princípios de implementação

- **Precisão monetária:** sempre `Prisma.Decimal`, nunca `number`. Helpers em `src/lib/money.ts`.
- **Auditoria:** toda mutação em `Lancamento`, `Recebivel`, `Distribuicao`, `ItemDistribuicao` registra em `Auditoria` (helper em `src/lib/audit.ts`).
- **Idempotência:** uma `Distribuicao` confirmada não pode ser duplicada. Reabertura exige reverter a distribuição anterior.
- **Reversibilidade:** todo lançamento gerado automaticamente por uma distribuição mantém o `distribuicaoItemId` em metadados, permitindo desfazer em cascata.
