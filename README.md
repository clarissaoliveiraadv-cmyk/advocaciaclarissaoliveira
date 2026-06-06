# Sistema de Gestão Financeira — Advocacia Clarissa Oliveira

Sistema web para substituir e aprimorar a planilha Excel de controle de caixa, recebíveis, ressarcimentos, parcerias e sucumbência do escritório.

Baseado na **Especificação Funcional** (documento `ESPECI1.DOC`).

## Stack

- **Next.js 15** (App Router) + **React 19** + **TypeScript** strict
- **Tailwind CSS** + **shadcn/ui** (Radix UI primitives)
- **Prisma** ORM + **PostgreSQL**
- **Auth.js v5** (NextAuth) — login por credenciais, perfis (`ADMIN`, `SOCIA`, `SECRETARIA`, `PARCEIRO_LEITURA`)
- **React Hook Form + Zod** — validação única para form e Server Actions
- **Vitest** (unit) — Playwright entra na Slice 2
- **ESLint + Prettier + Husky + lint-staged** — pre-commit obrigatório

## Documentação arquitetural

- [`docs/arquitetura-financeira.md`](./docs/arquitetura-financeira.md) — premissas das 3 camadas (Lançamento / Recebível / Distribuição), regra "sistema sugere, usuário confirma", beneficiários de distribuição
- [`docs/CONVENCOES.md`](./docs/CONVENCOES.md) — regras de código (vertical slices, limites de tamanho, sem `any`, etc.)

## Setup

```bash
# 1. Dependências
npm install

# 2. Variáveis de ambiente
cp .env.example .env
#   - DATABASE_URL apontando para um Postgres (local via Docker, Neon, Supabase ou Railway)
#   - AUTH_SECRET: gerar com `openssl rand -base64 32`

# 3. Banco
npm run db:push       # cria as tabelas
npm run db:seed       # cria admin + contas + categorias padrão

# 4. Rodar
npm run dev
```

Acesse http://localhost:3000 — login inicial: `clarissaoliveira.adv@gmail.com` / senha `trocar-em-producao` (trocar imediatamente).

## Estrutura

```
src/
  app/
    (app)/            # área autenticada (layout com sidebar)
      dashboard/      # painel inicial
      movimento/      # módulo Movimento de Caixa
      recebiveis/     # módulo Recebíveis
      ressarcimentos/
      parcerias/
      sucumbencia/
      clientes/  processos/  cadastros/  relatorios/
    login/
    api/auth/         # rotas do Auth.js
  auth.ts             # config do Auth.js
  middleware.ts       # protege rotas (auth.callbacks.authorized)
  lib/prisma.ts
prisma/
  schema.prisma       # modelo de dados (§10 da especificação)
  seed.ts             # dados iniciais
```

## Comandos

```bash
npm run dev          # servidor local
npm run lint         # ESLint
npm run typecheck    # tsc --noEmit
npm test             # vitest (watch)
npm test -- --run    # vitest (single run)
npm run format       # prettier --write
npm run build        # next build (validação completa)
npm run db:push      # sincroniza schema com o banco
npm run db:seed      # popular admin + contas + categorias
```

## Roadmap

### Slice 0 — Fundação ✅
- Auth.js v5 + perfis, guards de permissão
- shadcn/ui (Button, Input, Form, Card, Table, Dialog, Select, Sonner)
- Helpers monetários (`src/lib/money.ts`) com testes
- Helper de auditoria (`src/lib/audit.ts`)
- ESLint + Prettier + Husky + lint-staged
- Vitest configurado
- CI (lint + typecheck + test + build em PRs)
- Estrutura de módulos (`src/modules/`)
- Docs arquiteturais (3 camadas + "sistema sugere, usuário confirma")

### Slice 1 — Cadastros essenciais (próximo)
Clientes → Processos → Contas → Categorias → Parceiros (um PR por entidade).

### Slice 2 — Movimento de Caixa
CRUD + filtros (mês/conta/categoria) + transferência entre contas (2 lançamentos vinculados) + saldo por conta.

### Slice 3 — Recebíveis Jurídicos
Inclui introdução do modelo `Distribuicao` / `ItemDistribuicao` (3ª camada).
"Marcar recebido" → tela de revisão da distribuição sugerida → usuário confirma → gera lançamentos.

### Slice 4 — Prestação de Contas
Demonstrativo por processo: valor recebido, honorários, sucumbência, perito, parceiro, ressarcimento, repasse líquido.

### Slice 5 — Dashboard real
Saldos por conta calculados de `Lancamento`, faturamento líquido do mês, gráficos.

### Fase 2 — Parcerias e Sucumbência
- [ ] Parceria Pagável
- [ ] Parceria Cível (Vivian)
- [ ] Sucumbência 34/33/33 + Saldo Fundo (VIEW cumulativa)
- [ ] Relatórios de repasses devidos

### Fase 3 — Inteligência
- [ ] Importação OFX/CSV de extrato
- [ ] Alertas (vencimentos, inadimplência, saldo mínimo, repasses devidos)
- [ ] Auditoria completa (já modelada — tabela `auditoria`)
- [ ] Anexos com OCR
- [ ] Mobile

## Modelo de dados (resumo)

Entidades principais (ver `prisma/schema.prisma`):

- `Cliente` 1—N `Processo`
- `Processo` 1—N `Recebivel` / `Ressarcimento` / `Sucumbencia` / `ParceriaPaga`
- `Recebivel` 1—N `Lancamento` (entrada do recebimento + saída do repasse)
- `ContaBancaria` 1—N `Lancamento`
- `Categoria` 1—N `Lancamento` (hierárquica via `categoriaPaiId`)
- `Usuario` com `Perfil` (ADMIN, SOCIA, SECRETARIA, PARCEIRO_LEITURA)
- `Auditoria` registra alterações em todas as tabelas financeiras

## Legado

O app antigo (single-page HTML + bundle.js) foi movido para `/legacy/` apenas como referência. Não faz mais parte do build.
