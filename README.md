# Sistema de Gestão Financeira — Advocacia Clarissa Oliveira

Sistema web para substituir e aprimorar a planilha Excel de controle de caixa, recebíveis, ressarcimentos, parcerias e sucumbência do escritório.

Baseado na **Especificação Funcional** (documento `ESPECI1.DOC`).

## Stack

- **Next.js 15** (App Router) + **React 19** + **TypeScript**
- **Tailwind CSS**
- **Prisma** ORM + **PostgreSQL**
- **Auth.js v5** (NextAuth) — login por credenciais, perfis (`ADMIN`, `SOCIA`, `SECRETARIA`, `PARCEIRO_LEITURA`)

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

## Roadmap (conforme §13 da especificação)

### Fase 1 — MVP (reposição da planilha)
- [x] Schema relacional cobrindo todas as entidades
- [x] Login + perfis
- [x] Layout / navegação
- [ ] CRUD Clientes / Processos / Categorias / Parceiros / Contas
- [ ] Movimento de Caixa (CRUD + filtros + totalizadores)
- [ ] Recebíveis (CRUD + transição PREVISTA → RECEBIDA → REPASSADA)
- [ ] Vinculação automática Recebível → Lançamento (eliminar duplo lançamento)
- [ ] Ressarcimentos
- [ ] Dashboard com saldos por conta e faturamento mensal

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
