# Convenções de Código

Regras duras para evitar o sistema virar monolito.

## Limites de tamanho

- **Máx 250 linhas por arquivo** (sinaliza fragmentar).
- **Máx 40 linhas por função** (sinaliza extrair).
- Componente React: máx 1 por arquivo (excetuam-se subcomponentes triviais).

## Vertical slices

Cada módulo de domínio mora em `src/modules/<modulo>/`:

```
modules/<modulo>/
  schema.ts        # Zod schemas + tipos derivados
  queries.ts       # leituras Prisma (Server Components consomem)
  actions.ts       # Server Actions (mutações)
  components/      # UI específica do módulo
```

- **Rotas em `src/app/`** são finas: só importam e compõem.
- **Promoção para shared:** só se usado em >2 módulos. Caso contrário, fica local.

## TypeScript

- `strict: true` (já está).
- **Sem `any`.** Use `unknown` + narrowing, ou tipo concreto.
- **Sem `@ts-ignore` / `@ts-expect-error`** (exceto com comentário explicando bug externo).
- **Sem `as` casts** entre tipos não-relacionados. Use Zod parse ou narrowing.

## Server vs Client

- Server Components por padrão.
- `"use client"` apenas em arquivos que precisam de hooks/eventos.
- Formulários: client (RHF + Zod) → submetem para Server Action.

## Validação

- **Zod é a fonte única de verdade.** O mesmo schema valida o form e a Server Action.
- Server Actions sempre validam input com `schema.safeParse(input)` antes de tocar o banco.

## Estilo

- Tailwind via classes utilitárias + tokens shadcn (`bg-background`, `text-foreground` etc.). Sem cores cruas.
- Componentes acessíveis: usar primitivos shadcn/Radix.

## Comentários

- Não comente "o quê" — o código já diz. Comente apenas "porquê não-óbvio".
- **Sem comentários decorativos** (`// ===== SECTION =====`).

## Commits

- Português curto, voz ativa. Ex: `feat(clientes): CRUD com validação Zod`.
- Um commit = uma intenção.

## Testes

- `src/lib/**` → testes unitários (Vitest) obrigatórios para helpers monetários e auditoria.
- `src/modules/**/actions.ts` → testes unitários quando contêm regras de negócio (cálculo de distribuição etc.).
- Smoke E2E (Playwright) entra em Slice 2+.
