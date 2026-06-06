# Deploy no Vercel + Neon (gratuito)

Guia passo a passo. **Não precisa de Node/npm na sua máquina** — tudo é feito pelo navegador.

Tempo estimado: 10 minutos.

---

## Etapa 1 — Criar banco de dados Postgres (Neon)

1. Acesse https://neon.tech e clique em **"Sign up"** (pode usar sua conta Google ou GitHub).
2. Escolha a opção gratuita (**Free plan**).
3. Crie um novo projeto:
   - Project name: `advocacia-clarissa`
   - Postgres version: `16` (padrão)
   - Region: `AWS - US East (Ohio)` (mais barato; latência ainda boa para o Brasil)
4. Após criar, copie a **connection string** que aparece na tela. Ela é parecida com:
   ```
   postgresql://NEONUSER:SENHA@ep-xxxx.region.aws.neon.tech/neondb?sslmode=require
   ```
5. Guarde essa string — você vai colá-la no Vercel.

---

## Etapa 2 — Criar conta no Vercel e importar o repositório

1. Acesse https://vercel.com e faça login com **GitHub** (mesmo usuário que tem este repositório).
2. No dashboard, clique em **"Add New..."** → **"Project"**.
3. Encontre o repositório `advocaciaclarissaoliveira` na lista e clique em **"Import"**.
4. Na tela de configuração:
   - **Framework Preset**: já deve aparecer como **Next.js** ✓
   - **Root Directory**: deixe `./` (padrão)
   - **Build Command**: deixe vazio para usar o automático (`vercel-build` do `package.json`)
5. **NÃO clique em Deploy ainda** — primeiro adicione as variáveis de ambiente abaixo.

---

## Etapa 3 — Adicionar variáveis de ambiente

Ainda na tela de configuração do projeto, expanda **"Environment Variables"** e adicione **três** variáveis:

| Nome             | Valor                                                                 |
| ---------------- | --------------------------------------------------------------------- |
| `DATABASE_URL`   | A connection string que você copiou do Neon (Etapa 1, passo 4)       |
| `AUTH_SECRET`    | Gere uma string aleatória aqui: https://generate-secret.vercel.app/32 |
| `SEED_TOKEN`     | Outra string aleatória do mesmo site (qualquer 32+ caracteres)        |

Marque as 3 como disponíveis em **Production**, **Preview** e **Development**.

Depois clique em **"Deploy"**.

---

## Etapa 4 — Aguardar o build

O Vercel vai:
1. Rodar `npm install` (≈30s)
2. Rodar `vercel-build` que aplica a migração no Neon e compila o Next.js (≈1min)
3. Publicar em uma URL `https://NOME-DO-PROJETO.vercel.app`

Se aparecer erro de build, verifique nas configurações do projeto se as 3 variáveis estão presentes.

---

## Etapa 5 — Popular dados iniciais (admin + contas + categorias)

Após o build verde, abra o terminal do seu navegador (F12 → aba **Console**) e cole **substituindo** os valores:

```js
fetch("https://SEU-PROJETO.vercel.app/api/admin/seed", {
  method: "POST",
  headers: { "X-Seed-Token": "COLE-AQUI-O-VALOR-DE-SEED_TOKEN" }
})
  .then(r => r.json())
  .then(console.log);
```

Resposta esperada:
```json
{
  "ok": true,
  "adminEmail": "clarissaoliveira.adv@gmail.com",
  "senhaPadrao": "trocar-em-producao (TROQUE AGORA)",
  "contasCadastradas": 3,
  "categoriasCadastradas": 8
}
```

Se quiser usar outra senha já no seed inicial, acrescente `?senha=SUA_SENHA`:
```
https://SEU-PROJETO.vercel.app/api/admin/seed?senha=MinhaSenh@Forte
```

---

## Etapa 6 — Primeiro login

1. Acesse `https://SEU-PROJETO.vercel.app/login`
2. E-mail: `clarissaoliveira.adv@gmail.com`
3. Senha: a que você escolheu (ou `trocar-em-producao` se não escolheu)

Pronto.

---

## Sobre segurança

- **Troque a senha** assim que entrar. (Por ora, isso requer acesso ao banco; uma tela de "trocar senha" pode entrar num próximo slice.)
- **Remova ou rotacione `SEED_TOKEN`** após o primeiro seed para evitar abuso.
- O `AUTH_SECRET` nunca deve ser commitado nem compartilhado.

## O que cada commit no GitHub vai fazer

A partir daqui, todo `git push` na branch principal dispara um redeploy automático no Vercel. Migrações novas (`prisma migrate dev --name xxx` localmente, commitadas em `prisma/migrations/`) são aplicadas automaticamente no Neon via `prisma migrate deploy` no build.
