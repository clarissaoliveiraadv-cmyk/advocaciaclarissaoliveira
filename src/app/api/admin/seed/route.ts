import { NextResponse } from "next/server";
import { Perfil, TipoCategoria, TipoConta } from "@prisma/client";
import bcrypt from "bcryptjs";
import { prisma } from "@/lib/prisma";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

/**
 * Endpoint one-shot para popular o banco após o primeiro deploy.
 *
 * Protegido por header `X-Seed-Token` que deve bater com a env `SEED_TOKEN`
 * (definida no Vercel). Idempotente — pode ser chamado várias vezes sem
 * duplicar dados.
 *
 * Uso (após o deploy):
 *   curl -X POST https://SEU-APP.vercel.app/api/admin/seed \
 *        -H "X-Seed-Token: <valor de SEED_TOKEN>"
 */
export async function POST(request: Request) {
  const seedToken = process.env.SEED_TOKEN;
  if (!seedToken) {
    return NextResponse.json(
      { ok: false, error: "SEED_TOKEN não configurado no servidor." },
      { status: 500 },
    );
  }
  const providedToken = request.headers.get("x-seed-token");
  if (providedToken !== seedToken) {
    return NextResponse.json({ ok: false, error: "Token inválido" }, { status: 401 });
  }

  const url = new URL(request.url);
  const senha = url.searchParams.get("senha") ?? "trocar-em-producao";

  // 1. Usuário admin
  const senhaHash = await bcrypt.hash(senha, 10);
  const admin = await prisma.usuario.upsert({
    where: { email: "clarissaoliveira.adv@gmail.com" },
    update: {},
    create: {
      nome: "Clarissa Oliveira",
      email: "clarissaoliveira.adv@gmail.com",
      senhaHash,
      perfil: Perfil.ADMIN,
    },
  });

  // 2. Contas bancárias
  const contas = [
    { codigo: "INTER_PJ", nome: "Banco Inter PJ", tipo: TipoConta.CONTA_CORRENTE, banco: "Banco Inter" },
    {
      codigo: "INTER_PF",
      nome: "Inter PF / Cora",
      tipo: TipoConta.CONTA_CORRENTE,
      banco: "Banco Inter / Cora",
    },
    { codigo: "DIN", nome: "Caixa Físico", tipo: TipoConta.CAIXA_FISICO, banco: null },
  ];
  for (const c of contas) {
    await prisma.contaBancaria.upsert({ where: { codigo: c.codigo }, update: {}, create: c });
  }

  // 3. Categorias padrão (sem upsert pelo compound unique com NULL, usamos findFirst+create)
  const categorias: Array<{ nome: string; tipo: TipoCategoria; isPessoal?: boolean }> = [
    { nome: "Ressarcir", tipo: TipoCategoria.DESPESA },
    { nome: "Salário/Honorário", tipo: TipoCategoria.DESPESA },
    { nome: "Fixo", tipo: TipoCategoria.DESPESA },
    { nome: "Consumo/Insumo", tipo: TipoCategoria.DESPESA },
    { nome: "Pessoal", tipo: TipoCategoria.DESPESA, isPessoal: true },
    { nome: "Honorário Contratual", tipo: TipoCategoria.RECEITA },
    { nome: "Honorário Sucumbência", tipo: TipoCategoria.RECEITA },
    { nome: "Ressarcimento Recebido", tipo: TipoCategoria.RECEITA },
  ];
  for (const cat of categorias) {
    const existing = await prisma.categoria.findFirst({
      where: { nome: cat.nome, categoriaPaiId: null },
    });
    if (!existing) await prisma.categoria.create({ data: cat });
  }

  return NextResponse.json({
    ok: true,
    adminEmail: admin.email,
    senhaPadrao: senha === "trocar-em-producao" ? "trocar-em-producao (TROQUE AGORA)" : "(custom)",
    contasCadastradas: contas.length,
    categoriasCadastradas: categorias.length,
  });
}
