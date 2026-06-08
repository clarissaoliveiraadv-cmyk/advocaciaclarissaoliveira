import { NextResponse } from "next/server";
import bcrypt from "bcryptjs";
import { prisma } from "@/lib/prisma";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

/**
 * Endpoint para resetar a senha de um usuário usando o SEED_TOKEN como
 * autorização. Útil quando a senha foi perdida e ainda não há outro
 * caminho de recuperação. Use apenas em emergências.
 *
 * Uso:
 *   curl -X POST 'https://SEU-APP.vercel.app/api/admin/reset-senha?email=foo@bar.com&senha=NOVA' \
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
  const provided = request.headers.get("x-seed-token");
  if (provided !== seedToken) {
    return NextResponse.json({ ok: false, error: "Token inválido" }, { status: 401 });
  }

  const url = new URL(request.url);
  const email = url.searchParams.get("email")?.trim();
  const senha = url.searchParams.get("senha");

  if (!email) {
    return NextResponse.json(
      { ok: false, error: "Parâmetro 'email' obrigatório" },
      { status: 400 },
    );
  }
  if (!senha || senha.length < 6) {
    return NextResponse.json(
      { ok: false, error: "Parâmetro 'senha' obrigatório (mínimo 6 caracteres)" },
      { status: 400 },
    );
  }

  const usuario = await prisma.usuario.findUnique({ where: { email } });
  if (!usuario) {
    return NextResponse.json({ ok: false, error: "Usuário não encontrado" }, { status: 404 });
  }

  const senhaHash = await bcrypt.hash(senha, 10);
  await prisma.usuario.update({ where: { id: usuario.id }, data: { senhaHash } });

  return NextResponse.json({
    ok: true,
    email: usuario.email,
    perfil: usuario.perfil,
    mensagem: "Senha redefinida com sucesso.",
  });
}
