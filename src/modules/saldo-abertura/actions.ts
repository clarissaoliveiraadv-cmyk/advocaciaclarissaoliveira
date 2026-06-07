"use server";

import { AcaoAuditoria, Prisma } from "@prisma/client";
import { prisma } from "@/lib/prisma";
import { registrarAuditoria } from "@/lib/audit";
import { PERFIS_ADMIN, requirePerfil } from "@/lib/auth/guards";
import { revalidarCaixa } from "@/lib/cache";
import type { ActionResult } from "@/modules/_shared/types";
import {
  importarSaldoSchema,
  limparAberturaSchema,
  type ImportarSaldoInput,
  type LimparAberturaInput,
} from "./schema";

const RESOURCE = "conta_bancaria";

/**
 * Define saldo de abertura para um conjunto de contas. Tudo em uma
 * transação atômica: ou todas as contas são atualizadas ou nenhuma.
 */
export async function importarSaldoAbertura(
  input: ImportarSaldoInput,
): Promise<ActionResult<{ contasAtualizadas: number }>> {
  const session = await requirePerfil(PERFIS_ADMIN);
  const parsed = importarSaldoSchema.safeParse(input);
  if (!parsed.success) {
    return { ok: false, error: "Dados inválidos" };
  }

  const ids = parsed.data.itens.map((i) => i.contaId);
  const existentes = await prisma.contaBancaria.findMany({
    where: { id: { in: ids } },
    select: { id: true },
  });
  if (existentes.length !== ids.length) {
    return { ok: false, error: "Uma ou mais contas não existem." };
  }

  await prisma.$transaction(
    parsed.data.itens.map((item) =>
      prisma.contaBancaria.update({
        where: { id: item.contaId },
        data: {
          saldoInicial: new Prisma.Decimal(item.saldoInicial),
          saldoAberturaData: new Date(`${item.saldoAberturaData}T00:00:00.000Z`),
        },
      }),
    ),
  );

  await Promise.all(
    parsed.data.itens.map((item) =>
      registrarAuditoria({
        entidade: RESOURCE,
        entidadeId: item.contaId,
        acao: AcaoAuditoria.ATUALIZAR,
        usuarioId: session.user.id,
        dadosDepois: {
          saldoInicial: String(item.saldoInicial),
          saldoAberturaData: item.saldoAberturaData,
          origem: "importacao_saldo_abertura",
        },
      }),
    ),
  );

  revalidarCaixa(["/cadastros/saldo-abertura", "/cadastros/contas"]);
  return { ok: true, data: { contasAtualizadas: parsed.data.itens.length } };
}

/**
 * Remove a data de abertura de uma conta, fazendo com que o cálculo passe a
 * considerar todos os lançamentos novamente. O saldoInicial é mantido.
 */
export async function limparSaldoAbertura(input: LimparAberturaInput): Promise<ActionResult> {
  const session = await requirePerfil(PERFIS_ADMIN);
  const parsed = limparAberturaSchema.safeParse(input);
  if (!parsed.success) {
    return { ok: false, error: "Dados inválidos" };
  }

  const antes = await prisma.contaBancaria.findUnique({
    where: { id: parsed.data.contaId },
    select: { saldoAberturaData: true },
  });
  if (!antes) return { ok: false, error: "Conta não encontrada" };

  await prisma.contaBancaria.update({
    where: { id: parsed.data.contaId },
    data: { saldoAberturaData: null },
  });

  await registrarAuditoria({
    entidade: RESOURCE,
    entidadeId: parsed.data.contaId,
    acao: AcaoAuditoria.ATUALIZAR,
    usuarioId: session.user.id,
    dadosAntes: { saldoAberturaData: antes.saldoAberturaData?.toISOString() ?? null },
    dadosDepois: { saldoAberturaData: null },
  });

  revalidarCaixa(["/cadastros/saldo-abertura", "/cadastros/contas"]);
  return { ok: true, data: undefined };
}
