"use server";

import { revalidatePath } from "next/cache";
import { AcaoAuditoria, Prisma } from "@prisma/client";
import { prisma } from "@/lib/prisma";
import { registrarAuditoria } from "@/lib/audit";
import { PERFIS_ESCRITA, requirePerfil } from "@/lib/auth/guards";
import { fromPercent } from "@/lib/money";
import type { ActionResult } from "@/modules/_shared/types";
import {
  parceiroCreateSchema,
  parceiroUpdateSchema,
  type ParceiroCreateInput,
  type ParceiroUpdateInput,
} from "./schema";
import { parceiroTemDependencias } from "./queries";

const RESOURCE = "advogado_parceiro";
const ROUTE = "/cadastros/parceiros";

export async function criarParceiro(
  input: ParceiroCreateInput,
): Promise<ActionResult<{ id: string }>> {
  const session = await requirePerfil(PERFIS_ESCRITA);
  const parsed = parceiroCreateSchema.safeParse(input);
  if (!parsed.success)
    return {
      ok: false,
      error: "Dados inválidos",
      fieldErrors: parsed.error.flatten().fieldErrors,
    };

  const data = toDbData(parsed.data);
  const parceiro = await prisma.advogadoParceiro.create({ data });

  await registrarAuditoria({
    entidade: RESOURCE,
    entidadeId: parceiro.id,
    acao: AcaoAuditoria.CRIAR,
    usuarioId: session.user.id,
    dadosDepois: serializarAudit(data),
  });

  revalidatePath(ROUTE);
  return { ok: true, data: { id: parceiro.id } };
}

export async function atualizarParceiro(input: ParceiroUpdateInput): Promise<ActionResult> {
  const session = await requirePerfil(PERFIS_ESCRITA);
  const parsed = parceiroUpdateSchema.safeParse(input);
  if (!parsed.success)
    return {
      ok: false,
      error: "Dados inválidos",
      fieldErrors: parsed.error.flatten().fieldErrors,
    };

  const { id, ...rest } = parsed.data;
  const antes = await prisma.advogadoParceiro.findUnique({ where: { id } });
  if (!antes) return { ok: false, error: "Parceiro não encontrado" };

  const data = toDbData(rest);
  await prisma.advogadoParceiro.update({ where: { id }, data });

  await registrarAuditoria({
    entidade: RESOURCE,
    entidadeId: id,
    acao: AcaoAuditoria.ATUALIZAR,
    usuarioId: session.user.id,
    dadosAntes: serializarAudit({
      nome: antes.nome,
      tipo: antes.tipo,
      oab: antes.oab,
      percentualPadraoSucumbencia: antes.percentualPadraoSucumbencia,
    }),
    dadosDepois: serializarAudit(data),
  });

  revalidatePath(ROUTE);
  return { ok: true, data: undefined };
}

export async function alternarAtivoParceiro(id: string): Promise<ActionResult> {
  const session = await requirePerfil(PERFIS_ESCRITA);
  const antes = await prisma.advogadoParceiro.findUnique({ where: { id } });
  if (!antes) return { ok: false, error: "Parceiro não encontrado" };

  await prisma.advogadoParceiro.update({ where: { id }, data: { ativo: !antes.ativo } });
  await registrarAuditoria({
    entidade: RESOURCE,
    entidadeId: id,
    acao: AcaoAuditoria.ATUALIZAR,
    usuarioId: session.user.id,
    dadosAntes: { ativo: antes.ativo },
    dadosDepois: { ativo: !antes.ativo },
  });
  revalidatePath(ROUTE);
  return { ok: true, data: undefined };
}

export async function excluirParceiro(id: string): Promise<ActionResult> {
  const session = await requirePerfil(PERFIS_ESCRITA);
  const antes = await prisma.advogadoParceiro.findUnique({ where: { id } });
  if (!antes) return { ok: false, error: "Parceiro não encontrado" };

  const deps = await parceiroTemDependencias(id);
  const motivos: string[] = [];
  if (deps.recebiveis > 0) motivos.push(`${deps.recebiveis} recebível(is)`);
  if (deps.parcerias > 0) motivos.push(`${deps.parcerias} acordo(s) de parceria`);
  if (deps.sucumbencias > 0) motivos.push(`${deps.sucumbencias} sucumbência(s)`);
  if (motivos.length > 0) {
    return {
      ok: false,
      error: `Parceiro possui ${motivos.join(", ")} vinculados. Inative em vez de excluir.`,
    };
  }

  await prisma.advogadoParceiro.delete({ where: { id } });
  await registrarAuditoria({
    entidade: RESOURCE,
    entidadeId: id,
    acao: AcaoAuditoria.EXCLUIR,
    usuarioId: session.user.id,
    dadosAntes: serializarAudit({
      nome: antes.nome,
      tipo: antes.tipo,
      oab: antes.oab,
      percentualPadraoSucumbencia: antes.percentualPadraoSucumbencia,
    }),
  });
  revalidatePath(ROUTE);
  return { ok: true, data: undefined };
}

// ----- helpers -----

function toDbData(input: ParceiroCreateInput) {
  const text = (v: string | undefined) => {
    const t = v?.trim();
    return t ? t : null;
  };
  const perc = input.percentualPadraoSucumbencia?.trim();
  return {
    nome: input.nome.trim(),
    tipo: input.tipo,
    oab: text(input.oab),
    percentualPadraoSucumbencia: perc ? fromPercent(perc) : null,
  };
}

function serializarAudit(data: Record<string, unknown>): Prisma.InputJsonValue {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(data)) {
    out[k] = v instanceof Prisma.Decimal ? v.toString() : (v ?? null);
  }
  return out as Prisma.InputJsonValue;
}
