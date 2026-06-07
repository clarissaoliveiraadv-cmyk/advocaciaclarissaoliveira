"use server";

import { revalidatePath } from "next/cache";
import { AcaoAuditoria, Prisma } from "@prisma/client";
import { prisma } from "@/lib/prisma";
import { registrarAuditoria } from "@/lib/audit";
import { requirePerfil } from "@/lib/auth/guards";
import { fromPercent } from "@/lib/money";
import type { ActionResult } from "@/modules/_shared/types";
import {
  marcarRepasseSchema,
  sucumbenciaCreateSchema,
  sucumbenciaUpdateSchema,
  type MarcarRepasseInput,
  type SucumbenciaCreateInput,
  type SucumbenciaUpdateInput,
} from "./schema";

const PERFIS_ESCRITA = ["ADMIN", "SOCIA", "SECRETARIA"] as const;
const RESOURCE = "sucumbencia";
const ROUTE = "/sucumbencia";

type ActionError = { ok: false; error: string; fieldErrors?: Record<string, string[]> };

export async function criarSucumbencia(
  input: SucumbenciaCreateInput,
): Promise<ActionResult<{ id: string }>> {
  const session = await requirePerfil(PERFIS_ESCRITA);
  const parsed = sucumbenciaCreateSchema.safeParse(input);
  if (!parsed.success)
    return {
      ok: false,
      error: "Dados inválidos",
      fieldErrors: parsed.error.flatten().fieldErrors,
    };

  const proc = await prisma.processo.findUnique({
    where: { id: parsed.data.processoId },
    select: { id: true, clienteId: true },
  });
  if (!proc) return { ok: false, error: "Processo não encontrado" };

  const erroParceiro = await validarParceiro(parsed.data.parceiroExternoId);
  if (erroParceiro) return erroParceiro;

  const data = toDbData(parsed.data, proc.clienteId);
  const suc = await prisma.sucumbencia.create({ data });

  await registrarAuditoria({
    entidade: RESOURCE,
    entidadeId: suc.id,
    acao: AcaoAuditoria.CRIAR,
    usuarioId: session.user.id,
    dadosDepois: serializarAudit(data),
  });

  revalidatePath(ROUTE);
  return { ok: true, data: { id: suc.id } };
}

export async function atualizarSucumbencia(input: SucumbenciaUpdateInput): Promise<ActionResult> {
  const session = await requirePerfil(PERFIS_ESCRITA);
  const parsed = sucumbenciaUpdateSchema.safeParse(input);
  if (!parsed.success)
    return {
      ok: false,
      error: "Dados inválidos",
      fieldErrors: parsed.error.flatten().fieldErrors,
    };

  const { id, ...rest } = parsed.data;
  const antes = await prisma.sucumbencia.findUnique({ where: { id } });
  if (!antes) return { ok: false, error: "Sucumbência não encontrada" };

  const proc = await prisma.processo.findUnique({
    where: { id: rest.processoId },
    select: { clienteId: true },
  });
  if (!proc) return { ok: false, error: "Processo não encontrado" };

  const erroParceiro = await validarParceiro(rest.parceiroExternoId);
  if (erroParceiro) return erroParceiro;

  const data = toDbData(rest, proc.clienteId);
  await prisma.sucumbencia.update({ where: { id }, data });

  await registrarAuditoria({
    entidade: RESOURCE,
    entidadeId: id,
    acao: AcaoAuditoria.ATUALIZAR,
    usuarioId: session.user.id,
    dadosAntes: serializarAudit(snapshot(antes)),
    dadosDepois: serializarAudit(data),
  });

  revalidatePath(ROUTE);
  return { ok: true, data: undefined };
}

export async function marcarRepasse(input: MarcarRepasseInput): Promise<ActionResult> {
  const session = await requirePerfil(PERFIS_ESCRITA);
  const parsed = marcarRepasseSchema.safeParse(input);
  if (!parsed.success)
    return {
      ok: false,
      error: "Dados inválidos",
      fieldErrors: parsed.error.flatten().fieldErrors,
    };

  const antes = await prisma.sucumbencia.findUnique({ where: { id: parsed.data.id } });
  if (!antes) return { ok: false, error: "Sucumbência não encontrada" };

  const campo = parsed.data.socia === "clarissa" ? "dataRepasseClarissa" : "dataRepasseVivian";
  if (antes[campo]) {
    return { ok: false, error: `Repasse para ${parsed.data.socia} já registrado.` };
  }

  const dataRepasse = new Date(`${parsed.data.data}T00:00:00.000Z`);
  await prisma.sucumbencia.update({
    where: { id: parsed.data.id },
    data: { [campo]: dataRepasse },
  });

  await registrarAuditoria({
    entidade: RESOURCE,
    entidadeId: parsed.data.id,
    acao: AcaoAuditoria.ATUALIZAR,
    usuarioId: session.user.id,
    dadosAntes: { [campo]: null },
    dadosDepois: { [campo]: dataRepasse.toISOString() },
  });

  revalidatePath(ROUTE);
  return { ok: true, data: undefined };
}

export async function reverterRepasse(
  id: string,
  socia: "clarissa" | "vivian",
): Promise<ActionResult> {
  const session = await requirePerfil(PERFIS_ESCRITA);
  const antes = await prisma.sucumbencia.findUnique({ where: { id } });
  if (!antes) return { ok: false, error: "Sucumbência não encontrada" };

  const campo = socia === "clarissa" ? "dataRepasseClarissa" : "dataRepasseVivian";
  if (!antes[campo]) {
    return { ok: false, error: `Repasse para ${socia} ainda não foi feito.` };
  }

  await prisma.sucumbencia.update({ where: { id }, data: { [campo]: null } });

  await registrarAuditoria({
    entidade: RESOURCE,
    entidadeId: id,
    acao: AcaoAuditoria.ATUALIZAR,
    usuarioId: session.user.id,
    dadosAntes: { [campo]: antes[campo]?.toISOString() ?? null },
    dadosDepois: { [campo]: null },
  });

  revalidatePath(ROUTE);
  return { ok: true, data: undefined };
}

export async function excluirSucumbencia(id: string): Promise<ActionResult> {
  const session = await requirePerfil(PERFIS_ESCRITA);
  const antes = await prisma.sucumbencia.findUnique({ where: { id } });
  if (!antes) return { ok: false, error: "Sucumbência não encontrada" };

  await prisma.sucumbencia.delete({ where: { id } });

  await registrarAuditoria({
    entidade: RESOURCE,
    entidadeId: id,
    acao: AcaoAuditoria.EXCLUIR,
    usuarioId: session.user.id,
    dadosAntes: serializarAudit(snapshot(antes)),
  });

  revalidatePath(ROUTE);
  return { ok: true, data: undefined };
}

// ----- helpers -----

async function validarParceiro(parceiroId: string | undefined): Promise<ActionError | null> {
  const id = parceiroId?.trim();
  if (!id) return null;
  const p = await prisma.advogadoParceiro.findUnique({
    where: { id },
    select: { ativo: true },
  });
  if (!p) {
    return {
      ok: false,
      error: "Parceiro externo não encontrado",
      fieldErrors: { parceiroExternoId: ["Parceiro inexistente"] },
    };
  }
  if (!p.ativo) {
    return {
      ok: false,
      error: "Parceiro externo está inativo",
      fieldErrors: { parceiroExternoId: ["Parceiro inativo"] },
    };
  }
  return null;
}

function toDbData(
  input: Omit<SucumbenciaCreateInput, never>,
  clienteId: string,
) {
  const text = (v: string | undefined) => {
    const t = v?.trim();
    return t ? t : null;
  };
  const parcId = input.parceiroExternoId?.trim() || null;
  const percParc = input.percParceiroExterno?.trim();
  return {
    processoId: input.processoId,
    clienteId,
    valorTotal: new Prisma.Decimal(input.valorTotal),
    dataRecebimento: new Date(`${input.dataRecebimento}T00:00:00.000Z`),
    parceiroExternoId: parcId,
    percParceiroExterno: parcId && percParc ? fromPercent(percParc) : null,
    percEscritorio: fromPercent(input.percEscritorio),
    percClarissa: fromPercent(input.percClarissa),
    percVivian: fromPercent(input.percVivian),
    observacoes: text(input.observacoes),
  };
}

function snapshot(s: {
  processoId: string;
  clienteId: string;
  valorTotal: Prisma.Decimal;
  dataRecebimento: Date;
  parceiroExternoId: string | null;
  percParceiroExterno: Prisma.Decimal | null;
  percEscritorio: Prisma.Decimal;
  percClarissa: Prisma.Decimal;
  percVivian: Prisma.Decimal;
  dataRepasseClarissa: Date | null;
  dataRepasseVivian: Date | null;
  observacoes: string | null;
}) {
  return { ...s };
}

type AuditSerialized = Record<string, string | number | boolean | null>;

function serializarAudit(data: Record<string, unknown>): AuditSerialized {
  const out: AuditSerialized = {};
  for (const [k, v] of Object.entries(data)) {
    if (v instanceof Prisma.Decimal) out[k] = v.toString();
    else if (v instanceof Date) out[k] = v.toISOString();
    else if (v === undefined || v === null) out[k] = null;
    else if (typeof v === "string" || typeof v === "number" || typeof v === "boolean") out[k] = v;
    else out[k] = String(v);
  }
  return out;
}
