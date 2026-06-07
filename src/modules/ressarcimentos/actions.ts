"use server";

import { revalidarCaixa } from "@/lib/cache";
import { AcaoAuditoria, Prisma, StatusRessarcimento } from "@prisma/client";
import { prisma } from "@/lib/prisma";
import { registrarAuditoria } from "@/lib/audit";
import { PERFIS_ESCRITA, requirePerfil } from "@/lib/auth/guards";
import type { ActionResult } from "@/modules/_shared/types";
import {
  marcarReembolsadoSchema,
  ressarcimentoCreateSchema,
  ressarcimentoUpdateSchema,
  type MarcarReembolsadoInput,
  type RessarcimentoCreateInput,
  type RessarcimentoUpdateInput,
} from "./schema";

const RESOURCE = "ressarcimento";

export async function criarRessarcimento(
  input: RessarcimentoCreateInput,
): Promise<ActionResult<{ id: string }>> {
  const session = await requirePerfil(PERFIS_ESCRITA);
  const parsed = ressarcimentoCreateSchema.safeParse(input);
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

  const data = toDbData(parsed.data, proc.clienteId);
  const ressarc = await prisma.ressarcimento.create({ data });

  await registrarAuditoria({
    entidade: RESOURCE,
    entidadeId: ressarc.id,
    acao: AcaoAuditoria.CRIAR,
    usuarioId: session.user.id,
    dadosDepois: serializarAudit(data),
  });

  revalidarCaixa();
  return { ok: true, data: { id: ressarc.id } };
}

export async function atualizarRessarcimento(
  input: RessarcimentoUpdateInput,
): Promise<ActionResult> {
  const session = await requirePerfil(PERFIS_ESCRITA);
  const parsed = ressarcimentoUpdateSchema.safeParse(input);
  if (!parsed.success)
    return {
      ok: false,
      error: "Dados inválidos",
      fieldErrors: parsed.error.flatten().fieldErrors,
    };

  const { id } = parsed.data;
  const antes = await prisma.ressarcimento.findUnique({ where: { id } });
  if (!antes) return { ok: false, error: "Ressarcimento não encontrado" };

  if (antes.status === StatusRessarcimento.REEMBOLSADO) {
    return {
      ok: false,
      error: "Ressarcimento já reembolsado. Reverta o reembolso antes de editar.",
    };
  }

  const proc = await prisma.processo.findUnique({
    where: { id: parsed.data.processoId },
    select: { clienteId: true },
  });
  if (!proc) return { ok: false, error: "Processo não encontrado" };

  const data = toDbData(parsed.data, proc.clienteId);
  await prisma.ressarcimento.update({ where: { id }, data });

  await registrarAuditoria({
    entidade: RESOURCE,
    entidadeId: id,
    acao: AcaoAuditoria.ATUALIZAR,
    usuarioId: session.user.id,
    dadosAntes: serializarAudit(snapshotRessarcimento(antes)),
    dadosDepois: serializarAudit(data),
  });

  revalidarCaixa();
  return { ok: true, data: undefined };
}

export async function marcarRessarcimentoReembolsado(
  input: MarcarReembolsadoInput,
): Promise<ActionResult> {
  const session = await requirePerfil(PERFIS_ESCRITA);
  const parsed = marcarReembolsadoSchema.safeParse(input);
  if (!parsed.success)
    return {
      ok: false,
      error: "Dados inválidos",
      fieldErrors: parsed.error.flatten().fieldErrors,
    };

  const antes = await prisma.ressarcimento.findUnique({ where: { id: parsed.data.id } });
  if (!antes) return { ok: false, error: "Ressarcimento não encontrado" };

  if (antes.status === StatusRessarcimento.REEMBOLSADO) {
    return { ok: false, error: "Ressarcimento já está marcado como reembolsado." };
  }

  const dataReembolso = new Date(`${parsed.data.dataReembolso}T00:00:00.000Z`);
  await prisma.ressarcimento.update({
    where: { id: parsed.data.id },
    data: { status: StatusRessarcimento.REEMBOLSADO, dataReembolso },
  });

  await registrarAuditoria({
    entidade: RESOURCE,
    entidadeId: parsed.data.id,
    acao: AcaoAuditoria.ATUALIZAR,
    usuarioId: session.user.id,
    dadosAntes: { status: antes.status, dataReembolso: null },
    dadosDepois: {
      status: StatusRessarcimento.REEMBOLSADO,
      dataReembolso: dataReembolso.toISOString(),
    },
  });

  revalidarCaixa();
  return { ok: true, data: undefined };
}

export async function reverterReembolso(id: string): Promise<ActionResult> {
  const session = await requirePerfil(PERFIS_ESCRITA);
  const antes = await prisma.ressarcimento.findUnique({ where: { id } });
  if (!antes) return { ok: false, error: "Ressarcimento não encontrado" };

  if (antes.status !== StatusRessarcimento.REEMBOLSADO) {
    return { ok: false, error: "Só é possível reverter um ressarcimento REEMBOLSADO." };
  }

  await prisma.ressarcimento.update({
    where: { id },
    data: { status: StatusRessarcimento.PAGO_PELO_ESCRITORIO, dataReembolso: null },
  });

  await registrarAuditoria({
    entidade: RESOURCE,
    entidadeId: id,
    acao: AcaoAuditoria.ATUALIZAR,
    usuarioId: session.user.id,
    dadosAntes: {
      status: antes.status,
      dataReembolso: antes.dataReembolso?.toISOString() ?? null,
    },
    dadosDepois: { status: StatusRessarcimento.PAGO_PELO_ESCRITORIO, dataReembolso: null },
  });

  revalidarCaixa();
  return { ok: true, data: undefined };
}

export async function excluirRessarcimento(id: string): Promise<ActionResult> {
  const session = await requirePerfil(PERFIS_ESCRITA);
  const antes = await prisma.ressarcimento.findUnique({ where: { id } });
  if (!antes) return { ok: false, error: "Ressarcimento não encontrado" };

  const lancamentosVinculados = await prisma.lancamento.count({
    where: { ressarcimentoId: id },
  });
  if (lancamentosVinculados > 0) {
    return {
      ok: false,
      error: "Ressarcimento possui lançamentos vinculados. Desvincule-os antes de excluir.",
    };
  }

  await prisma.ressarcimento.delete({ where: { id } });

  await registrarAuditoria({
    entidade: RESOURCE,
    entidadeId: id,
    acao: AcaoAuditoria.EXCLUIR,
    usuarioId: session.user.id,
    dadosAntes: serializarAudit(snapshotRessarcimento(antes)),
  });

  revalidarCaixa();
  return { ok: true, data: undefined };
}

// ----- helpers -----

function toDbData(input: RessarcimentoCreateInput, clienteId: string) {
  const text = (v: string | undefined) => {
    const t = v?.trim();
    return t ? t : null;
  };
  return {
    processoId: input.processoId,
    clienteId,
    data: new Date(`${input.data}T00:00:00.000Z`),
    descricao: input.descricao.trim(),
    valor: new Prisma.Decimal(input.valor),
    recebivelId: text(input.recebivelId),
  };
}

function snapshotRessarcimento(r: {
  processoId: string;
  clienteId: string;
  data: Date;
  descricao: string;
  valor: Prisma.Decimal;
  status: string;
  dataReembolso: Date | null;
  recebivelId: string | null;
}) {
  return { ...r };
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
