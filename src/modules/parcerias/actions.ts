"use server";

import { revalidarCaixa } from "@/lib/cache";
import { AcaoAuditoria, Prisma } from "@prisma/client";
import { prisma } from "@/lib/prisma";
import { registrarAuditoria } from "@/lib/audit";
import { PERFIS_ESCRITA, requirePerfil } from "@/lib/auth/guards";
import { fromPercent } from "@/lib/money";
import type { ActionResult } from "@/modules/_shared/types";
import {
  marcarParceriaPagaSchema,
  parceriaCreateSchema,
  parceriaUpdateSchema,
  type MarcarParceriaPagaInput,
  type ParceriaCreateInput,
  type ParceriaUpdateInput,
} from "./schema";

const RESOURCE = "parceria_paga";

type ActionError = { ok: false; error: string; fieldErrors?: Record<string, string[]> };

export async function criarParceria(
  input: ParceriaCreateInput,
): Promise<ActionResult<{ id: string }>> {
  const session = await requirePerfil(PERFIS_ESCRITA);
  const parsed = parceriaCreateSchema.safeParse(input);
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

  const erroParceiro = await validarParceiro(parsed.data.parceiroId);
  if (erroParceiro) return erroParceiro;

  const data = toDbData(parsed.data, proc.clienteId);
  const parceria = await prisma.parceriaPaga.create({ data });

  await registrarAuditoria({
    entidade: RESOURCE,
    entidadeId: parceria.id,
    acao: AcaoAuditoria.CRIAR,
    usuarioId: session.user.id,
    dadosDepois: serializarAudit(data),
  });

  revalidarCaixa();
  return { ok: true, data: { id: parceria.id } };
}

export async function atualizarParceria(input: ParceriaUpdateInput): Promise<ActionResult> {
  const session = await requirePerfil(PERFIS_ESCRITA);
  const parsed = parceriaUpdateSchema.safeParse(input);
  if (!parsed.success)
    return {
      ok: false,
      error: "Dados inválidos",
      fieldErrors: parsed.error.flatten().fieldErrors,
    };

  const { id } = parsed.data;
  const antes = await prisma.parceriaPaga.findUnique({ where: { id } });
  if (!antes) return { ok: false, error: "Parceria não encontrada" };

  const proc = await prisma.processo.findUnique({
    where: { id: parsed.data.processoId },
    select: { clienteId: true },
  });
  if (!proc) return { ok: false, error: "Processo não encontrado" };

  const erroParceiro = await validarParceiro(parsed.data.parceiroId);
  if (erroParceiro) return erroParceiro;

  const data = toDbData(parsed.data, proc.clienteId);
  await prisma.parceriaPaga.update({ where: { id }, data });

  await registrarAuditoria({
    entidade: RESOURCE,
    entidadeId: id,
    acao: AcaoAuditoria.ATUALIZAR,
    usuarioId: session.user.id,
    dadosAntes: serializarAudit(snapshot(antes)),
    dadosDepois: serializarAudit(data),
  });

  revalidarCaixa();
  return { ok: true, data: undefined };
}

export async function marcarParceriaPaga(
  input: MarcarParceriaPagaInput,
): Promise<ActionResult> {
  const session = await requirePerfil(PERFIS_ESCRITA);
  const parsed = marcarParceriaPagaSchema.safeParse(input);
  if (!parsed.success)
    return {
      ok: false,
      error: "Dados inválidos",
      fieldErrors: parsed.error.flatten().fieldErrors,
    };

  const antes = await prisma.parceriaPaga.findUnique({ where: { id: parsed.data.id } });
  if (!antes) return { ok: false, error: "Parceria não encontrada" };
  if (antes.dataPgto) {
    return { ok: false, error: "Parceria já está marcada como paga." };
  }

  const dataPgto = new Date(`${parsed.data.dataPgto}T00:00:00.000Z`);
  await prisma.parceriaPaga.update({
    where: { id: parsed.data.id },
    data: { dataPgto },
  });

  await registrarAuditoria({
    entidade: RESOURCE,
    entidadeId: parsed.data.id,
    acao: AcaoAuditoria.ATUALIZAR,
    usuarioId: session.user.id,
    dadosAntes: { dataPgto: null },
    dadosDepois: { dataPgto: dataPgto.toISOString() },
  });

  revalidarCaixa();
  return { ok: true, data: undefined };
}

export async function reverterParceriaPaga(id: string): Promise<ActionResult> {
  const session = await requirePerfil(PERFIS_ESCRITA);
  const antes = await prisma.parceriaPaga.findUnique({ where: { id } });
  if (!antes) return { ok: false, error: "Parceria não encontrada" };
  if (!antes.dataPgto) {
    return { ok: false, error: "Só é possível reverter uma parceria já PAGA." };
  }

  await prisma.parceriaPaga.update({ where: { id }, data: { dataPgto: null } });

  await registrarAuditoria({
    entidade: RESOURCE,
    entidadeId: id,
    acao: AcaoAuditoria.ATUALIZAR,
    usuarioId: session.user.id,
    dadosAntes: { dataPgto: antes.dataPgto.toISOString() },
    dadosDepois: { dataPgto: null },
  });

  revalidarCaixa();
  return { ok: true, data: undefined };
}

export async function excluirParceria(id: string): Promise<ActionResult> {
  const session = await requirePerfil(PERFIS_ESCRITA);
  const antes = await prisma.parceriaPaga.findUnique({ where: { id } });
  if (!antes) return { ok: false, error: "Parceria não encontrada" };

  await prisma.parceriaPaga.delete({ where: { id } });

  await registrarAuditoria({
    entidade: RESOURCE,
    entidadeId: id,
    acao: AcaoAuditoria.EXCLUIR,
    usuarioId: session.user.id,
    dadosAntes: serializarAudit(snapshot(antes)),
  });

  revalidarCaixa();
  return { ok: true, data: undefined };
}

// ----- helpers -----

async function validarParceiro(id: string): Promise<ActionError | null> {
  const p = await prisma.advogadoParceiro.findUnique({
    where: { id },
    select: { ativo: true },
  });
  if (!p) {
    return {
      ok: false,
      error: "Parceiro não encontrado",
      fieldErrors: { parceiroId: ["Parceiro inexistente"] },
    };
  }
  if (!p.ativo) {
    return {
      ok: false,
      error: "Parceiro está inativo",
      fieldErrors: { parceiroId: ["Parceiro inativo"] },
    };
  }
  return null;
}

function toDbData(input: ParceriaCreateInput, clienteId: string) {
  const text = (v: string | undefined) => {
    const t = v?.trim();
    return t ? t : null;
  };
  return {
    parceiroId: input.parceiroId,
    processoId: input.processoId,
    clienteId,
    dataAcordo: new Date(`${input.dataAcordo}T00:00:00.000Z`),
    valorTotal: new Prisma.Decimal(input.valorTotal),
    valorRecebido: new Prisma.Decimal(input.valorRecebido),
    percHonorarios: fromPercent(input.percHonorarios),
    ressarcimentos: new Prisma.Decimal(input.ressarcimentos),
    percParceiro: fromPercent(input.percParceiro),
    dataPgto: input.dataPgto ? new Date(`${input.dataPgto}T00:00:00.000Z`) : null,
    observacoes: text(input.observacoes),
  };
}

function snapshot(r: {
  parceiroId: string;
  processoId: string;
  clienteId: string;
  dataAcordo: Date;
  valorTotal: Prisma.Decimal;
  valorRecebido: Prisma.Decimal;
  percHonorarios: Prisma.Decimal;
  ressarcimentos: Prisma.Decimal;
  percParceiro: Prisma.Decimal;
  dataPgto: Date | null;
  observacoes: string | null;
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
