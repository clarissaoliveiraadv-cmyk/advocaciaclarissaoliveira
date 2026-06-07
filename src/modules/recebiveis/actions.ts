"use server";

import { revalidatePath } from "next/cache";
import { AcaoAuditoria, Prisma, StatusRecebivel } from "@prisma/client";
import { prisma } from "@/lib/prisma";
import { registrarAuditoria } from "@/lib/audit";
import { PERFIS_ESCRITA, requirePerfil } from "@/lib/auth/guards";
import { fromPercent } from "@/lib/money";
import type { ActionResult } from "@/modules/_shared/types";
import {
  recebivelCreateSchema,
  recebivelUpdateSchema,
  type RecebivelCreateInput,
  type RecebivelUpdateInput,
} from "./schema";
import { recebivelTemDistribuicao, recebivelTemLancamentos } from "./queries";

const RESOURCE = "recebivel";
const ROUTE = "/recebiveis";

type ActionError = { ok: false; error: string; fieldErrors?: Record<string, string[]> };

export async function criarRecebivel(
  input: RecebivelCreateInput,
): Promise<ActionResult<{ id: string }>> {
  const session = await requirePerfil(PERFIS_ESCRITA);
  const parsed = recebivelCreateSchema.safeParse(input);
  if (!parsed.success)
    return {
      ok: false,
      error: "Dados inválidos",
      fieldErrors: parsed.error.flatten().fieldErrors,
    };

  const proc = await prisma.processo.findUnique({
    where: { id: parsed.data.processoId },
    select: { id: true, clienteId: true, ativo: true },
  });
  if (!proc) return { ok: false, error: "Processo não encontrado" };

  const erroParceiro = await validarParceiro(parsed.data.parceiroId);
  if (erroParceiro) return erroParceiro;

  const data = toDbData(parsed.data, proc.clienteId);
  const recebivel = await prisma.recebivel.create({ data });

  await registrarAuditoria({
    entidade: RESOURCE,
    entidadeId: recebivel.id,
    acao: AcaoAuditoria.CRIAR,
    usuarioId: session.user.id,
    dadosDepois: serializarAudit(data),
  });

  revalidatePath(ROUTE);
  return { ok: true, data: { id: recebivel.id } };
}

export async function atualizarRecebivel(input: RecebivelUpdateInput): Promise<ActionResult> {
  const session = await requirePerfil(PERFIS_ESCRITA);
  const parsed = recebivelUpdateSchema.safeParse(input);
  if (!parsed.success)
    return {
      ok: false,
      error: "Dados inválidos",
      fieldErrors: parsed.error.flatten().fieldErrors,
    };

  const { id } = parsed.data;
  const antes = await prisma.recebivel.findUnique({ where: { id } });
  if (!antes) return { ok: false, error: "Recebível não encontrado" };

  if (antes.status !== StatusRecebivel.PREVISTA) {
    return {
      ok: false,
      error: "Apenas recebíveis em PREVISTA podem ser editados livremente.",
    };
  }

  const proc = await prisma.processo.findUnique({
    where: { id: parsed.data.processoId },
    select: { clienteId: true },
  });
  if (!proc) return { ok: false, error: "Processo não encontrado" };

  const erroParceiro = await validarParceiro(parsed.data.parceiroId);
  if (erroParceiro) return erroParceiro;

  const data = toDbData(parsed.data, proc.clienteId);
  await prisma.recebivel.update({ where: { id }, data });

  await registrarAuditoria({
    entidade: RESOURCE,
    entidadeId: id,
    acao: AcaoAuditoria.ATUALIZAR,
    usuarioId: session.user.id,
    dadosAntes: serializarAudit(snapshotRecebivel(antes)),
    dadosDepois: serializarAudit(data),
  });

  revalidatePath(ROUTE);
  return { ok: true, data: undefined };
}

export async function cancelarRecebivel(id: string): Promise<ActionResult> {
  const session = await requirePerfil(PERFIS_ESCRITA);
  const antes = await prisma.recebivel.findUnique({ where: { id } });
  if (!antes) return { ok: false, error: "Recebível não encontrado" };

  if (antes.status === StatusRecebivel.CANCELADA) {
    return { ok: false, error: "Recebível já está cancelado." };
  }
  if (antes.status === StatusRecebivel.RECEBIDA || antes.status === StatusRecebivel.REPASSADA) {
    return {
      ok: false,
      error: "Não é possível cancelar um recebível já recebido. Reverta o recebimento primeiro.",
    };
  }

  await prisma.recebivel.update({
    where: { id },
    data: { status: StatusRecebivel.CANCELADA },
  });

  await registrarAuditoria({
    entidade: RESOURCE,
    entidadeId: id,
    acao: AcaoAuditoria.ATUALIZAR,
    usuarioId: session.user.id,
    dadosAntes: { status: antes.status },
    dadosDepois: { status: StatusRecebivel.CANCELADA },
  });

  revalidatePath(ROUTE);
  return { ok: true, data: undefined };
}

export async function reabrirRecebivel(id: string): Promise<ActionResult> {
  const session = await requirePerfil(PERFIS_ESCRITA);
  const antes = await prisma.recebivel.findUnique({ where: { id } });
  if (!antes) return { ok: false, error: "Recebível não encontrado" };

  if (antes.status !== StatusRecebivel.CANCELADA) {
    return { ok: false, error: "Só é possível reabrir um recebível CANCELADO." };
  }

  await prisma.recebivel.update({
    where: { id },
    data: { status: StatusRecebivel.PREVISTA },
  });

  await registrarAuditoria({
    entidade: RESOURCE,
    entidadeId: id,
    acao: AcaoAuditoria.ATUALIZAR,
    usuarioId: session.user.id,
    dadosAntes: { status: antes.status },
    dadosDepois: { status: StatusRecebivel.PREVISTA },
  });

  revalidatePath(ROUTE);
  return { ok: true, data: undefined };
}

export async function excluirRecebivel(id: string): Promise<ActionResult> {
  const session = await requirePerfil(PERFIS_ESCRITA);
  const antes = await prisma.recebivel.findUnique({ where: { id } });
  if (!antes) return { ok: false, error: "Recebível não encontrado" };

  if (await recebivelTemDistribuicao(id)) {
    return {
      ok: false,
      error: "Recebível possui distribuição registrada. Reverta a distribuição antes de excluir.",
    };
  }
  if (await recebivelTemLancamentos(id)) {
    return {
      ok: false,
      error: "Recebível possui lançamentos vinculados. Cancele em vez de excluir.",
    };
  }

  await prisma.recebivel.delete({ where: { id } });

  await registrarAuditoria({
    entidade: RESOURCE,
    entidadeId: id,
    acao: AcaoAuditoria.EXCLUIR,
    usuarioId: session.user.id,
    dadosAntes: serializarAudit(snapshotRecebivel(antes)),
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

function toDbData(input: RecebivelCreateInput, clienteId: string) {
  const text = (v: string | undefined) => {
    const t = v?.trim();
    return t ? t : null;
  };
  const parceiroId = input.parceiroId?.trim() || null;
  const percParc = input.percParceiro?.trim();
  const numParc = input.numeroParcela?.trim();
  const totalParc = input.totalParcelas?.trim();
  return {
    processoId: input.processoId,
    clienteId,
    dataPrevista: new Date(`${input.dataPrevista}T00:00:00.000Z`),
    tipoParcela: input.tipoParcela,
    numeroParcela: numParc ? Number(numParc) : null,
    totalParcelas: totalParc ? Number(totalParc) : null,
    valorIntegral: new Prisma.Decimal(input.valorIntegral),
    valorParcela: new Prisma.Decimal(input.valorParcela),
    ressarcimentoEmbutido: new Prisma.Decimal(input.ressarcimentoEmbutido),
    percHonorarios: fromPercent(input.percHonorarios),
    parceiroId,
    percParceiro: parceiroId && percParc ? fromPercent(percParc) : null,
    observacoes: text(input.observacoes),
  };
}

function snapshotRecebivel(r: {
  processoId: string;
  clienteId: string;
  dataPrevista: Date;
  tipoParcela: string;
  numeroParcela: number | null;
  totalParcelas: number | null;
  valorIntegral: Prisma.Decimal;
  valorParcela: Prisma.Decimal;
  ressarcimentoEmbutido: Prisma.Decimal;
  percHonorarios: Prisma.Decimal;
  parceiroId: string | null;
  percParceiro: Prisma.Decimal | null;
  status: string;
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
