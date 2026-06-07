"use server";

import { revalidatePath } from "next/cache";
import { AcaoAuditoria, Prisma, TipoLancamento } from "@prisma/client";
import { prisma } from "@/lib/prisma";
import { registrarAuditoria } from "@/lib/audit";
import { PERFIS_ESCRITA, requirePerfil } from "@/lib/auth/guards";
import type { ActionResult } from "@/modules/_shared/types";
import {
  lancamentoCreateSchema,
  lancamentoUpdateSchema,
  transferenciaCreateSchema,
  transferenciaUpdateSchema,
  type LancamentoCreateInput,
  type LancamentoUpdateInput,
  type TransferenciaCreateInput,
  type TransferenciaUpdateInput,
} from "./schema";

const RESOURCE = "lancamento";
const ROUTE = "/movimento";

type ActionError = { ok: false; error: string; fieldErrors?: Record<string, string[]> };

// =============================================================================
// LANÇAMENTO SIMPLES (ENTRADA / SAIDA, sem ser perna de transferência)
// =============================================================================

export async function criarLancamento(
  input: LancamentoCreateInput,
): Promise<ActionResult<{ id: string }>> {
  const session = await requirePerfil(PERFIS_ESCRITA);
  const parsed = lancamentoCreateSchema.safeParse(input);
  if (!parsed.success)
    return {
      ok: false,
      error: "Dados inválidos",
      fieldErrors: parsed.error.flatten().fieldErrors,
    };

  const erroCategoria = await validarCategoriaParaTipo(parsed.data.categoriaId, parsed.data.tipo);
  if (erroCategoria) return erroCategoria;

  const erroProcesso = await validarProcessoVsCliente(
    parsed.data.processoId,
    parsed.data.clienteId,
  );
  if (erroProcesso) return erroProcesso;

  const data = toDbData(parsed.data, session.user.id);
  const lanc = await prisma.lancamento.create({ data });

  await registrarAuditoria({
    entidade: RESOURCE,
    entidadeId: lanc.id,
    acao: AcaoAuditoria.CRIAR,
    usuarioId: session.user.id,
    dadosDepois: serializarAudit(data),
  });

  revalidatePath(ROUTE);
  return { ok: true, data: { id: lanc.id } };
}

export async function atualizarLancamento(input: LancamentoUpdateInput): Promise<ActionResult> {
  const session = await requirePerfil(PERFIS_ESCRITA);
  const parsed = lancamentoUpdateSchema.safeParse(input);
  if (!parsed.success)
    return {
      ok: false,
      error: "Dados inválidos",
      fieldErrors: parsed.error.flatten().fieldErrors,
    };

  const { id } = parsed.data;
  const antes = await prisma.lancamento.findUnique({ where: { id } });
  if (!antes) return { ok: false, error: "Lançamento não encontrado" };

  const bloqueio = bloqueioPorOrigem(antes);
  if (bloqueio) return bloqueio;

  if (antes.transferenciaParId) {
    return {
      ok: false,
      error: "Este lançamento faz parte de uma transferência. Use a edição de transferência.",
    };
  }

  const erroCategoria = await validarCategoriaParaTipo(parsed.data.categoriaId, parsed.data.tipo);
  if (erroCategoria) return erroCategoria;

  const erroProcesso = await validarProcessoVsCliente(
    parsed.data.processoId,
    parsed.data.clienteId,
  );
  if (erroProcesso) return erroProcesso;

  const data = toDbData(parsed.data, session.user.id);
  await prisma.lancamento.update({ where: { id }, data });

  await registrarAuditoria({
    entidade: RESOURCE,
    entidadeId: id,
    acao: AcaoAuditoria.ATUALIZAR,
    usuarioId: session.user.id,
    dadosAntes: serializarAudit(snapshotLancamento(antes)),
    dadosDepois: serializarAudit(data),
  });

  revalidatePath(ROUTE);
  return { ok: true, data: undefined };
}

export async function excluirLancamento(id: string): Promise<ActionResult> {
  const session = await requirePerfil(PERFIS_ESCRITA);
  const antes = await prisma.lancamento.findUnique({ where: { id } });
  if (!antes) return { ok: false, error: "Lançamento não encontrado" };

  const bloqueio = bloqueioPorOrigem(antes);
  if (bloqueio) return bloqueio;

  if (antes.transferenciaParId) {
    return await excluirTransferencia(id);
  }

  await prisma.lancamento.delete({ where: { id } });
  await registrarAuditoria({
    entidade: RESOURCE,
    entidadeId: id,
    acao: AcaoAuditoria.EXCLUIR,
    usuarioId: session.user.id,
    dadosAntes: serializarAudit(snapshotLancamento(antes)),
  });

  revalidatePath(ROUTE);
  return { ok: true, data: undefined };
}

// =============================================================================
// TRANSFERÊNCIA INTERNA — par atômico
// =============================================================================

export async function criarTransferencia(
  input: TransferenciaCreateInput,
): Promise<ActionResult<{ saidaId: string; entradaId: string }>> {
  const session = await requirePerfil(PERFIS_ESCRITA);
  const parsed = transferenciaCreateSchema.safeParse(input);
  if (!parsed.success)
    return {
      ok: false,
      error: "Dados inválidos",
      fieldErrors: parsed.error.flatten().fieldErrors,
    };

  const d = parsed.data;
  const partilhado = {
    data: new Date(`${d.data}T00:00:00.000Z`),
    descricao: d.descricao.trim(),
    valor: new Prisma.Decimal(d.valor),
    categoriaId: d.categoriaId,
    observacoes: d.observacoes?.trim() || null,
    criadoPorId: session.user.id,
  };

  const result = await prisma.$transaction(async (tx) => {
    const saida = await tx.lancamento.create({
      data: { ...partilhado, contaId: d.contaOrigemId, tipo: TipoLancamento.SAIDA },
    });
    const entrada = await tx.lancamento.create({
      data: { ...partilhado, contaId: d.contaDestinoId, tipo: TipoLancamento.ENTRADA },
    });
    await tx.lancamento.update({
      where: { id: saida.id },
      data: { transferenciaParId: entrada.id },
    });
    await tx.lancamento.update({
      where: { id: entrada.id },
      data: { transferenciaParId: saida.id },
    });
    return { saida, entrada };
  });

  await Promise.all([
    registrarAuditoria({
      entidade: RESOURCE,
      entidadeId: result.saida.id,
      acao: AcaoAuditoria.CRIAR,
      usuarioId: session.user.id,
      dadosDepois: { ...serializarAudit(partilhado), perna: "SAIDA", parId: result.entrada.id },
    }),
    registrarAuditoria({
      entidade: RESOURCE,
      entidadeId: result.entrada.id,
      acao: AcaoAuditoria.CRIAR,
      usuarioId: session.user.id,
      dadosDepois: { ...serializarAudit(partilhado), perna: "ENTRADA", parId: result.saida.id },
    }),
  ]);

  revalidatePath(ROUTE);
  return { ok: true, data: { saidaId: result.saida.id, entradaId: result.entrada.id } };
}

export async function atualizarTransferencia(
  input: TransferenciaUpdateInput,
): Promise<ActionResult> {
  const session = await requirePerfil(PERFIS_ESCRITA);
  const parsed = transferenciaUpdateSchema.safeParse(input);
  if (!parsed.success)
    return {
      ok: false,
      error: "Dados inválidos",
      fieldErrors: parsed.error.flatten().fieldErrors,
    };

  const { id, ...d } = parsed.data;
  const anyLeg = await prisma.lancamento.findUnique({ where: { id } });
  if (!anyLeg || !anyLeg.transferenciaParId) {
    return { ok: false, error: "Transferência não encontrada" };
  }

  const par = await prisma.lancamento.findUnique({
    where: { id: anyLeg.transferenciaParId },
  });
  if (!par) return { ok: false, error: "Par da transferência não encontrado" };

  const saidaAntes = anyLeg.tipo === TipoLancamento.SAIDA ? anyLeg : par;
  const entradaAntes = anyLeg.tipo === TipoLancamento.ENTRADA ? anyLeg : par;

  const partilhado = {
    data: new Date(`${d.data}T00:00:00.000Z`),
    descricao: d.descricao.trim(),
    valor: new Prisma.Decimal(d.valor),
    categoriaId: d.categoriaId,
    observacoes: d.observacoes?.trim() || null,
    criadoPorId: session.user.id,
  };

  await prisma.$transaction([
    prisma.lancamento.update({
      where: { id: saidaAntes.id },
      data: { ...partilhado, contaId: d.contaOrigemId, tipo: TipoLancamento.SAIDA },
    }),
    prisma.lancamento.update({
      where: { id: entradaAntes.id },
      data: { ...partilhado, contaId: d.contaDestinoId, tipo: TipoLancamento.ENTRADA },
    }),
  ]);

  await Promise.all([
    registrarAuditoria({
      entidade: RESOURCE,
      entidadeId: saidaAntes.id,
      acao: AcaoAuditoria.ATUALIZAR,
      usuarioId: session.user.id,
      dadosAntes: serializarAudit(snapshotLancamento(saidaAntes)),
      dadosDepois: { ...serializarAudit(partilhado), perna: "SAIDA", contaId: d.contaOrigemId },
    }),
    registrarAuditoria({
      entidade: RESOURCE,
      entidadeId: entradaAntes.id,
      acao: AcaoAuditoria.ATUALIZAR,
      usuarioId: session.user.id,
      dadosAntes: serializarAudit(snapshotLancamento(entradaAntes)),
      dadosDepois: { ...serializarAudit(partilhado), perna: "ENTRADA", contaId: d.contaDestinoId },
    }),
  ]);

  revalidatePath(ROUTE);
  return { ok: true, data: undefined };
}

export async function excluirTransferencia(id: string): Promise<ActionResult> {
  const session = await requirePerfil(PERFIS_ESCRITA);
  const anyLeg = await prisma.lancamento.findUnique({ where: { id } });
  if (!anyLeg) return { ok: false, error: "Lançamento não encontrado" };
  if (!anyLeg.transferenciaParId)
    return { ok: false, error: "Lançamento não é parte de transferência" };

  const par = await prisma.lancamento.findUnique({
    where: { id: anyLeg.transferenciaParId },
  });
  if (!par) return { ok: false, error: "Par da transferência não encontrado" };

  await prisma.$transaction([
    prisma.lancamento.update({ where: { id: anyLeg.id }, data: { transferenciaParId: null } }),
    prisma.lancamento.update({ where: { id: par.id }, data: { transferenciaParId: null } }),
    prisma.lancamento.delete({ where: { id: anyLeg.id } }),
    prisma.lancamento.delete({ where: { id: par.id } }),
  ]);

  await Promise.all([
    registrarAuditoria({
      entidade: RESOURCE,
      entidadeId: anyLeg.id,
      acao: AcaoAuditoria.EXCLUIR,
      usuarioId: session.user.id,
      dadosAntes: serializarAudit(snapshotLancamento(anyLeg)),
    }),
    registrarAuditoria({
      entidade: RESOURCE,
      entidadeId: par.id,
      acao: AcaoAuditoria.EXCLUIR,
      usuarioId: session.user.id,
      dadosAntes: serializarAudit(snapshotLancamento(par)),
    }),
  ]);

  revalidatePath(ROUTE);
  return { ok: true, data: undefined };
}

// =============================================================================
// helpers
// =============================================================================

function bloqueioPorOrigem(l: {
  recebivelId: string | null;
  ressarcimentoId: string | null;
}): ActionError | null {
  if (l.recebivelId) {
    return {
      ok: false,
      error: "Este lançamento foi gerado pelo módulo Recebíveis. Edite/exclua por lá.",
    };
  }
  if (l.ressarcimentoId) {
    return {
      ok: false,
      error: "Este lançamento foi gerado pelo módulo Ressarcimento. Edite/exclua por lá.",
    };
  }
  return null;
}

async function validarCategoriaParaTipo(
  categoriaId: string,
  tipo: TipoLancamento,
): Promise<ActionError | null> {
  const cat = await prisma.categoria.findUnique({
    where: { id: categoriaId },
    select: { tipo: true, ativo: true },
  });
  if (!cat) {
    return {
      ok: false,
      error: "Categoria não encontrada",
      fieldErrors: { categoriaId: ["Categoria inexistente"] },
    };
  }
  if (!cat.ativo) {
    return {
      ok: false,
      error: "Categoria está inativa",
      fieldErrors: { categoriaId: ["Categoria inativa"] },
    };
  }
  const esperado = tipo === TipoLancamento.ENTRADA ? "RECEITA" : "DESPESA";
  if (cat.tipo !== esperado) {
    return {
      ok: false,
      error: `Categoria do tipo "${cat.tipo}" não é compatível com lançamento de ${tipo}.`,
      fieldErrors: { categoriaId: ["Tipo da categoria incompatível"] },
    };
  }
  return null;
}

async function validarProcessoVsCliente(
  processoId: string | undefined,
  clienteId: string | undefined,
): Promise<ActionError | null> {
  if (!processoId) return null;
  const proc = await prisma.processo.findUnique({
    where: { id: processoId },
    select: { clienteId: true },
  });
  if (!proc) {
    return {
      ok: false,
      error: "Processo não encontrado",
      fieldErrors: { processoId: ["Processo inexistente"] },
    };
  }
  if (clienteId && proc.clienteId !== clienteId) {
    return {
      ok: false,
      error: "Processo não pertence ao cliente selecionado",
      fieldErrors: { processoId: ["Processo de outro cliente"] },
    };
  }
  return null;
}

function toDbData(input: LancamentoCreateInput, criadoPorId: string) {
  return {
    data: new Date(`${input.data}T00:00:00.000Z`),
    descricao: input.descricao.trim(),
    tipo: input.tipo,
    contaId: input.contaId,
    categoriaId: input.categoriaId,
    valor: new Prisma.Decimal(input.valor),
    clienteId: input.clienteId?.trim() || null,
    processoId: input.processoId?.trim() || null,
    comprovanteUrl: input.comprovanteUrl?.trim() || null,
    observacoes: input.observacoes?.trim() || null,
    criadoPorId,
  };
}

function snapshotLancamento(l: {
  data: Date;
  descricao: string;
  tipo: TipoLancamento;
  contaId: string;
  categoriaId: string;
  valor: Prisma.Decimal;
  clienteId: string | null;
  processoId: string | null;
  comprovanteUrl: string | null;
  observacoes: string | null;
  transferenciaParId: string | null;
}) {
  return {
    data: l.data,
    descricao: l.descricao,
    tipo: l.tipo,
    contaId: l.contaId,
    categoriaId: l.categoriaId,
    valor: l.valor,
    clienteId: l.clienteId,
    processoId: l.processoId,
    comprovanteUrl: l.comprovanteUrl,
    observacoes: l.observacoes,
    transferenciaParId: l.transferenciaParId,
  };
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
