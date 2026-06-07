"use server";

import { revalidarCaixa } from "@/lib/cache";
import { AcaoAuditoria, Prisma, TipoLancamento } from "@prisma/client";
import { prisma } from "@/lib/prisma";
import { registrarAuditoria } from "@/lib/audit";
import { PERFIS_ESCRITA, requirePerfil } from "@/lib/auth/guards";
import { fromPercent } from "@/lib/money";
import type { ActionResult } from "@/modules/_shared/types";
import {
  marcarRepasseParceiroSchema,
  sucumbenciaCreateSchema,
  sucumbenciaUpdateSchema,
  type MarcarRepasseParceiroInput,
  type SucumbenciaCreateInput,
  type SucumbenciaUpdateInput,
} from "./schema";

const RESOURCE = "sucumbencia";

type ActionError = { ok: false; error: string; fieldErrors?: Record<string, string[]> };

/**
 * Cria uma sucumbência. Em uma transação atômica:
 *   - cria o Lançamento de ENTRADA pelo valor bruto na conta indicada
 *   - cria a Sucumbencia ligada a esse lançamento
 *
 * Se houver parceiro externo, a fatia dele fica como obrigação pendente
 * (dataRepasseParceiroExterno = null) — o pagamento real é feito depois
 * por meio de um lançamento manual de SAÍDA quando ela quitar.
 */
export async function criarSucumbencia(
  input: SucumbenciaCreateInput,
): Promise<ActionResult<{ id: string; lancamentoId: string }>> {
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

  const erroCategoria = await validarCategoriaReceita(parsed.data.categoriaLancamentoId);
  if (erroCategoria) return erroCategoria;

  const erroParceiro = await validarParceiro(parsed.data.parceiroExternoId);
  if (erroParceiro) return erroParceiro;

  const d = parsed.data;
  const dataRecebimento = new Date(`${d.dataRecebimento}T00:00:00.000Z`);
  const parceiroId = d.parceiroExternoId?.trim() || null;
  const percParc = parceiroId && d.percParceiroExterno ? d.percParceiroExterno.trim() : null;

  try {
    const result = await prisma.$transaction(async (tx) => {
      const lancamento = await tx.lancamento.create({
        data: {
          data: dataRecebimento,
          descricao: d.descricaoLancamento.trim(),
          tipo: TipoLancamento.ENTRADA,
          contaId: d.contaRecebimentoId,
          categoriaId: d.categoriaLancamentoId,
          valor: new Prisma.Decimal(d.valorTotal),
          clienteId: proc.clienteId,
          processoId: proc.id,
          criadoPorId: session.user.id,
        },
      });

      const sucumbencia = await tx.sucumbencia.create({
        data: {
          processoId: proc.id,
          clienteId: proc.clienteId,
          valorTotal: new Prisma.Decimal(d.valorTotal),
          dataRecebimento,
          contaRecebimentoId: d.contaRecebimentoId,
          categoriaLancamentoId: d.categoriaLancamentoId,
          parceiroExternoId: parceiroId,
          percParceiroExterno: percParc ? fromPercent(percParc) : null,
          lancamentoEntradaId: lancamento.id,
          observacoes: d.observacoes?.trim() || null,
        },
      });

      return { sucumbencia, lancamento };
    });

    await registrarAuditoria({
      entidade: RESOURCE,
      entidadeId: result.sucumbencia.id,
      acao: AcaoAuditoria.CRIAR,
      usuarioId: session.user.id,
      dadosDepois: {
        valorTotal: String(d.valorTotal),
        contaRecebimentoId: d.contaRecebimentoId,
        categoriaLancamentoId: d.categoriaLancamentoId,
        parceiroExternoId: parceiroId,
        lancamentoId: result.lancamento.id,
      },
    });

    revalidarCaixa();
    return {
      ok: true,
      data: { id: result.sucumbencia.id, lancamentoId: result.lancamento.id },
    };
  } catch (error) {
    if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === "P2003") {
      return { ok: false, error: "Conta ou categoria referenciada não existe." };
    }
    throw error;
  }
}

/**
 * Atualiza uma sucumbência junto com o lançamento de entrada vinculado
 * (em transação atômica).
 */
export async function atualizarSucumbencia(input: SucumbenciaUpdateInput): Promise<ActionResult> {
  const session = await requirePerfil(PERFIS_ESCRITA);
  const parsed = sucumbenciaUpdateSchema.safeParse(input);
  if (!parsed.success)
    return {
      ok: false,
      error: "Dados inválidos",
      fieldErrors: parsed.error.flatten().fieldErrors,
    };

  const { id, ...d } = parsed.data;
  const antes = await prisma.sucumbencia.findUnique({ where: { id } });
  if (!antes) return { ok: false, error: "Sucumbência não encontrada" };

  const proc = await prisma.processo.findUnique({
    where: { id: d.processoId },
    select: { clienteId: true },
  });
  if (!proc) return { ok: false, error: "Processo não encontrado" };

  const erroCategoria = await validarCategoriaReceita(d.categoriaLancamentoId);
  if (erroCategoria) return erroCategoria;

  const erroParceiro = await validarParceiro(d.parceiroExternoId);
  if (erroParceiro) return erroParceiro;

  const dataRecebimento = new Date(`${d.dataRecebimento}T00:00:00.000Z`);
  const parceiroId = d.parceiroExternoId?.trim() || null;
  const percParc = parceiroId && d.percParceiroExterno ? d.percParceiroExterno.trim() : null;

  await prisma.$transaction(async (tx) => {
    if (antes.lancamentoEntradaId) {
      await tx.lancamento.update({
        where: { id: antes.lancamentoEntradaId },
        data: {
          data: dataRecebimento,
          descricao: d.descricaoLancamento.trim(),
          contaId: d.contaRecebimentoId,
          categoriaId: d.categoriaLancamentoId,
          valor: new Prisma.Decimal(d.valorTotal),
          clienteId: proc.clienteId,
          processoId: d.processoId,
        },
      });
    }
    await tx.sucumbencia.update({
      where: { id },
      data: {
        processoId: d.processoId,
        clienteId: proc.clienteId,
        valorTotal: new Prisma.Decimal(d.valorTotal),
        dataRecebimento,
        contaRecebimentoId: d.contaRecebimentoId,
        categoriaLancamentoId: d.categoriaLancamentoId,
        parceiroExternoId: parceiroId,
        percParceiroExterno: percParc ? fromPercent(percParc) : null,
        // se trocou de "com parceiro" para "sem parceiro", limpa a data de repasse
        dataRepasseParceiroExterno: parceiroId ? antes.dataRepasseParceiroExterno : null,
        observacoes: d.observacoes?.trim() || null,
      },
    });
  });

  await registrarAuditoria({
    entidade: RESOURCE,
    entidadeId: id,
    acao: AcaoAuditoria.ATUALIZAR,
    usuarioId: session.user.id,
    dadosAntes: {
      valorTotal: antes.valorTotal.toString(),
      parceiroExternoId: antes.parceiroExternoId,
    },
    dadosDepois: {
      valorTotal: String(d.valorTotal),
      parceiroExternoId: parceiroId,
    },
  });

  revalidarCaixa();
  return { ok: true, data: undefined };
}

export async function marcarRepasseParceiro(
  input: MarcarRepasseParceiroInput,
): Promise<ActionResult> {
  const session = await requirePerfil(PERFIS_ESCRITA);
  const parsed = marcarRepasseParceiroSchema.safeParse(input);
  if (!parsed.success)
    return {
      ok: false,
      error: "Dados inválidos",
      fieldErrors: parsed.error.flatten().fieldErrors,
    };

  const antes = await prisma.sucumbencia.findUnique({ where: { id: parsed.data.id } });
  if (!antes) return { ok: false, error: "Sucumbência não encontrada" };
  if (!antes.parceiroExternoId) {
    return { ok: false, error: "Esta sucumbência não tem parceiro externo." };
  }
  if (antes.dataRepasseParceiroExterno) {
    return { ok: false, error: "Repasse ao parceiro externo já registrado." };
  }

  const dataRepasse = new Date(`${parsed.data.data}T00:00:00.000Z`);
  await prisma.sucumbencia.update({
    where: { id: parsed.data.id },
    data: { dataRepasseParceiroExterno: dataRepasse },
  });

  await registrarAuditoria({
    entidade: RESOURCE,
    entidadeId: parsed.data.id,
    acao: AcaoAuditoria.ATUALIZAR,
    usuarioId: session.user.id,
    dadosAntes: { dataRepasseParceiroExterno: null },
    dadosDepois: { dataRepasseParceiroExterno: dataRepasse.toISOString() },
  });

  revalidarCaixa();
  return { ok: true, data: undefined };
}

export async function reverterRepasseParceiro(id: string): Promise<ActionResult> {
  const session = await requirePerfil(PERFIS_ESCRITA);
  const antes = await prisma.sucumbencia.findUnique({ where: { id } });
  if (!antes) return { ok: false, error: "Sucumbência não encontrada" };
  if (!antes.dataRepasseParceiroExterno) {
    return { ok: false, error: "Não há repasse ao parceiro para reverter." };
  }

  await prisma.sucumbencia.update({
    where: { id },
    data: { dataRepasseParceiroExterno: null },
  });

  await registrarAuditoria({
    entidade: RESOURCE,
    entidadeId: id,
    acao: AcaoAuditoria.ATUALIZAR,
    usuarioId: session.user.id,
    dadosAntes: { dataRepasseParceiroExterno: antes.dataRepasseParceiroExterno.toISOString() },
    dadosDepois: { dataRepasseParceiroExterno: null },
  });

  revalidarCaixa();
  return { ok: true, data: undefined };
}

/**
 * Exclui a sucumbência e o lançamento de entrada vinculado em transação atômica.
 */
export async function excluirSucumbencia(id: string): Promise<ActionResult> {
  const session = await requirePerfil(PERFIS_ESCRITA);
  const antes = await prisma.sucumbencia.findUnique({ where: { id } });
  if (!antes) return { ok: false, error: "Sucumbência não encontrada" };

  await prisma.$transaction(async (tx) => {
    await tx.sucumbencia.delete({ where: { id } });
    if (antes.lancamentoEntradaId) {
      await tx.lancamento.delete({ where: { id: antes.lancamentoEntradaId } });
    }
  });

  await registrarAuditoria({
    entidade: RESOURCE,
    entidadeId: id,
    acao: AcaoAuditoria.EXCLUIR,
    usuarioId: session.user.id,
    dadosAntes: {
      valorTotal: antes.valorTotal.toString(),
      lancamentoExcluidoId: antes.lancamentoEntradaId,
    },
  });

  revalidarCaixa();
  return { ok: true, data: undefined };
}

// ----- helpers -----

async function validarCategoriaReceita(categoriaId: string): Promise<ActionError | null> {
  const cat = await prisma.categoria.findUnique({
    where: { id: categoriaId },
    select: { tipo: true, ativo: true },
  });
  if (!cat) {
    return {
      ok: false,
      error: "Categoria não encontrada",
      fieldErrors: { categoriaLancamentoId: ["Categoria inexistente"] },
    };
  }
  if (!cat.ativo) {
    return {
      ok: false,
      error: "Categoria inativa",
      fieldErrors: { categoriaLancamentoId: ["Categoria inativa"] },
    };
  }
  if (cat.tipo !== "RECEITA") {
    return {
      ok: false,
      error: "Categoria escolhida deve ser de RECEITA.",
      fieldErrors: { categoriaLancamentoId: ["Tipo deve ser RECEITA"] },
    };
  }
  return null;
}

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
