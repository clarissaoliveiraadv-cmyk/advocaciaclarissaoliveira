"use server";

import { revalidatePath } from "next/cache";
import { AcaoAuditoria, Prisma, TipoLancamento } from "@prisma/client";
import { prisma } from "@/lib/prisma";
import { registrarAuditoria } from "@/lib/audit";
import { PERFIS_ESCRITA, requirePerfil } from "@/lib/auth/guards";
import type { ActionResult } from "@/modules/_shared/types";
import {
  calcularDataVencimento,
  competenciaToDate,
  despesaFixaCreateSchema,
  despesaFixaUpdateSchema,
  gerarPrevisoesSchema,
  marcarPrevisaoPagaSchema,
  type DespesaFixaCreateInput,
  type DespesaFixaUpdateInput,
  type GerarPrevisoesInput,
  type MarcarPrevisaoPagaInput,
} from "./schema";

const RESOURCE = "despesa_fixa";
const ROUTE_CADASTRO = "/cadastros/despesas-fixas";
const ROUTE_PAGAR = "/contas-a-pagar";

type ActionError = { ok: false; error: string; fieldErrors?: Record<string, string[]> };

// ----- CRUD da despesa fixa (template) -----

export async function criarDespesaFixa(
  input: DespesaFixaCreateInput,
): Promise<ActionResult<{ id: string }>> {
  const session = await requirePerfil(PERFIS_ESCRITA);
  const parsed = despesaFixaCreateSchema.safeParse(input);
  if (!parsed.success)
    return {
      ok: false,
      error: "Dados inválidos",
      fieldErrors: parsed.error.flatten().fieldErrors,
    };

  const erroCategoria = await validarCategoriaDespesa(parsed.data.categoriaId);
  if (erroCategoria) return erroCategoria;

  const d = parsed.data;
  const dadosCriacao = {
    nome: d.nome.trim(),
    categoriaId: d.categoriaId,
    contaId: d.contaId,
    valorEstimado: new Prisma.Decimal(d.valorEstimado),
    diaVencimento: d.diaVencimento,
    ativo: d.ativo,
    observacoes: d.observacoes?.trim() || null,
  };
  const despesa = await prisma.despesaFixa.create({ data: dadosCriacao });

  await registrarAuditoria({
    entidade: RESOURCE,
    entidadeId: despesa.id,
    acao: AcaoAuditoria.CRIAR,
    usuarioId: session.user.id,
    dadosDepois: {
      nome: dadosCriacao.nome,
      valorEstimado: String(d.valorEstimado),
      diaVencimento: d.diaVencimento,
    },
  });

  revalidatePath(ROUTE_CADASTRO);
  return { ok: true, data: { id: despesa.id } };
}

export async function atualizarDespesaFixa(input: DespesaFixaUpdateInput): Promise<ActionResult> {
  const session = await requirePerfil(PERFIS_ESCRITA);
  const parsed = despesaFixaUpdateSchema.safeParse(input);
  if (!parsed.success)
    return {
      ok: false,
      error: "Dados inválidos",
      fieldErrors: parsed.error.flatten().fieldErrors,
    };

  const { id, ...d } = parsed.data;
  const antes = await prisma.despesaFixa.findUnique({ where: { id } });
  if (!antes) return { ok: false, error: "Despesa fixa não encontrada" };

  const erroCategoria = await validarCategoriaDespesa(d.categoriaId);
  if (erroCategoria) return erroCategoria;

  await prisma.despesaFixa.update({
    where: { id },
    data: {
      nome: d.nome.trim(),
      categoriaId: d.categoriaId,
      contaId: d.contaId,
      valorEstimado: new Prisma.Decimal(d.valorEstimado),
      diaVencimento: d.diaVencimento,
      ativo: d.ativo,
      observacoes: d.observacoes?.trim() || null,
    },
  });

  await registrarAuditoria({
    entidade: RESOURCE,
    entidadeId: id,
    acao: AcaoAuditoria.ATUALIZAR,
    usuarioId: session.user.id,
    dadosAntes: { nome: antes.nome, valorEstimado: antes.valorEstimado.toString() },
    dadosDepois: { nome: d.nome, valorEstimado: String(d.valorEstimado) },
  });

  revalidatePath(ROUTE_CADASTRO);
  revalidatePath(ROUTE_PAGAR);
  return { ok: true, data: undefined };
}

export async function excluirDespesaFixa(id: string): Promise<ActionResult> {
  const session = await requirePerfil(PERFIS_ESCRITA);
  const antes = await prisma.despesaFixa.findUnique({ where: { id } });
  if (!antes) return { ok: false, error: "Despesa fixa não encontrada" };

  const previsoesPagas = await prisma.despesaFixaPrevisao.count({
    where: { despesaFixaId: id, lancamentoId: { not: null } },
  });
  if (previsoesPagas > 0) {
    return {
      ok: false,
      error:
        "Esta despesa fixa já gerou pagamentos. Marque como inativa para parar de gerar previsões.",
    };
  }

  // previsões pendentes são removidas em cascata
  await prisma.despesaFixa.delete({ where: { id } });

  await registrarAuditoria({
    entidade: RESOURCE,
    entidadeId: id,
    acao: AcaoAuditoria.EXCLUIR,
    usuarioId: session.user.id,
    dadosAntes: { nome: antes.nome },
  });

  revalidatePath(ROUTE_CADASTRO);
  revalidatePath(ROUTE_PAGAR);
  return { ok: true, data: undefined };
}

// ----- Geração das previsões mensais -----

/**
 * Gera (idempotentemente) uma previsão para cada despesa fixa ativa na
 * competência informada (yyyy-MM). Despesas inativas são ignoradas. Se já
 * existe previsão para a competência, mantém a existente sem alteração.
 */
export async function gerarPrevisoes(
  input: GerarPrevisoesInput,
): Promise<ActionResult<{ criadas: number; jaExistiam: number }>> {
  const session = await requirePerfil(PERFIS_ESCRITA);
  const parsed = gerarPrevisoesSchema.safeParse(input);
  if (!parsed.success)
    return { ok: false, error: "Competência inválida (formato yyyy-MM)" };

  const competencia = competenciaToDate(parsed.data.competencia);

  const despesas = await prisma.despesaFixa.findMany({ where: { ativo: true } });
  if (despesas.length === 0) {
    return {
      ok: false,
      error: "Nenhuma despesa fixa ativa para gerar. Cadastre em /cadastros/despesas-fixas.",
    };
  }

  let criadas = 0;
  let jaExistiam = 0;

  for (const d of despesas) {
    const existente = await prisma.despesaFixaPrevisao.findUnique({
      where: {
        despesaFixaId_competencia: { despesaFixaId: d.id, competencia },
      },
      select: { id: true },
    });
    if (existente) {
      jaExistiam += 1;
      continue;
    }
    await prisma.despesaFixaPrevisao.create({
      data: {
        despesaFixaId: d.id,
        competencia,
        dataVencimento: calcularDataVencimento(parsed.data.competencia, d.diaVencimento),
        valorPrevisto: d.valorEstimado,
      },
    });
    criadas += 1;
  }

  if (criadas > 0) {
    await registrarAuditoria({
      entidade: RESOURCE,
      entidadeId: "previsoes",
      acao: AcaoAuditoria.CRIAR,
      usuarioId: session.user.id,
      dadosDepois: { competencia: parsed.data.competencia, criadas, jaExistiam },
    });
  }

  revalidatePath(ROUTE_PAGAR);
  return { ok: true, data: { criadas, jaExistiam } };
}

// ----- Pagamento / reversão -----

/**
 * Marca uma previsão como paga, criando atomicamente um Lançamento de SAÍDA
 * e vinculando-o à previsão.
 */
export async function marcarPrevisaoPaga(
  input: MarcarPrevisaoPagaInput,
): Promise<ActionResult<{ lancamentoId: string }>> {
  const session = await requirePerfil(PERFIS_ESCRITA);
  const parsed = marcarPrevisaoPagaSchema.safeParse(input);
  if (!parsed.success)
    return {
      ok: false,
      error: "Dados inválidos",
      fieldErrors: parsed.error.flatten().fieldErrors,
    };

  const previsao = await prisma.despesaFixaPrevisao.findUnique({
    where: { id: parsed.data.id },
    include: { despesaFixa: true },
  });
  if (!previsao) return { ok: false, error: "Previsão não encontrada" };
  if (previsao.lancamentoId) {
    return { ok: false, error: "Previsão já está marcada como paga." };
  }

  const d = parsed.data;
  const dataPagamento = new Date(`${d.dataPagamento}T00:00:00.000Z`);

  try {
    const result = await prisma.$transaction(async (tx) => {
      const lancamento = await tx.lancamento.create({
        data: {
          data: dataPagamento,
          descricao: d.descricao.trim(),
          tipo: TipoLancamento.SAIDA,
          contaId: d.contaId,
          categoriaId: previsao.despesaFixa.categoriaId,
          valor: new Prisma.Decimal(d.valorPago),
          criadoPorId: session.user.id,
        },
      });
      await tx.despesaFixaPrevisao.update({
        where: { id: previsao.id },
        data: { lancamentoId: lancamento.id, dataPagamento },
      });
      return { lancamento };
    });

    await registrarAuditoria({
      entidade: RESOURCE,
      entidadeId: previsao.id,
      acao: AcaoAuditoria.ATUALIZAR,
      usuarioId: session.user.id,
      dadosDepois: {
        lancamentoId: result.lancamento.id,
        valorPago: String(d.valorPago),
        dataPagamento: dataPagamento.toISOString(),
      },
    });

    revalidatePath(ROUTE_PAGAR);
    revalidatePath("/movimento");
    return { ok: true, data: { lancamentoId: result.lancamento.id } };
  } catch (error) {
    if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === "P2003") {
      return { ok: false, error: "Conta referenciada não existe." };
    }
    throw error;
  }
}

/**
 * Reverte o pagamento: exclui o Lancamento e zera o vínculo na previsão.
 */
export async function reverterPagamento(id: string): Promise<ActionResult> {
  const session = await requirePerfil(PERFIS_ESCRITA);
  const previsao = await prisma.despesaFixaPrevisao.findUnique({ where: { id } });
  if (!previsao) return { ok: false, error: "Previsão não encontrada" };
  if (!previsao.lancamentoId) {
    return { ok: false, error: "Esta previsão ainda não foi paga." };
  }

  const lancamentoId = previsao.lancamentoId;
  await prisma.$transaction(async (tx) => {
    await tx.despesaFixaPrevisao.update({
      where: { id },
      data: { lancamentoId: null, dataPagamento: null },
    });
    await tx.lancamento.delete({ where: { id: lancamentoId } });
  });

  await registrarAuditoria({
    entidade: RESOURCE,
    entidadeId: id,
    acao: AcaoAuditoria.ATUALIZAR,
    usuarioId: session.user.id,
    dadosAntes: { lancamentoId },
    dadosDepois: { lancamentoId: null },
  });

  revalidatePath(ROUTE_PAGAR);
  revalidatePath("/movimento");
  return { ok: true, data: undefined };
}

/**
 * Exclui uma previsão pendente (não paga). Útil quando o usuário quer pular
 * o mês para uma despesa fixa específica.
 */
export async function excluirPrevisao(id: string): Promise<ActionResult> {
  const session = await requirePerfil(PERFIS_ESCRITA);
  const previsao = await prisma.despesaFixaPrevisao.findUnique({ where: { id } });
  if (!previsao) return { ok: false, error: "Previsão não encontrada" };
  if (previsao.lancamentoId) {
    return {
      ok: false,
      error: "Previsão já paga não pode ser excluída. Reverta o pagamento antes.",
    };
  }

  await prisma.despesaFixaPrevisao.delete({ where: { id } });

  await registrarAuditoria({
    entidade: RESOURCE,
    entidadeId: id,
    acao: AcaoAuditoria.EXCLUIR,
    usuarioId: session.user.id,
    dadosAntes: { despesaFixaId: previsao.despesaFixaId },
  });

  revalidatePath(ROUTE_PAGAR);
  return { ok: true, data: undefined };
}

// ----- helpers -----

async function validarCategoriaDespesa(categoriaId: string): Promise<ActionError | null> {
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
      error: "Categoria inativa",
      fieldErrors: { categoriaId: ["Categoria inativa"] },
    };
  }
  if (cat.tipo !== "DESPESA") {
    return {
      ok: false,
      error: "Categoria escolhida deve ser de DESPESA.",
      fieldErrors: { categoriaId: ["Tipo deve ser DESPESA"] },
    };
  }
  return null;
}
