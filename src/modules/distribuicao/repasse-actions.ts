"use server";

import { revalidatePath } from "next/cache";
import {
  AcaoAuditoria,
  Prisma,
  StatusItemDistribuicao,
  StatusRecebivel,
  TipoBeneficiario,
  TipoLancamento,
} from "@prisma/client";
import { prisma } from "@/lib/prisma";
import { registrarAuditoria } from "@/lib/audit";
import { requirePerfil } from "@/lib/auth/guards";
import type { ActionResult } from "@/modules/_shared/types";
import { registrarRepasseSchema, type RegistrarRepasseInput } from "./repasse-schema";

const PERFIS_ESCRITA = ["ADMIN", "SOCIA", "SECRETARIA"] as const;
const RESOURCE_ITEM = "item_distribuicao";
const ROUTE_REC = "/recebiveis";

const BENEFICIARIOS_ESCRITORIO: ReadonlyArray<TipoBeneficiario> = [
  TipoBeneficiario.ESCRITORIO_CONTRATUAL,
  TipoBeneficiario.ESCRITORIO_SUCUMBENCIA,
];

type ActionError = { ok: false; error: string; fieldErrors?: Record<string, string[]> };

/**
 * Registra um repasse para um item da distribuição:
 *   - cria Lançamento de SAIDA na conta escolhida
 *   - marca item.status = REPASSADO + item.lancamentoId
 *   - recalcula status do Recebível (RECEBIDA ↔ REPASSADA)
 * Tudo dentro de uma transação Prisma.
 */
export async function registrarRepasse(input: RegistrarRepasseInput): Promise<ActionResult> {
  const session = await requirePerfil(PERFIS_ESCRITA);
  const parsed = registrarRepasseSchema.safeParse(input);
  if (!parsed.success)
    return {
      ok: false,
      error: "Dados inválidos",
      fieldErrors: parsed.error.flatten().fieldErrors,
    };

  const item = await prisma.itemDistribuicao.findUnique({
    where: { id: parsed.data.itemId },
    include: {
      distribuicao: { select: { recebivelId: true } },
    },
  });
  if (!item) return { ok: false, error: "Item de distribuição não encontrado" };
  if (item.status !== StatusItemDistribuicao.PENDENTE_REPASSE) {
    return {
      ok: false,
      error: `Item está em status ${item.status}. Apenas itens PENDENTE_REPASSE podem ser repassados.`,
    };
  }

  const recebivel = await prisma.recebivel.findUnique({
    where: { id: item.distribuicao.recebivelId },
    select: { clienteId: true, processoId: true, status: true },
  });
  if (!recebivel) return { ok: false, error: "Recebível associado não encontrado" };

  const erroCategoria = await validarCategoriaDespesa(parsed.data.categoriaId);
  if (erroCategoria) return erroCategoria;

  const erroConta = await validarConta(parsed.data.contaSaidaId);
  if (erroConta) return erroConta;

  const dataLanc = new Date(`${parsed.data.data}T00:00:00.000Z`);

  try {
    const result = await prisma.$transaction(async (tx) => {
      const lancamento = await tx.lancamento.create({
        data: {
          data: dataLanc,
          descricao: parsed.data.descricao.trim(),
          tipo: TipoLancamento.SAIDA,
          contaId: parsed.data.contaSaidaId,
          categoriaId: parsed.data.categoriaId,
          valor: item.valor,
          clienteId: recebivel.clienteId,
          processoId: recebivel.processoId,
          observacoes: parsed.data.observacoes?.trim() || null,
          criadoPorId: session.user.id,
        },
      });

      await tx.itemDistribuicao.update({
        where: { id: item.id },
        data: {
          status: StatusItemDistribuicao.REPASSADO,
          lancamentoId: lancamento.id,
        },
      });

      await recalcularStatusRecebivel(tx, item.distribuicao.recebivelId, dataLanc);

      return { lancamento };
    });

    await Promise.all([
      registrarAuditoria({
        entidade: RESOURCE_ITEM,
        entidadeId: item.id,
        acao: AcaoAuditoria.ATUALIZAR,
        usuarioId: session.user.id,
        dadosAntes: { status: item.status, lancamentoId: item.lancamentoId },
        dadosDepois: {
          status: StatusItemDistribuicao.REPASSADO,
          lancamentoId: result.lancamento.id,
          valor: item.valor.toString(),
        },
      }),
    ]);

    revalidatePath(ROUTE_REC);
    revalidatePath("/movimento");
    return { ok: true, data: undefined };
  } catch (error) {
    if (error instanceof Prisma.PrismaClientKnownRequestError) {
      if (error.code === "P2003") {
        return { ok: false, error: "Conta ou categoria referenciada não existe." };
      }
    }
    throw error;
  }
}

/**
 * Desfaz um repasse:
 *   - deleta o Lançamento de SAIDA gerado
 *   - volta item.status para PENDENTE_REPASSE + zera lancamentoId
 *   - recalcula status do Recebível
 */
export async function reverterRepasse(itemId: string): Promise<ActionResult> {
  const session = await requirePerfil(PERFIS_ESCRITA);
  const item = await prisma.itemDistribuicao.findUnique({
    where: { id: itemId },
    include: { distribuicao: { select: { recebivelId: true } } },
  });
  if (!item) return { ok: false, error: "Item não encontrado" };
  if (item.status !== StatusItemDistribuicao.REPASSADO) {
    return { ok: false, error: "Item não está repassado." };
  }
  if (!item.lancamentoId) {
    return { ok: false, error: "Item marcado como REPASSADO sem lançamento vinculado." };
  }

  await prisma.$transaction(async (tx) => {
    await tx.itemDistribuicao.update({
      where: { id: item.id },
      data: { status: StatusItemDistribuicao.PENDENTE_REPASSE, lancamentoId: null },
    });
    await tx.lancamento.delete({ where: { id: item.lancamentoId as string } });
    await recalcularStatusRecebivel(tx, item.distribuicao.recebivelId, null);
  });

  await registrarAuditoria({
    entidade: RESOURCE_ITEM,
    entidadeId: item.id,
    acao: AcaoAuditoria.ATUALIZAR,
    usuarioId: session.user.id,
    dadosAntes: {
      status: StatusItemDistribuicao.REPASSADO,
      lancamentoId: item.lancamentoId,
    },
    dadosDepois: {
      status: StatusItemDistribuicao.PENDENTE_REPASSE,
      lancamentoId: null,
    },
  });

  revalidatePath(ROUTE_REC);
  revalidatePath("/movimento");
  return { ok: true, data: undefined };
}

/**
 * Marca um item como retido em custódia (sem gerar lançamento).
 * Útil para honorários de escritório que não precisam de "saída" e para
 * casos especiais de valores parados na conta.
 */
export async function marcarEmCustodia(itemId: string): Promise<ActionResult> {
  const session = await requirePerfil(PERFIS_ESCRITA);
  const item = await prisma.itemDistribuicao.findUnique({
    where: { id: itemId },
    include: { distribuicao: { select: { recebivelId: true } } },
  });
  if (!item) return { ok: false, error: "Item não encontrado" };
  if (item.status !== StatusItemDistribuicao.PENDENTE_REPASSE) {
    return { ok: false, error: `Item está em status ${item.status}, não pode ir para custódia.` };
  }

  await prisma.$transaction(async (tx) => {
    await tx.itemDistribuicao.update({
      where: { id: item.id },
      data: { status: StatusItemDistribuicao.RETIDO_CUSTODIA },
    });
    await recalcularStatusRecebivel(tx, item.distribuicao.recebivelId, new Date());
  });

  await registrarAuditoria({
    entidade: RESOURCE_ITEM,
    entidadeId: item.id,
    acao: AcaoAuditoria.ATUALIZAR,
    usuarioId: session.user.id,
    dadosAntes: { status: item.status },
    dadosDepois: { status: StatusItemDistribuicao.RETIDO_CUSTODIA },
  });

  revalidatePath(ROUTE_REC);
  return { ok: true, data: undefined };
}

/** Reverte a marcação de custódia, voltando para PENDENTE_REPASSE. */
export async function liberarCustodia(itemId: string): Promise<ActionResult> {
  const session = await requirePerfil(PERFIS_ESCRITA);
  const item = await prisma.itemDistribuicao.findUnique({
    where: { id: itemId },
    include: { distribuicao: { select: { recebivelId: true } } },
  });
  if (!item) return { ok: false, error: "Item não encontrado" };
  if (item.status !== StatusItemDistribuicao.RETIDO_CUSTODIA) {
    return { ok: false, error: "Item não está em custódia." };
  }

  await prisma.$transaction(async (tx) => {
    await tx.itemDistribuicao.update({
      where: { id: item.id },
      data: { status: StatusItemDistribuicao.PENDENTE_REPASSE },
    });
    await recalcularStatusRecebivel(tx, item.distribuicao.recebivelId, null);
  });

  await registrarAuditoria({
    entidade: RESOURCE_ITEM,
    entidadeId: item.id,
    acao: AcaoAuditoria.ATUALIZAR,
    usuarioId: session.user.id,
    dadosAntes: { status: item.status },
    dadosDepois: { status: StatusItemDistribuicao.PENDENTE_REPASSE },
  });

  revalidatePath(ROUTE_REC);
  return { ok: true, data: undefined };
}

// =============================================================================
// helpers
// =============================================================================

/**
 * REPASSADA = todos os itens não-escritório estão REPASSADO ou RETIDO_CUSTODIA.
 * RECEBIDA = caso contrário.
 * Recalcula e ajusta o status + dataRepasseCliente do Recebível na MESMA transação.
 */
async function recalcularStatusRecebivel(
  tx: Prisma.TransactionClient,
  recebivelId: string,
  dataRepasseSugerida: Date | null,
): Promise<void> {
  const recebivel = await tx.recebivel.findUnique({
    where: { id: recebivelId },
    select: { status: true, dataRepasseCliente: true },
  });
  if (!recebivel) return;
  // Só ajustamos quando o ciclo está entre RECEBIDA e REPASSADA — não mexe em PREVISTA/CANCELADA
  if (
    recebivel.status !== StatusRecebivel.RECEBIDA &&
    recebivel.status !== StatusRecebivel.REPASSADA
  ) {
    return;
  }

  const itens = await tx.itemDistribuicao.findMany({
    where: { distribuicao: { recebivelId } },
    select: { beneficiario: true, status: true },
  });
  const naoEscritorio = itens.filter((i) => !BENEFICIARIOS_ESCRITORIO.includes(i.beneficiario));
  const todosResolvidos =
    naoEscritorio.length > 0 &&
    naoEscritorio.every(
      (i) =>
        i.status === StatusItemDistribuicao.REPASSADO ||
        i.status === StatusItemDistribuicao.RETIDO_CUSTODIA,
    );

  if (todosResolvidos && recebivel.status !== StatusRecebivel.REPASSADA) {
    await tx.recebivel.update({
      where: { id: recebivelId },
      data: {
        status: StatusRecebivel.REPASSADA,
        dataRepasseCliente: dataRepasseSugerida ?? new Date(),
      },
    });
  } else if (!todosResolvidos && recebivel.status === StatusRecebivel.REPASSADA) {
    await tx.recebivel.update({
      where: { id: recebivelId },
      data: { status: StatusRecebivel.RECEBIDA, dataRepasseCliente: null },
    });
  }
}

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
      error: "Categoria do repasse deve ser DESPESA.",
      fieldErrors: { categoriaId: ["Tipo deve ser DESPESA"] },
    };
  }
  return null;
}

async function validarConta(contaId: string): Promise<ActionError | null> {
  const conta = await prisma.contaBancaria.findUnique({
    where: { id: contaId },
    select: { ativo: true },
  });
  if (!conta) {
    return {
      ok: false,
      error: "Conta não encontrada",
      fieldErrors: { contaSaidaId: ["Conta inexistente"] },
    };
  }
  if (!conta.ativo) {
    return {
      ok: false,
      error: "Conta inativa",
      fieldErrors: { contaSaidaId: ["Conta inativa"] },
    };
  }
  return null;
}
