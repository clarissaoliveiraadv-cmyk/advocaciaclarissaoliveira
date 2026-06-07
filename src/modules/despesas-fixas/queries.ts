import "server-only";
import type {
  Categoria,
  ContaBancaria,
  DespesaFixa,
  DespesaFixaPrevisao,
  Prisma,
} from "@prisma/client";
import { prisma } from "@/lib/prisma";
import { competenciaDoMesAtual, competenciaToDate, type PrevisaoFiltros } from "./schema";

export type DespesaFixaComRelacoes = DespesaFixa & {
  categoria: Pick<Categoria, "id" | "nome">;
  conta: Pick<ContaBancaria, "id" | "nome" | "codigo">;
};

export type PrevisaoComRelacoes = DespesaFixaPrevisao & {
  despesaFixa: DespesaFixa & {
    categoria: Pick<Categoria, "id" | "nome">;
    conta: Pick<ContaBancaria, "id" | "nome" | "codigo">;
  };
};

export type CategoriaDespesaOpcao = Pick<Categoria, "id" | "nome">;
export type ContaOpcao = Pick<ContaBancaria, "id" | "nome" | "codigo">;

export async function listDespesasFixas(): Promise<DespesaFixaComRelacoes[]> {
  return prisma.despesaFixa.findMany({
    orderBy: [{ ativo: "desc" }, { nome: "asc" }],
    include: {
      categoria: { select: { id: true, nome: true } },
      conta: { select: { id: true, nome: true, codigo: true } },
    },
  });
}

export async function getDespesaFixaById(id: string): Promise<DespesaFixa | null> {
  return prisma.despesaFixa.findUnique({ where: { id } });
}

export async function listPrevisoes(filtros: PrevisaoFiltros): Promise<{
  competencia: string;
  itens: PrevisaoComRelacoes[];
  totalPrevisto: number;
  totalPago: number;
  countPendente: number;
  countPaga: number;
}> {
  const competencia = filtros.competencia || competenciaDoMesAtual();
  const dataCompetencia = competenciaToDate(competencia);

  const where: Prisma.DespesaFixaPrevisaoWhereInput = { competencia: dataCompetencia };
  if (filtros.status === "pendente") where.lancamentoId = null;
  if (filtros.status === "paga") where.lancamentoId = { not: null };

  const itens = await prisma.despesaFixaPrevisao.findMany({
    where,
    orderBy: [{ dataVencimento: "asc" }, { criadoEm: "asc" }],
    include: {
      despesaFixa: {
        include: {
          categoria: { select: { id: true, nome: true } },
          conta: { select: { id: true, nome: true, codigo: true } },
        },
      },
    },
  });

  let totalPrevisto = 0;
  let totalPago = 0;
  let countPendente = 0;
  let countPaga = 0;
  for (const p of itens) {
    totalPrevisto += Number(p.valorPrevisto);
    if (p.lancamentoId) {
      countPaga += 1;
      totalPago += Number(p.valorPrevisto);
    } else {
      countPendente += 1;
    }
  }

  return { competencia, itens, totalPrevisto, totalPago, countPendente, countPaga };
}

export async function listOpcoesCategoriasDespesa(): Promise<CategoriaDespesaOpcao[]> {
  return prisma.categoria.findMany({
    where: { ativo: true, tipo: "DESPESA" },
    orderBy: { nome: "asc" },
    select: { id: true, nome: true },
  });
}

export async function listOpcoesContas(): Promise<ContaOpcao[]> {
  return prisma.contaBancaria.findMany({
    where: { ativo: true },
    orderBy: { nome: "asc" },
    select: { id: true, nome: true, codigo: true },
  });
}
