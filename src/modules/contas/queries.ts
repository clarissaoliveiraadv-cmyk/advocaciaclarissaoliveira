import "server-only";
import type { ContaBancaria, Prisma } from "@prisma/client";
import { prisma } from "@/lib/prisma";
import type { ListResult } from "@/modules/_shared/types";
import type { ContaFiltros } from "./schema";

export async function listContas(filtros: ContaFiltros): Promise<ListResult<ContaBancaria>> {
  const where = buildWhere(filtros);
  const { page, pageSize } = filtros;

  const [items, total] = await Promise.all([
    prisma.contaBancaria.findMany({
      where,
      orderBy: [{ ativo: "desc" }, { codigo: "asc" }],
      skip: (page - 1) * pageSize,
      take: pageSize,
    }),
    prisma.contaBancaria.count({ where }),
  ]);

  return { items, total, page, pageSize };
}

export function getContaById(id: string): Promise<ContaBancaria | null> {
  return prisma.contaBancaria.findUnique({ where: { id } });
}

export async function contaTemDependencias(id: string): Promise<boolean> {
  const [lancamentos, recebimentos, repasses] = await Promise.all([
    prisma.lancamento.count({ where: { contaId: id } }),
    prisma.recebivel.count({ where: { contaRecebimentoId: id } }),
    prisma.recebivel.count({ where: { contaRepasseId: id } }),
  ]);
  return lancamentos + recebimentos + repasses > 0;
}

export async function contaTemLancamentos(id: string): Promise<boolean> {
  const count = await prisma.lancamento.count({ where: { contaId: id } });
  return count > 0;
}

function buildWhere(filtros: ContaFiltros): Prisma.ContaBancariaWhereInput {
  const where: Prisma.ContaBancariaWhereInput = {};

  if (filtros.ativo === "ativos") where.ativo = true;
  if (filtros.ativo === "inativos") where.ativo = false;
  if (filtros.tipo !== "todos") where.tipo = filtros.tipo;

  const search = filtros.search?.trim();
  if (search) {
    where.OR = [
      { codigo: { contains: search, mode: "insensitive" } },
      { nome: { contains: search, mode: "insensitive" } },
      { banco: { contains: search, mode: "insensitive" } },
      { agencia: { contains: search } },
      { conta: { contains: search } },
    ];
  }

  return where;
}
