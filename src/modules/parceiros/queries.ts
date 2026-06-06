import "server-only";
import type { AdvogadoParceiro, Prisma } from "@prisma/client";
import { prisma } from "@/lib/prisma";
import type { ParceiroFiltros } from "./schema";

const MAX_PARCEIROS = 500;

export async function listParceiros(filtros: ParceiroFiltros): Promise<{
  items: AdvogadoParceiro[];
  total: number;
  limitAtingido: boolean;
}> {
  const where = buildWhere(filtros);

  const [items, total] = await Promise.all([
    prisma.advogadoParceiro.findMany({
      where,
      orderBy: [{ ativo: "desc" }, { nome: "asc" }],
      take: MAX_PARCEIROS,
    }),
    prisma.advogadoParceiro.count({ where }),
  ]);

  return { items, total, limitAtingido: total > MAX_PARCEIROS };
}

export function getParceiroById(id: string): Promise<AdvogadoParceiro | null> {
  return prisma.advogadoParceiro.findUnique({ where: { id } });
}

export async function parceiroTemDependencias(id: string): Promise<{
  recebiveis: number;
  parcerias: number;
  sucumbencias: number;
}> {
  const [recebiveis, parcerias, sucumbencias] = await Promise.all([
    prisma.recebivel.count({ where: { parceiroId: id } }),
    prisma.parceriaPaga.count({ where: { parceiroId: id } }),
    prisma.sucumbencia.count({ where: { parceiroExternoId: id } }),
  ]);
  return { recebiveis, parcerias, sucumbencias };
}

function buildWhere(filtros: ParceiroFiltros): Prisma.AdvogadoParceiroWhereInput {
  const where: Prisma.AdvogadoParceiroWhereInput = {};

  if (filtros.ativo === "ativos") where.ativo = true;
  if (filtros.ativo === "inativos") where.ativo = false;
  if (filtros.tipo !== "todos") where.tipo = filtros.tipo;

  const search = filtros.search?.trim();
  if (search) {
    where.OR = [
      { nome: { contains: search, mode: "insensitive" } },
      { oab: { contains: search, mode: "insensitive" } },
    ];
  }
  return where;
}
