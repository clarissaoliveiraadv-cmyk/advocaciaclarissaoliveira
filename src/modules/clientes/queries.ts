import "server-only";
import type { Cliente, Prisma } from "@prisma/client";
import { prisma } from "@/lib/prisma";
import { onlyDigits } from "@/lib/format";
import type { ListResult } from "@/modules/_shared/types";
import type { ClienteFiltros } from "./schema";

export async function listClientes(filtros: ClienteFiltros): Promise<ListResult<Cliente>> {
  const where = buildWhere(filtros);
  const { page, pageSize } = filtros;

  const [items, total] = await Promise.all([
    prisma.cliente.findMany({
      where,
      orderBy: [{ ativo: "desc" }, { nome: "asc" }],
      skip: (page - 1) * pageSize,
      take: pageSize,
    }),
    prisma.cliente.count({ where }),
  ]);

  return { items, total, page, pageSize };
}

export function getClienteById(id: string): Promise<Cliente | null> {
  return prisma.cliente.findUnique({ where: { id } });
}

export async function clienteTemDependencias(id: string): Promise<boolean> {
  const [processos, recebiveis, lancamentos, ressarcimentos] = await Promise.all([
    prisma.processo.count({ where: { clienteId: id } }),
    prisma.recebivel.count({ where: { clienteId: id } }),
    prisma.lancamento.count({ where: { clienteId: id } }),
    prisma.ressarcimento.count({ where: { clienteId: id } }),
  ]);
  return processos + recebiveis + lancamentos + ressarcimentos > 0;
}

function buildWhere(filtros: ClienteFiltros): Prisma.ClienteWhereInput {
  const where: Prisma.ClienteWhereInput = {};

  if (filtros.ativo === "ativos") where.ativo = true;
  if (filtros.ativo === "inativos") where.ativo = false;

  const search = filtros.search?.trim();
  if (search) {
    const termos: Prisma.ClienteWhereInput[] = [
      { nome: { contains: search, mode: "insensitive" } },
      { email: { contains: search, mode: "insensitive" } },
      { telefone: { contains: search, mode: "insensitive" } },
    ];
    const digitos = onlyDigits(search);
    if (digitos.length >= 3) termos.push({ cpfCnpj: { contains: digitos } });
    where.OR = termos;
  }

  return where;
}
