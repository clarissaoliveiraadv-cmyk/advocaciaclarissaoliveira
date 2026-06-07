import "server-only";
import type { Cliente, Prisma, Processo, Ressarcimento } from "@prisma/client";
import { prisma } from "@/lib/prisma";
import type { ListResult } from "@/modules/_shared/types";
import type { RessarcimentoFiltros } from "./schema";

export type RessarcimentoComRelacoes = Ressarcimento & {
  processo: Pick<Processo, "id" | "numeroCnj" | "natureza">;
  cliente: Pick<Cliente, "id" | "nome">;
};

export type ProcessoOpcao = Pick<Processo, "id" | "numeroCnj" | "clienteId"> & {
  cliente: Pick<Cliente, "id" | "nome">;
};

export type ClienteOpcao = Pick<Cliente, "id" | "nome">;

const INCLUDE_RELACOES = {
  processo: { select: { id: true, numeroCnj: true, natureza: true } },
  cliente: { select: { id: true, nome: true } },
} satisfies Prisma.RessarcimentoInclude;

export async function listRessarcimentos(
  filtros: RessarcimentoFiltros,
): Promise<ListResult<RessarcimentoComRelacoes>> {
  const where = buildWhere(filtros);
  const { page, pageSize } = filtros;

  const [items, total] = await Promise.all([
    prisma.ressarcimento.findMany({
      where,
      orderBy: [{ data: "desc" }, { criadoEm: "desc" }],
      skip: (page - 1) * pageSize,
      take: pageSize,
      include: INCLUDE_RELACOES,
    }),
    prisma.ressarcimento.count({ where }),
  ]);

  return { items, total, page, pageSize };
}

export async function statsRessarcimentos(filtros: RessarcimentoFiltros): Promise<{
  totalPago: number;
  countPago: number;
  totalReembolsado: number;
  countReembolsado: number;
  saldoAReceber: number;
}> {
  const where = buildWhere(filtros);
  const itens = await prisma.ressarcimento.findMany({
    where,
    select: { valor: true, status: true },
  });

  let totalPago = 0;
  let countPago = 0;
  let totalReembolsado = 0;
  let countReembolsado = 0;

  for (const i of itens) {
    const v = Number(i.valor);
    if (i.status === "PAGO_PELO_ESCRITORIO") {
      totalPago += v;
      countPago += 1;
    } else {
      totalReembolsado += v;
      countReembolsado += 1;
    }
  }

  return {
    totalPago,
    countPago,
    totalReembolsado,
    countReembolsado,
    saldoAReceber: totalPago,
  };
}

export async function listOpcoesProcessos(): Promise<ProcessoOpcao[]> {
  return prisma.processo.findMany({
    where: { ativo: true },
    orderBy: { criadoEm: "desc" },
    select: {
      id: true,
      numeroCnj: true,
      clienteId: true,
      cliente: { select: { id: true, nome: true } },
    },
    take: 1000,
  });
}

export async function listOpcoesClientes(): Promise<ClienteOpcao[]> {
  return prisma.cliente.findMany({
    where: { ativo: true },
    orderBy: { nome: "asc" },
    select: { id: true, nome: true },
    take: 500,
  });
}

function buildWhere(filtros: RessarcimentoFiltros): Prisma.RessarcimentoWhereInput {
  const where: Prisma.RessarcimentoWhereInput = {};

  if (filtros.inicio || filtros.fim) {
    where.data = {};
    if (filtros.inicio) where.data.gte = new Date(`${filtros.inicio}T00:00:00.000Z`);
    if (filtros.fim) where.data.lte = new Date(`${filtros.fim}T00:00:00.000Z`);
  }

  if (filtros.clienteId) where.clienteId = filtros.clienteId;
  if (filtros.processoId) where.processoId = filtros.processoId;
  if (filtros.status !== "todos") where.status = filtros.status;

  const search = filtros.search?.trim();
  if (search) {
    where.OR = [
      { descricao: { contains: search, mode: "insensitive" } },
      { cliente: { nome: { contains: search, mode: "insensitive" } } },
      { processo: { numeroCnj: { contains: search.replace(/\D/g, "") } } },
    ];
  }

  return where;
}
