import "server-only";
import type {
  AdvogadoParceiro,
  Cliente,
  ParceriaPaga,
  Prisma,
  Processo,
} from "@prisma/client";
import { prisma } from "@/lib/prisma";
import type { ListResult } from "@/modules/_shared/types";
import { calcularDevidoAoParceiro, type ParceriaFiltros } from "./schema";

export type ParceriaComRelacoes = ParceriaPaga & {
  parceiro: Pick<AdvogadoParceiro, "id" | "nome" | "tipo">;
  processo: Pick<Processo, "id" | "numeroCnj" | "natureza">;
  cliente: Pick<Cliente, "id" | "nome">;
};

export type ProcessoOpcao = Pick<Processo, "id" | "numeroCnj" | "clienteId"> & {
  cliente: Pick<Cliente, "id" | "nome">;
};
export type ClienteOpcao = Pick<Cliente, "id" | "nome">;
export type ParceiroOpcao = Pick<AdvogadoParceiro, "id" | "nome" | "tipo"> & {
  percentualPadraoSucumbencia: Prisma.Decimal | null;
};

const INCLUDE_RELACOES = {
  parceiro: { select: { id: true, nome: true, tipo: true } },
  processo: { select: { id: true, numeroCnj: true, natureza: true } },
  cliente: { select: { id: true, nome: true } },
} satisfies Prisma.ParceriaPagaInclude;

export async function listParcerias(
  filtros: ParceriaFiltros,
): Promise<ListResult<ParceriaComRelacoes>> {
  const where = buildWhere(filtros);
  const { page, pageSize } = filtros;

  const [items, total] = await Promise.all([
    prisma.parceriaPaga.findMany({
      where,
      orderBy: [{ dataAcordo: "desc" }, { criadoEm: "desc" }],
      skip: (page - 1) * pageSize,
      take: pageSize,
      include: INCLUDE_RELACOES,
    }),
    prisma.parceriaPaga.count({ where }),
  ]);

  return { items, total, page, pageSize };
}

export async function statsParcerias(filtros: ParceriaFiltros): Promise<{
  totalAcordado: number;
  totalRecebido: number;
  totalDevido: number;
  totalPago: number;
  countPendente: number;
  countPaga: number;
}> {
  const where = buildWhere(filtros);
  const itens = await prisma.parceriaPaga.findMany({
    where,
    select: {
      valorTotal: true,
      valorRecebido: true,
      percHonorarios: true,
      ressarcimentos: true,
      percParceiro: true,
      dataPgto: true,
    },
  });

  let totalAcordado = 0;
  let totalRecebido = 0;
  let totalDevido = 0;
  let totalPago = 0;
  let countPendente = 0;
  let countPaga = 0;

  for (const i of itens) {
    const devido = calcularDevidoAoParceiro({
      valorRecebido: Number(i.valorRecebido),
      percHonorarios: Number(i.percHonorarios),
      ressarcimentos: Number(i.ressarcimentos),
      percParceiro: Number(i.percParceiro),
    });
    totalAcordado += Number(i.valorTotal);
    totalRecebido += Number(i.valorRecebido);
    totalDevido += devido;
    if (i.dataPgto) {
      totalPago += devido;
      countPaga += 1;
    } else {
      countPendente += 1;
    }
  }

  return {
    totalAcordado,
    totalRecebido,
    totalDevido,
    totalPago,
    countPendente,
    countPaga,
  };
}

export async function listOpcoesParceiros(): Promise<ParceiroOpcao[]> {
  return prisma.advogadoParceiro.findMany({
    where: { ativo: true },
    orderBy: { nome: "asc" },
    select: { id: true, nome: true, tipo: true, percentualPadraoSucumbencia: true },
    take: 500,
  });
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

function buildWhere(filtros: ParceriaFiltros): Prisma.ParceriaPagaWhereInput {
  const where: Prisma.ParceriaPagaWhereInput = {};

  if (filtros.inicio || filtros.fim) {
    where.dataAcordo = {};
    if (filtros.inicio) where.dataAcordo.gte = new Date(`${filtros.inicio}T00:00:00.000Z`);
    if (filtros.fim) where.dataAcordo.lte = new Date(`${filtros.fim}T00:00:00.000Z`);
  }

  if (filtros.parceiroId) where.parceiroId = filtros.parceiroId;
  if (filtros.clienteId) where.clienteId = filtros.clienteId;
  if (filtros.processoId) where.processoId = filtros.processoId;
  if (filtros.status === "PENDENTE") where.dataPgto = null;
  if (filtros.status === "PAGA") where.dataPgto = { not: null };

  const search = filtros.search?.trim();
  if (search) {
    where.OR = [
      { observacoes: { contains: search, mode: "insensitive" } },
      { cliente: { nome: { contains: search, mode: "insensitive" } } },
      { parceiro: { nome: { contains: search, mode: "insensitive" } } },
      { processo: { numeroCnj: { contains: search.replace(/\D/g, "") } } },
    ];
  }

  return where;
}
