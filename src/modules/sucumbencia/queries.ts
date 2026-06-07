import "server-only";
import type {
  AdvogadoParceiro,
  Cliente,
  Prisma,
  Processo,
  Sucumbencia,
} from "@prisma/client";
import { prisma } from "@/lib/prisma";
import type { ListResult } from "@/modules/_shared/types";
import { calcularDistribuicaoSucumbencia, type SucumbenciaFiltros } from "./schema";

export type SucumbenciaComRelacoes = Sucumbencia & {
  processo: Pick<Processo, "id" | "numeroCnj" | "natureza">;
  cliente: Pick<Cliente, "id" | "nome">;
  parceiroExterno: Pick<AdvogadoParceiro, "id" | "nome"> | null;
};

export type ProcessoOpcao = Pick<Processo, "id" | "numeroCnj" | "clienteId"> & {
  cliente: Pick<Cliente, "id" | "nome">;
};
export type ClienteOpcao = Pick<Cliente, "id" | "nome">;
export type ParceiroOpcao = Pick<AdvogadoParceiro, "id" | "nome" | "tipo">;

const INCLUDE_RELACOES = {
  processo: { select: { id: true, numeroCnj: true, natureza: true } },
  cliente: { select: { id: true, nome: true } },
  parceiroExterno: { select: { id: true, nome: true } },
} satisfies Prisma.SucumbenciaInclude;

export async function listSucumbencias(
  filtros: SucumbenciaFiltros,
): Promise<ListResult<SucumbenciaComRelacoes>> {
  const where = buildWhere(filtros);
  const { page, pageSize } = filtros;

  const [items, total] = await Promise.all([
    prisma.sucumbencia.findMany({
      where,
      orderBy: [{ dataRecebimento: "desc" }, { criadoEm: "desc" }],
      skip: (page - 1) * pageSize,
      take: pageSize,
      include: INCLUDE_RELACOES,
    }),
    prisma.sucumbencia.count({ where }),
  ]);

  return { items, total, page, pageSize };
}

export async function statsSucumbencia(filtros: SucumbenciaFiltros): Promise<{
  totalBruto: number;
  totalEscritorio: number;
  totalClarissa: number;
  totalVivian: number;
  totalParceiro: number;
  saldoClarissa: number;
  saldoVivian: number;
}> {
  const where = buildWhere(filtros);
  const itens = await prisma.sucumbencia.findMany({
    where,
    select: {
      valorTotal: true,
      percParceiroExterno: true,
      percEscritorio: true,
      percClarissa: true,
      percVivian: true,
      dataRepasseClarissa: true,
      dataRepasseVivian: true,
    },
  });

  let totalBruto = 0;
  let totalEscritorio = 0;
  let totalClarissa = 0;
  let totalVivian = 0;
  let totalParceiro = 0;
  let saldoClarissa = 0;
  let saldoVivian = 0;

  for (const i of itens) {
    const dist = calcularDistribuicaoSucumbencia({
      valorTotal: Number(i.valorTotal),
      percParceiroExterno: i.percParceiroExterno ? Number(i.percParceiroExterno) : 0,
      percEscritorio: Number(i.percEscritorio),
      percClarissa: Number(i.percClarissa),
      percVivian: Number(i.percVivian),
    });
    totalBruto += Number(i.valorTotal);
    totalEscritorio += dist.escritorio;
    totalClarissa += dist.clarissa;
    totalVivian += dist.vivian;
    totalParceiro += dist.parceiroExterno;
    if (!i.dataRepasseClarissa) saldoClarissa += dist.clarissa;
    if (!i.dataRepasseVivian) saldoVivian += dist.vivian;
  }

  return {
    totalBruto,
    totalEscritorio,
    totalClarissa,
    totalVivian,
    totalParceiro,
    saldoClarissa,
    saldoVivian,
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

export async function listOpcoesParceiros(): Promise<ParceiroOpcao[]> {
  return prisma.advogadoParceiro.findMany({
    where: { ativo: true, tipo: "PARCEIRO_EXTERNO" },
    orderBy: { nome: "asc" },
    select: { id: true, nome: true, tipo: true },
    take: 500,
  });
}

function buildWhere(filtros: SucumbenciaFiltros): Prisma.SucumbenciaWhereInput {
  const where: Prisma.SucumbenciaWhereInput = {};

  if (filtros.inicio || filtros.fim) {
    where.dataRecebimento = {};
    if (filtros.inicio) where.dataRecebimento.gte = new Date(`${filtros.inicio}T00:00:00.000Z`);
    if (filtros.fim) where.dataRecebimento.lte = new Date(`${filtros.fim}T00:00:00.000Z`);
  }

  if (filtros.clienteId) where.clienteId = filtros.clienteId;
  if (filtros.processoId) where.processoId = filtros.processoId;

  if (filtros.status === "pendente_clarissa") where.dataRepasseClarissa = null;
  if (filtros.status === "pendente_vivian") where.dataRepasseVivian = null;
  if (filtros.status === "ambas_pagas") {
    where.dataRepasseClarissa = { not: null };
    where.dataRepasseVivian = { not: null };
  }

  const search = filtros.search?.trim();
  if (search) {
    where.OR = [
      { observacoes: { contains: search, mode: "insensitive" } },
      { cliente: { nome: { contains: search, mode: "insensitive" } } },
      { processo: { numeroCnj: { contains: search.replace(/\D/g, "") } } },
    ];
  }

  return where;
}
