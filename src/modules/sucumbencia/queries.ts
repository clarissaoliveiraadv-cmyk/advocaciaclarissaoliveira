import "server-only";
import type {
  AdvogadoParceiro,
  Categoria,
  Cliente,
  ContaBancaria,
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
  contaRecebimento: Pick<ContaBancaria, "id" | "nome">;
  categoriaLancamento: Pick<Categoria, "id" | "nome">;
  lancamentoEntrada: { descricao: string } | null;
};

export type ProcessoOpcao = Pick<Processo, "id" | "numeroCnj" | "clienteId"> & {
  cliente: Pick<Cliente, "id" | "nome">;
};
export type ClienteOpcao = Pick<Cliente, "id" | "nome">;
export type ParceiroOpcao = Pick<AdvogadoParceiro, "id" | "nome" | "tipo">;
export type ContaOpcao = Pick<ContaBancaria, "id" | "nome" | "codigo">;
export type CategoriaReceitaOpcao = Pick<Categoria, "id" | "nome">;

const INCLUDE_RELACOES = {
  processo: { select: { id: true, numeroCnj: true, natureza: true } },
  cliente: { select: { id: true, nome: true } },
  parceiroExterno: { select: { id: true, nome: true } },
  contaRecebimento: { select: { id: true, nome: true } },
  categoriaLancamento: { select: { id: true, nome: true } },
  lancamentoEntrada: { select: { descricao: true } },
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
  totalParceiro: number;
  saldoAPagarParceiro: number;
  count: number;
}> {
  const where = buildWhere(filtros);
  const itens = await prisma.sucumbencia.findMany({
    where,
    select: {
      valorTotal: true,
      percParceiroExterno: true,
      dataRepasseParceiroExterno: true,
    },
  });

  let totalBruto = 0;
  let totalEscritorio = 0;
  let totalParceiro = 0;
  let saldoAPagarParceiro = 0;

  for (const i of itens) {
    const dist = calcularDistribuicaoSucumbencia({
      valorTotal: Number(i.valorTotal),
      percParceiroExterno: i.percParceiroExterno ? Number(i.percParceiroExterno) : 0,
    });
    totalBruto += Number(i.valorTotal);
    totalEscritorio += dist.escritorio;
    totalParceiro += dist.parceiroExterno;
    if (i.percParceiroExterno && !i.dataRepasseParceiroExterno) {
      saldoAPagarParceiro += dist.parceiroExterno;
    }
  }

  return {
    totalBruto,
    totalEscritorio,
    totalParceiro,
    saldoAPagarParceiro,
    count: itens.length,
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

export async function listOpcoesContas(): Promise<ContaOpcao[]> {
  return prisma.contaBancaria.findMany({
    where: { ativo: true },
    orderBy: { nome: "asc" },
    select: { id: true, nome: true, codigo: true },
  });
}

export async function listOpcoesCategoriasReceita(): Promise<CategoriaReceitaOpcao[]> {
  return prisma.categoria.findMany({
    where: { ativo: true, tipo: "RECEITA" },
    orderBy: { nome: "asc" },
    select: { id: true, nome: true },
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

  if (filtros.status === "sem_parceiro") where.parceiroExternoId = null;
  if (filtros.status === "parceiro_pendente") {
    where.parceiroExternoId = { not: null };
    where.dataRepasseParceiroExterno = null;
  }
  if (filtros.status === "parceiro_pago") {
    where.parceiroExternoId = { not: null };
    where.dataRepasseParceiroExterno = { not: null };
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
