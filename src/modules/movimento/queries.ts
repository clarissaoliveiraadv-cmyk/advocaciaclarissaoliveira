import "server-only";
import type {
  Cliente,
  ContaBancaria,
  Categoria,
  Lancamento,
  Prisma,
  Processo,
} from "@prisma/client";
import { prisma } from "@/lib/prisma";
import type { ListResult } from "@/modules/_shared/types";
import type { LancamentoFiltros } from "./schema";

export type LancamentoComRelacoes = Lancamento & {
  conta: Pick<ContaBancaria, "id" | "codigo" | "nome">;
  categoria: Pick<Categoria, "id" | "nome" | "tipo" | "isPessoal">;
  cliente: Pick<Cliente, "id" | "nome"> | null;
  processo: Pick<Processo, "id" | "numeroCnj"> | null;
  transferenciaPar:
    | (Pick<Lancamento, "id" | "tipo" | "contaId"> & {
        conta: Pick<ContaBancaria, "id" | "codigo" | "nome">;
      })
    | null;
};

export type SaldoConta = {
  contaId: string;
  codigo: string;
  nome: string;
  saldoInicial: number;
  totalEntradas: number;
  totalSaidas: number;
  saldoAtual: number;
};

export type ClienteOpcao = Pick<Cliente, "id" | "nome" | "cpfCnpj">;
export type ProcessoOpcao = Pick<Processo, "id" | "numeroCnj" | "clienteId"> & {
  cliente: { nome: string };
};
export type ContaOpcao = Pick<ContaBancaria, "id" | "codigo" | "nome" | "tipo" | "ativo">;
export type CategoriaOpcao = Pick<
  Categoria,
  "id" | "nome" | "tipo" | "isPessoal" | "categoriaPaiId"
>;

const LANCAMENTO_INCLUDE = {
  conta: { select: { id: true, codigo: true, nome: true } },
  categoria: { select: { id: true, nome: true, tipo: true, isPessoal: true } },
  cliente: { select: { id: true, nome: true } },
  processo: { select: { id: true, numeroCnj: true } },
  transferenciaPar: {
    select: {
      id: true,
      tipo: true,
      contaId: true,
      conta: { select: { id: true, codigo: true, nome: true } },
    },
  },
} satisfies Prisma.LancamentoInclude;

export async function listLancamentos(
  filtros: LancamentoFiltros,
): Promise<ListResult<LancamentoComRelacoes>> {
  const where = buildWhere(filtros);
  const { page, pageSize } = filtros;

  const [items, total] = await Promise.all([
    prisma.lancamento.findMany({
      where,
      orderBy: [{ data: "desc" }, { criadoEm: "desc" }],
      skip: (page - 1) * pageSize,
      take: pageSize,
      include: LANCAMENTO_INCLUDE,
    }),
    prisma.lancamento.count({ where }),
  ]);

  return { items, total, page, pageSize };
}

export function getLancamentoById(id: string): Promise<LancamentoComRelacoes | null> {
  return prisma.lancamento.findUnique({ where: { id }, include: LANCAMENTO_INCLUDE });
}

/**
 * Retorna saldo de todas as contas (ativas e inativas com movimento).
 * Saldo atual = saldoInicial + Σ ENTRADA - Σ SAIDA (todas datas).
 */
export async function saldoPorConta(): Promise<SaldoConta[]> {
  const [contas, agregados] = await Promise.all([
    prisma.contaBancaria.findMany({
      orderBy: [{ ativo: "desc" }, { codigo: "asc" }],
    }),
    prisma.lancamento.groupBy({
      by: ["contaId", "tipo"],
      _sum: { valor: true },
    }),
  ]);

  const totais = new Map<string, { entradas: number; saidas: number }>();
  for (const a of agregados) {
    const cur = totais.get(a.contaId) ?? { entradas: 0, saidas: 0 };
    const v = Number(a._sum.valor ?? 0);
    if (a.tipo === "ENTRADA") cur.entradas += v;
    else if (a.tipo === "SAIDA") cur.saidas += v;
    totais.set(a.contaId, cur);
  }

  return contas.map((c) => {
    const t = totais.get(c.id) ?? { entradas: 0, saidas: 0 };
    const inicial = Number(c.saldoInicial);
    return {
      contaId: c.id,
      codigo: c.codigo,
      nome: c.nome,
      saldoInicial: inicial,
      totalEntradas: t.entradas,
      totalSaidas: t.saidas,
      saldoAtual: inicial + t.entradas - t.saidas,
    };
  });
}

export async function listOpcoesContas(): Promise<ContaOpcao[]> {
  return prisma.contaBancaria.findMany({
    where: { ativo: true },
    orderBy: { codigo: "asc" },
    select: { id: true, codigo: true, nome: true, tipo: true, ativo: true },
  });
}

export async function listOpcoesCategorias(): Promise<CategoriaOpcao[]> {
  return prisma.categoria.findMany({
    where: { ativo: true },
    orderBy: { nome: "asc" },
    select: {
      id: true,
      nome: true,
      tipo: true,
      isPessoal: true,
      categoriaPaiId: true,
    },
    take: 500,
  });
}

export async function listOpcoesClientes(): Promise<ClienteOpcao[]> {
  return prisma.cliente.findMany({
    where: { ativo: true },
    orderBy: { nome: "asc" },
    select: { id: true, nome: true, cpfCnpj: true },
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
      cliente: { select: { nome: true } },
    },
    take: 1000,
  });
}

function buildWhere(filtros: LancamentoFiltros): Prisma.LancamentoWhereInput {
  const where: Prisma.LancamentoWhereInput = {};

  if (filtros.inicio || filtros.fim) {
    where.data = {};
    if (filtros.inicio) where.data.gte = new Date(`${filtros.inicio}T00:00:00.000Z`);
    if (filtros.fim) where.data.lte = new Date(`${filtros.fim}T00:00:00.000Z`);
  }

  if (filtros.contaId) where.contaId = filtros.contaId;
  if (filtros.categoriaId) where.categoriaId = filtros.categoriaId;
  if (filtros.clienteId) where.clienteId = filtros.clienteId;

  switch (filtros.tipo) {
    case "ENTRADA":
      where.tipo = "ENTRADA";
      where.transferenciaParId = null;
      break;
    case "SAIDA":
      where.tipo = "SAIDA";
      where.transferenciaParId = null;
      break;
    case "TRANSFERENCIA":
      where.transferenciaParId = { not: null };
      break;
    case "REAIS":
      where.transferenciaParId = null;
      break;
    case "todos":
    default:
      break;
  }

  const search = filtros.search?.trim();
  if (search) {
    where.OR = [
      { descricao: { contains: search, mode: "insensitive" } },
      { observacoes: { contains: search, mode: "insensitive" } },
      { cliente: { nome: { contains: search, mode: "insensitive" } } },
    ];
  }

  return where;
}
