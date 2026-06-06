import "server-only";
import type { AdvogadoParceiro, Cliente, Prisma, Processo, Recebivel } from "@prisma/client";
import { prisma } from "@/lib/prisma";
import type { ListResult } from "@/modules/_shared/types";
import type { RecebivelFiltros } from "./schema";

export type RecebivelComRelacoes = Recebivel & {
  processo: Pick<Processo, "id" | "numeroCnj" | "natureza">;
  cliente: Pick<Cliente, "id" | "nome">;
  parceiro: Pick<AdvogadoParceiro, "id" | "nome"> | null;
};

export type ProcessoOpcao = Pick<Processo, "id" | "numeroCnj" | "clienteId"> & {
  cliente: Pick<Cliente, "id" | "nome">;
};

export type ClienteOpcao = Pick<Cliente, "id" | "nome" | "cpfCnpj">;
export type ParceiroOpcao = Pick<AdvogadoParceiro, "id" | "nome" | "tipo">;

const INCLUDE_RELACOES = {
  processo: { select: { id: true, numeroCnj: true, natureza: true } },
  cliente: { select: { id: true, nome: true } },
  parceiro: { select: { id: true, nome: true } },
} satisfies Prisma.RecebivelInclude;

export async function listRecebiveis(
  filtros: RecebivelFiltros,
): Promise<ListResult<RecebivelComRelacoes>> {
  const where = buildWhere(filtros);
  const { page, pageSize } = filtros;

  const [items, total] = await Promise.all([
    prisma.recebivel.findMany({
      where,
      orderBy: [{ dataPrevista: "asc" }, { criadoEm: "asc" }],
      skip: (page - 1) * pageSize,
      take: pageSize,
      include: INCLUDE_RELACOES,
    }),
    prisma.recebivel.count({ where }),
  ]);

  return { items, total, page, pageSize };
}

export function getRecebivelById(id: string): Promise<RecebivelComRelacoes | null> {
  return prisma.recebivel.findUnique({ where: { id }, include: INCLUDE_RELACOES });
}

/**
 * Reservado para Slice 3.2 — quando confirmar distribuição, o recebível terá
 * uma `Distribuicao` 1-1. No 3.1 sempre retorna `false`.
 */
export async function recebivelTemDistribuicao(id: string): Promise<boolean> {
  const found = await prisma.distribuicao.findUnique({
    where: { recebivelId: id },
    select: { id: true },
  });
  return !!found;
}

export async function recebivelTemLancamentos(id: string): Promise<boolean> {
  const count = await prisma.lancamento.count({ where: { recebivelId: id } });
  return count > 0;
}

export async function statsPrevistos(filtros: RecebivelFiltros): Promise<{
  totalValor: number;
  totalRessarcimento: number;
  totalHonorariosSugeridos: number;
  totalClienteSugerido: number;
  count: number;
}> {
  const where: Prisma.RecebivelWhereInput = {
    ...buildWhere(filtros),
    status: filtros.status === "todos" ? "PREVISTA" : filtros.status,
  };

  const itens = await prisma.recebivel.findMany({
    where,
    select: {
      valorParcela: true,
      ressarcimentoEmbutido: true,
      percHonorarios: true,
    },
  });

  let totalValor = 0;
  let totalRessarcimento = 0;
  let totalHonorariosSugeridos = 0;
  for (const i of itens) {
    const v = Number(i.valorParcela);
    const r = Number(i.ressarcimentoEmbutido);
    const honor = v * Number(i.percHonorarios);
    totalValor += v;
    totalRessarcimento += r;
    totalHonorariosSugeridos += honor;
  }
  const totalClienteSugerido = Math.max(
    0,
    totalValor - totalRessarcimento - totalHonorariosSugeridos,
  );

  return {
    totalValor,
    totalRessarcimento,
    totalHonorariosSugeridos,
    totalClienteSugerido,
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
    select: { id: true, nome: true, cpfCnpj: true },
    take: 500,
  });
}

export async function listOpcoesParceiros(): Promise<ParceiroOpcao[]> {
  return prisma.advogadoParceiro.findMany({
    where: { ativo: true },
    orderBy: { nome: "asc" },
    select: { id: true, nome: true, tipo: true },
    take: 500,
  });
}

function buildWhere(filtros: RecebivelFiltros): Prisma.RecebivelWhereInput {
  const where: Prisma.RecebivelWhereInput = {};

  if (filtros.inicio || filtros.fim) {
    where.dataPrevista = {};
    if (filtros.inicio) where.dataPrevista.gte = new Date(`${filtros.inicio}T00:00:00.000Z`);
    if (filtros.fim) where.dataPrevista.lte = new Date(`${filtros.fim}T00:00:00.000Z`);
  }

  if (filtros.clienteId) where.clienteId = filtros.clienteId;
  if (filtros.processoId) where.processoId = filtros.processoId;
  if (filtros.parceiroId) where.parceiroId = filtros.parceiroId;
  if (filtros.status !== "todos") where.status = filtros.status;

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
