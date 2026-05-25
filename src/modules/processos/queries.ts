import "server-only";
import type { Cliente, Prisma, Processo } from "@prisma/client";
import { prisma } from "@/lib/prisma";
import { onlyDigits } from "@/lib/format";
import type { ListResult } from "@/modules/_shared/types";
import type { ProcessoFiltros } from "./schema";

export type ProcessoComCliente = Processo & {
  cliente: Pick<Cliente, "id" | "nome" | "cpfCnpj">;
};

export async function listProcessos(
  filtros: ProcessoFiltros,
): Promise<ListResult<ProcessoComCliente>> {
  const where = buildWhere(filtros);
  const { page, pageSize } = filtros;

  const [items, total] = await Promise.all([
    prisma.processo.findMany({
      where,
      orderBy: [{ ativo: "desc" }, { criadoEm: "desc" }],
      skip: (page - 1) * pageSize,
      take: pageSize,
      include: { cliente: { select: { id: true, nome: true, cpfCnpj: true } } },
    }),
    prisma.processo.count({ where }),
  ]);

  return { items, total, page, pageSize };
}

export function getProcessoById(id: string): Promise<ProcessoComCliente | null> {
  return prisma.processo.findUnique({
    where: { id },
    include: { cliente: { select: { id: true, nome: true, cpfCnpj: true } } },
  });
}

export async function processoTemDependencias(id: string): Promise<boolean> {
  const [recebiveis, lancamentos, ressarcimentos, sucumbencias, parcerias] = await Promise.all([
    prisma.recebivel.count({ where: { processoId: id } }),
    prisma.lancamento.count({ where: { processoId: id } }),
    prisma.ressarcimento.count({ where: { processoId: id } }),
    prisma.sucumbencia.count({ where: { processoId: id } }),
    prisma.parceriaPaga.count({ where: { processoId: id } }),
  ]);
  return recebiveis + lancamentos + ressarcimentos + sucumbencias + parcerias > 0;
}

export async function listClientesParaSelecao(): Promise<
  Array<Pick<Cliente, "id" | "nome" | "cpfCnpj">>
> {
  return prisma.cliente.findMany({
    where: { ativo: true },
    orderBy: { nome: "asc" },
    select: { id: true, nome: true, cpfCnpj: true },
    take: 500,
  });
}

function buildWhere(filtros: ProcessoFiltros): Prisma.ProcessoWhereInput {
  const where: Prisma.ProcessoWhereInput = {};

  if (filtros.ativo === "ativos") where.ativo = true;
  if (filtros.ativo === "inativos") where.ativo = false;
  if (filtros.status !== "todos") where.status = filtros.status;

  const search = filtros.search?.trim();
  if (search) {
    const termos: Prisma.ProcessoWhereInput[] = [
      { numeroCnj: { contains: onlyDigits(search) || search } },
      { vara: { contains: search, mode: "insensitive" } },
      { tribunal: { contains: search, mode: "insensitive" } },
      { parteContraria: { contains: search, mode: "insensitive" } },
      { cliente: { nome: { contains: search, mode: "insensitive" } } },
    ];
    where.OR = termos;
  }

  return where;
}
