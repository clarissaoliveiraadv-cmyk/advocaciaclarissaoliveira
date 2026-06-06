import "server-only";
import type { Categoria, Prisma } from "@prisma/client";
import { prisma } from "@/lib/prisma";
import type { CategoriaFiltros } from "./schema";

export type CategoriaComPai = Categoria & {
  categoriaPai: { id: string; nome: string } | null;
};

export type CategoriaArvore = CategoriaComPai & { profundidade: number };

export type CategoriaOpcao = Pick<Categoria, "id" | "nome" | "tipo" | "isPessoal"> & {
  categoriaPaiId: string | null;
};

const MAX_CATEGORIAS = 500;

export async function listCategorias(filtros: CategoriaFiltros): Promise<{
  items: CategoriaArvore[];
  total: number;
  limitAtingido: boolean;
}> {
  const where = buildWhere(filtros);

  const [items, total] = await Promise.all([
    prisma.categoria.findMany({
      where,
      orderBy: { nome: "asc" },
      include: { categoriaPai: { select: { id: true, nome: true } } },
      take: MAX_CATEGORIAS,
    }),
    prisma.categoria.count({ where }),
  ]);

  return {
    items: organizarHierarquia(items),
    total,
    limitAtingido: total > MAX_CATEGORIAS,
  };
}

export function getCategoriaById(id: string): Promise<CategoriaComPai | null> {
  return prisma.categoria.findUnique({
    where: { id },
    include: { categoriaPai: { select: { id: true, nome: true } } },
  });
}

export async function categoriaTemDependencias(id: string): Promise<{
  lancamentos: number;
  filhas: number;
}> {
  const [lancamentos, filhas] = await Promise.all([
    prisma.lancamento.count({ where: { categoriaId: id } }),
    prisma.categoria.count({ where: { categoriaPaiId: id } }),
  ]);
  return { lancamentos, filhas };
}

export async function listCategoriasParaSelecao(): Promise<CategoriaOpcao[]> {
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
    take: MAX_CATEGORIAS,
  });
}

function buildWhere(filtros: CategoriaFiltros): Prisma.CategoriaWhereInput {
  const where: Prisma.CategoriaWhereInput = {};
  if (filtros.ativo === "ativos") where.ativo = true;
  if (filtros.ativo === "inativos") where.ativo = false;
  if (filtros.tipo !== "todos") where.tipo = filtros.tipo;
  if (filtros.escopo === "escritorio") where.isPessoal = false;
  if (filtros.escopo === "pessoal") where.isPessoal = true;

  const search = filtros.search?.trim();
  if (search) {
    where.OR = [
      { nome: { contains: search, mode: "insensitive" } },
      { categoriaPai: { nome: { contains: search, mode: "insensitive" } } },
    ];
  }
  return where;
}

/**
 * Reorganiza a lista em forma de árvore (depth-first). Categorias cujo pai NÃO
 * está no resultado filtrado são tratadas como raízes (profundidade 0).
 *
 * Ordem: tipo RECEITA antes de DESPESA, escritório antes de pessoal, depois nome.
 */
export function organizarHierarquia(cats: CategoriaComPai[]): CategoriaArvore[] {
  const byId = new Map(cats.map((c) => [c.id, c]));
  const filhasPorPai = new Map<string, CategoriaComPai[]>();
  const raizes: CategoriaComPai[] = [];

  for (const c of cats) {
    const paiPresente = c.categoriaPaiId && byId.has(c.categoriaPaiId);
    if (paiPresente && c.categoriaPaiId) {
      const lista = filhasPorPai.get(c.categoriaPaiId) ?? [];
      lista.push(c);
      filhasPorPai.set(c.categoriaPaiId, lista);
    } else {
      raizes.push(c);
    }
  }

  const ordenar = (a: CategoriaComPai, b: CategoriaComPai) => {
    if (a.tipo !== b.tipo) return a.tipo === "RECEITA" ? -1 : 1;
    if (a.isPessoal !== b.isPessoal) return a.isPessoal ? 1 : -1;
    return a.nome.localeCompare(b.nome, "pt-BR");
  };

  raizes.sort(ordenar);
  for (const filhas of filhasPorPai.values()) filhas.sort(ordenar);

  const out: CategoriaArvore[] = [];
  const visit = (cat: CategoriaComPai, prof: number) => {
    out.push({ ...cat, profundidade: prof });
    const filhas = filhasPorPai.get(cat.id) ?? [];
    for (const f of filhas) visit(f, prof + 1);
  };
  for (const raiz of raizes) visit(raiz, 0);

  return out;
}
