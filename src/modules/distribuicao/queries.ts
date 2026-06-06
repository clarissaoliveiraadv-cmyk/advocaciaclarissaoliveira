import "server-only";
import {
  type ContaBancaria,
  type Categoria,
  type Cliente,
  type Distribuicao,
  type ItemDistribuicao,
  type AdvogadoParceiro,
  type Recebivel,
  TipoBeneficiario,
} from "@prisma/client";
import { prisma } from "@/lib/prisma";
import type { ItemInput } from "./schema";

export type DistribuicaoCompleta = Distribuicao & {
  itens: (ItemDistribuicao & {
    cliente: Pick<Cliente, "id" | "nome"> | null;
    parceiro: Pick<AdvogadoParceiro, "id" | "nome"> | null;
  })[];
};

export type RecebivelParaReceber = Recebivel & {
  cliente: Pick<Cliente, "id" | "nome">;
  processo: { id: string; numeroCnj: string | null };
  parceiro: Pick<AdvogadoParceiro, "id" | "nome"> | null;
};

export type ContaOpcao = Pick<ContaBancaria, "id" | "codigo" | "nome" | "tipo" | "ativo">;
export type CategoriaReceitaOpcao = Pick<Categoria, "id" | "nome" | "isPessoal">;
export type ParceiroOpcao = Pick<AdvogadoParceiro, "id" | "nome" | "tipo">;

export function getDistribuicaoCompleta(recebivelId: string): Promise<DistribuicaoCompleta | null> {
  return prisma.distribuicao.findUnique({
    where: { recebivelId },
    include: {
      itens: {
        include: {
          cliente: { select: { id: true, nome: true } },
          parceiro: { select: { id: true, nome: true } },
        },
        orderBy: { criadoEm: "asc" },
      },
    },
  });
}

export async function getRecebivelParaReceber(id: string): Promise<RecebivelParaReceber | null> {
  return prisma.recebivel.findUnique({
    where: { id },
    include: {
      cliente: { select: { id: true, nome: true } },
      processo: { select: { id: true, numeroCnj: true } },
      parceiro: { select: { id: true, nome: true } },
    },
  });
}

export async function listOpcoesContas(): Promise<ContaOpcao[]> {
  return prisma.contaBancaria.findMany({
    where: { ativo: true },
    orderBy: { codigo: "asc" },
    select: { id: true, codigo: true, nome: true, tipo: true, ativo: true },
  });
}

export async function listOpcoesCategoriasReceita(): Promise<CategoriaReceitaOpcao[]> {
  return prisma.categoria.findMany({
    where: { ativo: true, tipo: "RECEITA" },
    orderBy: { nome: "asc" },
    select: { id: true, nome: true, isPessoal: true },
  });
}

export type CategoriaDespesaOpcao = Pick<Categoria, "id" | "nome" | "isPessoal">;

export async function listOpcoesCategoriasDespesa(): Promise<CategoriaDespesaOpcao[]> {
  return prisma.categoria.findMany({
    where: { ativo: true, tipo: "DESPESA" },
    orderBy: { nome: "asc" },
    select: { id: true, nome: true, isPessoal: true },
  });
}

export async function listOpcoesParceiros(): Promise<ParceiroOpcao[]> {
  return prisma.advogadoParceiro.findMany({
    where: { ativo: true },
    orderBy: { nome: "asc" },
    select: { id: true, nome: true, tipo: true },
  });
}

/**
 * Helper PURO (sem acesso ao banco): a partir de um Recebivel já carregado,
 * monta a lista de itens sugeridos para pré-popular o formulário de receber.
 */
export function sugerirItens(
  recebivel: Pick<
    Recebivel,
    | "clienteId"
    | "valorParcela"
    | "ressarcimentoEmbutido"
    | "percHonorarios"
    | "parceiroId"
    | "percParceiro"
  >,
): ItemInput[] {
  const v = Number(recebivel.valorParcela);
  const r = Number(recebivel.ressarcimentoEmbutido);
  const ph = Number(recebivel.percHonorarios);
  const pp = recebivel.percParceiro ? Number(recebivel.percParceiro) : 0;
  const honor = v * ph;
  const parceiroValor = recebivel.parceiroId ? honor * pp : 0;
  const escritorio = honor - parceiroValor;
  const cliente = Math.max(0, v - r - honor);

  const itens: ItemInput[] = [];

  if (r > 0) {
    itens.push({
      beneficiario: TipoBeneficiario.RESSARCIMENTO,
      descricao: "Ressarcimento de custas adiantadas",
      valor: r,
    });
  }
  if (escritorio > 0) {
    itens.push({
      beneficiario: TipoBeneficiario.ESCRITORIO_CONTRATUAL,
      descricao: "Honorário contratual",
      valor: round2(escritorio),
    });
  }
  if (parceiroValor > 0 && recebivel.parceiroId) {
    itens.push({
      beneficiario: TipoBeneficiario.PARCEIRO,
      descricao: "Honorário de parceria",
      valor: round2(parceiroValor),
      parceiroId: recebivel.parceiroId,
    });
  }
  if (cliente > 0) {
    itens.push({
      beneficiario: TipoBeneficiario.CLIENTE,
      descricao: "Líquido a repassar ao cliente",
      valor: round2(cliente),
      clienteId: recebivel.clienteId,
    });
  }

  return itens;
}

function round2(n: number): number {
  return Math.round(n * 100) / 100;
}

/** Sugere uma categoria de RECEITA para o lançamento de entrada (heurística). */
export async function categoriaReceitaSugerida(): Promise<string | null> {
  const cat = await prisma.categoria.findFirst({
    where: {
      ativo: true,
      tipo: "RECEITA",
      isPessoal: false,
      OR: [
        { nome: { contains: "honorário", mode: "insensitive" } },
        { nome: { contains: "honorario", mode: "insensitive" } },
      ],
    },
    select: { id: true },
  });
  return cat?.id ?? null;
}
