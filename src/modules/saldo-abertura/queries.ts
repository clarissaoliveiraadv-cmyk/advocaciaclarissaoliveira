import "server-only";
import { prisma } from "@/lib/prisma";

export type ContaSaldoAbertura = {
  id: string;
  codigo: string;
  nome: string;
  saldoInicial: number;
  saldoAberturaData: Date | null;
  /** Quantidade de lançamentos anteriores a `saldoAberturaData` (ignorados pelo cálculo). */
  lancamentosIgnorados: number;
  /** Quantidade total de lançamentos da conta (independentemente da data). */
  lancamentosTotais: number;
};

/**
 * Lista todas as contas (ativas e inativas) com informação relevante para
 * a página de saldo de abertura: saldo, data de abertura, e contagem de
 * lançamentos que ficariam ignorados.
 */
export async function listContasParaAbertura(): Promise<ContaSaldoAbertura[]> {
  const contas = await prisma.contaBancaria.findMany({
    orderBy: [{ ativo: "desc" }, { codigo: "asc" }],
  });

  return Promise.all(
    contas.map(async (c) => {
      const lancamentosTotais = await prisma.lancamento.count({ where: { contaId: c.id } });
      const lancamentosIgnorados = c.saldoAberturaData
        ? await prisma.lancamento.count({
            where: { contaId: c.id, data: { lt: c.saldoAberturaData } },
          })
        : 0;
      return {
        id: c.id,
        codigo: c.codigo,
        nome: c.nome,
        saldoInicial: Number(c.saldoInicial),
        saldoAberturaData: c.saldoAberturaData,
        lancamentosIgnorados,
        lancamentosTotais,
      };
    }),
  );
}
