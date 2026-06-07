import "server-only";
import { TipoBeneficiario } from "@prisma/client";
import { prisma } from "@/lib/prisma";
import { fimDoMesAtual, inicioDoMesAtual } from "@/lib/datas";

/**
 * Beneficiários cujo dinheiro pertence ao ESCRITÓRIO — não conta como
 * obrigação pendente. RESSARCIMENTO entra aqui porque é apenas recuperação
 * de despesa adiantada pelo escritório.
 */
const BENEFICIARIOS_DO_ESCRITORIO: ReadonlyArray<TipoBeneficiario> = [
  TipoBeneficiario.ESCRITORIO_CONTRATUAL,
  TipoBeneficiario.ESCRITORIO_SUCUMBENCIA,
  TipoBeneficiario.RESSARCIMENTO,
];

/**
 * Beneficiários cujo dinheiro NÃO é do escritório — entram como obrigação
 * pendente até serem repassados.
 */
const BENEFICIARIOS_OBRIGACAO: ReadonlyArray<TipoBeneficiario> = [
  TipoBeneficiario.CLIENTE,
  TipoBeneficiario.PARCEIRO,
  TipoBeneficiario.PERITO,
  TipoBeneficiario.FGTS,
  TipoBeneficiario.CUSTAS,
  TipoBeneficiario.OUTRO,
];

export type IndicadoresFinanceiros = {
  /** Soma do saldo de TODAS as contas (ativas e inativas). */
  saldoBancario: number;
  /**
   * Dinheiro que está nas contas mas pertence a terceiros e ainda não foi
   * repassado (itens de distribuição PENDENTE_REPASSE com beneficiário
   * cliente/parceiro/perito/FGTS/custas/outro).
   */
  emCustodia: number;
  /** O que é do escritório de verdade. Pode ser negativo em caso de descompasso. */
  saldoLiquido: number;
  /** Honorários efetivamente apurados no mês (ESCRITORIO_* dos itens confirmados no mês). */
  faturamentoHonorariosMes: number;
  /** Recuperação de custas adiantadas (RESSARCIMENTO) no mês. */
  ressarcimentoMes: number;
  /** Soma de valores de parcelas PREVISTAS com dataPrevista no mês corrente. */
  recebiveisPrevistosMes: number;
  /** Quantidade de parcelas previstas no mês. */
  quantidadeRecebiveisPrevistos: number;
  /** Detalhamento da custódia por beneficiário (apenas valores > 0). */
  custodiaPorBeneficiario: Array<{ beneficiario: TipoBeneficiario; valor: number }>;
};

export async function getIndicadoresFinanceiros(): Promise<IndicadoresFinanceiros> {
  const inicioMes = inicioDoMesAtual();
  const fimMes = fimDoMesAtual();

  const [contas, agregadosLanc, itensPendentes, itensMes, recebiveisMes] = await Promise.all([
    prisma.contaBancaria.findMany({ select: { saldoInicial: true } }),
    prisma.lancamento.groupBy({
      by: ["tipo"],
      _sum: { valor: true },
    }),
    prisma.itemDistribuicao.groupBy({
      by: ["beneficiario"],
      where: { status: "PENDENTE_REPASSE" },
      _sum: { valor: true },
    }),
    prisma.itemDistribuicao.findMany({
      where: {
        distribuicao: {
          status: "CONFIRMADA",
          dataRecebimento: { gte: inicioMes, lte: fimMes },
        },
      },
      select: { beneficiario: true, valor: true },
    }),
    prisma.recebivel.findMany({
      where: {
        status: "PREVISTA",
        dataPrevista: { gte: inicioMes, lte: fimMes },
      },
      select: { valorParcela: true },
    }),
  ]);

  // Saldo bancário = saldosIniciais + entradas - saídas
  let saldoBancario = 0;
  for (const c of contas) saldoBancario += Number(c.saldoInicial);
  for (const a of agregadosLanc) {
    const v = Number(a._sum.valor ?? 0);
    if (a.tipo === "ENTRADA") saldoBancario += v;
    else if (a.tipo === "SAIDA") saldoBancario -= v;
  }

  // Em custódia = pendentes de beneficiários não-escritório
  let emCustodia = 0;
  const custodiaPorBeneficiario: Array<{ beneficiario: TipoBeneficiario; valor: number }> = [];
  for (const i of itensPendentes) {
    const v = Number(i._sum.valor ?? 0);
    if (BENEFICIARIOS_OBRIGACAO.includes(i.beneficiario)) {
      emCustodia += v;
      if (v > 0) custodiaPorBeneficiario.push({ beneficiario: i.beneficiario, valor: v });
    }
  }
  custodiaPorBeneficiario.sort((a, b) => b.valor - a.valor);

  // Faturamento e ressarcimento do mês
  let faturamentoHonorariosMes = 0;
  let ressarcimentoMes = 0;
  for (const i of itensMes) {
    const v = Number(i.valor);
    if (
      i.beneficiario === TipoBeneficiario.ESCRITORIO_CONTRATUAL ||
      i.beneficiario === TipoBeneficiario.ESCRITORIO_SUCUMBENCIA
    ) {
      faturamentoHonorariosMes += v;
    } else if (i.beneficiario === TipoBeneficiario.RESSARCIMENTO) {
      ressarcimentoMes += v;
    }
  }

  // Recebíveis previstos no mês
  let recebiveisPrevistosMes = 0;
  for (const r of recebiveisMes) recebiveisPrevistosMes += Number(r.valorParcela);

  return {
    saldoBancario,
    emCustodia,
    saldoLiquido: saldoBancario - emCustodia,
    faturamentoHonorariosMes,
    ressarcimentoMes,
    recebiveisPrevistosMes,
    quantidadeRecebiveisPrevistos: recebiveisMes.length,
    custodiaPorBeneficiario,
  };
}

export { BENEFICIARIOS_DO_ESCRITORIO, BENEFICIARIOS_OBRIGACAO };
