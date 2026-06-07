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
   * repassado. Inclui:
   *  - itens de distribuição PENDENTE_REPASSE (cliente/parceiro/perito/FGTS/custas/outro)
   *  - fatia de parceiro externo em Sucumbência ainda não repassada
   *  - fatia devida em ParceriaPaga (valorRecebido × %honor − ressarc) × %parceiro,
   *    quando dataPgto = null
   *  - recebíveis RECEBIDOS sem Distribuição confirmada (estimativa da parte do
   *    cliente, postura conservadora)
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

  const [
    contas,
    agregadosLanc,
    itensPendentes,
    itensMes,
    recebiveisMes,
    sucumbenciaParceiroPendente,
    sucumbenciaMes,
    recebidasSemDistribuicao,
    parceriasPendentes,
  ] = await Promise.all([
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
    prisma.sucumbencia.findMany({
      where: {
        parceiroExternoId: { not: null },
        dataRepasseParceiroExterno: null,
      },
      select: { valorTotal: true, percParceiroExterno: true },
    }),
    prisma.sucumbencia.findMany({
      where: { dataRecebimento: { gte: inicioMes, lte: fimMes } },
      select: { valorTotal: true, percParceiroExterno: true },
    }),
    // Crítico #1: recebíveis marcados como RECEBIDA mas SEM distribuição confirmada.
    // O dinheiro entrou no caixa (compõe saldoBancario), mas nenhum item de custódia
    // foi criado. Sem isso, saldoLiquido fica inflado.
    prisma.recebivel.findMany({
      where: {
        status: "RECEBIDA",
        OR: [{ distribuicao: { is: null } }, { distribuicao: { status: { not: "CONFIRMADA" } } }],
      },
      select: {
        valorParcela: true,
        ressarcimentoEmbutido: true,
        percHonorarios: true,
        percParceiro: true,
      },
    }),
    // Crítico #2: parcerias com valorRecebido > 0 e ainda não pagas. A fatia do
    // parceiro já está no caixa do escritório mas é obrigação pendente.
    prisma.parceriaPaga.findMany({
      where: { dataPgto: null, valorRecebido: { gt: 0 } },
      select: {
        valorRecebido: true,
        percHonorarios: true,
        ressarcimentos: true,
        percParceiro: true,
      },
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
  // Sucumbência: fatia de parceiro externo ainda não repassada é obrigação pendente
  let custodiaParceiros = 0;
  for (const s of sucumbenciaParceiroPendente) {
    custodiaParceiros += Number(s.valorTotal) * Number(s.percParceiroExterno ?? 0);
  }
  // Parcerias: fatia devida a parceiros já recebida mas ainda não paga
  for (const p of parceriasPendentes) {
    const baseHonor = Number(p.valorRecebido) * Number(p.percHonorarios);
    const honorLiquido = Math.max(0, baseHonor - Number(p.ressarcimentos));
    const devido = Math.max(0, honorLiquido * Number(p.percParceiro));
    custodiaParceiros += devido;
  }
  if (custodiaParceiros > 0) {
    emCustodia += custodiaParceiros;
    custodiaPorBeneficiario.push({
      beneficiario: TipoBeneficiario.PARCEIRO,
      valor: custodiaParceiros,
    });
  }
  // Recebíveis RECEBIDOS sem distribuição confirmada: estimamos a parte do
  // cliente + ressarcimento embutido como "ainda do cliente" até a usuária
  // confirmar a distribuição (postura conservadora — não inflar o saldo).
  let custodiaSemDist = 0;
  for (const r of recebidasSemDistribuicao) {
    const v = Number(r.valorParcela);
    const ressarc = Number(r.ressarcimentoEmbutido);
    const honor = v * Number(r.percHonorarios);
    const valorCliente = Math.max(0, v - ressarc - honor);
    custodiaSemDist += valorCliente;
  }
  if (custodiaSemDist > 0) {
    emCustodia += custodiaSemDist;
    custodiaPorBeneficiario.push({
      beneficiario: TipoBeneficiario.CLIENTE,
      valor: custodiaSemDist,
    });
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
  // Sucumbência do mês entra no faturamento de honorários (parte líquida do escritório)
  for (const s of sucumbenciaMes) {
    const bruto = Number(s.valorTotal);
    const percParc = Number(s.percParceiroExterno ?? 0);
    faturamentoHonorariosMes += bruto * (1 - percParc);
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
