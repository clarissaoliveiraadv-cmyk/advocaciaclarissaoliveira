import "server-only";
import { TipoLancamento, TipoBeneficiario } from "@prisma/client";
import { prisma } from "@/lib/prisma";

type Periodo = { inicio: Date; fim: Date };

/**
 * DRE simplificado:
 *   Receitas = ENTRADAs (exceto transferências)
 *   Despesas = SAIDAs (exceto transferências)
 *   Resultado = Receitas - Despesas
 *
 * Quebrado por categoria.
 */
export async function getDRE(periodo: Periodo): Promise<{
  receitas: { categoria: string; valor: number }[];
  despesas: { categoria: string; valor: number }[];
  totalReceitas: number;
  totalDespesas: number;
  resultado: number;
}> {
  const lancamentos = await prisma.lancamento.findMany({
    where: {
      data: { gte: periodo.inicio, lte: periodo.fim },
      tipo: { in: [TipoLancamento.ENTRADA, TipoLancamento.SAIDA] },
      transferenciaParId: null, // exclui pares de transferência
    },
    select: {
      tipo: true,
      valor: true,
      categoria: { select: { nome: true } },
    },
  });

  const receitasMap = new Map<string, number>();
  const despesasMap = new Map<string, number>();
  let totalReceitas = 0;
  let totalDespesas = 0;

  for (const l of lancamentos) {
    const cat = l.categoria.nome;
    const v = Number(l.valor);
    if (l.tipo === TipoLancamento.ENTRADA) {
      receitasMap.set(cat, (receitasMap.get(cat) ?? 0) + v);
      totalReceitas += v;
    } else {
      despesasMap.set(cat, (despesasMap.get(cat) ?? 0) + v);
      totalDespesas += v;
    }
  }

  const receitas = Array.from(receitasMap.entries())
    .map(([categoria, valor]) => ({ categoria, valor }))
    .sort((a, b) => b.valor - a.valor);
  const despesas = Array.from(despesasMap.entries())
    .map(([categoria, valor]) => ({ categoria, valor }))
    .sort((a, b) => b.valor - a.valor);

  return {
    receitas,
    despesas,
    totalReceitas,
    totalDespesas,
    resultado: totalReceitas - totalDespesas,
  };
}

/**
 * Fluxo mensal: para cada mês do período, retorna entradas, saídas e saldo.
 */
export async function getFluxoMensal(periodo: Periodo): Promise<
  Array<{ mes: string; entradas: number; saidas: number; saldo: number }>
> {
  const lancamentos = await prisma.lancamento.findMany({
    where: {
      data: { gte: periodo.inicio, lte: periodo.fim },
      tipo: { in: [TipoLancamento.ENTRADA, TipoLancamento.SAIDA] },
      transferenciaParId: null,
    },
    select: { data: true, tipo: true, valor: true },
  });

  const mapa = new Map<string, { entradas: number; saidas: number }>();
  for (const l of lancamentos) {
    const ano = l.data.getUTCFullYear();
    const mes = String(l.data.getUTCMonth() + 1).padStart(2, "0");
    const chave = `${ano}-${mes}`;
    const atual = mapa.get(chave) ?? { entradas: 0, saidas: 0 };
    const v = Number(l.valor);
    if (l.tipo === TipoLancamento.ENTRADA) atual.entradas += v;
    else atual.saidas += v;
    mapa.set(chave, atual);
  }

  return Array.from(mapa.entries())
    .map(([mes, v]) => ({ mes, entradas: v.entradas, saidas: v.saidas, saldo: v.entradas - v.saidas }))
    .sort((a, b) => a.mes.localeCompare(b.mes));
}

/**
 * Posição por cliente: para cada cliente com movimentação no período,
 *   - total bruto recebido (entradas vinculadas a recebíveis dele)
 *   - total repassado (itens REPASSADO com beneficiario=CLIENTE)
 *   - em custódia (itens RETIDO_CUSTODIA com beneficiario=CLIENTE)
 *   - pendente (PENDENTE_REPASSE)
 *   - ressarcimentos a receber (PAGO_PELO_ESCRITORIO)
 */
export async function getPosicaoPorCliente(periodo: Periodo): Promise<
  Array<{
    clienteId: string;
    nome: string;
    bruto: number;
    repassado: number;
    custodia: number;
    pendente: number;
    ressarcAReceber: number;
  }>
> {
  const itens = await prisma.itemDistribuicao.findMany({
    where: {
      beneficiario: TipoBeneficiario.CLIENTE,
      distribuicao: { dataRecebimento: { gte: periodo.inicio, lte: periodo.fim } },
    },
    select: {
      valor: true,
      status: true,
      clienteId: true,
      cliente: { select: { id: true, nome: true } },
      distribuicao: { select: { valorBrutoRecebido: true, recebivelId: true } },
    },
  });

  const ressarcimentos = await prisma.ressarcimento.findMany({
    where: {
      data: { gte: periodo.inicio, lte: periodo.fim },
      status: "PAGO_PELO_ESCRITORIO",
    },
    select: { valor: true, clienteId: true, cliente: { select: { id: true, nome: true } } },
  });

  type Acc = {
    nome: string;
    bruto: number;
    repassado: number;
    custodia: number;
    pendente: number;
    ressarcAReceber: number;
    recebiveisVistos: Set<string>;
  };
  const mapa = new Map<string, Acc>();

  function getOrInit(id: string, nome: string): Acc {
    let v = mapa.get(id);
    if (!v) {
      v = {
        nome,
        bruto: 0,
        repassado: 0,
        custodia: 0,
        pendente: 0,
        ressarcAReceber: 0,
        recebiveisVistos: new Set(),
      };
      mapa.set(id, v);
    }
    return v;
  }

  for (const i of itens) {
    if (!i.clienteId || !i.cliente) continue;
    const acc = getOrInit(i.cliente.id, i.cliente.nome);
    const recId = i.distribuicao.recebivelId;
    if (!acc.recebiveisVistos.has(recId)) {
      acc.bruto += Number(i.distribuicao.valorBrutoRecebido);
      acc.recebiveisVistos.add(recId);
    }
    const v = Number(i.valor);
    if (i.status === "REPASSADO") acc.repassado += v;
    else if (i.status === "RETIDO_CUSTODIA") acc.custodia += v;
    else acc.pendente += v;
  }

  for (const r of ressarcimentos) {
    if (!r.cliente) continue;
    const acc = getOrInit(r.cliente.id, r.cliente.nome);
    acc.ressarcAReceber += Number(r.valor);
  }

  return Array.from(mapa.entries())
    .map(([clienteId, acc]) => ({
      clienteId,
      nome: acc.nome,
      bruto: acc.bruto,
      repassado: acc.repassado,
      custodia: acc.custodia,
      pendente: acc.pendente,
      ressarcAReceber: acc.ressarcAReceber,
    }))
    .sort((a, b) => b.bruto - a.bruto);
}

/**
 * Demonstrativo por parceiro:
 *   - total acordado, recebido, devido, pago (de ParceriaPaga no período)
 *   - + itens de distribuição com beneficiario=PARCEIRO (repassados/pendentes)
 */
export async function getPorParceiro(periodo: Periodo): Promise<
  Array<{
    parceiroId: string;
    nome: string;
    devidoParcerias: number;
    pagoParcerias: number;
    repassadoDistribuicao: number;
    pendenteDistribuicao: number;
  }>
> {
  const parcerias = await prisma.parceriaPaga.findMany({
    where: { dataAcordo: { gte: periodo.inicio, lte: periodo.fim } },
    select: {
      parceiroId: true,
      valorRecebido: true,
      percHonorarios: true,
      ressarcimentos: true,
      percParceiro: true,
      dataPgto: true,
      parceiro: { select: { id: true, nome: true } },
    },
  });

  const itensDist = await prisma.itemDistribuicao.findMany({
    where: {
      beneficiario: TipoBeneficiario.PARCEIRO,
      distribuicao: { dataRecebimento: { gte: periodo.inicio, lte: periodo.fim } },
    },
    select: {
      valor: true,
      status: true,
      parceiroId: true,
      parceiro: { select: { id: true, nome: true } },
    },
  });

  type Acc = {
    nome: string;
    devidoParcerias: number;
    pagoParcerias: number;
    repassadoDistribuicao: number;
    pendenteDistribuicao: number;
  };
  const mapa = new Map<string, Acc>();

  function getOrInit(id: string, nome: string): Acc {
    let v = mapa.get(id);
    if (!v) {
      v = {
        nome,
        devidoParcerias: 0,
        pagoParcerias: 0,
        repassadoDistribuicao: 0,
        pendenteDistribuicao: 0,
      };
      mapa.set(id, v);
    }
    return v;
  }

  for (const p of parcerias) {
    const baseHonor = Number(p.valorRecebido) * Number(p.percHonorarios);
    const honorLiquido = Math.max(0, baseHonor - Number(p.ressarcimentos));
    const devido = Math.max(0, honorLiquido * Number(p.percParceiro));
    const acc = getOrInit(p.parceiro.id, p.parceiro.nome);
    acc.devidoParcerias += devido;
    if (p.dataPgto) acc.pagoParcerias += devido;
  }

  for (const i of itensDist) {
    if (!i.parceiroId || !i.parceiro) continue;
    const acc = getOrInit(i.parceiro.id, i.parceiro.nome);
    const v = Number(i.valor);
    if (i.status === "REPASSADO") acc.repassadoDistribuicao += v;
    else acc.pendenteDistribuicao += v;
  }

  return Array.from(mapa.entries())
    .map(([parceiroId, acc]) => ({ parceiroId, ...acc }))
    .sort((a, b) => b.devidoParcerias - a.devidoParcerias);
}
