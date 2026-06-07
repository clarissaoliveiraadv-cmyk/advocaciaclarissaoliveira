import "server-only";
import type {
  AdvogadoParceiro,
  Cliente,
  Distribuicao,
  ItemDistribuicao,
  Prisma,
  Processo,
  TipoBeneficiario,
} from "@prisma/client";
import { prisma } from "@/lib/prisma";

export type ProcessoComReceita = Pick<
  Processo,
  "id" | "numeroCnj" | "natureza" | "vara" | "tribunal" | "parteContraria"
> & {
  cliente: Pick<Cliente, "id" | "nome" | "cpfCnpj">;
  totalRecebido: number;
  quantidadeDistribuicoes: number;
  primeiraData: Date | null;
  ultimaData: Date | null;
};

export type LinhaDistribuicao = Distribuicao & {
  recebivel: {
    id: string;
    dataPrevista: Date;
    tipoParcela: string;
    numeroParcela: number | null;
    totalParcelas: number | null;
  };
  itens: (ItemDistribuicao & {
    parceiro: Pick<AdvogadoParceiro, "id" | "nome"> | null;
  })[];
};

export type PrestacaoContas = {
  processo: Pick<
    Processo,
    "id" | "numeroCnj" | "natureza" | "vara" | "tribunal" | "parteContraria" | "observacoes"
  >;
  cliente: Pick<Cliente, "id" | "nome" | "cpfCnpj">;
  periodo: { inicio: Date | null; fim: Date | null };
  distribuicoes: LinhaDistribuicao[];
  totalBruto: number;
  porBeneficiario: Record<TipoBeneficiario, number>;
  totalCliente: number;
  totalEscritorio: number;
};

export async function listProcessosComReceita(filtros: {
  search?: string;
}): Promise<ProcessoComReceita[]> {
  const distribuicoes = await prisma.distribuicao.findMany({
    where: { status: "CONFIRMADA" },
    select: {
      valorBrutoRecebido: true,
      dataRecebimento: true,
      recebivel: {
        select: {
          processo: {
            select: {
              id: true,
              numeroCnj: true,
              natureza: true,
              vara: true,
              tribunal: true,
              parteContraria: true,
              cliente: { select: { id: true, nome: true, cpfCnpj: true } },
            },
          },
        },
      },
    },
  });

  const porProcesso = new Map<string, ProcessoComReceita>();
  for (const d of distribuicoes) {
    const p = d.recebivel.processo;
    const cur = porProcesso.get(p.id) ?? {
      id: p.id,
      numeroCnj: p.numeroCnj,
      natureza: p.natureza,
      vara: p.vara,
      tribunal: p.tribunal,
      parteContraria: p.parteContraria,
      cliente: p.cliente,
      totalRecebido: 0,
      quantidadeDistribuicoes: 0,
      primeiraData: null as Date | null,
      ultimaData: null as Date | null,
    };
    cur.totalRecebido += Number(d.valorBrutoRecebido);
    cur.quantidadeDistribuicoes += 1;
    if (!cur.primeiraData || d.dataRecebimento < cur.primeiraData)
      cur.primeiraData = d.dataRecebimento;
    if (!cur.ultimaData || d.dataRecebimento > cur.ultimaData) cur.ultimaData = d.dataRecebimento;
    porProcesso.set(p.id, cur);
  }

  let lista = Array.from(porProcesso.values());

  const search = filtros.search?.trim().toLowerCase();
  if (search) {
    const digitos = search.replace(/\D/g, "");
    lista = lista.filter(
      (p) =>
        p.cliente.nome.toLowerCase().includes(search) ||
        (p.numeroCnj && p.numeroCnj.includes(digitos)) ||
        (p.parteContraria && p.parteContraria.toLowerCase().includes(search)),
    );
  }

  lista.sort((a, b) => a.cliente.nome.localeCompare(b.cliente.nome, "pt-BR"));
  return lista;
}

export async function getPrestacaoContas(
  processoId: string,
  filtros: { inicio?: string; fim?: string },
): Promise<PrestacaoContas | null> {
  const processo = await prisma.processo.findUnique({
    where: { id: processoId },
    select: {
      id: true,
      numeroCnj: true,
      natureza: true,
      vara: true,
      tribunal: true,
      parteContraria: true,
      observacoes: true,
      cliente: { select: { id: true, nome: true, cpfCnpj: true } },
    },
  });
  if (!processo) return null;

  const where: Prisma.DistribuicaoWhereInput = {
    status: "CONFIRMADA",
    recebivel: { processoId },
  };
  if (filtros.inicio || filtros.fim) {
    where.dataRecebimento = {};
    if (filtros.inicio) where.dataRecebimento.gte = new Date(`${filtros.inicio}T00:00:00.000Z`);
    if (filtros.fim) where.dataRecebimento.lte = new Date(`${filtros.fim}T00:00:00.000Z`);
  }

  const distribuicoes = await prisma.distribuicao.findMany({
    where,
    orderBy: { dataRecebimento: "asc" },
    include: {
      recebivel: {
        select: {
          id: true,
          dataPrevista: true,
          tipoParcela: true,
          numeroParcela: true,
          totalParcelas: true,
        },
      },
      itens: {
        include: { parceiro: { select: { id: true, nome: true } } },
        orderBy: { criadoEm: "asc" },
      },
    },
  });

  let totalBruto = 0;
  const porBeneficiario: Record<TipoBeneficiario, number> = {
    CLIENTE: 0,
    ESCRITORIO_CONTRATUAL: 0,
    ESCRITORIO_SUCUMBENCIA: 0,
    PARCEIRO: 0,
    PERITO: 0,
    FGTS: 0,
    RESSARCIMENTO: 0,
    CUSTAS: 0,
    OUTRO: 0,
  };
  for (const d of distribuicoes) {
    totalBruto += Number(d.valorBrutoRecebido);
    for (const i of d.itens) {
      porBeneficiario[i.beneficiario] += Number(i.valor);
    }
  }
  const totalCliente = porBeneficiario.CLIENTE;
  const totalEscritorio =
    porBeneficiario.ESCRITORIO_CONTRATUAL + porBeneficiario.ESCRITORIO_SUCUMBENCIA;

  const datas = distribuicoes.map((d) => d.dataRecebimento);
  const periodo = {
    inicio: datas.length ? datas[0] : null,
    fim: datas.length ? datas[datas.length - 1] : null,
  };

  return {
    processo,
    cliente: processo.cliente,
    periodo,
    distribuicoes,
    totalBruto,
    porBeneficiario,
    totalCliente,
    totalEscritorio,
  };
}
