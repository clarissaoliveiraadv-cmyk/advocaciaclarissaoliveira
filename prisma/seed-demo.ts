import "dotenv/config";
import {
  NaturezaProcesso,
  PrismaClient,
  StatusProcesso,
  StatusRecebivel,
  TipoBeneficiario,
  TipoParceiro,
  TipoParcela,
} from "@prisma/client";

const prisma = new PrismaClient();

async function main() {
  console.warn("Limpando dados de demo...");
  await prisma.itemDistribuicao.deleteMany();
  await prisma.distribuicao.deleteMany();
  await prisma.lancamento.deleteMany();
  await prisma.recebivel.deleteMany();
  await prisma.processo.deleteMany();
  await prisma.cliente.deleteMany({ where: { email: { contains: "@demo" } } });
  await prisma.advogadoParceiro.deleteMany({ where: { nome: { contains: "Demo" } } });

  console.warn("Criando clientes...");
  const clientes = await Promise.all([
    prisma.cliente.create({
      data: {
        nome: "Maria Santos da Silva",
        cpfCnpj: "52998224725",
        email: "maria@demo.com",
        telefone: "11987654321",
      },
    }),
    prisma.cliente.create({
      data: {
        nome: "João Pereira",
        cpfCnpj: "11144477735",
        email: "joao@demo.com",
        telefone: "11999998888",
      },
    }),
    prisma.cliente.create({
      data: {
        nome: "Construtora Alfa LTDA",
        cpfCnpj: "11222333000181",
        email: "contato@alfa-demo.com",
        telefone: "1133334444",
      },
    }),
  ]);

  console.warn("Criando parceiro de demonstração...");
  const parceiro = await prisma.advogadoParceiro.create({
    data: {
      nome: "Dra. Vivian Lamounier (Demo)",
      tipo: TipoParceiro.PARCEIRO_EXTERNO,
      oab: "123456/MG",
      percentualPadraoSucumbencia: 0.4,
    },
  });

  console.warn("Criando processos...");
  const processos = await Promise.all([
    prisma.processo.create({
      data: {
        clienteId: clientes[0].id,
        numeroCnj: "00008374320238130024",
        natureza: NaturezaProcesso.TRABALHISTA,
        vara: "2ª Vara do Trabalho",
        tribunal: "TRT-3",
        parteContraria: "Empresa XYZ",
        status: StatusProcesso.EM_ANDAMENTO,
      },
    }),
    prisma.processo.create({
      data: {
        clienteId: clientes[1].id,
        numeroCnj: "00000014520248260001",
        natureza: NaturezaProcesso.PREVIDENCIARIO,
        vara: "Vara Federal de Previdenciário",
        tribunal: "TRF-3",
        status: StatusProcesso.EM_ANDAMENTO,
      },
    }),
    prisma.processo.create({
      data: {
        clienteId: clientes[2].id,
        natureza: NaturezaProcesso.CIVEL,
        vara: "Procedimento extrajudicial",
        status: StatusProcesso.EM_ANDAMENTO,
        observacoes: "Acordo direto, sem judicialização",
      },
    }),
  ]);

  console.warn("Criando recebíveis...");
  const hoje = new Date();
  const inicioMes = new Date(Date.UTC(hoje.getUTCFullYear(), hoje.getUTCMonth(), 1));
  const meio = new Date(Date.UTC(hoje.getUTCFullYear(), hoje.getUTCMonth(), 15));
  const fim = new Date(Date.UTC(hoje.getUTCFullYear(), hoje.getUTCMonth(), 25));

  // PREVISTA — sem parceria
  await prisma.recebivel.create({
    data: {
      processoId: processos[0].id,
      clienteId: clientes[0].id,
      dataPrevista: meio,
      tipoParcela: TipoParcela.NORMAL,
      numeroParcela: 1,
      totalParcelas: 5,
      valorIntegral: 50000,
      valorParcela: 10000,
      ressarcimentoEmbutido: 200,
      percHonorarios: 0.3,
      status: StatusRecebivel.PREVISTA,
    },
  });

  // PREVISTA — com parceria
  await prisma.recebivel.create({
    data: {
      processoId: processos[1].id,
      clienteId: clientes[1].id,
      dataPrevista: fim,
      tipoParcela: TipoParcela.UNICA,
      valorIntegral: 20000,
      valorParcela: 20000,
      ressarcimentoEmbutido: 0,
      percHonorarios: 0.3,
      parceiroId: parceiro.id,
      percParceiro: 0.4,
      status: StatusRecebivel.PREVISTA,
    },
  });

  // PREVISTA — extrajudicial
  await prisma.recebivel.create({
    data: {
      processoId: processos[2].id,
      clienteId: clientes[2].id,
      dataPrevista: inicioMes,
      tipoParcela: TipoParcela.NORMAL,
      numeroParcela: 1,
      totalParcelas: 3,
      valorIntegral: 90000,
      valorParcela: 30000,
      ressarcimentoEmbutido: 500,
      percHonorarios: 0.25,
      status: StatusRecebivel.PREVISTA,
      observacoes: "Acordo extrajudicial — Construtora Alfa",
    },
  });

  // RECEBIDA com distribuição confirmada (pronto para repasses)
  console.warn("Criando recebível RECEBIDO com distribuição...");
  const contaInter = await prisma.contaBancaria.findUnique({ where: { codigo: "INTER_PJ" } });
  const catHonor = await prisma.categoria.findFirst({
    where: { nome: "Honorário Contratual" },
  });
  if (!contaInter || !catHonor) throw new Error("Conta/categoria padrão não encontradas");

  const recebido = await prisma.recebivel.create({
    data: {
      processoId: processos[1].id,
      clienteId: clientes[1].id,
      dataPrevista: inicioMes,
      tipoParcela: TipoParcela.HONORARIOS_SUCUMBENCIA,
      valorIntegral: 8000,
      valorParcela: 8000,
      ressarcimentoEmbutido: 0,
      percHonorarios: 0.3,
      parceiroId: parceiro.id,
      percParceiro: 0.4,
      status: StatusRecebivel.RECEBIDA,
      dataRecebimento: meio,
      contaRecebimentoId: contaInter.id,
    },
  });

  await prisma.lancamento.create({
    data: {
      data: meio,
      descricao: "Honorário recebido — João Pereira",
      tipo: "ENTRADA",
      contaId: contaInter.id,
      categoriaId: catHonor.id,
      valor: 8000,
      recebivelId: recebido.id,
      clienteId: clientes[1].id,
      processoId: processos[1].id,
    },
  });

  await prisma.distribuicao.create({
    data: {
      recebivelId: recebido.id,
      valorBrutoRecebido: 8000,
      dataRecebimento: meio,
      status: "CONFIRMADA",
      itens: {
        create: [
          {
            beneficiario: TipoBeneficiario.ESCRITORIO_CONTRATUAL,
            descricao: "Honorário contratual",
            valor: 1440,
            status: "PENDENTE_REPASSE",
          },
          {
            beneficiario: TipoBeneficiario.PARCEIRO,
            descricao: "Honorário de parceria",
            valor: 960,
            status: "PENDENTE_REPASSE",
            parceiroId: parceiro.id,
          },
          {
            beneficiario: TipoBeneficiario.CLIENTE,
            descricao: "Líquido a repassar ao cliente",
            valor: 5600,
            status: "PENDENTE_REPASSE",
            clienteId: clientes[1].id,
          },
        ],
      },
    },
  });

  console.warn("Criando alguns lançamentos avulsos no movimento...");
  const catFixo = await prisma.categoria.findFirst({ where: { nome: "Fixo" } });
  const catConsumo = await prisma.categoria.findFirst({ where: { nome: "Consumo/Insumo" } });
  if (catFixo && catConsumo) {
    await prisma.lancamento.createMany({
      data: [
        {
          data: inicioMes,
          descricao: "Aluguel do escritório",
          tipo: "SAIDA",
          contaId: contaInter.id,
          categoriaId: catFixo.id,
          valor: 3500,
        },
        {
          data: meio,
          descricao: "Material de escritório",
          tipo: "SAIDA",
          contaId: contaInter.id,
          categoriaId: catConsumo.id,
          valor: 285.5,
        },
      ],
    });
  }

  console.warn("\n✓ Dados de demo criados:");
  console.warn("  • 3 clientes (Maria, João, Construtora Alfa)");
  console.warn("  • 1 parceiro (Vivian Demo)");
  console.warn("  • 3 processos (1 trabalhista, 1 previdenciário, 1 cível extrajudicial)");
  console.warn("  • 3 recebíveis PREVISTOS");
  console.warn("  • 1 recebível RECEBIDO com distribuição CONFIRMADA (pronto para repasses)");
  console.warn("  • 1 lançamento de ENTRADA + 2 SAÍDAS no movimento");
  console.warn("\nLogin: clarissaoliveira.adv@gmail.com / trocar-em-producao\n");
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
