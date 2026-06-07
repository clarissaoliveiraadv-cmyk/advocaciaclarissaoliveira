"use server";

import { revalidarCaixa } from "@/lib/cache";
import {
  AcaoAuditoria,
  Prisma,
  StatusDistribuicao,
  StatusItemDistribuicao,
  StatusRecebivel,
  TipoBeneficiario,
  TipoLancamento,
} from "@prisma/client";
import { prisma } from "@/lib/prisma";
import { registrarAuditoria } from "@/lib/audit";
import { PERFIS_ESCRITA, requirePerfil } from "@/lib/auth/guards";
import type { ActionResult } from "@/modules/_shared/types";
import { confirmarDistribuicaoSchema, type ConfirmarDistribuicaoInput } from "./schema";

const RESOURCE_DIST = "distribuicao";
const RESOURCE_REC = "recebivel";

/**
 * Beneficiários cujo dinheiro pertence ao escritório — não precisam de repasse.
 * Ao confirmar a distribuição, esses itens entram direto como RETIDO_CUSTODIA.
 */
const BENEFICIARIOS_NO_CAIXA: ReadonlyArray<TipoBeneficiario> = [
  TipoBeneficiario.ESCRITORIO_CONTRATUAL,
  TipoBeneficiario.ESCRITORIO_SUCUMBENCIA,
  TipoBeneficiario.RESSARCIMENTO,
];

/**
 * Confirma a distribuição de um recebível em estado PREVISTA:
 *   - cria a Distribuicao + todos os itens
 *   - cria um Lançamento de ENTRADA na conta de recebimento (valor bruto)
 *   - atualiza o Recebível para status=RECEBIDA com data e conta preenchidos
 *
 * Tudo dentro de uma transação Prisma atômica.
 */
export async function confirmarDistribuicao(
  input: ConfirmarDistribuicaoInput,
): Promise<ActionResult<{ distribuicaoId: string; lancamentoId: string }>> {
  const session = await requirePerfil(PERFIS_ESCRITA);
  const parsed = confirmarDistribuicaoSchema.safeParse(input);
  if (!parsed.success)
    return {
      ok: false,
      error: "Dados inválidos",
      fieldErrors: parsed.error.flatten().fieldErrors,
    };

  const d = parsed.data;

  const recebivel = await prisma.recebivel.findUnique({ where: { id: d.recebivelId } });
  if (!recebivel) return { ok: false, error: "Recebível não encontrado" };
  if (recebivel.status !== StatusRecebivel.PREVISTA) {
    return {
      ok: false,
      error: `Recebível está em status ${recebivel.status}. Só PREVISTA pode ser recebido.`,
    };
  }

  const jaExiste = await prisma.distribuicao.findUnique({
    where: { recebivelId: d.recebivelId },
    select: { id: true },
  });
  if (jaExiste) {
    return {
      ok: false,
      error: "Já existe uma distribuição para este recebível. Reverta antes de criar nova.",
    };
  }

  const erroCategoria = await validarCategoriaReceita(d.categoriaLancamentoId);
  if (erroCategoria) return erroCategoria;

  const dataRecebimento = new Date(`${d.dataRecebimento}T00:00:00.000Z`);

  try {
    const result = await prisma.$transaction(async (tx) => {
      const lancamento = await tx.lancamento.create({
        data: {
          data: dataRecebimento,
          descricao: d.descricaoLancamento.trim(),
          tipo: TipoLancamento.ENTRADA,
          contaId: d.contaRecebimentoId,
          categoriaId: d.categoriaLancamentoId,
          valor: new Prisma.Decimal(d.valorBrutoRecebido),
          recebivelId: recebivel.id,
          clienteId: recebivel.clienteId,
          processoId: recebivel.processoId,
          criadoPorId: session.user.id,
        },
      });

      const distribuicao = await tx.distribuicao.create({
        data: {
          recebivelId: recebivel.id,
          valorBrutoRecebido: new Prisma.Decimal(d.valorBrutoRecebido),
          dataRecebimento,
          observacoes: d.observacoesDistribuicao?.trim() || null,
          status: StatusDistribuicao.CONFIRMADA,
          criadoPorId: session.user.id,
          itens: {
            create: d.itens.map((i) => ({
              beneficiario: i.beneficiario,
              descricao: i.descricao?.trim() || null,
              valor: new Prisma.Decimal(i.valor),
              // Itens do escritório (honorários e ressarcimento) já entram resolvidos
              // — o dinheiro está no caixa, não há nada a "repassar".
              status: BENEFICIARIOS_NO_CAIXA.includes(i.beneficiario)
                ? StatusItemDistribuicao.RETIDO_CUSTODIA
                : StatusItemDistribuicao.PENDENTE_REPASSE,
              clienteId: i.beneficiario === TipoBeneficiario.CLIENTE ? i.clienteId || null : null,
              parceiroId:
                i.beneficiario === TipoBeneficiario.PARCEIRO ? i.parceiroId || null : null,
              observacoes: i.observacoes?.trim() || null,
            })),
          },
        },
      });

      await tx.recebivel.update({
        where: { id: recebivel.id },
        data: {
          status: StatusRecebivel.RECEBIDA,
          dataRecebimento,
          contaRecebimentoId: d.contaRecebimentoId,
        },
      });

      return { lancamento, distribuicao };
    });

    await Promise.all([
      registrarAuditoria({
        entidade: RESOURCE_DIST,
        entidadeId: result.distribuicao.id,
        acao: AcaoAuditoria.CRIAR,
        usuarioId: session.user.id,
        dadosDepois: {
          recebivelId: recebivel.id,
          valorBruto: String(d.valorBrutoRecebido),
          quantidadeItens: d.itens.length,
          lancamentoId: result.lancamento.id,
        },
      }),
      registrarAuditoria({
        entidade: RESOURCE_REC,
        entidadeId: recebivel.id,
        acao: AcaoAuditoria.ATUALIZAR,
        usuarioId: session.user.id,
        dadosAntes: { status: recebivel.status },
        dadosDepois: {
          status: StatusRecebivel.RECEBIDA,
          dataRecebimento: dataRecebimento.toISOString(),
          contaRecebimentoId: d.contaRecebimentoId,
        },
      }),
    ]);

    revalidarCaixa();
    return {
      ok: true,
      data: { distribuicaoId: result.distribuicao.id, lancamentoId: result.lancamento.id },
    };
  } catch (error) {
    if (error instanceof Prisma.PrismaClientKnownRequestError) {
      if (error.code === "P2003") {
        return { ok: false, error: "Conta ou categoria referenciada não existe." };
      }
    }
    throw error;
  }
}

/**
 * Reverte uma distribuição CONFIRMADA:
 *   - deleta o lançamento de entrada
 *   - deleta a Distribuicao (cascade nos itens)
 *   - volta o recebível para status PREVISTA, limpa data/conta de recebimento
 *
 * Tudo atomicamente. A auditoria registra o evento.
 */
export async function reverterDistribuicao(recebivelId: string): Promise<ActionResult> {
  const session = await requirePerfil(PERFIS_ESCRITA);

  const recebivel = await prisma.recebivel.findUnique({ where: { id: recebivelId } });
  if (!recebivel) return { ok: false, error: "Recebível não encontrado" };

  const distribuicao = await prisma.distribuicao.findUnique({
    where: { recebivelId },
    include: { itens: { select: { id: true, status: true } } },
  });
  if (!distribuicao) return { ok: false, error: "Distribuição não encontrada" };

  // Bloqueio: se algum item já foi REPASSADO, não pode reverter sem desfazer o repasse primeiro
  const itemRepassado = distribuicao.itens.find(
    (i) => i.status === StatusItemDistribuicao.REPASSADO,
  );
  if (itemRepassado) {
    return {
      ok: false,
      error:
        "Esta distribuição possui itens já repassados. Reverta os repasses antes de reverter a distribuição.",
    };
  }

  const lancamento = await prisma.lancamento.findFirst({
    where: { recebivelId, transferenciaParId: null },
    select: { id: true },
  });

  await prisma.$transaction(async (tx) => {
    if (lancamento) {
      await tx.lancamento.delete({ where: { id: lancamento.id } });
    }
    await tx.distribuicao.delete({ where: { id: distribuicao.id } });
    await tx.recebivel.update({
      where: { id: recebivelId },
      data: {
        status: StatusRecebivel.PREVISTA,
        dataRecebimento: null,
        contaRecebimentoId: null,
      },
    });
  });

  await Promise.all([
    registrarAuditoria({
      entidade: RESOURCE_DIST,
      entidadeId: distribuicao.id,
      acao: AcaoAuditoria.EXCLUIR,
      usuarioId: session.user.id,
      dadosAntes: {
        recebivelId,
        valorBruto: distribuicao.valorBrutoRecebido.toString(),
        quantidadeItens: distribuicao.itens.length,
        lancamentoDeletadoId: lancamento?.id ?? null,
      },
    }),
    registrarAuditoria({
      entidade: RESOURCE_REC,
      entidadeId: recebivelId,
      acao: AcaoAuditoria.ATUALIZAR,
      usuarioId: session.user.id,
      dadosAntes: { status: recebivel.status },
      dadosDepois: { status: StatusRecebivel.PREVISTA },
    }),
  ]);

  revalidarCaixa();
  return { ok: true, data: undefined };
}

// ----- helpers -----

type ActionError = { ok: false; error: string; fieldErrors?: Record<string, string[]> };

async function validarCategoriaReceita(categoriaId: string): Promise<ActionError | null> {
  const cat = await prisma.categoria.findUnique({
    where: { id: categoriaId },
    select: { tipo: true, ativo: true },
  });
  if (!cat) {
    return {
      ok: false,
      error: "Categoria não encontrada",
      fieldErrors: { categoriaLancamentoId: ["Categoria inexistente"] },
    };
  }
  if (!cat.ativo) {
    return {
      ok: false,
      error: "Categoria inativa",
      fieldErrors: { categoriaLancamentoId: ["Categoria inativa"] },
    };
  }
  if (cat.tipo !== "RECEITA") {
    return {
      ok: false,
      error: "Categoria escolhida deve ser de RECEITA.",
      fieldErrors: { categoriaLancamentoId: ["Tipo deve ser RECEITA"] },
    };
  }
  return null;
}
