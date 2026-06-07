import "server-only";
import type { Cliente, Distribuicao, Processo } from "@prisma/client";
import { prisma } from "@/lib/prisma";

export type ComprovanteRecebimento = {
  recebivelId: string;
  cliente: Pick<Cliente, "id" | "nome" | "cpfCnpj">;
  processo: Pick<Processo, "id" | "numeroCnj" | "vara" | "tribunal" | "parteContraria">;
  valorRecebido: number;
  dataRecebimento: Date;
  contaNome: string;
  contaCodigo: string;
  descricao: string | null;
  observacoes: string | null;
  distribuicaoId: Distribuicao["id"];
};

/**
 * Carrega os dados necessários para gerar o comprovante de recebimento de
 * um recebível. Disponível apenas quando o recebível tem uma `Distribuicao`
 * CONFIRMADA (status RECEBIDA ou REPASSADA).
 */
export async function getComprovante(recebivelId: string): Promise<ComprovanteRecebimento | null> {
  const recebivel = await prisma.recebivel.findUnique({
    where: { id: recebivelId },
    select: {
      id: true,
      cliente: { select: { id: true, nome: true, cpfCnpj: true } },
      processo: {
        select: {
          id: true,
          numeroCnj: true,
          vara: true,
          tribunal: true,
          parteContraria: true,
        },
      },
      distribuicao: {
        select: {
          id: true,
          valorBrutoRecebido: true,
          dataRecebimento: true,
          observacoes: true,
          status: true,
        },
      },
      lancamentos: {
        where: { tipo: "ENTRADA", transferenciaParId: null },
        select: {
          id: true,
          descricao: true,
          observacoes: true,
          conta: { select: { codigo: true, nome: true } },
        },
        orderBy: { criadoEm: "asc" },
        take: 1,
      },
    },
  });

  if (!recebivel || !recebivel.distribuicao || recebivel.distribuicao.status !== "CONFIRMADA") {
    return null;
  }

  const lanc = recebivel.lancamentos[0];
  if (!lanc) return null;

  return {
    recebivelId: recebivel.id,
    cliente: recebivel.cliente,
    processo: recebivel.processo,
    valorRecebido: Number(recebivel.distribuicao.valorBrutoRecebido),
    dataRecebimento: recebivel.distribuicao.dataRecebimento,
    contaNome: lanc.conta.nome,
    contaCodigo: lanc.conta.codigo,
    descricao: lanc.descricao,
    observacoes: recebivel.distribuicao.observacoes ?? lanc.observacoes,
    distribuicaoId: recebivel.distribuicao.id,
  };
}
