import type { Prisma, AcaoAuditoria } from "@prisma/client";
import { prisma } from "@/lib/prisma";

type AuditInput = {
  entidade: string;
  entidadeId: string;
  acao: AcaoAuditoria;
  usuarioId?: string | null;
  dadosAntes?: Prisma.InputJsonValue;
  dadosDepois?: Prisma.InputJsonValue;
};

export async function registrarAuditoria(input: AuditInput): Promise<void> {
  await prisma.auditoria.create({
    data: {
      entidade: input.entidade,
      entidadeId: input.entidadeId,
      acao: input.acao,
      usuarioId: input.usuarioId ?? null,
      dadosAntes: input.dadosAntes,
      dadosDepois: input.dadosDepois,
    },
  });
}
