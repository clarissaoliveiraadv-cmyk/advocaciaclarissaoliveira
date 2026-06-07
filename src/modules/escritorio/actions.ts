"use server";

import { revalidatePath } from "next/cache";
import { AcaoAuditoria } from "@prisma/client";
import { prisma } from "@/lib/prisma";
import { registrarAuditoria } from "@/lib/audit";
import { requirePerfil } from "@/lib/auth/guards";
import type { ActionResult } from "@/modules/_shared/types";
import { escritorioUpdateSchema, type EscritorioUpdateInput } from "./schema";

const PERFIS_ESCRITA = ["ADMIN", "SOCIA"] as const;
const RESOURCE = "escritorio";
const ID_PADRAO = "default";

export async function atualizarEscritorio(input: EscritorioUpdateInput): Promise<ActionResult> {
  const session = await requirePerfil(PERFIS_ESCRITA);
  const parsed = escritorioUpdateSchema.safeParse(input);
  if (!parsed.success)
    return {
      ok: false,
      error: "Dados inválidos",
      fieldErrors: parsed.error.flatten().fieldErrors,
    };

  const antes = await prisma.escritorio.findUnique({ where: { id: ID_PADRAO } });

  const data = {
    nome: parsed.data.nome.trim(),
    oab: text(parsed.data.oab),
    cnpj: text(parsed.data.cnpj),
    endereco: text(parsed.data.endereco),
    cidade: text(parsed.data.cidade),
    uf: parsed.data.uf?.trim().toUpperCase() || null,
    cep: text(parsed.data.cep),
    telefone: text(parsed.data.telefone),
    email: text(parsed.data.email),
    observacoes: text(parsed.data.observacoes),
  };

  await prisma.escritorio.upsert({
    where: { id: ID_PADRAO },
    update: data,
    create: { id: ID_PADRAO, ...data },
  });

  await registrarAuditoria({
    entidade: RESOURCE,
    entidadeId: ID_PADRAO,
    acao: antes ? AcaoAuditoria.ATUALIZAR : AcaoAuditoria.CRIAR,
    usuarioId: session.user.id,
    dadosAntes: antes
      ? {
          nome: antes.nome,
          oab: antes.oab,
          cnpj: antes.cnpj,
          endereco: antes.endereco,
          cidade: antes.cidade,
          uf: antes.uf,
          cep: antes.cep,
          telefone: antes.telefone,
          email: antes.email,
          observacoes: antes.observacoes,
        }
      : undefined,
    dadosDepois: data,
  });

  revalidatePath("/cadastros/escritorio");
  revalidatePath("/prestacao-contas");
  return { ok: true, data: undefined };
}

function text(v: string | undefined): string | null {
  const t = v?.trim();
  return t ? t : null;
}
