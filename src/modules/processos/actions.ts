"use server";

import { revalidatePath } from "next/cache";
import { AcaoAuditoria, Prisma } from "@prisma/client";
import { prisma } from "@/lib/prisma";
import { registrarAuditoria } from "@/lib/audit";
import { requirePerfil } from "@/lib/auth/guards";
import { onlyDigits } from "@/lib/format";
import type { ActionResult } from "@/modules/_shared/types";
import {
  processoCreateSchema,
  processoUpdateSchema,
  type ProcessoCreateInput,
  type ProcessoUpdateInput,
} from "./schema";
import { processoTemDependencias } from "./queries";

const PERFIS_ESCRITA = ["ADMIN", "SOCIA", "SECRETARIA"] as const;
const RESOURCE = "processo";

export async function criarProcesso(
  input: ProcessoCreateInput,
): Promise<ActionResult<{ id: string }>> {
  const session = await requirePerfil(PERFIS_ESCRITA);
  const parsed = processoCreateSchema.safeParse(input);
  if (!parsed.success)
    return {
      ok: false,
      error: "Dados inválidos",
      fieldErrors: parsed.error.flatten().fieldErrors,
    };

  const data = toDbData(parsed.data);

  try {
    const processo = await prisma.processo.create({ data });
    await registrarAuditoria({
      entidade: RESOURCE,
      entidadeId: processo.id,
      acao: AcaoAuditoria.CRIAR,
      usuarioId: session.user.id,
      dadosDepois: data,
    });
    revalidatePath("/processos");
    return { ok: true, data: { id: processo.id } };
  } catch (error) {
    return tratarErro(error);
  }
}

export async function atualizarProcesso(input: ProcessoUpdateInput): Promise<ActionResult> {
  const session = await requirePerfil(PERFIS_ESCRITA);
  const parsed = processoUpdateSchema.safeParse(input);
  if (!parsed.success)
    return {
      ok: false,
      error: "Dados inválidos",
      fieldErrors: parsed.error.flatten().fieldErrors,
    };

  const { id, ...rest } = parsed.data;
  const antes = await prisma.processo.findUnique({ where: { id } });
  if (!antes) return { ok: false, error: "Processo não encontrado" };

  const data = toDbData(rest);

  try {
    await prisma.processo.update({ where: { id }, data });
    await registrarAuditoria({
      entidade: RESOURCE,
      entidadeId: id,
      acao: AcaoAuditoria.ATUALIZAR,
      usuarioId: session.user.id,
      dadosAntes: snapshot(antes),
      dadosDepois: data,
    });
    revalidatePath("/processos");
    return { ok: true, data: undefined };
  } catch (error) {
    return tratarErro(error);
  }
}

export async function alternarAtivoProcesso(id: string): Promise<ActionResult> {
  const session = await requirePerfil(PERFIS_ESCRITA);
  const antes = await prisma.processo.findUnique({ where: { id } });
  if (!antes) return { ok: false, error: "Processo não encontrado" };

  await prisma.processo.update({ where: { id }, data: { ativo: !antes.ativo } });
  await registrarAuditoria({
    entidade: RESOURCE,
    entidadeId: id,
    acao: AcaoAuditoria.ATUALIZAR,
    usuarioId: session.user.id,
    dadosAntes: { ativo: antes.ativo },
    dadosDepois: { ativo: !antes.ativo },
  });
  revalidatePath("/processos");
  return { ok: true, data: undefined };
}

export async function excluirProcesso(id: string): Promise<ActionResult> {
  const session = await requirePerfil(PERFIS_ESCRITA);
  const antes = await prisma.processo.findUnique({ where: { id } });
  if (!antes) return { ok: false, error: "Processo não encontrado" };

  if (await processoTemDependencias(id)) {
    return {
      ok: false,
      error:
        "Processo possui recebíveis, lançamentos ou outros registros vinculados. Inative em vez de excluir.",
    };
  }

  await prisma.processo.delete({ where: { id } });
  await registrarAuditoria({
    entidade: RESOURCE,
    entidadeId: id,
    acao: AcaoAuditoria.EXCLUIR,
    usuarioId: session.user.id,
    dadosAntes: snapshot(antes),
  });
  revalidatePath("/processos");
  return { ok: true, data: undefined };
}

function toDbData(input: ProcessoCreateInput) {
  const text = (v: string | undefined) => {
    const t = v?.trim();
    return t ? t : null;
  };
  const cnj = input.numeroCnj ? onlyDigits(input.numeroCnj) : "";
  return {
    clienteId: input.clienteId,
    numeroCnj: cnj || null,
    natureza: input.natureza,
    status: input.status,
    vara: text(input.vara),
    tribunal: text(input.tribunal),
    parteContraria: text(input.parteContraria),
    observacoes: text(input.observacoes),
  };
}

function snapshot(p: {
  clienteId: string;
  numeroCnj: string | null;
  natureza: string;
  status: string;
  vara: string | null;
  tribunal: string | null;
  parteContraria: string | null;
  observacoes: string | null;
  ativo: boolean;
}) {
  return { ...p };
}

function tratarErro<T>(error: unknown): ActionResult<T> {
  if (error instanceof Prisma.PrismaClientKnownRequestError) {
    if (error.code === "P2002") {
      return {
        ok: false,
        error: "Já existe um processo com este número CNJ.",
        fieldErrors: { numeroCnj: ["Número já cadastrado"] },
      };
    }
    if (error.code === "P2003") {
      return { ok: false, error: "Cliente selecionado não existe ou foi removido." };
    }
  }
  throw error;
}
