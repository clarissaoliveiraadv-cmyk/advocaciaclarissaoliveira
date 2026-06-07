"use server";

import { revalidatePath } from "next/cache";
import { AcaoAuditoria, Prisma } from "@prisma/client";
import { prisma } from "@/lib/prisma";
import { registrarAuditoria } from "@/lib/audit";
import { PERFIS_ESCRITA, requirePerfil } from "@/lib/auth/guards";
import type { ActionResult } from "@/modules/_shared/types";
import {
  contaCreateSchema,
  contaUpdateSchema,
  type ContaCreateInput,
  type ContaUpdateInput,
} from "./schema";
import { contaTemDependencias } from "./queries";

const RESOURCE = "conta_bancaria";
const ROUTE = "/cadastros/contas";

export async function criarConta(input: ContaCreateInput): Promise<ActionResult<{ id: string }>> {
  const session = await requirePerfil(PERFIS_ESCRITA);
  const parsed = contaCreateSchema.safeParse(input);
  if (!parsed.success)
    return {
      ok: false,
      error: "Dados inválidos",
      fieldErrors: parsed.error.flatten().fieldErrors,
    };

  const data = toDbData(parsed.data);

  try {
    const conta = await prisma.contaBancaria.create({ data });
    await registrarAuditoria({
      entidade: RESOURCE,
      entidadeId: conta.id,
      acao: AcaoAuditoria.CRIAR,
      usuarioId: session.user.id,
      dadosDepois: serializarAudit(data),
    });
    revalidatePath(ROUTE);
    return { ok: true, data: { id: conta.id } };
  } catch (error) {
    return tratarErro(error);
  }
}

export async function atualizarConta(input: ContaUpdateInput): Promise<ActionResult> {
  const session = await requirePerfil(PERFIS_ESCRITA);
  const parsed = contaUpdateSchema.safeParse(input);
  if (!parsed.success)
    return {
      ok: false,
      error: "Dados inválidos",
      fieldErrors: parsed.error.flatten().fieldErrors,
    };

  const { id, ...rest } = parsed.data;
  const antes = await prisma.contaBancaria.findUnique({ where: { id } });
  if (!antes) return { ok: false, error: "Conta não encontrada" };

  const data = toDbData(rest);

  try {
    await prisma.contaBancaria.update({ where: { id }, data });
    await registrarAuditoria({
      entidade: RESOURCE,
      entidadeId: id,
      acao: AcaoAuditoria.ATUALIZAR,
      usuarioId: session.user.id,
      dadosAntes: serializarAudit({
        codigo: antes.codigo,
        nome: antes.nome,
        tipo: antes.tipo,
        banco: antes.banco,
        agencia: antes.agencia,
        conta: antes.conta,
        saldoInicial: antes.saldoInicial,
      }),
      dadosDepois: serializarAudit(data),
    });
    revalidatePath(ROUTE);
    return { ok: true, data: undefined };
  } catch (error) {
    return tratarErro(error);
  }
}

export async function alternarAtivoConta(id: string): Promise<ActionResult> {
  const session = await requirePerfil(PERFIS_ESCRITA);
  const antes = await prisma.contaBancaria.findUnique({ where: { id } });
  if (!antes) return { ok: false, error: "Conta não encontrada" };

  await prisma.contaBancaria.update({ where: { id }, data: { ativo: !antes.ativo } });
  await registrarAuditoria({
    entidade: RESOURCE,
    entidadeId: id,
    acao: AcaoAuditoria.ATUALIZAR,
    usuarioId: session.user.id,
    dadosAntes: { ativo: antes.ativo },
    dadosDepois: { ativo: !antes.ativo },
  });
  revalidatePath(ROUTE);
  return { ok: true, data: undefined };
}

export async function excluirConta(id: string): Promise<ActionResult> {
  const session = await requirePerfil(PERFIS_ESCRITA);
  const antes = await prisma.contaBancaria.findUnique({ where: { id } });
  if (!antes) return { ok: false, error: "Conta não encontrada" };

  if (await contaTemDependencias(id)) {
    return {
      ok: false,
      error: "Conta possui lançamentos ou recebimentos vinculados. Inative em vez de excluir.",
    };
  }

  await prisma.contaBancaria.delete({ where: { id } });
  await registrarAuditoria({
    entidade: RESOURCE,
    entidadeId: id,
    acao: AcaoAuditoria.EXCLUIR,
    usuarioId: session.user.id,
    dadosAntes: serializarAudit({
      codigo: antes.codigo,
      nome: antes.nome,
      tipo: antes.tipo,
      banco: antes.banco,
      agencia: antes.agencia,
      conta: antes.conta,
      saldoInicial: antes.saldoInicial,
    }),
  });
  revalidatePath(ROUTE);
  return { ok: true, data: undefined };
}

function toDbData(input: ContaCreateInput) {
  const text = (v: string | undefined) => {
    const t = v?.trim();
    return t ? t : null;
  };
  return {
    codigo: input.codigo.trim().toUpperCase(),
    nome: input.nome.trim(),
    tipo: input.tipo,
    banco: text(input.banco),
    agencia: text(input.agencia),
    conta: text(input.conta),
    saldoInicial: new Prisma.Decimal(input.saldoInicial),
  };
}

function serializarAudit(data: Record<string, unknown>): Prisma.InputJsonValue {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(data)) {
    out[k] = v instanceof Prisma.Decimal ? v.toString() : (v ?? null);
  }
  return out as Prisma.InputJsonValue;
}

function tratarErro<T>(error: unknown): ActionResult<T> {
  if (error instanceof Prisma.PrismaClientKnownRequestError) {
    if (error.code === "P2002") {
      return {
        ok: false,
        error: "Já existe uma conta com este código.",
        fieldErrors: { codigo: ["Código já cadastrado"] },
      };
    }
  }
  throw error;
}
