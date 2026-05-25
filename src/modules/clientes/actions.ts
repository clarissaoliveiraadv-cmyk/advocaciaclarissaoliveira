"use server";

import { revalidatePath } from "next/cache";
import { AcaoAuditoria } from "@prisma/client";
import { prisma } from "@/lib/prisma";
import { registrarAuditoria } from "@/lib/audit";
import { requirePerfil } from "@/lib/auth/guards";
import { onlyDigits } from "@/lib/format";
import type { ActionResult } from "@/modules/_shared/types";
import {
  clienteCreateSchema,
  clienteUpdateSchema,
  type ClienteCreateInput,
  type ClienteUpdateInput,
} from "./schema";
import { clienteTemDependencias } from "./queries";

const PERFIS_ESCRITA = ["ADMIN", "SOCIA", "SECRETARIA"] as const;
const RESOURCE = "cliente";

export async function criarCliente(
  input: ClienteCreateInput,
): Promise<ActionResult<{ id: string }>> {
  const session = await requirePerfil(PERFIS_ESCRITA);
  const parsed = clienteCreateSchema.safeParse(input);
  if (!parsed.success)
    return { ok: false, error: "Dados inválidos", fieldErrors: parsed.error.flatten().fieldErrors };

  const data = toDbData(parsed.data);
  const cliente = await prisma.cliente.create({ data });

  await registrarAuditoria({
    entidade: RESOURCE,
    entidadeId: cliente.id,
    acao: AcaoAuditoria.CRIAR,
    usuarioId: session.user.id,
    dadosDepois: data,
  });

  revalidatePath("/clientes");
  return { ok: true, data: { id: cliente.id } };
}

export async function atualizarCliente(input: ClienteUpdateInput): Promise<ActionResult> {
  const session = await requirePerfil(PERFIS_ESCRITA);
  const parsed = clienteUpdateSchema.safeParse(input);
  if (!parsed.success)
    return { ok: false, error: "Dados inválidos", fieldErrors: parsed.error.flatten().fieldErrors };

  const { id, ...rest } = parsed.data;
  const antes = await prisma.cliente.findUnique({ where: { id } });
  if (!antes) return { ok: false, error: "Cliente não encontrado" };

  const data = toDbData(rest);
  await prisma.cliente.update({ where: { id }, data });

  await registrarAuditoria({
    entidade: RESOURCE,
    entidadeId: id,
    acao: AcaoAuditoria.ATUALIZAR,
    usuarioId: session.user.id,
    dadosAntes: snapshot(antes),
    dadosDepois: data,
  });

  revalidatePath("/clientes");
  return { ok: true, data: undefined };
}

export async function alternarAtivoCliente(id: string): Promise<ActionResult> {
  const session = await requirePerfil(PERFIS_ESCRITA);
  const antes = await prisma.cliente.findUnique({ where: { id } });
  if (!antes) return { ok: false, error: "Cliente não encontrado" };

  await prisma.cliente.update({ where: { id }, data: { ativo: !antes.ativo } });

  await registrarAuditoria({
    entidade: RESOURCE,
    entidadeId: id,
    acao: AcaoAuditoria.ATUALIZAR,
    usuarioId: session.user.id,
    dadosAntes: { ativo: antes.ativo },
    dadosDepois: { ativo: !antes.ativo },
  });

  revalidatePath("/clientes");
  return { ok: true, data: undefined };
}

export async function excluirCliente(id: string): Promise<ActionResult> {
  const session = await requirePerfil(PERFIS_ESCRITA);
  const antes = await prisma.cliente.findUnique({ where: { id } });
  if (!antes) return { ok: false, error: "Cliente não encontrado" };

  if (await clienteTemDependencias(id)) {
    return {
      ok: false,
      error:
        "Cliente possui processos, recebíveis ou lançamentos vinculados. Inative em vez de excluir.",
    };
  }

  await prisma.cliente.delete({ where: { id } });

  await registrarAuditoria({
    entidade: RESOURCE,
    entidadeId: id,
    acao: AcaoAuditoria.EXCLUIR,
    usuarioId: session.user.id,
    dadosAntes: snapshot(antes),
  });

  revalidatePath("/clientes");
  return { ok: true, data: undefined };
}

function toDbData(input: ClienteCreateInput) {
  const text = (v: string | undefined) => {
    const t = v?.trim();
    return t ? t : null;
  };
  const digits = (v: string | undefined) => {
    const d = v ? onlyDigits(v) : "";
    return d || null;
  };
  return {
    nome: input.nome.trim(),
    cpfCnpj: digits(input.cpfCnpj),
    email: text(input.email),
    telefone: digits(input.telefone),
    observacoes: text(input.observacoes),
  };
}

function snapshot(c: {
  nome: string;
  cpfCnpj: string | null;
  email: string | null;
  telefone: string | null;
  observacoes: string | null;
  ativo: boolean;
}) {
  return {
    nome: c.nome,
    cpfCnpj: c.cpfCnpj,
    email: c.email,
    telefone: c.telefone,
    observacoes: c.observacoes,
    ativo: c.ativo,
  };
}
