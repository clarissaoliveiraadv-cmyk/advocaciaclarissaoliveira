"use server";

import { revalidatePath } from "next/cache";
import { AcaoAuditoria, Prisma } from "@prisma/client";
import bcrypt from "bcryptjs";
import { prisma } from "@/lib/prisma";
import { registrarAuditoria } from "@/lib/audit";
import { PERFIS_ADMIN, requirePerfil } from "@/lib/auth/guards";
import type { ActionResult } from "@/modules/_shared/types";
import {
  resetSenhaSchema,
  usuarioCreateSchema,
  usuarioUpdateSchema,
  type ResetSenhaInput,
  type UsuarioCreateInput,
  type UsuarioUpdateInput,
} from "./schema";

const RESOURCE = "usuario";
const ROUTE = "/cadastros/usuarios";

export async function criarUsuario(
  input: UsuarioCreateInput,
): Promise<ActionResult<{ id: string }>> {
  const session = await requirePerfil(PERFIS_ADMIN);
  const parsed = usuarioCreateSchema.safeParse(input);
  if (!parsed.success) {
    return {
      ok: false,
      error: "Dados inválidos",
      fieldErrors: parsed.error.flatten().fieldErrors,
    };
  }

  const senhaHash = await bcrypt.hash(parsed.data.senha, 10);
  try {
    const usuario = await prisma.usuario.create({
      data: {
        nome: parsed.data.nome.trim(),
        email: parsed.data.email,
        perfil: parsed.data.perfil,
        senhaHash,
      },
    });

    await registrarAuditoria({
      entidade: RESOURCE,
      entidadeId: usuario.id,
      acao: AcaoAuditoria.CRIAR,
      usuarioId: session.user.id,
      dadosDepois: { email: usuario.email, perfil: usuario.perfil },
    });

    revalidatePath(ROUTE);
    return { ok: true, data: { id: usuario.id } };
  } catch (error) {
    if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === "P2002") {
      return {
        ok: false,
        error: "Já existe um usuário com esse e-mail.",
        fieldErrors: { email: ["E-mail já cadastrado"] },
      };
    }
    throw error;
  }
}

export async function atualizarUsuario(input: UsuarioUpdateInput): Promise<ActionResult> {
  const session = await requirePerfil(PERFIS_ADMIN);
  const parsed = usuarioUpdateSchema.safeParse(input);
  if (!parsed.success) {
    return {
      ok: false,
      error: "Dados inválidos",
      fieldErrors: parsed.error.flatten().fieldErrors,
    };
  }

  const antes = await prisma.usuario.findUnique({ where: { id: parsed.data.id } });
  if (!antes) return { ok: false, error: "Usuário não encontrado" };

  // Bloqueio: não deixar o próprio usuário se rebaixar/desativar a ponto de
  // perder acesso. Se está mudando o próprio registro, força perfil ADMIN e
  // ativo=true para evitar lockout.
  if (parsed.data.id === session.user.id) {
    if (parsed.data.perfil !== "ADMIN" || !parsed.data.ativo) {
      return {
        ok: false,
        error: "Você não pode rebaixar ou desativar a si mesma. Peça a outro ADMIN.",
      };
    }
  }

  await prisma.usuario.update({
    where: { id: parsed.data.id },
    data: {
      nome: parsed.data.nome.trim(),
      perfil: parsed.data.perfil,
      ativo: parsed.data.ativo,
    },
  });

  await registrarAuditoria({
    entidade: RESOURCE,
    entidadeId: parsed.data.id,
    acao: AcaoAuditoria.ATUALIZAR,
    usuarioId: session.user.id,
    dadosAntes: { nome: antes.nome, perfil: antes.perfil, ativo: antes.ativo },
    dadosDepois: {
      nome: parsed.data.nome,
      perfil: parsed.data.perfil,
      ativo: parsed.data.ativo,
    },
  });

  revalidatePath(ROUTE);
  return { ok: true, data: undefined };
}

export async function resetSenhaUsuario(input: ResetSenhaInput): Promise<ActionResult> {
  const session = await requirePerfil(PERFIS_ADMIN);
  const parsed = resetSenhaSchema.safeParse(input);
  if (!parsed.success) {
    return {
      ok: false,
      error: "Dados inválidos",
      fieldErrors: parsed.error.flatten().fieldErrors,
    };
  }

  const antes = await prisma.usuario.findUnique({ where: { id: parsed.data.id } });
  if (!antes) return { ok: false, error: "Usuário não encontrado" };

  const senhaHash = await bcrypt.hash(parsed.data.senha, 10);
  await prisma.usuario.update({ where: { id: parsed.data.id }, data: { senhaHash } });

  await registrarAuditoria({
    entidade: RESOURCE,
    entidadeId: parsed.data.id,
    acao: AcaoAuditoria.ATUALIZAR,
    usuarioId: session.user.id,
    dadosDepois: { senhaRedefinida: true },
  });

  revalidatePath(ROUTE);
  return { ok: true, data: undefined };
}
