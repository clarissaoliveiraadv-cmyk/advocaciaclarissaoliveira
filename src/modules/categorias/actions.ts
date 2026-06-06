"use server";

import { revalidatePath } from "next/cache";
import { AcaoAuditoria } from "@prisma/client";
import { prisma } from "@/lib/prisma";
import { registrarAuditoria } from "@/lib/audit";
import { requirePerfil } from "@/lib/auth/guards";
import type { ActionResult } from "@/modules/_shared/types";

type ActionError = { ok: false; error: string; fieldErrors?: Record<string, string[]> };
import {
  categoriaCreateSchema,
  categoriaUpdateSchema,
  type CategoriaCreateInput,
  type CategoriaUpdateInput,
} from "./schema";
import { categoriaTemDependencias } from "./queries";

const PERFIS_ESCRITA = ["ADMIN", "SOCIA", "SECRETARIA"] as const;
const RESOURCE = "categoria";
const ROUTE = "/cadastros/categorias";

export async function criarCategoria(
  input: CategoriaCreateInput,
): Promise<ActionResult<{ id: string }>> {
  const session = await requirePerfil(PERFIS_ESCRITA);
  const parsed = categoriaCreateSchema.safeParse(input);
  if (!parsed.success)
    return {
      ok: false,
      error: "Dados inválidos",
      fieldErrors: parsed.error.flatten().fieldErrors,
    };

  const paiId = normalizarPaiId(parsed.data.categoriaPaiId);

  if (paiId) {
    const erroPai = await validarPai(paiId, parsed.data.tipo);
    if (erroPai) return erroPai;
  }

  const duplicado = await existeIrmaoMesmoNome(parsed.data.nome, paiId);
  if (duplicado) return erroNomeDuplicado(paiId);

  const data = {
    nome: parsed.data.nome.trim(),
    tipo: parsed.data.tipo,
    isPessoal: parsed.data.isPessoal,
    categoriaPaiId: paiId,
  };
  const categoria = await prisma.categoria.create({ data });

  await registrarAuditoria({
    entidade: RESOURCE,
    entidadeId: categoria.id,
    acao: AcaoAuditoria.CRIAR,
    usuarioId: session.user.id,
    dadosDepois: data,
  });

  revalidatePath(ROUTE);
  return { ok: true, data: { id: categoria.id } };
}

export async function atualizarCategoria(input: CategoriaUpdateInput): Promise<ActionResult> {
  const session = await requirePerfil(PERFIS_ESCRITA);
  const parsed = categoriaUpdateSchema.safeParse(input);
  if (!parsed.success)
    return {
      ok: false,
      error: "Dados inválidos",
      fieldErrors: parsed.error.flatten().fieldErrors,
    };

  const { id } = parsed.data;
  const antes = await prisma.categoria.findUnique({ where: { id } });
  if (!antes) return { ok: false, error: "Categoria não encontrada" };

  const paiId = normalizarPaiId(parsed.data.categoriaPaiId);
  const novoTipo = parsed.data.tipo;

  if (paiId === id) {
    return {
      ok: false,
      error: "Uma categoria não pode ser pai dela mesma.",
      fieldErrors: { categoriaPaiId: ["Auto-vínculo não permitido"] },
    };
  }

  if (paiId) {
    const erroPai = await validarPai(paiId, novoTipo);
    if (erroPai) return erroPai;

    if (await formaCiclo(id, paiId)) {
      return {
        ok: false,
        error: "Não é possível: o pai escolhido é descendente desta categoria.",
        fieldErrors: { categoriaPaiId: ["Ciclo hierárquico"] },
      };
    }
  }

  if (novoTipo !== antes.tipo) {
    const temFilhas = await prisma.categoria.count({ where: { categoriaPaiId: id } });
    if (temFilhas > 0) {
      return {
        ok: false,
        error:
          "Não é possível mudar o tipo: esta categoria tem subcategorias. Mude/remova as filhas primeiro.",
        fieldErrors: { tipo: ["Possui subcategorias"] },
      };
    }
  }

  const duplicado = await existeIrmaoMesmoNome(parsed.data.nome, paiId, id);
  if (duplicado) return erroNomeDuplicado(paiId);

  const data = {
    nome: parsed.data.nome.trim(),
    tipo: novoTipo,
    isPessoal: parsed.data.isPessoal,
    categoriaPaiId: paiId,
  };

  await prisma.categoria.update({ where: { id }, data });

  await registrarAuditoria({
    entidade: RESOURCE,
    entidadeId: id,
    acao: AcaoAuditoria.ATUALIZAR,
    usuarioId: session.user.id,
    dadosAntes: {
      nome: antes.nome,
      tipo: antes.tipo,
      isPessoal: antes.isPessoal,
      categoriaPaiId: antes.categoriaPaiId,
    },
    dadosDepois: data,
  });

  revalidatePath(ROUTE);
  return { ok: true, data: undefined };
}

export async function alternarAtivoCategoria(id: string): Promise<ActionResult> {
  const session = await requirePerfil(PERFIS_ESCRITA);
  const antes = await prisma.categoria.findUnique({ where: { id } });
  if (!antes) return { ok: false, error: "Categoria não encontrada" };

  await prisma.categoria.update({ where: { id }, data: { ativo: !antes.ativo } });
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

export async function excluirCategoria(id: string): Promise<ActionResult> {
  const session = await requirePerfil(PERFIS_ESCRITA);
  const antes = await prisma.categoria.findUnique({ where: { id } });
  if (!antes) return { ok: false, error: "Categoria não encontrada" };

  const deps = await categoriaTemDependencias(id);
  if (deps.lancamentos > 0 || deps.filhas > 0) {
    const motivos: string[] = [];
    if (deps.lancamentos > 0) motivos.push(`${deps.lancamentos} lançamento(s)`);
    if (deps.filhas > 0) motivos.push(`${deps.filhas} subcategoria(s)`);
    return {
      ok: false,
      error: `Categoria possui ${motivos.join(" e ")} vinculados. Inative em vez de excluir.`,
    };
  }

  await prisma.categoria.delete({ where: { id } });
  await registrarAuditoria({
    entidade: RESOURCE,
    entidadeId: id,
    acao: AcaoAuditoria.EXCLUIR,
    usuarioId: session.user.id,
    dadosAntes: {
      nome: antes.nome,
      tipo: antes.tipo,
      isPessoal: antes.isPessoal,
      categoriaPaiId: antes.categoriaPaiId,
    },
  });
  revalidatePath(ROUTE);
  return { ok: true, data: undefined };
}

// ----- helpers -----

function normalizarPaiId(raw: string | undefined): string | null {
  const v = raw?.trim();
  return v ? v : null;
}

async function validarPai(paiId: string, tipoFilha: string): Promise<ActionError | null> {
  const pai = await prisma.categoria.findUnique({
    where: { id: paiId },
    select: { id: true, tipo: true, ativo: true },
  });
  if (!pai) {
    return {
      ok: false,
      error: "Categoria pai não encontrada.",
      fieldErrors: { categoriaPaiId: ["Pai inexistente"] },
    };
  }
  if (pai.tipo !== tipoFilha) {
    return {
      ok: false,
      error: `A categoria pai é de tipo "${pai.tipo}", incompatível com "${tipoFilha}".`,
      fieldErrors: { categoriaPaiId: ["Tipo incompatível com o pai"] },
    };
  }
  return null;
}

/**
 * Sobe a árvore a partir de paiId verificando se passa por idAtual.
 * Caminho protegido por Set para evitar loops infinitos em dados inconsistentes.
 */
async function formaCiclo(idAtual: string, paiId: string): Promise<boolean> {
  const visitados = new Set<string>();
  let cursor: string | null = paiId;
  while (cursor) {
    if (cursor === idAtual) return true;
    if (visitados.has(cursor)) return true;
    visitados.add(cursor);
    const pai: { categoriaPaiId: string | null } | null = await prisma.categoria.findUnique({
      where: { id: cursor },
      select: { categoriaPaiId: true },
    });
    cursor = pai?.categoriaPaiId ?? null;
  }
  return false;
}

async function existeIrmaoMesmoNome(
  nome: string,
  paiId: string | null,
  excludeId?: string,
): Promise<boolean> {
  const existing = await prisma.categoria.findFirst({
    where: {
      nome: { equals: nome.trim(), mode: "insensitive" },
      categoriaPaiId: paiId,
      ...(excludeId ? { NOT: { id: excludeId } } : {}),
    },
    select: { id: true },
  });
  return !!existing;
}

function erroNomeDuplicado(paiId: string | null): ActionError {
  return {
    ok: false,
    error: paiId
      ? "Já existe uma subcategoria com este nome sob o mesmo pai."
      : "Já existe uma categoria raiz com este nome.",
    fieldErrors: { nome: ["Nome já cadastrado"] },
  };
}
