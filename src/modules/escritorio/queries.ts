import "server-only";
import type { Escritorio } from "@prisma/client";
import { prisma } from "@/lib/prisma";

const ID_PADRAO = "default";

/**
 * Retorna o registro singleton de configuração do escritório, criando um
 * placeholder vazio caso ainda não exista.
 */
export async function getOuCriarEscritorio(): Promise<Escritorio> {
  const existente = await prisma.escritorio.findUnique({ where: { id: ID_PADRAO } });
  if (existente) return existente;
  return prisma.escritorio.create({
    data: { id: ID_PADRAO, nome: "Advocacia Clarissa Oliveira" },
  });
}

export function escritorioEstaCompleto(e: Escritorio): boolean {
  return !!(e.nome && e.oab && e.endereco && e.cidade && e.uf);
}
