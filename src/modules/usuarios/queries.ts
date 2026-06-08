import "server-only";
import type { Perfil } from "@prisma/client";
import { prisma } from "@/lib/prisma";

export type UsuarioListado = {
  id: string;
  nome: string;
  email: string;
  perfil: Perfil;
  ativo: boolean;
  criadoEm: Date;
};

export async function listUsuarios(): Promise<UsuarioListado[]> {
  return prisma.usuario.findMany({
    orderBy: [{ ativo: "desc" }, { nome: "asc" }],
    select: {
      id: true,
      nome: true,
      email: true,
      perfil: true,
      ativo: true,
      criadoEm: true,
    },
  });
}
