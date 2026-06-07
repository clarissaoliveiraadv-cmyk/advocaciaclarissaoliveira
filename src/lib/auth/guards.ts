import { redirect } from "next/navigation";
import type { Perfil } from "@prisma/client";
import { auth } from "@/auth";

/** Perfis que podem criar/editar/excluir registros do sistema. */
export const PERFIS_ESCRITA: ReadonlyArray<Perfil> = ["ADMIN", "SECRETARIA"];

/** Perfis com acesso a configurações sensíveis do escritório. */
export const PERFIS_ADMIN: ReadonlyArray<Perfil> = ["ADMIN"];

export async function requireAuth() {
  const session = await auth();
  if (!session?.user) redirect("/login");
  return session;
}

export async function requirePerfil(permitidos: ReadonlyArray<Perfil>) {
  const session = await requireAuth();
  if (!permitidos.includes(session.user.perfil)) {
    redirect("/dashboard?erro=sem-permissao");
  }
  return session;
}

export function temPerfil(atual: Perfil, permitidos: ReadonlyArray<Perfil>): boolean {
  return permitidos.includes(atual);
}
