import { redirect } from "next/navigation";
import type { Perfil } from "@prisma/client";
import { auth } from "@/auth";

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
