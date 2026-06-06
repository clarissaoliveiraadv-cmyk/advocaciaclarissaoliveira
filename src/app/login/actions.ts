"use server";

import { redirect } from "next/navigation";
import { AuthError } from "next-auth";
import { signIn } from "@/auth";
import { loginSchema } from "./schema";
import type { ActionResult } from "@/modules/_shared/types";

export async function loginAction(formData: FormData): Promise<ActionResult> {
  const parsed = loginSchema.safeParse({
    email: formData.get("email"),
    senha: formData.get("senha"),
  });

  if (!parsed.success) {
    return { ok: false, error: "Dados inválidos", fieldErrors: parsed.error.flatten().fieldErrors };
  }

  try {
    await signIn("credentials", {
      email: parsed.data.email,
      senha: parsed.data.senha,
      redirectTo: "/dashboard",
    });
  } catch (error) {
    if (error instanceof AuthError) {
      redirect("/login?erro=1");
    }
    throw error;
  }

  return { ok: true, data: undefined };
}
