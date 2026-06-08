import { z } from "zod";
import { Perfil } from "@prisma/client";

const emailSchema = z
  .string()
  .trim()
  .toLowerCase()
  .min(1, "E-mail obrigatório")
  .email("E-mail inválido");

const senhaSchema = z
  .string()
  .min(6, "Senha deve ter ao menos 6 caracteres")
  .max(120, "Senha muito longa");

export const usuarioCreateSchema = z.object({
  nome: z.string().trim().min(1, "Nome obrigatório").max(120),
  email: emailSchema,
  perfil: z.nativeEnum(Perfil),
  senha: senhaSchema,
});

export const usuarioUpdateSchema = z.object({
  id: z.string().min(1),
  nome: z.string().trim().min(1, "Nome obrigatório").max(120),
  perfil: z.nativeEnum(Perfil),
  ativo: z.coerce.boolean(),
});

export const resetSenhaSchema = z.object({
  id: z.string().min(1),
  senha: senhaSchema,
});

export type UsuarioCreateInput = z.infer<typeof usuarioCreateSchema>;
export type UsuarioUpdateInput = z.infer<typeof usuarioUpdateSchema>;
export type ResetSenhaInput = z.infer<typeof resetSenhaSchema>;

export const PERFIL_LABELS: Record<Perfil, string> = {
  ADMIN: "Administrador",
  SECRETARIA: "Operacional",
  PARCEIRO_LEITURA: "Parceiro (somente leitura)",
};

export const PERFIL_DESCRICOES: Record<Perfil, string> = {
  ADMIN: "Acesso total, incluindo configurações sensíveis (dados do escritório, usuários).",
  SECRETARIA:
    "Pode cadastrar e operar lançamentos, recebíveis, distribuições — tudo do dia a dia.",
  PARCEIRO_LEITURA: "Apenas visualiza dados — não pode criar nem editar.",
};
