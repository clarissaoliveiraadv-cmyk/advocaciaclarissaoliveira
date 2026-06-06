import { z } from "zod";
import { onlyDigits, validarCpfCnpj } from "@/lib/format";

const isBlank = (v: string | undefined) => !v || v.trim() === "";

const nomeSchema = z.string().trim().min(2, "Nome obrigatório (mín. 2 caracteres)").max(200);

const cpfCnpjSchema = z
  .string()
  .trim()
  .optional()
  .refine((v) => isBlank(v) || validarCpfCnpj(v ?? ""), { message: "CPF/CNPJ inválido" });

const emailSchema = z
  .string()
  .trim()
  .optional()
  .refine((v) => isBlank(v) || z.string().email().safeParse(v).success, {
    message: "E-mail inválido",
  });

const telefoneSchema = z
  .string()
  .trim()
  .optional()
  .refine((v) => isBlank(v) || [10, 11].includes(onlyDigits(v ?? "").length), {
    message: "Telefone deve ter 10 ou 11 dígitos",
  });

const observacoesSchema = z.string().trim().max(2000).optional();

export const clienteCreateSchema = z.object({
  nome: nomeSchema,
  cpfCnpj: cpfCnpjSchema,
  email: emailSchema,
  telefone: telefoneSchema,
  observacoes: observacoesSchema,
});

export const clienteUpdateSchema = clienteCreateSchema.extend({
  id: z.string().min(1),
});

export const clienteFiltrosSchema = z.object({
  search: z.string().trim().optional(),
  ativo: z.enum(["todos", "ativos", "inativos"]).default("ativos"),
  page: z.coerce.number().int().positive().default(1),
  pageSize: z.coerce.number().int().positive().max(100).default(20),
});

export type ClienteCreateInput = z.infer<typeof clienteCreateSchema>;
export type ClienteUpdateInput = z.infer<typeof clienteUpdateSchema>;
export type ClienteFiltros = z.infer<typeof clienteFiltrosSchema>;
