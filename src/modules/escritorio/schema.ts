import { z } from "zod";

const textoOpcional = (max: number) => z.string().trim().max(max).optional();

export const escritorioUpdateSchema = z.object({
  nome: z.string().trim().min(2, "Nome obrigatório").max(200),
  oab: textoOpcional(50),
  cnpj: textoOpcional(20),
  endereco: textoOpcional(300),
  cidade: textoOpcional(100),
  uf: z
    .string()
    .trim()
    .optional()
    .refine((v) => !v || (v.length === 2 && /^[A-Za-z]{2}$/.test(v)), {
      message: "UF deve ter 2 letras",
    }),
  cep: textoOpcional(20),
  telefone: textoOpcional(30),
  email: z
    .string()
    .trim()
    .optional()
    .refine((v) => !v || z.string().email().safeParse(v).success, {
      message: "E-mail inválido",
    }),
  observacoes: textoOpcional(2000),
});

export type EscritorioUpdateInput = z.infer<typeof escritorioUpdateSchema>;
