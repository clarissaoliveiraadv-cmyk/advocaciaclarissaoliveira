import { z } from "zod";
import { TipoConta } from "@prisma/client";

const textoOpcional = (max: number) => z.string().trim().max(max).optional();

export const tipoContaSchema = z.nativeEnum(TipoConta);

export const contaCreateSchema = z.object({
  codigo: z
    .string()
    .trim()
    .min(2, "Mínimo 2 caracteres")
    .max(20, "Máximo 20 caracteres")
    .regex(/^[A-Za-z0-9_-]+$/, "Use apenas letras, números, _ ou -"),
  nome: z.string().trim().min(2, "Nome obrigatório").max(120),
  tipo: tipoContaSchema,
  banco: textoOpcional(100),
  agencia: textoOpcional(20),
  conta: textoOpcional(30),
  saldoInicial: z.coerce.number().finite("Valor inválido"),
});

export const contaUpdateSchema = contaCreateSchema.extend({
  id: z.string().min(1),
});

export const contaFiltrosSchema = z.object({
  search: z.string().trim().optional(),
  tipo: z.union([tipoContaSchema, z.literal("todos")]).default("todos"),
  ativo: z.enum(["todos", "ativos", "inativos"]).default("ativos"),
  page: z.coerce.number().int().positive().default(1),
  pageSize: z.coerce.number().int().positive().max(100).default(20),
});

export type ContaCreateInput = z.infer<typeof contaCreateSchema>;
export type ContaUpdateInput = z.infer<typeof contaUpdateSchema>;
export type ContaFiltros = z.infer<typeof contaFiltrosSchema>;

export const TIPO_CONTA_LABELS: Record<TipoConta, string> = {
  CAIXA_FISICO: "Caixa físico",
  CONTA_CORRENTE: "Conta corrente",
  POUPANCA: "Poupança",
  INVESTIMENTO: "Investimento",
};
