import { z } from "zod";
import { TipoParceiro } from "@prisma/client";

const textoOpcional = (max: number) => z.string().trim().max(max).optional();

const isBlank = (v: string | undefined) => !v || v.trim() === "";

export const tipoParceiroSchema = z.nativeEnum(TipoParceiro);

/**
 * Percentual padrão de sucumbência: 0 a 100, opcional.
 * Persistido no banco como FRAÇÃO (0..1) via Decimal(5,4).
 * Validamos como string (compatível com input HTML) e convertemos na action.
 */
const percentualSchema = z
  .string()
  .trim()
  .optional()
  .refine(
    (v) => {
      if (isBlank(v)) return true;
      const n = Number(v);
      return !Number.isNaN(n) && n >= 0 && n <= 100;
    },
    { message: "Percentual deve estar entre 0 e 100" },
  );

export const parceiroCreateSchema = z.object({
  nome: z.string().trim().min(2, "Nome obrigatório (mín. 2 caracteres)").max(200),
  tipo: tipoParceiroSchema,
  oab: textoOpcional(50),
  percentualPadraoSucumbencia: percentualSchema,
});

export const parceiroUpdateSchema = parceiroCreateSchema.extend({
  id: z.string().min(1),
});

export const parceiroFiltrosSchema = z.object({
  search: z.string().trim().optional(),
  tipo: z.union([tipoParceiroSchema, z.literal("todos")]).default("todos"),
  ativo: z.enum(["todos", "ativos", "inativos"]).default("ativos"),
});

export type ParceiroCreateInput = z.infer<typeof parceiroCreateSchema>;
export type ParceiroUpdateInput = z.infer<typeof parceiroUpdateSchema>;
export type ParceiroFiltros = z.infer<typeof parceiroFiltrosSchema>;

export const TIPO_PARCEIRO_LABELS: Record<TipoParceiro, string> = {
  PARCEIRO_EXTERNO: "Parceiro externo",
  FUNCIONARIO: "Funcionário",
};
