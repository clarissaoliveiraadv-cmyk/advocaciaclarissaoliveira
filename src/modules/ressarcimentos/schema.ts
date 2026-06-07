import { z } from "zod";
import { StatusRessarcimento } from "@prisma/client";

const textoOpcional = (max: number) => z.string().trim().max(max).optional();

const valorPositivo = z.coerce
  .number()
  .finite("Valor inválido")
  .positive("Valor deve ser maior que zero");

const dataObrigatoria = z
  .string()
  .trim()
  .min(1, "Data obrigatória")
  .regex(/^\d{4}-\d{2}-\d{2}$/, "Data deve estar no formato yyyy-MM-dd");

const dataOpcional = z
  .string()
  .trim()
  .optional()
  .refine((v) => !v || /^\d{4}-\d{2}-\d{2}$/.test(v), {
    message: "Data deve estar no formato yyyy-MM-dd",
  });

export const ressarcimentoCreateSchema = z.object({
  processoId: z.string().min(1, "Selecione um processo"),
  data: dataObrigatoria,
  descricao: z.string().trim().min(1, "Descrição obrigatória").max(500),
  valor: valorPositivo,
  recebivelId: textoOpcional(40),
});

export const ressarcimentoUpdateSchema = ressarcimentoCreateSchema.extend({
  id: z.string().min(1),
});

export const marcarReembolsadoSchema = z.object({
  id: z.string().min(1),
  dataReembolso: dataObrigatoria,
});

export const ressarcimentoFiltrosSchema = z.object({
  inicio: z.string().trim().optional(),
  fim: z.string().trim().optional(),
  clienteId: z.string().trim().optional(),
  processoId: z.string().trim().optional(),
  status: z.union([z.nativeEnum(StatusRessarcimento), z.literal("todos")]).default("todos"),
  search: z.string().trim().optional(),
  page: z.coerce.number().int().positive().default(1),
  pageSize: z.coerce.number().int().positive().max(100).default(50),
});

export type RessarcimentoCreateInput = z.infer<typeof ressarcimentoCreateSchema>;
export type RessarcimentoUpdateInput = z.infer<typeof ressarcimentoUpdateSchema>;
export type MarcarReembolsadoInput = z.infer<typeof marcarReembolsadoSchema>;
export type RessarcimentoFiltros = z.infer<typeof ressarcimentoFiltrosSchema>;

export const STATUS_RESSARCIMENTO_LABELS: Record<StatusRessarcimento, string> = {
  PAGO_PELO_ESCRITORIO: "Pago pelo escritório",
  REEMBOLSADO: "Reembolsado",
};

// Re-export para conveniência dos componentes
export { dataOpcional };
