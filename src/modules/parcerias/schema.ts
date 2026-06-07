import { z } from "zod";

const valorPositivo = z.coerce
  .number()
  .finite("Valor inválido")
  .positive("Valor deve ser maior que zero");

const valorNaoNegativo = z.coerce
  .number()
  .finite("Valor inválido")
  .nonnegative("Valor não pode ser negativo");

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

const percentualObrigatorio = z
  .string()
  .trim()
  .min(1, "Percentual obrigatório")
  .refine(
    (v) => {
      const n = Number(v);
      return !Number.isNaN(n) && n >= 0 && n <= 100;
    },
    { message: "Percentual deve estar entre 0 e 100" },
  );

const textoOpcional = (max: number) => z.string().trim().max(max).optional();

export const parceriaCreateSchema = z.object({
  parceiroId: z.string().min(1, "Selecione um parceiro"),
  processoId: z.string().min(1, "Selecione um processo"),
  dataAcordo: dataObrigatoria,
  valorTotal: valorPositivo,
  valorRecebido: valorNaoNegativo,
  percHonorarios: percentualObrigatorio,
  ressarcimentos: valorNaoNegativo,
  percParceiro: percentualObrigatorio,
  dataPgto: dataOpcional,
  observacoes: textoOpcional(2000),
});

export const parceriaUpdateSchema = parceriaCreateSchema.extend({
  id: z.string().min(1),
});

export const marcarParceriaPagaSchema = z.object({
  id: z.string().min(1),
  dataPgto: dataObrigatoria,
});

export const parceriaFiltrosSchema = z.object({
  inicio: z.string().trim().optional(),
  fim: z.string().trim().optional(),
  parceiroId: z.string().trim().optional(),
  clienteId: z.string().trim().optional(),
  processoId: z.string().trim().optional(),
  status: z.union([z.literal("PENDENTE"), z.literal("PAGA"), z.literal("todos")]).default("todos"),
  search: z.string().trim().optional(),
  page: z.coerce.number().int().positive().default(1),
  pageSize: z.coerce.number().int().positive().max(100).default(50),
});

export type ParceriaCreateInput = z.infer<typeof parceriaCreateSchema>;
export type ParceriaUpdateInput = z.infer<typeof parceriaUpdateSchema>;
export type MarcarParceriaPagaInput = z.infer<typeof marcarParceriaPagaSchema>;
export type ParceriaFiltros = z.infer<typeof parceriaFiltrosSchema>;

export const STATUS_PARCERIA_LABELS: Record<"PENDENTE" | "PAGA", string> = {
  PENDENTE: "Pendente",
  PAGA: "Paga",
};

/**
 * Calcula o valor devido ao parceiro com base nos valores correntes da parceria.
 *
 *   base honorários = valorRecebido × percHonorarios
 *   honorários líquidos = base − ressarcimentos
 *   devido ao parceiro = honorários líquidos × percParceiro
 *
 * Resultado nunca negativo.
 */
export function calcularDevidoAoParceiro(args: {
  valorRecebido: number;
  percHonorarios: number; // fração 0..1
  ressarcimentos: number;
  percParceiro: number; // fração 0..1
}): number {
  const baseHonor = args.valorRecebido * args.percHonorarios;
  const honorLiquido = Math.max(0, baseHonor - args.ressarcimentos);
  return Math.max(0, honorLiquido * args.percParceiro);
}
