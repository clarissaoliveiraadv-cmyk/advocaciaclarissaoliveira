import { z } from "zod";
import { StatusRecebivel, TipoParcela } from "@prisma/client";

const isBlank = (v: string | undefined) => !v || v.trim() === "";

const textoOpcional = (max: number) => z.string().trim().max(max).optional();

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

/**
 * Percentual humano (0..100). Persistido como fração via fromPercent().
 * Aceita vazio = sem percentual definido.
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

const inteiroPositivoOpcional = z
  .string()
  .trim()
  .optional()
  .refine(
    (v) => {
      if (isBlank(v)) return true;
      const n = Number(v);
      return Number.isInteger(n) && n > 0;
    },
    { message: "Deve ser um inteiro positivo" },
  );

export const recebivelCreateSchema = z.object({
  processoId: z.string().min(1, "Selecione um processo"),
  dataPrevista: dataObrigatoria,
  tipoParcela: z.nativeEnum(TipoParcela),
  numeroParcela: inteiroPositivoOpcional,
  totalParcelas: inteiroPositivoOpcional,
  valorIntegral: valorPositivo,
  valorParcela: valorPositivo,
  ressarcimentoEmbutido: valorNaoNegativo,
  percHonorarios: percentualObrigatorio,
  parceiroId: z.string().trim().optional(),
  percParceiro: percentualSchema,
  observacoes: textoOpcional(2000),
});

export const recebivelUpdateSchema = recebivelCreateSchema.extend({
  id: z.string().min(1),
});

export const recebivelFiltrosSchema = z.object({
  inicio: z.string().trim().optional(),
  fim: z.string().trim().optional(),
  clienteId: z.string().trim().optional(),
  processoId: z.string().trim().optional(),
  parceiroId: z.string().trim().optional(),
  status: z.union([z.nativeEnum(StatusRecebivel), z.literal("todos")]).default("todos"),
  search: z.string().trim().optional(),
  page: z.coerce.number().int().positive().default(1),
  pageSize: z.coerce.number().int().positive().max(100).default(50),
});

export type RecebivelCreateInput = z.infer<typeof recebivelCreateSchema>;
export type RecebivelUpdateInput = z.infer<typeof recebivelUpdateSchema>;
export type RecebivelFiltros = z.infer<typeof recebivelFiltrosSchema>;

export const TIPO_PARCELA_LABELS: Record<TipoParcela, string> = {
  NORMAL: "Normal",
  UNICA: "Única",
  HONORARIOS_SUCUMBENCIA: "Sucumbência",
  EXTRAORDINARIA: "Extraordinária",
};

export const STATUS_RECEBIVEL_LABELS: Record<StatusRecebivel, string> = {
  PREVISTA: "Prevista",
  RECEBIDA: "Recebida",
  REPASSADA: "Repassada",
  CANCELADA: "Cancelada",
};
