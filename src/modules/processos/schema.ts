import { z } from "zod";
import { NaturezaProcesso, StatusProcesso } from "@prisma/client";
import { validarCnj } from "@/lib/format";

const isBlank = (v: string | undefined) => !v || v.trim() === "";

export const naturezaSchema = z.nativeEnum(NaturezaProcesso);
export const statusSchema = z.nativeEnum(StatusProcesso);

const numeroCnjSchema = z
  .string()
  .trim()
  .optional()
  .refine((v) => isBlank(v) || validarCnj(v ?? ""), {
    message: "Número CNJ inválido (formato: NNNNNNN-DD.AAAA.J.TR.OOOO)",
  });

const textoOpcional = (max: number) => z.string().trim().max(max).optional();

export const processoCreateSchema = z.object({
  clienteId: z.string().min(1, "Selecione um cliente"),
  numeroCnj: numeroCnjSchema,
  natureza: naturezaSchema,
  vara: textoOpcional(200),
  tribunal: textoOpcional(100),
  parteContraria: textoOpcional(200),
  status: statusSchema,
  observacoes: textoOpcional(2000),
});

export const processoUpdateSchema = processoCreateSchema.extend({
  id: z.string().min(1),
});

export const processoFiltrosSchema = z.object({
  search: z.string().trim().optional(),
  status: z.union([statusSchema, z.literal("todos")]).default("todos"),
  ativo: z.enum(["todos", "ativos", "inativos"]).default("ativos"),
  page: z.coerce.number().int().positive().default(1),
  pageSize: z.coerce.number().int().positive().max(100).default(20),
});

export type ProcessoCreateInput = z.infer<typeof processoCreateSchema>;
export type ProcessoUpdateInput = z.infer<typeof processoUpdateSchema>;
export type ProcessoFiltros = z.infer<typeof processoFiltrosSchema>;

export const NATUREZA_LABELS: Record<NaturezaProcesso, string> = {
  TRABALHISTA: "Trabalhista",
  CIVEL: "Cível",
  PREVIDENCIARIO: "Previdenciário",
  TRIBUTARIO: "Tributário",
  FAMILIA: "Família",
  OUTRO: "Outro",
};

export const STATUS_LABELS: Record<StatusProcesso, string> = {
  EM_ANDAMENTO: "Em andamento",
  SUSPENSO: "Suspenso",
  ENCERRADO: "Encerrado",
  ARQUIVADO: "Arquivado",
};
