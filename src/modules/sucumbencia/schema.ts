import { z } from "zod";

const valorPositivo = z.coerce
  .number()
  .finite("Valor inválido")
  .positive("Valor deve ser maior que zero");

const dataObrigatoria = z
  .string()
  .trim()
  .min(1, "Data obrigatória")
  .regex(/^\d{4}-\d{2}-\d{2}$/, "Data deve estar no formato yyyy-MM-dd");

const percentualOpcional = z
  .string()
  .trim()
  .optional()
  .refine(
    (v) => {
      if (!v) return true;
      const n = Number(v);
      return !Number.isNaN(n) && n >= 0 && n <= 100;
    },
    { message: "Percentual deve estar entre 0 e 100" },
  );

const textoOpcional = (max: number) => z.string().trim().max(max).optional();

const baseShape = {
  processoId: z.string().min(1, "Selecione um processo"),
  valorTotal: valorPositivo,
  dataRecebimento: dataObrigatoria,
  contaRecebimentoId: z.string().min(1, "Selecione a conta de recebimento"),
  categoriaLancamentoId: z.string().min(1, "Selecione a categoria do lançamento"),
  descricaoLancamento: z
    .string()
    .trim()
    .min(1, "Descrição do lançamento obrigatória")
    .max(200),
  parceiroExternoId: textoOpcional(40),
  percParceiroExterno: percentualOpcional,
  observacoes: textoOpcional(2000),
};

const parceiroConsistente = (v: {
  parceiroExternoId?: string;
  percParceiroExterno?: string;
}) => {
  const id = v.parceiroExternoId?.trim();
  const perc = v.percParceiroExterno?.trim();
  if (id && !perc) return false;
  if (!id && perc) return false;
  return true;
};

export const sucumbenciaCreateSchema = z.object(baseShape).refine(parceiroConsistente, {
  message: "Informe parceiro externo e percentual juntos.",
  path: ["percParceiroExterno"],
});

export const sucumbenciaUpdateSchema = z
  .object({ id: z.string().min(1), ...baseShape })
  .refine(parceiroConsistente, {
    message: "Informe parceiro externo e percentual juntos.",
    path: ["percParceiroExterno"],
  });

export const marcarRepasseParceiroSchema = z.object({
  id: z.string().min(1),
  data: dataObrigatoria,
});

export const sucumbenciaFiltrosSchema = z.object({
  inicio: z.string().trim().optional(),
  fim: z.string().trim().optional(),
  clienteId: z.string().trim().optional(),
  processoId: z.string().trim().optional(),
  status: z
    .union([
      z.literal("sem_parceiro"),
      z.literal("parceiro_pendente"),
      z.literal("parceiro_pago"),
      z.literal("todos"),
    ])
    .default("todos"),
  search: z.string().trim().optional(),
  page: z.coerce.number().int().positive().default(1),
  pageSize: z.coerce.number().int().positive().max(100).default(50),
});

export type SucumbenciaCreateInput = z.infer<typeof sucumbenciaCreateSchema>;
export type SucumbenciaUpdateInput = z.infer<typeof sucumbenciaUpdateSchema>;
export type MarcarRepasseParceiroInput = z.infer<typeof marcarRepasseParceiroSchema>;
export type SucumbenciaFiltros = z.infer<typeof sucumbenciaFiltrosSchema>;

/**
 * Distribuição da sucumbência:
 *   - Se houver parceiro externo, sai a fatia dele (percParceiroExterno × bruto).
 *   - O restante é integralmente do escritório.
 */
export function calcularDistribuicaoSucumbencia(args: {
  valorTotal: number;
  percParceiroExterno: number; // fração 0..1
}) {
  const parceiroValor = args.valorTotal * args.percParceiroExterno;
  const escritorio = args.valorTotal - parceiroValor;
  return { parceiroExterno: parceiroValor, escritorio };
}
