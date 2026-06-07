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

export const sucumbenciaCreateSchema = z
  .object({
    processoId: z.string().min(1, "Selecione um processo"),
    valorTotal: valorPositivo,
    dataRecebimento: dataObrigatoria,
    parceiroExternoId: textoOpcional(40),
    percParceiroExterno: percentualOpcional,
    percEscritorio: percentualObrigatorio,
    percClarissa: percentualObrigatorio,
    percVivian: percentualObrigatorio,
    observacoes: textoOpcional(2000),
  })
  .refine(
    (v) => {
      const total =
        Number(v.percEscritorio) + Number(v.percClarissa) + Number(v.percVivian);
      // Aceita pequenas variações de arredondamento
      return Math.abs(total - 100) < 0.01;
    },
    {
      message: "% Escritório + % Clarissa + % Vivian deve somar 100",
      path: ["percEscritorio"],
    },
  )
  .refine(
    (v) => {
      const id = v.parceiroExternoId?.trim();
      const perc = v.percParceiroExterno?.trim();
      // Se um foi informado, o outro também deve estar
      if (id && !perc) return false;
      if (!id && perc) return false;
      return true;
    },
    {
      message: "Informe parceiro externo e percentual juntos.",
      path: ["percParceiroExterno"],
    },
  );

export const sucumbenciaUpdateSchema = z
  .object({
    id: z.string().min(1),
    processoId: z.string().min(1, "Selecione um processo"),
    valorTotal: valorPositivo,
    dataRecebimento: dataObrigatoria,
    parceiroExternoId: textoOpcional(40),
    percParceiroExterno: percentualOpcional,
    percEscritorio: percentualObrigatorio,
    percClarissa: percentualObrigatorio,
    percVivian: percentualObrigatorio,
    observacoes: textoOpcional(2000),
  })
  .refine(
    (v) =>
      Math.abs(
        Number(v.percEscritorio) + Number(v.percClarissa) + Number(v.percVivian) - 100,
      ) < 0.01,
    {
      message: "% Escritório + % Clarissa + % Vivian deve somar 100",
      path: ["percEscritorio"],
    },
  )
  .refine(
    (v) => {
      const id = v.parceiroExternoId?.trim();
      const perc = v.percParceiroExterno?.trim();
      if (id && !perc) return false;
      if (!id && perc) return false;
      return true;
    },
    {
      message: "Informe parceiro externo e percentual juntos.",
      path: ["percParceiroExterno"],
    },
  );

export const marcarRepasseSchema = z.object({
  id: z.string().min(1),
  socia: z.enum(["clarissa", "vivian"]),
  data: dataObrigatoria,
});

export const sucumbenciaFiltrosSchema = z.object({
  inicio: z.string().trim().optional(),
  fim: z.string().trim().optional(),
  clienteId: z.string().trim().optional(),
  processoId: z.string().trim().optional(),
  status: z
    .union([
      z.literal("pendente_clarissa"),
      z.literal("pendente_vivian"),
      z.literal("ambas_pagas"),
      z.literal("todos"),
    ])
    .default("todos"),
  search: z.string().trim().optional(),
  page: z.coerce.number().int().positive().default(1),
  pageSize: z.coerce.number().int().positive().max(100).default(50),
});

export type SucumbenciaCreateInput = z.infer<typeof sucumbenciaCreateSchema>;
export type SucumbenciaUpdateInput = z.infer<typeof sucumbenciaUpdateSchema>;
export type MarcarRepasseInput = z.infer<typeof marcarRepasseSchema>;
export type SucumbenciaFiltros = z.infer<typeof sucumbenciaFiltrosSchema>;

/**
 * Calcula a distribuição da sucumbência:
 *   - Se houver parceiro externo, sai primeiro a fatia dele do bruto.
 *   - O restante é dividido entre escritório, Clarissa e Vivian conforme percentuais.
 */
export function calcularDistribuicaoSucumbencia(args: {
  valorTotal: number;
  percParceiroExterno: number; // fração 0..1
  percEscritorio: number; // fração 0..1
  percClarissa: number; // fração 0..1
  percVivian: number; // fração 0..1
}) {
  const parceiroValor = args.valorTotal * args.percParceiroExterno;
  const base = args.valorTotal - parceiroValor;
  return {
    parceiroExterno: parceiroValor,
    escritorio: base * args.percEscritorio,
    clarissa: base * args.percClarissa,
    vivian: base * args.percVivian,
  };
}
