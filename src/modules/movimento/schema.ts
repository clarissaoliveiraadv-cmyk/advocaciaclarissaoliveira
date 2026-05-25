import { z } from "zod";
import { TipoLancamento } from "@prisma/client";

const isBlank = (v: string | undefined) => !v || v.trim() === "";

const textoOpcional = (max: number) => z.string().trim().max(max).optional();

const urlOpcional = z
  .string()
  .trim()
  .optional()
  .refine((v) => isBlank(v) || /^https?:\/\//i.test(v ?? ""), {
    message: "URL deve começar com http:// ou https://",
  });

const valorPositivo = z.coerce
  .number()
  .finite("Valor inválido")
  .positive("Valor deve ser maior que zero");

const dataObrigatoria = z
  .string()
  .trim()
  .min(1, "Data obrigatória")
  .regex(/^\d{4}-\d{2}-\d{2}$/, "Data deve estar no formato yyyy-MM-dd");

/**
 * Lançamento simples (ENTRADA ou SAIDA — sem ser perna de transferência).
 * Categoria precisa bater com o tipo (RECEITA para ENTRADA, DESPESA para SAIDA) —
 * validação reforçada na action contra o banco.
 */
export const lancamentoCreateSchema = z.object({
  data: dataObrigatoria,
  descricao: z.string().trim().min(2, "Descrição obrigatória (mín. 2 caracteres)").max(300),
  tipo: z.enum([TipoLancamento.ENTRADA, TipoLancamento.SAIDA]),
  contaId: z.string().min(1, "Selecione uma conta"),
  categoriaId: z.string().min(1, "Selecione uma categoria"),
  valor: valorPositivo,
  clienteId: z.string().trim().optional(),
  processoId: z.string().trim().optional(),
  comprovanteUrl: urlOpcional,
  observacoes: textoOpcional(2000),
});

export const lancamentoUpdateSchema = lancamentoCreateSchema.extend({
  id: z.string().min(1),
});

/**
 * Transferência interna: cria duas pernas vinculadas.
 * Conta origem != conta destino.
 */
export const transferenciaCreateSchema = z
  .object({
    data: dataObrigatoria,
    descricao: z.string().trim().min(2, "Descrição obrigatória").max(300),
    contaOrigemId: z.string().min(1, "Selecione a conta de origem"),
    contaDestinoId: z.string().min(1, "Selecione a conta de destino"),
    categoriaId: z.string().min(1, "Selecione uma categoria"),
    valor: valorPositivo,
    observacoes: textoOpcional(2000),
  })
  .refine((d) => d.contaOrigemId !== d.contaDestinoId, {
    message: "Origem e destino devem ser contas diferentes",
    path: ["contaDestinoId"],
  });

export const transferenciaUpdateSchema = z
  .object({
    id: z.string().min(1),
    data: dataObrigatoria,
    descricao: z.string().trim().min(2).max(300),
    contaOrigemId: z.string().min(1),
    contaDestinoId: z.string().min(1),
    categoriaId: z.string().min(1),
    valor: valorPositivo,
    observacoes: textoOpcional(2000),
  })
  .refine((d) => d.contaOrigemId !== d.contaDestinoId, {
    message: "Origem e destino devem ser contas diferentes",
    path: ["contaDestinoId"],
  });

/** Filtros via URL searchParams. Mês atual aplicado pela página se vier vazio. */
export const lancamentoFiltrosSchema = z.object({
  inicio: z.string().trim().optional(),
  fim: z.string().trim().optional(),
  contaId: z.string().trim().optional(),
  categoriaId: z.string().trim().optional(),
  clienteId: z.string().trim().optional(),
  tipo: z.enum(["todos", "ENTRADA", "SAIDA", "TRANSFERENCIA", "REAIS"]).default("todos"),
  search: z.string().trim().optional(),
  page: z.coerce.number().int().positive().default(1),
  pageSize: z.coerce.number().int().positive().max(100).default(50),
});

export type LancamentoCreateInput = z.infer<typeof lancamentoCreateSchema>;
export type LancamentoUpdateInput = z.infer<typeof lancamentoUpdateSchema>;
export type TransferenciaCreateInput = z.infer<typeof transferenciaCreateSchema>;
export type TransferenciaUpdateInput = z.infer<typeof transferenciaUpdateSchema>;
export type LancamentoFiltros = z.infer<typeof lancamentoFiltrosSchema>;

export const TIPO_LANCAMENTO_LABELS: Record<TipoLancamento, string> = {
  ENTRADA: "Entrada",
  SAIDA: "Saída",
  TRANSFERENCIA: "Transferência",
};

export const TIPO_FILTRO_LABELS: Record<LancamentoFiltros["tipo"], string> = {
  todos: "Todos",
  REAIS: "Apenas reais (sem transferências)",
  ENTRADA: "Entradas",
  SAIDA: "Saídas",
  TRANSFERENCIA: "Transferências internas",
};
