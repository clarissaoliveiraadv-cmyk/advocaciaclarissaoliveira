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

const competenciaSchema = z
  .string()
  .trim()
  .min(1, "Competência obrigatória")
  .regex(/^\d{4}-\d{2}$/, "Competência deve estar no formato yyyy-MM");

const diaVencimentoSchema = z.coerce
  .number()
  .int("Dia deve ser inteiro")
  .min(1, "Dia mínimo 1")
  .max(31, "Dia máximo 31");

const textoOpcional = (max: number) => z.string().trim().max(max).optional();

export const despesaFixaCreateSchema = z.object({
  nome: z.string().trim().min(1, "Nome obrigatório").max(120),
  categoriaId: z.string().min(1, "Selecione uma categoria de despesa"),
  contaId: z.string().min(1, "Selecione a conta de débito"),
  valorEstimado: valorPositivo,
  diaVencimento: diaVencimentoSchema,
  ativo: z.coerce.boolean(),
  observacoes: textoOpcional(1000),
});

export const despesaFixaUpdateSchema = despesaFixaCreateSchema.extend({
  id: z.string().min(1),
});

export const gerarPrevisoesSchema = z.object({
  competencia: competenciaSchema,
});

export const marcarPrevisaoPagaSchema = z.object({
  id: z.string().min(1),
  dataPagamento: dataObrigatoria,
  valorPago: valorPositivo,
  contaId: z.string().min(1, "Selecione a conta"),
  descricao: z.string().trim().min(1, "Descrição obrigatória").max(200),
});

export const previsaoFiltrosSchema = z.object({
  competencia: z.string().trim().optional(),
  status: z.union([z.literal("pendente"), z.literal("paga"), z.literal("todos")]).default("todos"),
});

export type DespesaFixaCreateInput = z.infer<typeof despesaFixaCreateSchema>;
export type DespesaFixaUpdateInput = z.infer<typeof despesaFixaUpdateSchema>;
export type GerarPrevisoesInput = z.infer<typeof gerarPrevisoesSchema>;
export type MarcarPrevisaoPagaInput = z.infer<typeof marcarPrevisaoPagaSchema>;
export type PrevisaoFiltros = z.infer<typeof previsaoFiltrosSchema>;

/**
 * Converte competência yyyy-MM no primeiro dia do mês (UTC) e calcula a data
 * de vencimento ajustando para o último dia do mês caso `diaVencimento` exceda.
 * Ex: dia 31 em fevereiro → 28 (ou 29 em bissexto).
 */
export function calcularDataVencimento(competencia: string, diaVencimento: number): Date {
  const [anoStr, mesStr] = competencia.split("-");
  const ano = Number(anoStr);
  const mes = Number(mesStr); // 1..12

  const ultimoDia = new Date(Date.UTC(ano, mes, 0)).getUTCDate();
  const dia = Math.min(diaVencimento, ultimoDia);
  return new Date(Date.UTC(ano, mes - 1, dia));
}

export function competenciaDoMesAtual(ref: Date = new Date()): string {
  const ano = ref.getUTCFullYear();
  const mes = String(ref.getUTCMonth() + 1).padStart(2, "0");
  return `${ano}-${mes}`;
}

export function competenciaToDate(competencia: string): Date {
  const [ano, mes] = competencia.split("-").map(Number);
  return new Date(Date.UTC(ano, mes - 1, 1));
}

export function formatCompetencia(competencia: string): string {
  const MESES = [
    "Janeiro",
    "Fevereiro",
    "Março",
    "Abril",
    "Maio",
    "Junho",
    "Julho",
    "Agosto",
    "Setembro",
    "Outubro",
    "Novembro",
    "Dezembro",
  ];
  const [ano, mes] = competencia.split("-").map(Number);
  const idx = mes - 1;
  if (idx < 0 || idx > 11) return competencia;
  return `${MESES[idx]}/${ano}`;
}
