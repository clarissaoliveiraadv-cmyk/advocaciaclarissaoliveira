import { z } from "zod";

const dataObrigatoria = z
  .string()
  .trim()
  .min(1, "Data obrigatória")
  .regex(/^\d{4}-\d{2}-\d{2}$/, "Data deve estar no formato yyyy-MM-dd");

const valorReal = z.coerce.number().finite("Valor inválido");

export const saldoAberturaItemSchema = z.object({
  contaId: z.string().min(1),
  saldoInicial: valorReal,
  saldoAberturaData: dataObrigatoria,
});

export const importarSaldoSchema = z.object({
  itens: z.array(saldoAberturaItemSchema).min(1, "Informe ao menos uma conta"),
});

export const limparAberturaSchema = z.object({
  contaId: z.string().min(1),
});

export type SaldoAberturaItem = z.infer<typeof saldoAberturaItemSchema>;
export type ImportarSaldoInput = z.infer<typeof importarSaldoSchema>;
export type LimparAberturaInput = z.infer<typeof limparAberturaSchema>;
