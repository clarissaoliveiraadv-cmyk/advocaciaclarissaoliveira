import { z } from "zod";

export const relatoriosFiltrosSchema = z.object({
  inicio: z.string().trim().optional(),
  fim: z.string().trim().optional(),
});

export type RelatoriosFiltros = z.infer<typeof relatoriosFiltrosSchema>;
