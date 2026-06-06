import { z } from "zod";

const textoOpcional = (max: number) => z.string().trim().max(max).optional();

const dataObrigatoria = z
  .string()
  .trim()
  .min(1, "Data obrigatória")
  .regex(/^\d{4}-\d{2}-\d{2}$/, "Data deve estar no formato yyyy-MM-dd");

export const registrarRepasseSchema = z.object({
  itemId: z.string().min(1),
  data: dataObrigatoria,
  contaSaidaId: z.string().min(1, "Selecione a conta de origem"),
  categoriaId: z.string().min(1, "Selecione a categoria de despesa"),
  descricao: z.string().trim().min(2, "Descrição obrigatória").max(300),
  observacoes: textoOpcional(2000),
});

export type RegistrarRepasseInput = z.infer<typeof registrarRepasseSchema>;
