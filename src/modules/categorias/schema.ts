import { z } from "zod";
import { TipoCategoria } from "@prisma/client";

export const tipoCategoriaSchema = z.nativeEnum(TipoCategoria);

export const categoriaCreateSchema = z.object({
  nome: z.string().trim().min(2, "Nome obrigatório (mín. 2 caracteres)").max(120),
  tipo: tipoCategoriaSchema,
  isPessoal: z.boolean(),
  categoriaPaiId: z.string().trim().optional(),
});

export const categoriaUpdateSchema = categoriaCreateSchema.extend({
  id: z.string().min(1),
});

export const categoriaFiltrosSchema = z.object({
  search: z.string().trim().optional(),
  tipo: z.union([tipoCategoriaSchema, z.literal("todos")]).default("todos"),
  ativo: z.enum(["todos", "ativos", "inativos"]).default("ativos"),
  escopo: z.enum(["todos", "escritorio", "pessoal"]).default("todos"),
});

export type CategoriaCreateInput = z.infer<typeof categoriaCreateSchema>;
export type CategoriaUpdateInput = z.infer<typeof categoriaUpdateSchema>;
export type CategoriaFiltros = z.infer<typeof categoriaFiltrosSchema>;

export const TIPO_CATEGORIA_LABELS: Record<TipoCategoria, string> = {
  RECEITA: "Receita",
  DESPESA: "Despesa",
};
