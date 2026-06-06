import { describe, expect, it } from "vitest";
import { TipoCategoria } from "@prisma/client";
import { categoriaCreateSchema, categoriaFiltrosSchema } from "./schema";

const base = {
  nome: "Honorário Contratual",
  tipo: TipoCategoria.RECEITA,
  isPessoal: false,
};

describe("categoriaCreateSchema", () => {
  it("aceita categoria raiz mínima", () => {
    expect(categoriaCreateSchema.safeParse(base).success).toBe(true);
  });

  it("exige nome (≥2 caracteres)", () => {
    expect(categoriaCreateSchema.safeParse({ ...base, nome: "A" }).success).toBe(false);
    expect(categoriaCreateSchema.safeParse({ ...base, nome: "  " }).success).toBe(false);
  });

  it("exige tipo RECEITA ou DESPESA", () => {
    expect(categoriaCreateSchema.safeParse({ ...base, tipo: "OUTRO" }).success).toBe(false);
    expect(categoriaCreateSchema.safeParse({ ...base, tipo: TipoCategoria.DESPESA }).success).toBe(
      true,
    );
  });

  it("exige isPessoal como boolean (sem default no schema, definido no formulário)", () => {
    const semFlag = categoriaCreateSchema.safeParse({ nome: base.nome, tipo: base.tipo });
    expect(semFlag.success).toBe(false);
  });

  it("aceita categoriaPaiId opcional", () => {
    const semPai = categoriaCreateSchema.safeParse(base);
    expect(semPai.success).toBe(true);
    const comPai = categoriaCreateSchema.safeParse({ ...base, categoriaPaiId: "cat_pai" });
    expect(comPai.success).toBe(true);
  });

  it("trata categoriaPaiId vazio como sem pai", () => {
    const r = categoriaCreateSchema.safeParse({ ...base, categoriaPaiId: "   " });
    expect(r.success).toBe(true);
    if (r.success) expect(r.data.categoriaPaiId).toBe("");
  });

  it("limita nome a 120 caracteres", () => {
    const longo = "x".repeat(121);
    expect(categoriaCreateSchema.safeParse({ ...base, nome: longo }).success).toBe(false);
  });
});

describe("categoriaFiltrosSchema", () => {
  it("aplica defaults", () => {
    const r = categoriaFiltrosSchema.parse({});
    expect(r.tipo).toBe("todos");
    expect(r.ativo).toBe("ativos");
    expect(r.escopo).toBe("todos");
  });

  it("aceita escopo pessoal", () => {
    const r = categoriaFiltrosSchema.parse({ escopo: "pessoal" });
    expect(r.escopo).toBe("pessoal");
  });

  it("aceita tipo específico", () => {
    const r = categoriaFiltrosSchema.parse({ tipo: TipoCategoria.RECEITA });
    expect(r.tipo).toBe(TipoCategoria.RECEITA);
  });

  it("rejeita escopo desconhecido", () => {
    expect(categoriaFiltrosSchema.safeParse({ escopo: "outro" }).success).toBe(false);
  });
});
