import { describe, expect, it } from "vitest";
import { TipoParceiro } from "@prisma/client";
import { parceiroCreateSchema, parceiroFiltrosSchema } from "./schema";

const base = { nome: "Dra. Vivian Lamounier", tipo: TipoParceiro.PARCEIRO_EXTERNO };

describe("parceiroCreateSchema", () => {
  it("aceita parceiro mínimo (nome + tipo)", () => {
    expect(parceiroCreateSchema.safeParse(base).success).toBe(true);
  });

  it("exige nome ≥ 2 caracteres", () => {
    expect(parceiroCreateSchema.safeParse({ ...base, nome: "A" }).success).toBe(false);
    expect(parceiroCreateSchema.safeParse({ ...base, nome: "  " }).success).toBe(false);
  });

  it("exige tipo válido", () => {
    expect(parceiroCreateSchema.safeParse({ ...base, tipo: "OUTRO" }).success).toBe(false);
    expect(parceiroCreateSchema.safeParse({ ...base, tipo: TipoParceiro.SOCIA }).success).toBe(
      true,
    );
    expect(
      parceiroCreateSchema.safeParse({ ...base, tipo: TipoParceiro.FUNCIONARIO }).success,
    ).toBe(true);
  });

  it("aceita OAB vazia ou preenchida", () => {
    expect(parceiroCreateSchema.safeParse({ ...base, oab: "" }).success).toBe(true);
    expect(parceiroCreateSchema.safeParse({ ...base, oab: "123456/SP" }).success).toBe(true);
  });

  it("aceita percentual vazio (sem padrão definido)", () => {
    const r = parceiroCreateSchema.safeParse({ ...base, percentualPadraoSucumbencia: "" });
    expect(r.success).toBe(true);
  });

  it("aceita percentual entre 0 e 100, incluindo decimais", () => {
    expect(
      parceiroCreateSchema.safeParse({ ...base, percentualPadraoSucumbencia: "0" }).success,
    ).toBe(true);
    expect(
      parceiroCreateSchema.safeParse({ ...base, percentualPadraoSucumbencia: "33.33" }).success,
    ).toBe(true);
    expect(
      parceiroCreateSchema.safeParse({ ...base, percentualPadraoSucumbencia: "100" }).success,
    ).toBe(true);
  });

  it("rejeita percentual fora do intervalo ou inválido", () => {
    expect(
      parceiroCreateSchema.safeParse({ ...base, percentualPadraoSucumbencia: "-1" }).success,
    ).toBe(false);
    expect(
      parceiroCreateSchema.safeParse({ ...base, percentualPadraoSucumbencia: "101" }).success,
    ).toBe(false);
    expect(
      parceiroCreateSchema.safeParse({ ...base, percentualPadraoSucumbencia: "abc" }).success,
    ).toBe(false);
  });

  it("limita nome a 200 caracteres", () => {
    const longo = "x".repeat(201);
    expect(parceiroCreateSchema.safeParse({ ...base, nome: longo }).success).toBe(false);
  });
});

describe("parceiroFiltrosSchema", () => {
  it("aplica defaults", () => {
    const r = parceiroFiltrosSchema.parse({});
    expect(r.tipo).toBe("todos");
    expect(r.ativo).toBe("ativos");
  });

  it("aceita tipo específico", () => {
    const r = parceiroFiltrosSchema.parse({ tipo: TipoParceiro.SOCIA });
    expect(r.tipo).toBe(TipoParceiro.SOCIA);
  });

  it("rejeita ativo desconhecido", () => {
    expect(parceiroFiltrosSchema.safeParse({ ativo: "qualquer" }).success).toBe(false);
  });
});
