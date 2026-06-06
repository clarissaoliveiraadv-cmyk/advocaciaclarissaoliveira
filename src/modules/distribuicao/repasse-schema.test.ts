import { describe, expect, it } from "vitest";
import { registrarRepasseSchema } from "./repasse-schema";

const base = {
  itemId: "item_1",
  data: "2024-03-15",
  contaSaidaId: "conta_1",
  categoriaId: "cat_despesa_1",
  descricao: "Repasse cliente — Cliente X",
};

describe("registrarRepasseSchema", () => {
  it("aceita input mínimo válido", () => {
    expect(registrarRepasseSchema.safeParse(base).success).toBe(true);
  });

  it("exige itemId", () => {
    expect(registrarRepasseSchema.safeParse({ ...base, itemId: "" }).success).toBe(false);
  });

  it("rejeita data fora de formato", () => {
    expect(registrarRepasseSchema.safeParse({ ...base, data: "15/03/2024" }).success).toBe(false);
  });

  it("exige conta e categoria", () => {
    expect(registrarRepasseSchema.safeParse({ ...base, contaSaidaId: "" }).success).toBe(false);
    expect(registrarRepasseSchema.safeParse({ ...base, categoriaId: "" }).success).toBe(false);
  });

  it("exige descrição mínima de 2 caracteres", () => {
    expect(registrarRepasseSchema.safeParse({ ...base, descricao: "A" }).success).toBe(false);
  });

  it("aceita observações opcionais", () => {
    expect(
      registrarRepasseSchema.safeParse({ ...base, observacoes: "Comprovante #123" }).success,
    ).toBe(true);
    expect(registrarRepasseSchema.safeParse({ ...base, observacoes: undefined }).success).toBe(
      true,
    );
  });
});
