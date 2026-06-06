import { describe, expect, it } from "vitest";
import { TipoConta } from "@prisma/client";
import { contaCreateSchema, contaFiltrosSchema } from "./schema";

const base = {
  codigo: "INTER_PJ",
  nome: "Banco Inter PJ",
  tipo: TipoConta.CONTA_CORRENTE,
  saldoInicial: 0,
};

describe("contaCreateSchema", () => {
  it("aceita conta válida básica", () => {
    expect(contaCreateSchema.safeParse(base).success).toBe(true);
  });

  it("rejeita código com caracteres inválidos", () => {
    const r = contaCreateSchema.safeParse({ ...base, codigo: "INTER PJ" });
    expect(r.success).toBe(false);
  });

  it("rejeita código curto demais", () => {
    const r = contaCreateSchema.safeParse({ ...base, codigo: "I" });
    expect(r.success).toBe(false);
  });

  it("rejeita nome vazio", () => {
    const r = contaCreateSchema.safeParse({ ...base, nome: "" });
    expect(r.success).toBe(false);
  });

  it("coerce saldoInicial vindo como string", () => {
    const r = contaCreateSchema.safeParse({ ...base, saldoInicial: "1234.56" });
    expect(r.success).toBe(true);
    if (r.success) expect(r.data.saldoInicial).toBe(1234.56);
  });

  it("rejeita saldoInicial não numérico", () => {
    const r = contaCreateSchema.safeParse({ ...base, saldoInicial: "abc" });
    expect(r.success).toBe(false);
  });

  it("aceita saldo negativo (cheque especial / sangria)", () => {
    const r = contaCreateSchema.safeParse({ ...base, saldoInicial: -150.5 });
    expect(r.success).toBe(true);
  });
});

describe("contaFiltrosSchema", () => {
  it("aplica defaults", () => {
    const r = contaFiltrosSchema.parse({});
    expect(r.tipo).toBe("todos");
    expect(r.ativo).toBe("ativos");
    expect(r.page).toBe(1);
  });

  it("aceita tipo específico", () => {
    const r = contaFiltrosSchema.parse({ tipo: TipoConta.POUPANCA });
    expect(r.tipo).toBe(TipoConta.POUPANCA);
  });
});
