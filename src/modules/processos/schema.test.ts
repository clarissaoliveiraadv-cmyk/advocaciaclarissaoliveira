import { describe, expect, it } from "vitest";
import { NaturezaProcesso, StatusProcesso } from "@prisma/client";
import { processoCreateSchema, processoFiltrosSchema } from "./schema";

const base = {
  clienteId: "cli_123",
  natureza: NaturezaProcesso.CIVEL,
  status: StatusProcesso.EM_ANDAMENTO,
};

describe("processoCreateSchema", () => {
  it("aceita processo apenas com cliente (CNJ opcional)", () => {
    const r = processoCreateSchema.safeParse(base);
    expect(r.success).toBe(true);
  });

  it("exige clienteId", () => {
    const r = processoCreateSchema.safeParse({ ...base, clienteId: "" });
    expect(r.success).toBe(false);
  });

  it("aceita CNJ válido", () => {
    const r = processoCreateSchema.safeParse({ ...base, numeroCnj: "0000837-43.2023.8.13.0024" });
    expect(r.success).toBe(true);
  });

  it("rejeita CNJ com dígito verificador errado", () => {
    const r = processoCreateSchema.safeParse({ ...base, numeroCnj: "0000837-99.2023.8.13.0024" });
    expect(r.success).toBe(false);
  });

  it("aceita CNJ em branco (procedimentos internos)", () => {
    const r = processoCreateSchema.safeParse({ ...base, numeroCnj: "   " });
    expect(r.success).toBe(true);
  });

  it("exige natureza e status (defaults aplicados no formulário)", () => {
    const r = processoCreateSchema.safeParse({ clienteId: "cli_1" });
    expect(r.success).toBe(false);
  });

  it("rejeita texto além do limite em observacoes", () => {
    const longo = "x".repeat(2001);
    const r = processoCreateSchema.safeParse({ ...base, observacoes: longo });
    expect(r.success).toBe(false);
  });
});

describe("processoFiltrosSchema", () => {
  it("aplica defaults", () => {
    const r = processoFiltrosSchema.parse({});
    expect(r.status).toBe("todos");
    expect(r.ativo).toBe("ativos");
    expect(r.page).toBe(1);
  });

  it("aceita status específico", () => {
    const r = processoFiltrosSchema.parse({ status: StatusProcesso.ENCERRADO });
    expect(r.status).toBe(StatusProcesso.ENCERRADO);
  });
});
