import { describe, expect, it } from "vitest";
import { clienteCreateSchema, clienteFiltrosSchema } from "./schema";

describe("clienteCreateSchema", () => {
  it("aceita cliente válido apenas com nome", () => {
    const r = clienteCreateSchema.safeParse({ nome: "Ana Souza" });
    expect(r.success).toBe(true);
    if (r.success) expect(r.data.cpfCnpj).toBeUndefined();
  });

  it("rejeita nome curto", () => {
    const r = clienteCreateSchema.safeParse({ nome: "A" });
    expect(r.success).toBe(false);
  });

  it("aceita campos opcionais em branco (normalização ocorre na action)", () => {
    const r = clienteCreateSchema.safeParse({
      nome: "Ana",
      cpfCnpj: "   ",
      email: "",
      telefone: "",
      observacoes: "",
    });
    expect(r.success).toBe(true);
  });

  it("rejeita CPF inválido e aceita CNPJ válido", () => {
    const ruim = clienteCreateSchema.safeParse({ nome: "X", cpfCnpj: "111.111.111-11" });
    expect(ruim.success).toBe(false);
    const ok = clienteCreateSchema.safeParse({ nome: "Empresa", cpfCnpj: "11.222.333/0001-81" });
    expect(ok.success).toBe(true);
  });

  it("rejeita e-mail malformado", () => {
    const r = clienteCreateSchema.safeParse({ nome: "Ana", email: "não-é-email" });
    expect(r.success).toBe(false);
  });

  it("rejeita telefone com dígitos insuficientes", () => {
    const r = clienteCreateSchema.safeParse({ nome: "Ana", telefone: "123" });
    expect(r.success).toBe(false);
  });
});

describe("clienteFiltrosSchema", () => {
  it("aplica defaults", () => {
    const r = clienteFiltrosSchema.parse({});
    expect(r.ativo).toBe("ativos");
    expect(r.page).toBe(1);
    expect(r.pageSize).toBe(20);
  });

  it("converte strings de page/pageSize", () => {
    const r = clienteFiltrosSchema.parse({ page: "3", pageSize: "50" });
    expect(r.page).toBe(3);
    expect(r.pageSize).toBe(50);
  });
});
