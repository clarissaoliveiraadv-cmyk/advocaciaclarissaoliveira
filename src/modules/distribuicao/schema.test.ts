import { describe, expect, it } from "vitest";
import { TipoBeneficiario } from "@prisma/client";
import { confirmarDistribuicaoSchema, itemSchema } from "./schema";

const itemBase = {
  beneficiario: TipoBeneficiario.ESCRITORIO_CONTRATUAL,
  valor: 1000,
};

const inputBase = {
  recebivelId: "rec_1",
  dataRecebimento: "2024-03-15",
  contaRecebimentoId: "conta_1",
  categoriaLancamentoId: "cat_1",
  valorBrutoRecebido: 1500,
  descricaoLancamento: "Recebimento honorário",
  itens: [
    { beneficiario: TipoBeneficiario.ESCRITORIO_CONTRATUAL, valor: 450 },
    { beneficiario: TipoBeneficiario.CLIENTE, valor: 1050, clienteId: "cli_1" },
  ],
};

describe("itemSchema", () => {
  it("aceita item válido", () => {
    expect(itemSchema.safeParse(itemBase).success).toBe(true);
  });

  it("aceita valor zero (item informativo)", () => {
    expect(itemSchema.safeParse({ ...itemBase, valor: 0 }).success).toBe(true);
  });

  it("rejeita valor negativo", () => {
    expect(itemSchema.safeParse({ ...itemBase, valor: -10 }).success).toBe(false);
  });

  it("rejeita beneficiário inválido", () => {
    expect(itemSchema.safeParse({ ...itemBase, beneficiario: "X" }).success).toBe(false);
  });
});

describe("confirmarDistribuicaoSchema", () => {
  it("aceita input válido com soma exata", () => {
    expect(confirmarDistribuicaoSchema.safeParse(inputBase).success).toBe(true);
  });

  it("rejeita soma divergente do valor bruto", () => {
    const r = confirmarDistribuicaoSchema.safeParse({
      ...inputBase,
      itens: [
        { beneficiario: TipoBeneficiario.ESCRITORIO_CONTRATUAL, valor: 500 },
        { beneficiario: TipoBeneficiario.CLIENTE, valor: 800, clienteId: "cli_1" },
      ],
    });
    expect(r.success).toBe(false);
    if (!r.success) {
      const msgs = r.error.flatten().fieldErrors;
      expect(JSON.stringify(msgs)).toMatch(/soma/i);
    }
  });

  it("tolera arredondamento até 0.005", () => {
    const r = confirmarDistribuicaoSchema.safeParse({
      ...inputBase,
      valorBrutoRecebido: 1500.003,
      itens: [
        { beneficiario: TipoBeneficiario.ESCRITORIO_CONTRATUAL, valor: 450 },
        { beneficiario: TipoBeneficiario.CLIENTE, valor: 1050, clienteId: "cli_1" },
      ],
    });
    expect(r.success).toBe(true);
  });

  it("exige clienteId quando beneficiário é CLIENTE", () => {
    const r = confirmarDistribuicaoSchema.safeParse({
      ...inputBase,
      itens: [
        { beneficiario: TipoBeneficiario.ESCRITORIO_CONTRATUAL, valor: 450 },
        { beneficiario: TipoBeneficiario.CLIENTE, valor: 1050 },
      ],
    });
    expect(r.success).toBe(false);
  });

  it("exige parceiroId quando beneficiário é PARCEIRO", () => {
    const r = confirmarDistribuicaoSchema.safeParse({
      ...inputBase,
      itens: [
        { beneficiario: TipoBeneficiario.PARCEIRO, valor: 300 },
        { beneficiario: TipoBeneficiario.ESCRITORIO_CONTRATUAL, valor: 150 },
        { beneficiario: TipoBeneficiario.CLIENTE, valor: 1050, clienteId: "cli_1" },
      ],
    });
    expect(r.success).toBe(false);
  });

  it("aceita beneficiários sem FK (ESCRITORIO_*, FGTS, CUSTAS, OUTRO)", () => {
    const r = confirmarDistribuicaoSchema.safeParse({
      ...inputBase,
      itens: [
        { beneficiario: TipoBeneficiario.ESCRITORIO_CONTRATUAL, valor: 300 },
        { beneficiario: TipoBeneficiario.ESCRITORIO_SUCUMBENCIA, valor: 200 },
        { beneficiario: TipoBeneficiario.FGTS, valor: 100 },
        { beneficiario: TipoBeneficiario.CUSTAS, valor: 50 },
        { beneficiario: TipoBeneficiario.OUTRO, valor: 850, descricao: "Pendência judicial" },
      ],
    });
    expect(r.success).toBe(true);
  });

  it("exige ao menos um item", () => {
    expect(confirmarDistribuicaoSchema.safeParse({ ...inputBase, itens: [] }).success).toBe(false);
  });

  it("rejeita valor bruto recebido zero ou negativo", () => {
    expect(
      confirmarDistribuicaoSchema.safeParse({ ...inputBase, valorBrutoRecebido: 0 }).success,
    ).toBe(false);
  });
});
