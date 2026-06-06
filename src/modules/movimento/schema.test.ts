import { describe, expect, it } from "vitest";
import { TipoLancamento } from "@prisma/client";
import {
  lancamentoCreateSchema,
  lancamentoFiltrosSchema,
  transferenciaCreateSchema,
} from "./schema";

const lancamentoBase = {
  data: "2024-03-15",
  descricao: "Honorário recebido",
  tipo: TipoLancamento.ENTRADA,
  contaId: "conta_x",
  categoriaId: "cat_y",
  valor: 1000,
};

describe("lancamentoCreateSchema", () => {
  it("aceita lançamento mínimo", () => {
    expect(lancamentoCreateSchema.safeParse(lancamentoBase).success).toBe(true);
  });

  it("rejeita data fora do formato yyyy-MM-dd", () => {
    expect(
      lancamentoCreateSchema.safeParse({ ...lancamentoBase, data: "15/03/2024" }).success,
    ).toBe(false);
  });

  it("rejeita valor zero ou negativo", () => {
    expect(lancamentoCreateSchema.safeParse({ ...lancamentoBase, valor: 0 }).success).toBe(false);
    expect(lancamentoCreateSchema.safeParse({ ...lancamentoBase, valor: -10 }).success).toBe(false);
  });

  it("aceita valor como string numérica", () => {
    const r = lancamentoCreateSchema.safeParse({ ...lancamentoBase, valor: "150.50" });
    expect(r.success).toBe(true);
    if (r.success) expect(r.data.valor).toBe(150.5);
  });

  it("rejeita tipo TRANSFERENCIA no lançamento simples", () => {
    expect(
      lancamentoCreateSchema.safeParse({ ...lancamentoBase, tipo: "TRANSFERENCIA" }).success,
    ).toBe(false);
  });

  it("exige conta e categoria", () => {
    expect(lancamentoCreateSchema.safeParse({ ...lancamentoBase, contaId: "" }).success).toBe(
      false,
    );
    expect(lancamentoCreateSchema.safeParse({ ...lancamentoBase, categoriaId: "" }).success).toBe(
      false,
    );
  });

  it("aceita comprovanteUrl http/https e rejeita outros", () => {
    expect(
      lancamentoCreateSchema.safeParse({
        ...lancamentoBase,
        comprovanteUrl: "https://drive.google.com/x",
      }).success,
    ).toBe(true);
    expect(
      lancamentoCreateSchema.safeParse({ ...lancamentoBase, comprovanteUrl: "javascript:alert(1)" })
        .success,
    ).toBe(false);
    expect(
      lancamentoCreateSchema.safeParse({ ...lancamentoBase, comprovanteUrl: "" }).success,
    ).toBe(true);
  });

  it("descrição mínima de 2 caracteres", () => {
    expect(lancamentoCreateSchema.safeParse({ ...lancamentoBase, descricao: "A" }).success).toBe(
      false,
    );
  });
});

describe("transferenciaCreateSchema", () => {
  const transfBase = {
    data: "2024-03-15",
    descricao: "Transferência Inter PJ → Caixa",
    contaOrigemId: "c_a",
    contaDestinoId: "c_b",
    categoriaId: "cat_x",
    valor: 500,
  };

  it("aceita transferência válida", () => {
    expect(transferenciaCreateSchema.safeParse(transfBase).success).toBe(true);
  });

  it("rejeita origem igual ao destino", () => {
    const r = transferenciaCreateSchema.safeParse({ ...transfBase, contaDestinoId: "c_a" });
    expect(r.success).toBe(false);
    if (!r.success) {
      expect(r.error.flatten().fieldErrors.contaDestinoId?.[0]).toMatch(/diferentes/);
    }
  });

  it("rejeita valor não positivo", () => {
    expect(transferenciaCreateSchema.safeParse({ ...transfBase, valor: 0 }).success).toBe(false);
  });
});

describe("lancamentoFiltrosSchema", () => {
  it("aplica defaults", () => {
    const r = lancamentoFiltrosSchema.parse({});
    expect(r.tipo).toBe("todos");
    expect(r.page).toBe(1);
    expect(r.pageSize).toBe(50);
  });

  it("aceita tipo REAIS (exclui transferências)", () => {
    const r = lancamentoFiltrosSchema.parse({ tipo: "REAIS" });
    expect(r.tipo).toBe("REAIS");
  });

  it("rejeita tipo desconhecido", () => {
    expect(lancamentoFiltrosSchema.safeParse({ tipo: "xyz" }).success).toBe(false);
  });
});
