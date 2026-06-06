import { describe, expect, it } from "vitest";
import { StatusRecebivel, TipoParcela } from "@prisma/client";
import { recebivelCreateSchema, recebivelFiltrosSchema } from "./schema";

const base = {
  processoId: "proc_1",
  dataPrevista: "2024-03-15",
  tipoParcela: TipoParcela.NORMAL,
  valorIntegral: 10000,
  valorParcela: 1500,
  ressarcimentoEmbutido: 0,
  percHonorarios: "30",
};

describe("recebivelCreateSchema", () => {
  it("aceita recebível mínimo", () => {
    expect(recebivelCreateSchema.safeParse(base).success).toBe(true);
  });

  it("exige processoId", () => {
    expect(recebivelCreateSchema.safeParse({ ...base, processoId: "" }).success).toBe(false);
  });

  it("rejeita valorParcela 0 ou negativo", () => {
    expect(recebivelCreateSchema.safeParse({ ...base, valorParcela: 0 }).success).toBe(false);
    expect(recebivelCreateSchema.safeParse({ ...base, valorParcela: -100 }).success).toBe(false);
  });

  it("aceita ressarcimentoEmbutido zero", () => {
    expect(recebivelCreateSchema.safeParse({ ...base, ressarcimentoEmbutido: 0 }).success).toBe(
      true,
    );
  });

  it("rejeita ressarcimentoEmbutido negativo", () => {
    expect(recebivelCreateSchema.safeParse({ ...base, ressarcimentoEmbutido: -10 }).success).toBe(
      false,
    );
  });

  it("exige percHonorarios entre 0 e 100", () => {
    expect(recebivelCreateSchema.safeParse({ ...base, percHonorarios: "" }).success).toBe(false);
    expect(recebivelCreateSchema.safeParse({ ...base, percHonorarios: "-1" }).success).toBe(false);
    expect(recebivelCreateSchema.safeParse({ ...base, percHonorarios: "101" }).success).toBe(false);
    expect(recebivelCreateSchema.safeParse({ ...base, percHonorarios: "30" }).success).toBe(true);
    expect(recebivelCreateSchema.safeParse({ ...base, percHonorarios: "33.33" }).success).toBe(
      true,
    );
  });

  it("percParceiro é opcional, com mesmo range", () => {
    expect(recebivelCreateSchema.safeParse({ ...base, percParceiro: undefined }).success).toBe(
      true,
    );
    expect(recebivelCreateSchema.safeParse({ ...base, percParceiro: "" }).success).toBe(true);
    expect(recebivelCreateSchema.safeParse({ ...base, percParceiro: "40" }).success).toBe(true);
    expect(recebivelCreateSchema.safeParse({ ...base, percParceiro: "150" }).success).toBe(false);
  });

  it("rejeita data fora do formato yyyy-MM-dd", () => {
    expect(recebivelCreateSchema.safeParse({ ...base, dataPrevista: "15/03/2024" }).success).toBe(
      false,
    );
  });

  it("rejeita tipoParcela inválido", () => {
    expect(recebivelCreateSchema.safeParse({ ...base, tipoParcela: "X" }).success).toBe(false);
  });

  it("numeroParcela e totalParcelas aceitam vazio (conversão na action)", () => {
    const r = recebivelCreateSchema.safeParse({
      ...base,
      numeroParcela: "",
      totalParcelas: "",
    });
    expect(r.success).toBe(true);
  });

  it("numeroParcela aceita inteiro positivo como string", () => {
    const r = recebivelCreateSchema.safeParse({ ...base, numeroParcela: "3", totalParcelas: "7" });
    expect(r.success).toBe(true);
    if (r.success) expect(r.data.numeroParcela).toBe("3");
  });

  it("numeroParcela rejeita decimal ou negativo", () => {
    expect(
      recebivelCreateSchema.safeParse({ ...base, numeroParcela: "1.5" }).success,
    ).toBe(false);
    expect(
      recebivelCreateSchema.safeParse({ ...base, numeroParcela: "-2" }).success,
    ).toBe(false);
  });
});

describe("recebivelFiltrosSchema", () => {
  it("aplica defaults", () => {
    const r = recebivelFiltrosSchema.parse({});
    expect(r.status).toBe("todos");
    expect(r.page).toBe(1);
    expect(r.pageSize).toBe(50);
  });

  it("aceita status específico", () => {
    const r = recebivelFiltrosSchema.parse({ status: StatusRecebivel.RECEBIDA });
    expect(r.status).toBe(StatusRecebivel.RECEBIDA);
  });
});
