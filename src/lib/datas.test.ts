import { describe, expect, it } from "vitest";
import {
  fimDoMes,
  fimDoMesAtual,
  formatDataBR,
  formatDataISO,
  inicioDoMes,
  inicioDoMesAtual,
  parseDataISO,
} from "./datas";

describe("datas", () => {
  it("formatDataBR formata em dd/MM/aaaa", () => {
    expect(formatDataBR("2024-03-15")).toBe("15/03/2024");
    expect(formatDataBR("2024-12-31")).toBe("31/12/2024");
  });

  it("formatDataBR trata data inválida", () => {
    expect(formatDataBR("invalida")).toBe("—");
  });

  it("formatDataISO retorna yyyy-MM-dd", () => {
    expect(formatDataISO("2024-03-15")).toBe("2024-03-15");
  });

  it("parseDataISO retorna Date UTC ou null", () => {
    const d = parseDataISO("2024-03-15");
    expect(d).not.toBeNull();
    expect(d?.toISOString()).toBe("2024-03-15T00:00:00.000Z");
    expect(parseDataISO("")).toBeNull();
  });

  it("inicioDoMes e fimDoMes batem com último dia correto", () => {
    expect(inicioDoMes(2024, 2).toISOString()).toBe("2024-02-01T00:00:00.000Z");
    expect(fimDoMes(2024, 2).toISOString()).toBe("2024-02-29T00:00:00.000Z"); // bissexto
    expect(fimDoMes(2023, 2).toISOString()).toBe("2023-02-28T00:00:00.000Z");
    expect(fimDoMes(2024, 12).toISOString()).toBe("2024-12-31T00:00:00.000Z");
  });

  it("inicioDoMesAtual/fimDoMesAtual usam mês de referência", () => {
    const ref = new Date(Date.UTC(2024, 5, 17)); // junho
    expect(inicioDoMesAtual(ref).toISOString()).toBe("2024-06-01T00:00:00.000Z");
    expect(fimDoMesAtual(ref).toISOString()).toBe("2024-06-30T00:00:00.000Z");
  });
});
