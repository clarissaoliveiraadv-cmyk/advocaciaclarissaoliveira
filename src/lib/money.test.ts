import { describe, expect, it } from "vitest";
import { isZero, money, parseBRL, sum, toBRL, toPercent, fromPercent } from "./money";

describe("money", () => {
  it("cria Decimal a partir de número/string", () => {
    expect(money(10).toString()).toBe("10");
    expect(money("1234.56").toString()).toBe("1234.56");
  });

  it("soma sem perder precisão", () => {
    expect(sum([0.1, 0.2, 0.3]).toString()).toBe("0.6");
    expect(sum(["100.10", "200.20", 0]).toString()).toBe("300.3");
  });

  it("formata em BRL", () => {
    expect(toBRL(1234.5)).toBe("R$ 1.234,50");
    expect(toBRL(0)).toBe("R$ 0,00");
  });

  it("parseBRL aceita formato brasileiro", () => {
    expect(parseBRL("R$ 1.234,56").toString()).toBe("1234.56");
    expect(parseBRL("0,01").toString()).toBe("0.01");
  });

  it("detecta zero", () => {
    expect(isZero(0)).toBe(true);
    expect(isZero("0.00")).toBe(true);
    expect(isZero(0.01)).toBe(false);
  });

  it("toPercent: fração → humano com sinal '%'", () => {
    expect(toPercent(0.34)).toBe("34,00%");
    expect(toPercent("0.3333")).toBe("33,33%");
    expect(toPercent(1)).toBe("100,00%");
    expect(toPercent(0)).toBe("0,00%");
  });

  it("toPercent: trata nulo/inválido", () => {
    expect(toPercent(null)).toBe("—");
    expect(toPercent(undefined)).toBe("—");
    expect(toPercent("abc")).toBe("—");
  });

  it("fromPercent: humano → fração com precisão", () => {
    expect(fromPercent(34).toString()).toBe("0.34");
    expect(fromPercent("33.33").toString()).toBe("0.3333");
    expect(fromPercent(0).toString()).toBe("0");
    expect(fromPercent(100).toString()).toBe("1");
  });
});
