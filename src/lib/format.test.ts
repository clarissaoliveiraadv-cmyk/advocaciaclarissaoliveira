import { describe, expect, it } from "vitest";
import {
  blankToUndefined,
  formatCpfCnpj,
  formatTelefone,
  onlyDigits,
  validarCnpj,
  validarCpf,
  validarCpfCnpj,
} from "./format";

describe("format", () => {
  it("onlyDigits remove tudo que não for número", () => {
    expect(onlyDigits("(11) 98765-4321")).toBe("11987654321");
    expect(onlyDigits("abc")).toBe("");
  });

  it("formatCpfCnpj aplica máscara correta por tamanho", () => {
    expect(formatCpfCnpj("52998224725")).toBe("529.982.247-25");
    expect(formatCpfCnpj("11222333000181")).toBe("11.222.333/0001-81");
    expect(formatCpfCnpj("123")).toBe("123");
  });

  it("formatTelefone aplica máscara fixo/celular", () => {
    expect(formatTelefone("11987654321")).toBe("(11) 98765-4321");
    expect(formatTelefone("1133334444")).toBe("(11) 3333-4444");
  });

  it("validarCpf rejeita dígitos verificadores errados e sequências repetidas", () => {
    expect(validarCpf("529.982.247-25")).toBe(true);
    expect(validarCpf("529.982.247-26")).toBe(false);
    expect(validarCpf("111.111.111-11")).toBe(false);
    expect(validarCpf("123")).toBe(false);
  });

  it("validarCnpj rejeita dígitos verificadores errados", () => {
    expect(validarCnpj("11.222.333/0001-81")).toBe(true);
    expect(validarCnpj("11.222.333/0001-82")).toBe(false);
    expect(validarCnpj("00.000.000/0000-00")).toBe(false);
  });

  it("validarCpfCnpj escolhe pelo tamanho", () => {
    expect(validarCpfCnpj("529.982.247-25")).toBe(true);
    expect(validarCpfCnpj("11.222.333/0001-81")).toBe(true);
    expect(validarCpfCnpj("123")).toBe(false);
  });

  it("blankToUndefined trata vazio e espaços", () => {
    expect(blankToUndefined("")).toBeUndefined();
    expect(blankToUndefined("   ")).toBeUndefined();
    expect(blankToUndefined("  foo ")).toBe("foo");
    expect(blankToUndefined(null)).toBeUndefined();
    expect(blankToUndefined(42)).toBeUndefined();
  });
});
