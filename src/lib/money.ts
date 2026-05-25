import { Prisma } from "@prisma/client";

const Decimal = Prisma.Decimal;
export type Money = Prisma.Decimal;

export function money(value: number | string | Money): Money {
  return new Decimal(value);
}

export function sum(values: ReadonlyArray<Money | number | string>): Money {
  return values.reduce<Money>((acc, v) => acc.plus(new Decimal(v)), new Decimal(0));
}

export function toBRL(value: Money | number | string): string {
  const n = value instanceof Decimal ? value.toNumber() : Number(value);
  // Normaliza non-breaking space (U+00A0) que o Intl produz para um espaço comum.
  return n.toLocaleString("pt-BR", { style: "currency", currency: "BRL" }).replace(/ /g, " ");
}

export function parseBRL(input: string): Money {
  const cleaned = input.replace(/\s|R\$|\./g, "").replace(",", ".");
  return new Decimal(cleaned || "0");
}

export function isZero(value: Money | number | string): boolean {
  return new Decimal(value).isZero();
}
