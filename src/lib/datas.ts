/**
 * Helpers de data específicos para o domínio financeiro.
 *
 * Política:
 * - Banco persiste DATE (sem hora) — Prisma Date type.
 * - UI exibe formato BR (dd/MM/aaaa).
 * - Inputs HTML usam ISO (yyyy-MM-dd).
 */

export function formatDataBR(date: Date | string): string {
  const d = typeof date === "string" ? new Date(date) : date;
  if (Number.isNaN(d.getTime())) return "—";
  const dia = String(d.getUTCDate()).padStart(2, "0");
  const mes = String(d.getUTCMonth() + 1).padStart(2, "0");
  const ano = d.getUTCFullYear();
  return `${dia}/${mes}/${ano}`;
}

export function formatDataISO(date: Date | string): string {
  const d = typeof date === "string" ? new Date(date) : date;
  if (Number.isNaN(d.getTime())) return "";
  return d.toISOString().slice(0, 10);
}

export function parseDataISO(input: string): Date | null {
  if (!input) return null;
  const d = new Date(`${input}T00:00:00.000Z`);
  return Number.isNaN(d.getTime()) ? null : d;
}

export function inicioDoMes(ano: number, mes: number): Date {
  return new Date(Date.UTC(ano, mes - 1, 1));
}

export function fimDoMes(ano: number, mes: number): Date {
  return new Date(Date.UTC(ano, mes, 0));
}

export function inicioDoMesAtual(ref: Date = new Date()): Date {
  return new Date(Date.UTC(ref.getUTCFullYear(), ref.getUTCMonth(), 1));
}

export function fimDoMesAtual(ref: Date = new Date()): Date {
  return new Date(Date.UTC(ref.getUTCFullYear(), ref.getUTCMonth() + 1, 0));
}
