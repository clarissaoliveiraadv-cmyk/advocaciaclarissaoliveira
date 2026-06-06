/**
 * Tipos compartilhados entre módulos.
 *
 * REGRA: este arquivo deve permanecer pequeno. Cada módulo (clientes, movimento,
 * recebíveis...) define seus próprios tipos em seu `schema.ts` ou `types.ts` local.
 * Só promova um tipo para cá quando ele for realmente cross-module.
 */

export type ActionResult<T = void> =
  | { ok: true; data: T }
  | { ok: false; error: string; fieldErrors?: Record<string, string[]> };

export type ListResult<T> = {
  items: T[];
  total: number;
  page: number;
  pageSize: number;
};
