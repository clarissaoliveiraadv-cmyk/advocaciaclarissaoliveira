import { revalidatePath } from "next/cache";

/**
 * Rotas que exibem indicadores financeiros ou saldos. Toda mutação que
 * afeta dinheiro (lançamento, distribuição, sucumbência, despesa fixa,
 * ressarcimento que vira lançamento, parceria etc.) deve passar por
 * `revalidarCaixa()` para garantir que o painel, o movimento de caixa
 * e os relatórios reflitam o novo estado imediatamente.
 */
const ROTAS_CAIXA = [
  "/dashboard",
  "/movimento",
  "/relatorios",
  "/contas-a-pagar",
  "/recebiveis",
  "/ressarcimentos",
  "/parcerias",
  "/sucumbencia",
  "/prestacao-contas",
] as const;

/**
 * Invalida o cache de todas as páginas com saldos / indicadores
 * + qualquer rota adicional (página específica do módulo, por exemplo).
 */
export function revalidarCaixa(extra?: string | string[]): void {
  for (const r of ROTAS_CAIXA) revalidatePath(r);
  if (extra) {
    const lista = Array.isArray(extra) ? extra : [extra];
    for (const r of lista) revalidatePath(r);
  }
}
