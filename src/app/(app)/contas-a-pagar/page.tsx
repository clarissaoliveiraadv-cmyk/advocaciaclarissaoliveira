import { Suspense } from "react";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { previsaoFiltrosSchema } from "@/modules/despesas-fixas/schema";
import { listPrevisoes, listOpcoesContas } from "@/modules/despesas-fixas/queries";
import { PrevisoesTable } from "@/modules/despesas-fixas/components/previsoes-table";
import { GerarPrevisoesButton } from "@/modules/despesas-fixas/components/gerar-previsoes-button";
import { CompetenciaPicker } from "@/modules/despesas-fixas/components/competencia-picker";
import { toBRL } from "@/lib/money";

export const dynamic = "force-dynamic";

type SearchParams = Promise<Record<string, string | string[] | undefined>>;

export default async function ContasAPagarPage({ searchParams }: { searchParams: SearchParams }) {
  const raw = await searchParams;
  const filtros = previsaoFiltrosSchema.parse(raw);

  const [{ competencia, itens, totalPrevisto, totalPago, countPendente, countPaga }, contas] =
    await Promise.all([listPrevisoes(filtros), listOpcoesContas()]);

  const saldoAPagar = Math.max(0, totalPrevisto - totalPago);

  return (
    <div className="space-y-6">
      <header className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold">Contas a pagar</h1>
          <p className="text-sm text-muted-foreground">
            Previsão mensal das despesas fixas. Marcar como paga cria o lançamento de SAÍDA real
            no Movimento de Caixa.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Suspense fallback={null}>
            <CompetenciaPicker competencia={competencia} />
          </Suspense>
          <GerarPrevisoesButton competencia={competencia} />
        </div>
      </header>

      <div className="grid gap-4 sm:grid-cols-3">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">
              Total previsto
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-semibold tabular-nums">{toBRL(totalPrevisto)}</div>
            <p className="text-xs text-muted-foreground">
              {countPendente + countPaga} conta{countPendente + countPaga === 1 ? "" : "s"} no mês
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">A pagar</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-semibold tabular-nums text-amber-700">
              {toBRL(saldoAPagar)}
            </div>
            <p className="text-xs text-muted-foreground">
              {countPendente} conta{countPendente === 1 ? "" : "s"} pendente
              {countPendente === 1 ? "" : "s"}
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Já pago</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-semibold tabular-nums text-emerald-700">
              {toBRL(totalPago)}
            </div>
            <p className="text-xs text-muted-foreground">
              {countPaga} conta{countPaga === 1 ? "" : "s"} quitada{countPaga === 1 ? "" : "s"}
            </p>
          </CardContent>
        </Card>
      </div>

      <PrevisoesTable previsoes={itens} contas={contas} />
    </div>
  );
}
