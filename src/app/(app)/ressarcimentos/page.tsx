import Link from "next/link";
import { Suspense } from "react";

import { Button } from "@/components/ui/button";
import { ressarcimentoFiltrosSchema } from "@/modules/ressarcimentos/schema";
import {
  listOpcoesClientes,
  listOpcoesProcessos,
  listRessarcimentos,
  statsRessarcimentos,
} from "@/modules/ressarcimentos/queries";
import { RessarcimentosTable } from "@/modules/ressarcimentos/components/ressarcimentos-table";
import { RessarcimentosSearch } from "@/modules/ressarcimentos/components/ressarcimentos-search";
import { RessarcimentosPagination } from "@/modules/ressarcimentos/components/ressarcimentos-pagination";
import { RessarcimentoFormDialog } from "@/modules/ressarcimentos/components/ressarcimento-form-dialog";
import { RessarcimentosStats } from "@/modules/ressarcimentos/components/ressarcimentos-stats";
import { fimDoMesAtual, formatDataISO, inicioDoMesAtual } from "@/lib/datas";

export const dynamic = "force-dynamic";

type SearchParams = Promise<Record<string, string | string[] | undefined>>;

export default async function RessarcimentosPage({
  searchParams,
}: {
  searchParams: SearchParams;
}) {
  const raw = await searchParams;
  const filtrosRaw = ressarcimentoFiltrosSchema.parse(raw);

  const filtros = {
    ...filtrosRaw,
    inicio: filtrosRaw.inicio || formatDataISO(inicioDoMesAtual()),
    fim: filtrosRaw.fim || formatDataISO(fimDoMesAtual()),
  };

  const [{ items, total, page, pageSize }, stats, processos, clientes] = await Promise.all([
    listRessarcimentos(filtros),
    statsRessarcimentos(filtros),
    listOpcoesProcessos(),
    listOpcoesClientes(),
  ]);

  const semProcessos = processos.length === 0;

  return (
    <div className="space-y-6">
      <header className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold">Ressarcimentos</h1>
          <p className="text-sm text-muted-foreground">
            Despesas pagas pelo escritório em nome do cliente (custas, deslocamento, cópias) que
            serão reembolsadas — em geral, embutidas em um recebível futuro.
          </p>
        </div>
        {semProcessos ? (
          <Button asChild variant="outline">
            <Link href="/processos">Cadastre um processo primeiro</Link>
          </Button>
        ) : (
          <RessarcimentoFormDialog modo="criar" processos={processos} />
        )}
      </header>

      <RessarcimentosStats {...stats} />

      <Suspense fallback={null}>
        <RessarcimentosSearch clientes={clientes} />
      </Suspense>

      <RessarcimentosTable ressarcimentos={items} processos={processos} />

      <Suspense fallback={null}>
        <RessarcimentosPagination page={page} pageSize={pageSize} total={total} />
      </Suspense>
    </div>
  );
}
