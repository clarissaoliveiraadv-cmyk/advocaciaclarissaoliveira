import Link from "next/link";
import { Suspense } from "react";

import { Button } from "@/components/ui/button";
import { processoFiltrosSchema } from "@/modules/processos/schema";
import { listClientesParaSelecao, listProcessos } from "@/modules/processos/queries";
import { ProcessosTable } from "@/modules/processos/components/processos-table";
import { ProcessosSearch } from "@/modules/processos/components/processos-search";
import { ProcessosPagination } from "@/modules/processos/components/processos-pagination";
import { ProcessoFormDialog } from "@/modules/processos/components/processo-form-dialog";

export const dynamic = "force-dynamic";

type SearchParams = Promise<Record<string, string | string[] | undefined>>;

export default async function ProcessosPage({ searchParams }: { searchParams: SearchParams }) {
  const raw = await searchParams;
  const filtros = processoFiltrosSchema.parse(raw);
  const [{ items, total, page, pageSize }, clientes] = await Promise.all([
    listProcessos(filtros),
    listClientesParaSelecao(),
  ]);

  return (
    <div className="space-y-6">
      <header className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold">Processos</h1>
          <p className="text-sm text-muted-foreground">
            Cadastro de processos e procedimentos do escritório. Vinculados a um cliente; número CNJ
            é opcional.
          </p>
        </div>
        {clientes.length > 0 ? (
          <ProcessoFormDialog modo="criar" clientes={clientes} />
        ) : (
          <Button asChild variant="outline">
            <Link href="/clientes">Cadastre um cliente primeiro</Link>
          </Button>
        )}
      </header>

      <Suspense fallback={null}>
        <ProcessosSearch />
      </Suspense>

      <ProcessosTable processos={items} clientes={clientes} />

      <Suspense fallback={null}>
        <ProcessosPagination page={page} pageSize={pageSize} total={total} />
      </Suspense>
    </div>
  );
}
