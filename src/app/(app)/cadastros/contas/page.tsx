import Link from "next/link";
import { Suspense } from "react";
import { ChevronLeft } from "lucide-react";

import { contaFiltrosSchema } from "@/modules/contas/schema";
import { listContas } from "@/modules/contas/queries";
import { ContasTable } from "@/modules/contas/components/contas-table";
import { ContasSearch } from "@/modules/contas/components/contas-search";
import { ContasPagination } from "@/modules/contas/components/contas-pagination";
import { ContaFormDialog } from "@/modules/contas/components/conta-form-dialog";

export const dynamic = "force-dynamic";

type SearchParams = Promise<Record<string, string | string[] | undefined>>;

export default async function ContasPage({ searchParams }: { searchParams: SearchParams }) {
  const raw = await searchParams;
  const filtros = contaFiltrosSchema.parse(raw);
  const { items, total, page, pageSize } = await listContas(filtros);

  return (
    <div className="space-y-6">
      <Link
        href="/cadastros"
        className="inline-flex items-center text-sm text-muted-foreground hover:text-foreground"
      >
        <ChevronLeft className="mr-1 h-4 w-4" />
        Voltar para Cadastros
      </Link>

      <header className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold">Contas Bancárias</h1>
          <p className="text-sm text-muted-foreground">
            Contas e caixas usados nos lançamentos. O código (ex.: INTER_PJ) é o identificador
            único.
          </p>
        </div>
        <ContaFormDialog modo="criar" />
      </header>

      <Suspense fallback={null}>
        <ContasSearch />
      </Suspense>

      <ContasTable contas={items} />

      <Suspense fallback={null}>
        <ContasPagination page={page} pageSize={pageSize} total={total} />
      </Suspense>
    </div>
  );
}
