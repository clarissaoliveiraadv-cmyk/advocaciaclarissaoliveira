import Link from "next/link";
import { Suspense } from "react";
import { ChevronLeft } from "lucide-react";

import { parceiroFiltrosSchema } from "@/modules/parceiros/schema";
import { listParceiros } from "@/modules/parceiros/queries";
import { ParceirosTable } from "@/modules/parceiros/components/parceiros-table";
import { ParceirosSearch } from "@/modules/parceiros/components/parceiros-search";
import { ParceiroFormDialog } from "@/modules/parceiros/components/parceiro-form-dialog";

export const dynamic = "force-dynamic";

type SearchParams = Promise<Record<string, string | string[] | undefined>>;

export default async function ParceirosPage({ searchParams }: { searchParams: SearchParams }) {
  const raw = await searchParams;
  const filtros = parceiroFiltrosSchema.parse(raw);
  const { items, total, limitAtingido } = await listParceiros(filtros);

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
          <h1 className="text-2xl font-semibold">Parceiros / Advogados</h1>
          <p className="text-sm text-muted-foreground">
            Sócia, parceiros externos e funcionários usados em sucumbência e repasses. O percentual
            registrado aqui é apenas o padrão de referência — o cálculo final é feito nos módulos
            financeiros.
          </p>
        </div>
        <ParceiroFormDialog modo="criar" />
      </header>

      <Suspense fallback={null}>
        <ParceirosSearch />
      </Suspense>

      <ParceirosTable parceiros={items} />

      <div className="text-sm text-muted-foreground">
        {total === 0 ? "Nenhum parceiro" : `${total} parceiro${total === 1 ? "" : "s"}`}
        {limitAtingido && " · exibindo os 500 primeiros"}
      </div>
    </div>
  );
}
