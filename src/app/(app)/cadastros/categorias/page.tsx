import Link from "next/link";
import { Suspense } from "react";
import { ChevronLeft } from "lucide-react";

import { categoriaFiltrosSchema } from "@/modules/categorias/schema";
import { listCategorias, listCategoriasParaSelecao } from "@/modules/categorias/queries";
import { CategoriasTable } from "@/modules/categorias/components/categorias-table";
import { CategoriasSearch } from "@/modules/categorias/components/categorias-search";
import { CategoriaFormDialog } from "@/modules/categorias/components/categoria-form-dialog";

export const dynamic = "force-dynamic";

type SearchParams = Promise<Record<string, string | string[] | undefined>>;

export default async function CategoriasPage({ searchParams }: { searchParams: SearchParams }) {
  const raw = await searchParams;
  const filtros = categoriaFiltrosSchema.parse(raw);

  const [{ items, total, limitAtingido }, opcoes] = await Promise.all([
    listCategorias(filtros),
    listCategoriasParaSelecao(),
  ]);

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
          <h1 className="text-2xl font-semibold">Categorias</h1>
          <p className="text-sm text-muted-foreground">
            Plano de contas (receitas e despesas) usado nos lançamentos. Suporta hierarquia e separa
            fluxo do escritório do pessoal da sócia.
          </p>
        </div>
        <CategoriaFormDialog modo="criar" categorias={opcoes} />
      </header>

      <Suspense fallback={null}>
        <CategoriasSearch />
      </Suspense>

      <CategoriasTable categorias={items} opcoes={opcoes} />

      <div className="text-sm text-muted-foreground">
        {total === 0 ? "Nenhuma categoria" : `${total} categoria${total === 1 ? "" : "s"}`}
        {limitAtingido && " · exibindo as 500 primeiras"}
      </div>
    </div>
  );
}
