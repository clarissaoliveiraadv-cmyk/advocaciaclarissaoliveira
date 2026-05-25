import { Suspense } from "react";

import { clienteFiltrosSchema } from "@/modules/clientes/schema";
import { listClientes } from "@/modules/clientes/queries";
import { ClientesTable } from "@/modules/clientes/components/clientes-table";
import { ClientesSearch } from "@/modules/clientes/components/clientes-search";
import { ClientesPagination } from "@/modules/clientes/components/clientes-pagination";
import { ClienteFormDialog } from "@/modules/clientes/components/cliente-form-dialog";

export const dynamic = "force-dynamic";

type SearchParams = Promise<Record<string, string | string[] | undefined>>;

export default async function ClientesPage({ searchParams }: { searchParams: SearchParams }) {
  const raw = await searchParams;
  const filtros = clienteFiltrosSchema.parse(raw);
  const { items, total, page, pageSize } = await listClientes(filtros);

  return (
    <div className="space-y-6">
      <header className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold">Clientes</h1>
          <p className="text-sm text-muted-foreground">
            Cadastro de clientes do escritório. Busque por nome, CPF/CNPJ, telefone ou e-mail.
          </p>
        </div>
        <ClienteFormDialog modo="criar" />
      </header>

      <Suspense fallback={null}>
        <ClientesSearch />
      </Suspense>

      <ClientesTable clientes={items} />

      <Suspense fallback={null}>
        <ClientesPagination page={page} pageSize={pageSize} total={total} />
      </Suspense>
    </div>
  );
}
