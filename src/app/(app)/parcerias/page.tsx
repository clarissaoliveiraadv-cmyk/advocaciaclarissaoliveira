import Link from "next/link";
import { Suspense } from "react";

import { Button } from "@/components/ui/button";
import { parceriaFiltrosSchema } from "@/modules/parcerias/schema";
import {
  listOpcoesClientes,
  listOpcoesParceiros,
  listOpcoesProcessos,
  listParcerias,
  statsParcerias,
} from "@/modules/parcerias/queries";
import { ParceriasTable } from "@/modules/parcerias/components/parcerias-table";
import { ParceriasSearch } from "@/modules/parcerias/components/parcerias-search";
import { ParceriasPagination } from "@/modules/parcerias/components/parcerias-pagination";
import { ParceriaFormDialog } from "@/modules/parcerias/components/parceria-form-dialog";
import { ParceriasStats } from "@/modules/parcerias/components/parcerias-stats";
import { fimDoMesAtual, formatDataISO, inicioDoMesAtual } from "@/lib/datas";

export const dynamic = "force-dynamic";

type SearchParams = Promise<Record<string, string | string[] | undefined>>;

export default async function ParceriasPage({ searchParams }: { searchParams: SearchParams }) {
  const raw = await searchParams;
  const filtrosRaw = parceriaFiltrosSchema.parse(raw);

  const filtros = {
    ...filtrosRaw,
    inicio: filtrosRaw.inicio || formatDataISO(inicioDoMesAtual()),
    fim: filtrosRaw.fim || formatDataISO(fimDoMesAtual()),
  };

  const [{ items, total, page, pageSize }, stats, processos, parceiros, clientes] =
    await Promise.all([
      listParcerias(filtros),
      statsParcerias(filtros),
      listOpcoesProcessos(),
      listOpcoesParceiros(),
      listOpcoesClientes(),
    ]);

  const semProcessos = processos.length === 0;
  const semParceiros = parceiros.length === 0;
  const bloqueado = semProcessos || semParceiros;

  return (
    <div className="space-y-6">
      <header className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold">Parcerias</h1>
          <p className="text-sm text-muted-foreground">
            Honorários compartilhados com advogados parceiros. O sistema calcula quanto está devido
            conforme o cliente paga; você marca como pago quando quita o parceiro.
          </p>
        </div>
        {bloqueado ? (
          <Button asChild variant="outline">
            <Link href={semParceiros ? "/cadastros/parceiros" : "/processos"}>
              {semParceiros ? "Cadastre um parceiro primeiro" : "Cadastre um processo primeiro"}
            </Link>
          </Button>
        ) : (
          <ParceriaFormDialog modo="criar" processos={processos} parceiros={parceiros} />
        )}
      </header>

      <ParceriasStats {...stats} />

      <Suspense fallback={null}>
        <ParceriasSearch clientes={clientes} parceiros={parceiros} />
      </Suspense>

      <ParceriasTable parcerias={items} processos={processos} parceiros={parceiros} />

      <Suspense fallback={null}>
        <ParceriasPagination page={page} pageSize={pageSize} total={total} />
      </Suspense>
    </div>
  );
}
