import Link from "next/link";
import { Suspense } from "react";

import { Button } from "@/components/ui/button";
import { recebivelFiltrosSchema } from "@/modules/recebiveis/schema";
import {
  listOpcoesClientes,
  listOpcoesParceiros,
  listOpcoesProcessos,
  listRecebiveis,
  statsPrevistos,
} from "@/modules/recebiveis/queries";
import { RecebiveisTable } from "@/modules/recebiveis/components/recebiveis-table";
import { RecebiveisSearch } from "@/modules/recebiveis/components/recebiveis-search";
import { RecebiveisPagination } from "@/modules/recebiveis/components/recebiveis-pagination";
import { RecebivelFormDialog } from "@/modules/recebiveis/components/recebivel-form-dialog";
import { RecebiveisStats } from "@/modules/recebiveis/components/recebiveis-stats";
import { fimDoMesAtual, formatDataISO, inicioDoMesAtual } from "@/lib/datas";

export const dynamic = "force-dynamic";

type SearchParams = Promise<Record<string, string | string[] | undefined>>;

export default async function RecebiveisPage({ searchParams }: { searchParams: SearchParams }) {
  const raw = await searchParams;
  const filtrosRaw = recebivelFiltrosSchema.parse(raw);

  // Default: mês atual quando nenhum período foi informado
  const filtros = {
    ...filtrosRaw,
    inicio: filtrosRaw.inicio || formatDataISO(inicioDoMesAtual()),
    fim: filtrosRaw.fim || formatDataISO(fimDoMesAtual()),
  };

  const [{ items, total, page, pageSize }, stats, processos, clientes, parceiros] =
    await Promise.all([
      listRecebiveis(filtros),
      statsPrevistos(filtros),
      listOpcoesProcessos(),
      listOpcoesClientes(),
      listOpcoesParceiros(),
    ]);

  const semProcessos = processos.length === 0;

  return (
    <div className="space-y-6">
      <header className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold">Recebíveis</h1>
          <p className="text-sm text-muted-foreground">
            Previsão de parcelas a receber por processo. Valores são apenas estimativas — a
            distribuição definitiva (honorários, parceiro, cliente, perito, FGTS, custas) é
            confirmada quando o valor é efetivamente recebido (Slice 3.2).
          </p>
        </div>
        {semProcessos ? (
          <Button asChild variant="outline">
            <Link href="/processos">Cadastre um processo primeiro</Link>
          </Button>
        ) : (
          <RecebivelFormDialog modo="criar" processos={processos} parceiros={parceiros} />
        )}
      </header>

      <RecebiveisStats {...stats} />

      <Suspense fallback={null}>
        <RecebiveisSearch clientes={clientes} parceiros={parceiros} />
      </Suspense>

      <RecebiveisTable recebiveis={items} processos={processos} parceiros={parceiros} />

      <Suspense fallback={null}>
        <RecebiveisPagination page={page} pageSize={pageSize} total={total} />
      </Suspense>
    </div>
  );
}
