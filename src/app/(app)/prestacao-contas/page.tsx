import Link from "next/link";
import { Suspense } from "react";
import { ArrowRight } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { listProcessosComReceita } from "@/modules/prestacao-contas/queries";
import { ListaProcessosBusca } from "@/modules/prestacao-contas/components/lista-processos-busca";
import { toBRL } from "@/lib/money";
import { formatCnj, formatCpfCnpj } from "@/lib/format";
import { formatDataBR } from "@/lib/datas";

export const dynamic = "force-dynamic";

type SearchParams = Promise<Record<string, string | string[] | undefined>>;

export default async function PrestacaoContasHome({
  searchParams,
}: {
  searchParams: SearchParams;
}) {
  const raw = await searchParams;
  const search = typeof raw.search === "string" ? raw.search : undefined;
  const processos = await listProcessosComReceita({ search });

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-semibold">Prestação de Contas</h1>
        <p className="text-sm text-muted-foreground">
          Documento entregue ao cliente mostrando como o valor recebido foi distribuído. Lista os
          processos com pelo menos uma distribuição confirmada.
        </p>
      </header>

      <Suspense fallback={null}>
        <ListaProcessosBusca />
      </Suspense>

      {processos.length === 0 ? (
        <div className="rounded-md border border-dashed bg-card p-8 text-center text-sm text-muted-foreground">
          Nenhum processo com distribuição confirmada{search ? " para esta busca" : ""}.
          {!search && " Confirme o recebimento de um recebível para gerar a primeira prestação."}
        </div>
      ) : (
        <div className="grid gap-3">
          {processos.map((p) => (
            <Link
              key={p.id}
              href={`/prestacao-contas/${p.id}`}
              className="group flex items-center justify-between rounded-md border bg-card p-4 transition hover:border-primary/40 hover:shadow-sm"
            >
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <h2 className="font-semibold">{p.cliente.nome}</h2>
                  {p.cliente.cpfCnpj && (
                    <span className="font-mono text-xs text-muted-foreground">
                      {formatCpfCnpj(p.cliente.cpfCnpj)}
                    </span>
                  )}
                </div>
                <div className="font-mono text-xs text-muted-foreground">
                  {p.numeroCnj ? formatCnj(p.numeroCnj) : "— sem CNJ —"}
                </div>
                <div className="flex flex-wrap items-center gap-2 pt-1">
                  <Badge variant="outline">{p.natureza}</Badge>
                  {p.parteContraria && (
                    <span className="text-xs text-muted-foreground">vs {p.parteContraria}</span>
                  )}
                </div>
              </div>
              <div className="text-right">
                <div className="font-mono text-base font-semibold tabular-nums">
                  {toBRL(p.totalRecebido)}
                </div>
                <div className="text-xs text-muted-foreground">
                  {p.quantidadeDistribuicoes} recebimento
                  {p.quantidadeDistribuicoes === 1 ? "" : "s"}
                </div>
                {p.primeiraData && p.ultimaData && (
                  <div className="mt-1 text-xs text-muted-foreground">
                    {formatDataBR(p.primeiraData.toISOString())}
                    {p.primeiraData.getTime() !== p.ultimaData.getTime() &&
                      ` a ${formatDataBR(p.ultimaData.toISOString())}`}
                  </div>
                )}
                <ArrowRight className="ml-auto mt-2 h-4 w-4 text-muted-foreground transition group-hover:translate-x-0.5 group-hover:text-foreground" />
              </div>
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}
