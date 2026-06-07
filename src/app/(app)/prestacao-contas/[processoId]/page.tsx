import Link from "next/link";
import { notFound } from "next/navigation";
import { ChevronLeft, Settings } from "lucide-react";

import { Button } from "@/components/ui/button";
import { getOuCriarEscritorio, escritorioEstaCompleto } from "@/modules/escritorio/queries";
import { getPrestacaoContas } from "@/modules/prestacao-contas/queries";
import { PrestacaoDetalhes } from "@/modules/prestacao-contas/components/prestacao-detalhes";
import { PrestacaoFiltros } from "@/modules/prestacao-contas/components/prestacao-filtros";
import { ImprimirButton } from "@/modules/prestacao-contas/components/imprimir-button";

export const dynamic = "force-dynamic";

type Params = Promise<{ processoId: string }>;
type SearchParams = Promise<Record<string, string | string[] | undefined>>;

export default async function PrestacaoProcessoPage({
  params,
  searchParams,
}: {
  params: Params;
  searchParams: SearchParams;
}) {
  const { processoId } = await params;
  const raw = await searchParams;
  const inicio = typeof raw.inicio === "string" ? raw.inicio : undefined;
  const fim = typeof raw.fim === "string" ? raw.fim : undefined;

  const [dados, escritorio] = await Promise.all([
    getPrestacaoContas(processoId, { inicio, fim }),
    getOuCriarEscritorio(),
  ]);

  if (!dados) notFound();

  const escritorioCompleto = escritorioEstaCompleto(escritorio);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between print:hidden">
        <Link
          href="/prestacao-contas"
          className="inline-flex items-center text-sm text-muted-foreground hover:text-foreground"
        >
          <ChevronLeft className="mr-1 h-4 w-4" />
          Voltar
        </Link>
        <ImprimirButton />
      </div>

      {!escritorioCompleto && (
        <div className="rounded-md border border-amber-300 bg-amber-50 p-3 text-sm text-amber-900 print:hidden">
          <div className="flex items-start justify-between gap-3">
            <p>
              Complete os dados do escritório (nome, OAB, endereço) para que apareçam corretamente
              no documento entregue ao cliente.
            </p>
            <Button asChild size="sm" variant="outline">
              <Link href="/cadastros/escritorio">
                <Settings className="mr-1 h-4 w-4" />
                Configurar
              </Link>
            </Button>
          </div>
        </div>
      )}

      <PrestacaoFiltros processoId={processoId} />

      <PrestacaoDetalhes dados={dados} escritorio={escritorio} />
    </div>
  );
}
