import { Suspense } from "react";

import { relatoriosFiltrosSchema } from "@/modules/relatorios/schema";
import {
  getDRE,
  getFluxoMensal,
  getPorParceiro,
  getPosicaoPorCliente,
} from "@/modules/relatorios/queries";
import { RelatoriosFiltros } from "@/modules/relatorios/components/relatorios-filtros";
import { DreSection } from "@/modules/relatorios/components/dre-section";
import { FluxoMensalSection } from "@/modules/relatorios/components/fluxo-mensal-section";
import { PorClienteSection } from "@/modules/relatorios/components/por-cliente-section";
import { PorParceiroSection } from "@/modules/relatorios/components/por-parceiro-section";
import { fimDoMesAtual, formatDataBR, formatDataISO, inicioDoMesAtual } from "@/lib/datas";

export const dynamic = "force-dynamic";

type SearchParams = Promise<Record<string, string | string[] | undefined>>;

export default async function RelatoriosPage({ searchParams }: { searchParams: SearchParams }) {
  const raw = await searchParams;
  const filtrosRaw = relatoriosFiltrosSchema.parse(raw);

  const inicioStr = filtrosRaw.inicio || formatDataISO(inicioDoMesAtual());
  const fimStr = filtrosRaw.fim || formatDataISO(fimDoMesAtual());

  const periodo = {
    inicio: new Date(`${inicioStr}T00:00:00.000Z`),
    fim: new Date(`${fimStr}T23:59:59.999Z`),
  };

  const [dre, fluxo, porCliente, porParceiro] = await Promise.all([
    getDRE(periodo),
    getFluxoMensal(periodo),
    getPosicaoPorCliente(periodo),
    getPorParceiro(periodo),
  ]);

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-semibold">Relatórios</h1>
        <p className="text-sm text-muted-foreground">
          Visão consolidada do período {formatDataBR(periodo.inicio)} a{" "}
          {formatDataBR(periodo.fim)}.
        </p>
      </header>

      <Suspense fallback={null}>
        <RelatoriosFiltros />
      </Suspense>

      <DreSection {...dre} />
      <FluxoMensalSection fluxo={fluxo} />
      <PorClienteSection itens={porCliente} />
      <PorParceiroSection itens={porParceiro} />
    </div>
  );
}
