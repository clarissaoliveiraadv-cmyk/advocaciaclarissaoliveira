import { getIndicadoresFinanceiros } from "@/modules/indicadores/queries";
import { CardsFinanceiros } from "@/modules/indicadores/components/cards-financeiros";

export const dynamic = "force-dynamic";

export default async function DashboardPage() {
  const indicadores = await getIndicadoresFinanceiros();

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-semibold text-slate-900">Painel</h1>
        <p className="text-sm text-slate-500">
          Visão geral do fluxo financeiro do escritório.
        </p>
      </header>

      <CardsFinanceiros indicadores={indicadores} variant="dashboard" />

      <section className="rounded-md border border-dashed bg-card p-4 text-xs text-muted-foreground">
        <p className="font-medium text-foreground">Como ler os indicadores:</p>
        <ul className="mt-2 list-disc space-y-1 pl-5">
          <li>
            <strong>Saldo bancário</strong> é o quanto há nas contas — incluindo dinheiro que ainda
            precisa ser repassado a clientes, parceiros, peritos etc.
          </li>
          <li>
            <strong>Em custódia</strong> é o total que pertence a terceiros e está aguardando
            repasse (status PENDENTE_REPASSE).
          </li>
          <li>
            <strong>Saldo líquido</strong> é o que efetivamente é do escritório — a diferença entre
            os dois acima.
          </li>
          <li>
            <strong>Ressarcimento</strong> aparece à parte para evitar confusão: é apenas a
            devolução de custas que o escritório havia adiantado, não receita nova.
          </li>
        </ul>
      </section>
    </div>
  );
}
