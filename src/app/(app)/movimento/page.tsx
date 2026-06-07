import { Suspense } from "react";

import { lancamentoFiltrosSchema } from "@/modules/movimento/schema";
import {
  listLancamentos,
  listOpcoesCategorias,
  listOpcoesClientes,
  listOpcoesContas,
  listOpcoesProcessos,
  saldoPorConta,
} from "@/modules/movimento/queries";
import { LancamentosTable } from "@/modules/movimento/components/lancamentos-table";
import { LancamentosSearch } from "@/modules/movimento/components/lancamentos-search";
import { LancamentosPagination } from "@/modules/movimento/components/lancamentos-pagination";
import { LancamentoFormDialog } from "@/modules/movimento/components/lancamento-form-dialog";
import { TransferenciaFormDialog } from "@/modules/movimento/components/transferencia-form-dialog";
import { SaldoCards } from "@/modules/movimento/components/saldo-cards";
import { getIndicadoresFinanceiros } from "@/modules/indicadores/queries";
import { CardsFinanceiros } from "@/modules/indicadores/components/cards-financeiros";
import { fimDoMesAtual, formatDataISO, inicioDoMesAtual } from "@/lib/datas";

export const dynamic = "force-dynamic";

type SearchParams = Promise<Record<string, string | string[] | undefined>>;

export default async function MovimentoPage({ searchParams }: { searchParams: SearchParams }) {
  const raw = await searchParams;
  const filtrosRaw = lancamentoFiltrosSchema.parse(raw);

  // Default: mês atual quando nenhum período foi informado
  const filtros = {
    ...filtrosRaw,
    inicio: filtrosRaw.inicio || formatDataISO(inicioDoMesAtual()),
    fim: filtrosRaw.fim || formatDataISO(fimDoMesAtual()),
  };

  const [
    { items, total, page, pageSize },
    saldos,
    contas,
    categorias,
    clientes,
    processos,
    indicadores,
  ] = await Promise.all([
    listLancamentos(filtros),
    saldoPorConta(),
    listOpcoesContas(),
    listOpcoesCategorias(),
    listOpcoesClientes(),
    listOpcoesProcessos(),
    getIndicadoresFinanceiros(),
  ]);

  const semContas = contas.length === 0;
  const semCategorias = categorias.length === 0;
  const bloqueado = semContas || semCategorias;

  return (
    <div className="space-y-6">
      <header className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold">Movimento de Caixa</h1>
          <p className="text-sm text-muted-foreground">
            Livro-caixa do escritório. Cada lançamento afeta UMA conta + UMA categoria. Saldos por
            conta abaixo são acumulados (todas as datas).
          </p>
        </div>
        {!bloqueado && (
          <div className="flex items-center gap-2">
            <TransferenciaFormDialog modo="criar" contas={contas} categorias={categorias} />
            <LancamentoFormDialog
              modo="criar"
              contas={contas}
              categorias={categorias}
              clientes={clientes}
              processos={processos}
            />
          </div>
        )}
      </header>

      {bloqueado && (
        <div className="rounded-md border border-dashed bg-card p-6 text-sm text-muted-foreground">
          {semContas && (
            <p>
              Cadastre ao menos uma conta em <code>/cadastros/contas</code> para começar.
            </p>
          )}
          {semCategorias && (
            <p>
              Cadastre ao menos uma categoria em <code>/cadastros/categorias</code>.
            </p>
          )}
        </div>
      )}

      <CardsFinanceiros indicadores={indicadores} variant="compact" />

      <SaldoCards saldos={saldos} />

      <Suspense fallback={null}>
        <LancamentosSearch contas={contas} categorias={categorias} />
      </Suspense>

      <LancamentosTable
        lancamentos={items}
        contas={contas}
        categorias={categorias}
        clientes={clientes}
        processos={processos}
      />

      <Suspense fallback={null}>
        <LancamentosPagination page={page} pageSize={pageSize} total={total} />
      </Suspense>
    </div>
  );
}
