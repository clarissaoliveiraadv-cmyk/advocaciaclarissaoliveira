import Link from "next/link";
import { Suspense } from "react";

import { Button } from "@/components/ui/button";
import { sucumbenciaFiltrosSchema } from "@/modules/sucumbencia/schema";
import {
  listOpcoesCategoriasReceita,
  listOpcoesClientes,
  listOpcoesContas,
  listOpcoesParceiros,
  listOpcoesProcessos,
  listSucumbencias,
  statsSucumbencia,
} from "@/modules/sucumbencia/queries";
import { SucumbenciasTable } from "@/modules/sucumbencia/components/sucumbencias-table";
import { SucumbenciasSearch } from "@/modules/sucumbencia/components/sucumbencias-search";
import { SucumbenciasPagination } from "@/modules/sucumbencia/components/sucumbencias-pagination";
import { SucumbenciaFormDialog } from "@/modules/sucumbencia/components/sucumbencia-form-dialog";
import { SucumbenciasStats } from "@/modules/sucumbencia/components/sucumbencias-stats";
import { fimDoMesAtual, formatDataISO, inicioDoMesAtual } from "@/lib/datas";

export const dynamic = "force-dynamic";

type SearchParams = Promise<Record<string, string | string[] | undefined>>;

export default async function SucumbenciaPage({ searchParams }: { searchParams: SearchParams }) {
  const raw = await searchParams;
  const filtrosRaw = sucumbenciaFiltrosSchema.parse(raw);

  const filtros = {
    ...filtrosRaw,
    inicio: filtrosRaw.inicio || formatDataISO(inicioDoMesAtual()),
    fim: filtrosRaw.fim || formatDataISO(fimDoMesAtual()),
  };

  const [
    { items, total, page, pageSize },
    stats,
    processos,
    parceiros,
    contas,
    categoriasReceita,
    clientes,
  ] = await Promise.all([
    listSucumbencias(filtros),
    statsSucumbencia(filtros),
    listOpcoesProcessos(),
    listOpcoesParceiros(),
    listOpcoesContas(),
    listOpcoesCategoriasReceita(),
    listOpcoesClientes(),
  ]);

  const semProcessos = processos.length === 0;
  const semContas = contas.length === 0;
  const semCategorias = categoriasReceita.length === 0;
  const bloqueado = semProcessos || semContas || semCategorias;

  const linkBloqueio = semProcessos
    ? { href: "/processos", label: "Cadastre um processo primeiro" }
    : semContas
      ? { href: "/cadastros/contas", label: "Cadastre uma conta primeiro" }
      : { href: "/cadastros/categorias", label: "Cadastre uma categoria de receita" };

  return (
    <div className="space-y-6">
      <header className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold">Sucumbência</h1>
          <p className="text-sm text-muted-foreground">
            Honorários de sucumbência arbitrados em sentença. O valor bruto entra no caixa
            automaticamente. Se você dividir com parceiro externo, a fatia dele vira obrigação
            pendente até ser paga.
          </p>
        </div>
        {bloqueado ? (
          <Button asChild variant="outline">
            <Link href={linkBloqueio.href}>{linkBloqueio.label}</Link>
          </Button>
        ) : (
          <SucumbenciaFormDialog
            modo="criar"
            processos={processos}
            parceiros={parceiros}
            contas={contas}
            categoriasReceita={categoriasReceita}
          />
        )}
      </header>

      <SucumbenciasStats {...stats} />

      <Suspense fallback={null}>
        <SucumbenciasSearch clientes={clientes} />
      </Suspense>

      <SucumbenciasTable
        sucumbencias={items}
        processos={processos}
        parceiros={parceiros}
        contas={contas}
        categoriasReceita={categoriasReceita}
      />

      <Suspense fallback={null}>
        <SucumbenciasPagination page={page} pageSize={pageSize} total={total} />
      </Suspense>
    </div>
  );
}
