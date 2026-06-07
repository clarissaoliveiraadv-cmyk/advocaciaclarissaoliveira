import Link from "next/link";

import { Button } from "@/components/ui/button";
import { DespesaFixaFormDialog } from "@/modules/despesas-fixas/components/despesa-fixa-form-dialog";
import { DespesasFixasTable } from "@/modules/despesas-fixas/components/despesas-fixas-table";
import {
  listDespesasFixas,
  listOpcoesCategoriasDespesa,
  listOpcoesContas,
} from "@/modules/despesas-fixas/queries";

export const dynamic = "force-dynamic";

export default async function DespesasFixasPage() {
  const [despesas, categorias, contas] = await Promise.all([
    listDespesasFixas(),
    listOpcoesCategoriasDespesa(),
    listOpcoesContas(),
  ]);

  const semContas = contas.length === 0;
  const semCategorias = categorias.length === 0;
  const bloqueado = semContas || semCategorias;
  const linkBloqueio = semContas
    ? { href: "/cadastros/contas", label: "Cadastre uma conta primeiro" }
    : { href: "/cadastros/categorias", label: "Cadastre uma categoria de DESPESA primeiro" };

  return (
    <div className="space-y-6">
      <header className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold">Despesas fixas</h1>
          <p className="text-sm text-muted-foreground">
            Contas que se repetem todo mês: luz, condomínio, internet, limpeza. Defina o template
            aqui — o sistema gera a &quot;conta a pagar&quot; mensal em <code>/contas-a-pagar</code>.
          </p>
        </div>
        {bloqueado ? (
          <Button asChild variant="outline">
            <Link href={linkBloqueio.href}>{linkBloqueio.label}</Link>
          </Button>
        ) : (
          <DespesaFixaFormDialog modo="criar" categorias={categorias} contas={contas} />
        )}
      </header>

      <DespesasFixasTable despesas={despesas} categorias={categorias} contas={contas} />
    </div>
  );
}
