import Link from "next/link";

import { Button } from "@/components/ui/button";
import { listContasParaAbertura } from "@/modules/saldo-abertura/queries";
import { SaldoAberturaForm } from "@/modules/saldo-abertura/components/saldo-abertura-form";

export const dynamic = "force-dynamic";

export default async function SaldoAberturaPage() {
  const contas = await listContasParaAbertura();

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-semibold">Saldo de abertura</h1>
        <p className="text-sm text-muted-foreground">
          Informe o saldo real de cada conta numa data de corte. A partir dessa data, só os
          lançamentos cadastrados aqui contam para o saldo — você não precisa importar o histórico
          antigo (de Projuris, planilhas, etc.).
        </p>
      </header>

      <section className="rounded-md border border-dashed bg-card p-4 text-sm text-muted-foreground">
        <p className="font-medium text-foreground">Como usar:</p>
        <ol className="mt-2 list-decimal space-y-1 pl-5">
          <li>Pegue o extrato de cada conta numa data de referência (hoje, por exemplo).</li>
          <li>Anote o saldo de cada conta nessa data.</li>
          <li>Preencha aqui e clique em &quot;Aplicar saldo de abertura&quot;.</li>
          <li>
            Daqui pra frente, registre apenas lançamentos a partir dessa data — o sistema continua
            o cálculo a partir do que você informou.
          </li>
        </ol>
        <p className="mt-2">
          Se você se enganou, pode rodar de novo a qualquer momento, ou remover a data para voltar
          a somar tudo.
        </p>
      </section>

      {contas.length === 0 ? (
        <div className="rounded-md border border-dashed bg-card p-6 text-center text-sm text-muted-foreground">
          <p>Nenhuma conta cadastrada ainda.</p>
          <Button asChild variant="outline" className="mt-3">
            <Link href="/cadastros/contas">Cadastrar uma conta</Link>
          </Button>
        </div>
      ) : (
        <SaldoAberturaForm contas={contas} />
      )}
    </div>
  );
}
