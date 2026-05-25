import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { toBRL } from "@/lib/money";
import { ArrowDownRight, ArrowUpRight } from "lucide-react";
import type { SaldoConta } from "../queries";

type Props = { saldos: SaldoConta[] };

export function SaldoCards({ saldos }: Props) {
  if (saldos.length === 0) {
    return (
      <div className="rounded-md border border-dashed bg-card p-6 text-sm text-muted-foreground">
        Nenhuma conta cadastrada. Cadastre em <code>/cadastros/contas</code>.
      </div>
    );
  }

  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
      {saldos.map((s) => (
        <Card key={s.contaId}>
          <CardHeader className="flex flex-row items-start justify-between space-y-0 pb-2">
            <div>
              <CardTitle className="text-base">{s.nome}</CardTitle>
              <p className="font-mono text-xs text-muted-foreground">{s.codigo}</p>
            </div>
          </CardHeader>
          <CardContent className="space-y-1">
            <div className="text-2xl font-semibold tabular-nums">{toBRL(s.saldoAtual)}</div>
            <div className="flex items-center gap-3 text-xs text-muted-foreground">
              <span className="flex items-center text-emerald-700">
                <ArrowUpRight className="mr-1 h-3 w-3" />
                {toBRL(s.totalEntradas)}
              </span>
              <span className="flex items-center text-red-700">
                <ArrowDownRight className="mr-1 h-3 w-3" />
                {toBRL(s.totalSaidas)}
              </span>
            </div>
            <p className="pt-1 text-xs text-muted-foreground">
              Saldo inicial: {toBRL(s.saldoInicial)}
            </p>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}
