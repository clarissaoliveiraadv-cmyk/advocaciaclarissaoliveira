import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { toBRL } from "@/lib/money";

type Props = {
  totalBruto: number;
  totalEscritorio: number;
  totalParceiro: number;
  saldoAPagarParceiro: number;
  count: number;
};

export function SucumbenciasStats({
  totalBruto,
  totalEscritorio,
  totalParceiro,
  saldoAPagarParceiro,
  count,
}: Props) {
  const semParceiros = totalParceiro === 0;

  return (
    <div className={`grid gap-4 sm:grid-cols-2 ${semParceiros ? "lg:grid-cols-2" : "lg:grid-cols-4"}`}>
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium text-muted-foreground">
            Bruto recebido
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-semibold tabular-nums">{toBRL(totalBruto)}</div>
          <p className="text-xs text-muted-foreground">
            {count} sucumbência{count === 1 ? "" : "s"} no período
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium text-muted-foreground">
            Fica com o escritório
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-semibold tabular-nums text-emerald-700">
            {toBRL(totalEscritorio)}
          </div>
          <p className="text-xs text-muted-foreground">
            Já integrado ao saldo do caixa (entrada automática)
          </p>
        </CardContent>
      </Card>

      {!semParceiros && (
        <>
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">
                Devido a parceiros
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-semibold tabular-nums">{toBRL(totalParceiro)}</div>
              <p className="text-xs text-muted-foreground">Total no período</p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">
                A pagar a parceiros
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-semibold tabular-nums text-amber-700">
                {toBRL(saldoAPagarParceiro)}
              </div>
              <p className="text-xs text-muted-foreground">Repasses ainda pendentes</p>
            </CardContent>
          </Card>
        </>
      )}
    </div>
  );
}
