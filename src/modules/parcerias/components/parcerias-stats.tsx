import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { toBRL } from "@/lib/money";

type Props = {
  totalAcordado: number;
  totalRecebido: number;
  totalDevido: number;
  totalPago: number;
  countPendente: number;
  countPaga: number;
};

export function ParceriasStats({
  totalRecebido,
  totalDevido,
  totalPago,
  countPendente,
  countPaga,
}: Props) {
  const saldoAPagar = Math.max(0, totalDevido - totalPago);

  return (
    <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium text-muted-foreground">
            Já recebido (base)
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-semibold tabular-nums">{toBRL(totalRecebido)}</div>
          <p className="text-xs text-muted-foreground">Valor sobre o qual aplica-se o percentual</p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium text-muted-foreground">
            Devido aos parceiros
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-semibold tabular-nums">{toBRL(totalDevido)}</div>
          <p className="text-xs text-muted-foreground">Total calculado no período</p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium text-muted-foreground">A pagar</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-semibold tabular-nums text-amber-700">
            {toBRL(saldoAPagar)}
          </div>
          <p className="text-xs text-muted-foreground">
            {countPendente} parceria{countPendente === 1 ? "" : "s"} pendente
            {countPendente === 1 ? "" : "s"}
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium text-muted-foreground">Já pago</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-semibold tabular-nums text-emerald-700">
            {toBRL(totalPago)}
          </div>
          <p className="text-xs text-muted-foreground">
            {countPaga} parceria{countPaga === 1 ? "" : "s"} quitada{countPaga === 1 ? "" : "s"}
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
