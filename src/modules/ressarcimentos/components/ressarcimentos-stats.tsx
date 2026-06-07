import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { toBRL } from "@/lib/money";

type Props = {
  totalPago: number;
  countPago: number;
  totalReembolsado: number;
  countReembolsado: number;
};

export function RessarcimentosStats({
  totalPago,
  countPago,
  totalReembolsado,
  countReembolsado,
}: Props) {
  return (
    <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium text-muted-foreground">
            A receber do cliente
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-semibold tabular-nums text-amber-700">
            {toBRL(totalPago)}
          </div>
          <p className="text-xs text-muted-foreground">
            {countPago} despesa{countPago === 1 ? "" : "s"} aguardando reembolso
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium text-muted-foreground">Reembolsadas</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-semibold tabular-nums text-emerald-700">
            {toBRL(totalReembolsado)}
          </div>
          <p className="text-xs text-muted-foreground">
            {countReembolsado} despesa{countReembolsado === 1 ? "" : "s"} já reembolsada
            {countReembolsado === 1 ? "" : "s"} no período
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium text-muted-foreground">Total geral</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-semibold tabular-nums">
            {toBRL(totalPago + totalReembolsado)}
          </div>
          <p className="text-xs text-muted-foreground">
            {countPago + countReembolsado} despesa
            {countPago + countReembolsado === 1 ? "" : "s"} no período
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
