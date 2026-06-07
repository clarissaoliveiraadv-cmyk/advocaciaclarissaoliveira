import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { toBRL } from "@/lib/money";

type Props = {
  totalBruto: number;
  totalEscritorio: number;
  totalClarissa: number;
  totalVivian: number;
  totalParceiro: number;
  saldoClarissa: number;
  saldoVivian: number;
};

export function SucumbenciasStats({
  totalBruto,
  totalEscritorio,
  totalClarissa,
  totalVivian,
  saldoClarissa,
  saldoVivian,
}: Props) {
  return (
    <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium text-muted-foreground">
            Bruto recebido
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-semibold tabular-nums">{toBRL(totalBruto)}</div>
          <p className="text-xs text-muted-foreground">Soma de todas as sucumbências</p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium text-muted-foreground">Escritório</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-semibold tabular-nums text-emerald-700">
            {toBRL(totalEscritorio)}
          </div>
          <p className="text-xs text-muted-foreground">Fica no caixa do escritório</p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium text-muted-foreground">Clarissa</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-semibold tabular-nums">{toBRL(totalClarissa)}</div>
          <p className="text-xs text-muted-foreground">
            {saldoClarissa > 0 ? (
              <span className="text-amber-700">A repassar: {toBRL(saldoClarissa)}</span>
            ) : (
              "Tudo repassado"
            )}
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium text-muted-foreground">Vivian</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-semibold tabular-nums">{toBRL(totalVivian)}</div>
          <p className="text-xs text-muted-foreground">
            {saldoVivian > 0 ? (
              <span className="text-amber-700">A repassar: {toBRL(saldoVivian)}</span>
            ) : (
              "Tudo repassado"
            )}
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
