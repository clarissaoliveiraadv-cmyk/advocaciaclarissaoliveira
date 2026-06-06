import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { toBRL } from "@/lib/money";

type Props = {
  totalValor: number;
  totalRessarcimento: number;
  totalHonorariosSugeridos: number;
  totalClienteSugerido: number;
  count: number;
};

export function RecebiveisStats({
  totalValor,
  totalRessarcimento,
  totalHonorariosSugeridos,
  totalClienteSugerido,
  count,
}: Props) {
  return (
    <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium text-muted-foreground">
            Previsão total
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-semibold tabular-nums">{toBRL(totalValor)}</div>
          <p className="text-xs text-muted-foreground">
            {count} parcela{count === 1 ? "" : "s"} prevista{count === 1 ? "" : "s"}
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium text-muted-foreground">
            Honorários sugeridos
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-semibold tabular-nums text-emerald-700">
            {toBRL(totalHonorariosSugeridos)}
          </div>
          <p className="text-xs text-muted-foreground">Sobre as parcelas previstas</p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium text-muted-foreground">
            Repasse a clientes
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-semibold tabular-nums">{toBRL(totalClienteSugerido)}</div>
          <p className="text-xs text-muted-foreground">Valor a repassar (sugerido)</p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium text-muted-foreground">
            Ressarcimentos embutidos
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-semibold tabular-nums">{toBRL(totalRessarcimento)}</div>
          <p className="text-xs text-muted-foreground">Custos a recuperar do cliente</p>
        </CardContent>
      </Card>
    </div>
  );
}
