import {
  Banknote,
  Calendar,
  Lock,
  TrendingUp,
  Wallet,
} from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { toBRL } from "@/lib/money";
import { cn } from "@/lib/utils";
import type { IndicadoresFinanceiros } from "../queries";

const TIPO_LABEL: Record<string, string> = {
  CLIENTE: "Clientes",
  PARCEIRO: "Parceiros",
  PERITO: "Peritos",
  FGTS: "FGTS",
  CUSTAS: "Custas",
  OUTRO: "Outros",
};

type Props = { indicadores: IndicadoresFinanceiros; variant?: "dashboard" | "compact" };

export function CardsFinanceiros({ indicadores, variant = "dashboard" }: Props) {
  const isDashboard = variant === "dashboard";
  const liquidoNegativo = indicadores.saldoLiquido < 0;

  return (
    <div className="space-y-4">
      <div className={cn("grid gap-4", isDashboard ? "md:grid-cols-3" : "md:grid-cols-3")}>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">
              Saldo bancário
            </CardTitle>
            <Banknote className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-semibold tabular-nums">
              {toBRL(indicadores.saldoBancario)}
            </div>
            <p className="text-xs text-muted-foreground">
              Soma das contas (todo dinheiro nas contas)
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">
              Em custódia
            </CardTitle>
            <Lock className="h-4 w-4 text-amber-600" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-semibold tabular-nums text-amber-700">
              {toBRL(indicadores.emCustodia)}
            </div>
            <p className="text-xs text-muted-foreground">
              Dinheiro de terceiros aguardando repasse
            </p>
          </CardContent>
        </Card>

        <Card className={liquidoNegativo ? "border-destructive/40" : "border-emerald-200"}>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">
              Saldo líquido do escritório
            </CardTitle>
            <Wallet
              className={cn(
                "h-4 w-4",
                liquidoNegativo ? "text-destructive" : "text-emerald-700",
              )}
            />
          </CardHeader>
          <CardContent>
            <div
              className={cn(
                "text-2xl font-semibold tabular-nums",
                liquidoNegativo ? "text-destructive" : "text-emerald-700",
              )}
            >
              {toBRL(indicadores.saldoLiquido)}
            </div>
            <p className="text-xs text-muted-foreground">
              {liquidoNegativo
                ? "Atenção: obrigações maiores que o saldo"
                : "É seu de verdade (saldo − custódia)"}
            </p>
          </CardContent>
        </Card>
      </div>

      {isDashboard && (
        <div className="grid gap-4 md:grid-cols-3">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">
                Faturamento de honorários (mês)
              </CardTitle>
              <TrendingUp className="h-4 w-4 text-emerald-700" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-semibold tabular-nums text-emerald-700">
                {toBRL(indicadores.faturamentoHonorariosMes)}
              </div>
              <p className="text-xs text-muted-foreground">
                Apenas honorários contratuais + sucumbenciais
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">
                Ressarcimento (mês)
              </CardTitle>
              <TrendingUp className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-semibold tabular-nums">
                {toBRL(indicadores.ressarcimentoMes)}
              </div>
              <p className="text-xs text-muted-foreground">
                Recuperação de custas adiantadas (não é receita nova)
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">
                Recebíveis previstos (mês)
              </CardTitle>
              <Calendar className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-semibold tabular-nums">
                {toBRL(indicadores.recebiveisPrevistosMes)}
              </div>
              <p className="text-xs text-muted-foreground">
                {indicadores.quantidadeRecebiveisPrevistos === 0
                  ? "Sem parcelas previstas"
                  : `${indicadores.quantidadeRecebiveisPrevistos} parcela${
                      indicadores.quantidadeRecebiveisPrevistos === 1 ? "" : "s"
                    } prevista${indicadores.quantidadeRecebiveisPrevistos === 1 ? "" : "s"}`}
              </p>
            </CardContent>
          </Card>
        </div>
      )}

      {isDashboard && indicadores.custodiaPorBeneficiario.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-sm font-medium text-muted-foreground">
              Custódia por beneficiário
            </CardTitle>
          </CardHeader>
          <CardContent className="pt-0">
            <ul className="space-y-2">
              {indicadores.custodiaPorBeneficiario.map((c) => (
                <li
                  key={c.beneficiario}
                  className="flex items-center justify-between border-b pb-2 last:border-b-0"
                >
                  <div className="flex items-center gap-2">
                    <Badge variant="outline">{TIPO_LABEL[c.beneficiario] ?? c.beneficiario}</Badge>
                  </div>
                  <span className="font-mono tabular-nums text-amber-700">{toBRL(c.valor)}</span>
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
