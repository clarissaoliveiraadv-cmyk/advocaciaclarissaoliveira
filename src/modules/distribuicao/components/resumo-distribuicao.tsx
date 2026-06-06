"use client";

import { AlertCircle, CheckCircle2 } from "lucide-react";
import { cn } from "@/lib/utils";
import { toBRL } from "@/lib/money";

type Props = { valorBruto: number; soma: number };

export function ResumoDistribuicao({ valorBruto, soma }: Props) {
  const delta = soma - valorBruto;
  const ok = Math.abs(delta) <= 0.005;

  return (
    <div
      className={cn(
        "flex items-center justify-between rounded-md border p-3",
        ok ? "border-emerald-200 bg-emerald-50" : "border-amber-300 bg-amber-50",
      )}
    >
      <div className="flex items-center gap-2 text-sm">
        {ok ? (
          <CheckCircle2 className="h-4 w-4 text-emerald-700" />
        ) : (
          <AlertCircle className="h-4 w-4 text-amber-700" />
        )}
        <span className={ok ? "text-emerald-900" : "text-amber-900"}>
          {ok
            ? "Soma dos itens bate com o valor bruto recebido."
            : "Soma dos itens ainda não bate com o valor bruto recebido."}
        </span>
      </div>
      <div className="text-right text-sm">
        <div className="font-mono tabular-nums">
          {toBRL(soma)} / {toBRL(valorBruto)}
        </div>
        {!ok && (
          <div className="text-xs text-amber-900">
            Δ {delta > 0 ? "+" : ""}
            {toBRL(delta)}
          </div>
        )}
      </div>
    </div>
  );
}
