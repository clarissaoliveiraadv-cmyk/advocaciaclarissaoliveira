"use client";

import { useState, useTransition } from "react";
import { toast } from "sonner";
import { Calendar, RotateCcw } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { toBRL } from "@/lib/money";
import { formatDataBR } from "@/lib/datas";

import { importarSaldoAbertura, limparSaldoAbertura } from "../actions";
import type { ContaSaldoAbertura } from "../queries";

type Linha = {
  contaId: string;
  codigo: string;
  nome: string;
  saldoInicial: string;
  saldoAberturaData: string;
  saldoAberturaDataAtual: Date | null;
  lancamentosIgnorados: number;
  lancamentosTotais: number;
};

function toLinha(c: ContaSaldoAbertura): Linha {
  return {
    contaId: c.id,
    codigo: c.codigo,
    nome: c.nome,
    saldoInicial: String(c.saldoInicial),
    saldoAberturaData: c.saldoAberturaData
      ? c.saldoAberturaData.toISOString().slice(0, 10)
      : new Date().toISOString().slice(0, 10),
    saldoAberturaDataAtual: c.saldoAberturaData,
    lancamentosIgnorados: c.lancamentosIgnorados,
    lancamentosTotais: c.lancamentosTotais,
  };
}

export function SaldoAberturaForm({ contas }: { contas: ContaSaldoAbertura[] }) {
  const [linhas, setLinhas] = useState<Linha[]>(() => contas.map(toLinha));
  const [dataComum, setDataComum] = useState("");
  const [pending, startTransition] = useTransition();

  function updateLinha(i: number, patch: Partial<Linha>) {
    setLinhas((prev) => prev.map((l, idx) => (idx === i ? { ...l, ...patch } : l)));
  }

  function aplicarDataComum() {
    if (!dataComum) return;
    setLinhas((prev) => prev.map((l) => ({ ...l, saldoAberturaData: dataComum })));
  }

  function onSubmit() {
    // Coleta apenas linhas que tenham valor + data preenchidos
    const itens = linhas
      .filter((l) => l.saldoAberturaData && l.saldoInicial !== "")
      .map((l) => ({
        contaId: l.contaId,
        saldoInicial: Number(l.saldoInicial),
        saldoAberturaData: l.saldoAberturaData,
      }));

    if (itens.length === 0) {
      toast.error("Informe ao menos uma conta com saldo e data preenchidos.");
      return;
    }

    startTransition(async () => {
      const result = await importarSaldoAbertura({ itens });
      if (!result.ok) {
        toast.error(result.error);
        return;
      }
      toast.success(`Saldo de abertura importado em ${result.data.contasAtualizadas} conta(s).`);
    });
  }

  function onLimpar(contaId: string) {
    if (!confirm("Remover a data de abertura desta conta? O saldo passará a considerar TODOS os lançamentos da conta novamente.")) {
      return;
    }
    startTransition(async () => {
      const result = await limparSaldoAbertura({ contaId });
      if (!result.ok) {
        toast.error(result.error);
        return;
      }
      toast.success("Data de abertura removida.");
      updateLinha(
        linhas.findIndex((l) => l.contaId === contaId),
        { saldoAberturaDataAtual: null, lancamentosIgnorados: 0 },
      );
    });
  }

  return (
    <div className="space-y-4">
      <div className="rounded-md border bg-card p-4">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-end">
          <div className="flex-1">
            <label className="mb-1 block text-xs font-medium text-muted-foreground">
              Data comum (atalho)
            </label>
            <Input
              type="date"
              value={dataComum}
              onChange={(e) => setDataComum(e.target.value)}
              placeholder="Aplicar a todas as contas"
            />
            <p className="mt-1 text-xs text-muted-foreground">
              Útil quando você está partindo do zero hoje. Preenche o campo &quot;Data de abertura&quot;
              de todas as contas com a mesma data.
            </p>
          </div>
          <Button type="button" variant="outline" onClick={aplicarDataComum} disabled={!dataComum}>
            <Calendar className="mr-2 h-4 w-4" />
            Aplicar a todas
          </Button>
        </div>
      </div>

      <div className="overflow-x-auto rounded-md border bg-card">
        <table className="w-full text-sm">
          <thead className="border-b bg-muted/40">
            <tr className="text-left">
              <th className="p-3">Conta</th>
              <th className="p-3 w-[180px]">Saldo na data (R$)</th>
              <th className="p-3 w-[180px]">Data de abertura</th>
              <th className="p-3">Estado atual</th>
              <th className="p-3 w-[140px] text-right">Ações</th>
            </tr>
          </thead>
          <tbody>
            {linhas.map((l, i) => (
              <tr key={l.contaId} className="border-b last:border-0">
                <td className="p-3">
                  <div className="font-medium">{l.nome}</div>
                  <div className="text-xs text-muted-foreground">{l.codigo}</div>
                </td>
                <td className="p-3">
                  <Input
                    type="number"
                    step="0.01"
                    inputMode="decimal"
                    value={l.saldoInicial}
                    onChange={(e) => updateLinha(i, { saldoInicial: e.target.value })}
                  />
                </td>
                <td className="p-3">
                  <Input
                    type="date"
                    value={l.saldoAberturaData}
                    onChange={(e) => updateLinha(i, { saldoAberturaData: e.target.value })}
                  />
                </td>
                <td className="p-3 text-xs">
                  {l.saldoAberturaDataAtual ? (
                    <div className="space-y-0.5">
                      <Badge variant="secondary">
                        Configurada em {formatDataBR(l.saldoAberturaDataAtual)}
                      </Badge>
                      <div className="text-muted-foreground">
                        Saldo na data: <span className="font-mono">{toBRL(Number(l.saldoInicial) || 0)}</span>
                      </div>
                      {l.lancamentosIgnorados > 0 && (
                        <div className="text-amber-700">
                          {l.lancamentosIgnorados} de {l.lancamentosTotais} lançamentos ignorados
                          (anteriores à data).
                        </div>
                      )}
                    </div>
                  ) : (
                    <Badge variant="outline">Sem data — soma tudo desde sempre</Badge>
                  )}
                </td>
                <td className="p-3 text-right">
                  {l.saldoAberturaDataAtual && (
                    <Button
                      type="button"
                      variant="ghost"
                      size="sm"
                      onClick={() => onLimpar(l.contaId)}
                      disabled={pending}
                    >
                      <RotateCcw className="mr-1 h-3 w-3" />
                      Remover data
                    </Button>
                  )}
                </td>
              </tr>
            ))}
            {linhas.length === 0 && (
              <tr>
                <td colSpan={5} className="p-6 text-center text-sm text-muted-foreground">
                  Nenhuma conta cadastrada. Cadastre em <code>/cadastros/contas</code>.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      <div className="flex justify-end gap-2">
        <Button onClick={onSubmit} disabled={pending || linhas.length === 0}>
          {pending ? "Aplicando..." : "Aplicar saldo de abertura"}
        </Button>
      </div>
    </div>
  );
}
