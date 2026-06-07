"use client";

import { useTransition } from "react";
import { useRouter, useSearchParams } from "next/navigation";

import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";

const PRESETS = [
  { label: "Mês atual", fn: () => mesAtual() },
  { label: "Mês anterior", fn: () => mesAnterior() },
  { label: "Ano atual", fn: () => anoAtual() },
  { label: "12 meses", fn: () => ultimosDozeMeses() },
];

export function RelatoriosFiltros() {
  const router = useRouter();
  const params = useSearchParams();
  const [, startTransition] = useTransition();

  const inicio = params.get("inicio") ?? "";
  const fim = params.get("fim") ?? "";

  function updateParams(updates: Record<string, string>) {
    const next = new URLSearchParams(params.toString());
    for (const [k, v] of Object.entries(updates)) {
      if (!v) next.delete(k);
      else next.set(k, v);
    }
    startTransition(() => router.replace(`/relatorios?${next.toString()}`));
  }

  function aplicarPreset(p: { inicio: string; fim: string }) {
    updateParams(p);
  }

  return (
    <div className="space-y-3 rounded-md border bg-card p-4">
      <div className="grid gap-3 sm:grid-cols-3">
        <div>
          <label className="mb-1 block text-xs font-medium text-muted-foreground">Período (de)</label>
          <Input
            type="date"
            value={inicio}
            onChange={(e) => updateParams({ inicio: e.target.value })}
          />
        </div>
        <div>
          <label className="mb-1 block text-xs font-medium text-muted-foreground">
            Período (até)
          </label>
          <Input
            type="date"
            value={fim}
            onChange={(e) => updateParams({ fim: e.target.value })}
          />
        </div>
        <div>
          <label className="mb-1 block text-xs font-medium text-muted-foreground">Atalhos</label>
          <div className="flex flex-wrap gap-1">
            {PRESETS.map((p) => (
              <Button
                key={p.label}
                type="button"
                variant="outline"
                size="sm"
                onClick={() => aplicarPreset(p.fn())}
              >
                {p.label}
              </Button>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

function fmt(d: Date) {
  return d.toISOString().slice(0, 10);
}

function mesAtual() {
  const hoje = new Date();
  const inicio = new Date(Date.UTC(hoje.getUTCFullYear(), hoje.getUTCMonth(), 1));
  const fim = new Date(Date.UTC(hoje.getUTCFullYear(), hoje.getUTCMonth() + 1, 0));
  return { inicio: fmt(inicio), fim: fmt(fim) };
}

function mesAnterior() {
  const hoje = new Date();
  const inicio = new Date(Date.UTC(hoje.getUTCFullYear(), hoje.getUTCMonth() - 1, 1));
  const fim = new Date(Date.UTC(hoje.getUTCFullYear(), hoje.getUTCMonth(), 0));
  return { inicio: fmt(inicio), fim: fmt(fim) };
}

function anoAtual() {
  const hoje = new Date();
  const inicio = new Date(Date.UTC(hoje.getUTCFullYear(), 0, 1));
  const fim = new Date(Date.UTC(hoje.getUTCFullYear(), 11, 31));
  return { inicio: fmt(inicio), fim: fmt(fim) };
}

function ultimosDozeMeses() {
  const hoje = new Date();
  const inicio = new Date(Date.UTC(hoje.getUTCFullYear(), hoje.getUTCMonth() - 11, 1));
  const fim = new Date(Date.UTC(hoje.getUTCFullYear(), hoje.getUTCMonth() + 1, 0));
  return { inicio: fmt(inicio), fim: fmt(fim) };
}
