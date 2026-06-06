"use client";

import { useEffect, useState, useTransition } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { Search } from "lucide-react";
import type { TipoParceiro } from "@prisma/client";

import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

import { TIPO_PARCEIRO_LABELS } from "../schema";

const FILTROS_ATIVO = [
  { value: "ativos", label: "Apenas ativos" },
  { value: "inativos", label: "Apenas inativos" },
  { value: "todos", label: "Todos" },
] as const;

export function ParceirosSearch() {
  const router = useRouter();
  const params = useSearchParams();
  const [, startTransition] = useTransition();

  const [search, setSearch] = useState(params.get("search") ?? "");
  const tipo = params.get("tipo") ?? "todos";
  const ativo = params.get("ativo") ?? "ativos";

  useEffect(() => {
    const handle = setTimeout(() => updateParams({ search }), 300);
    return () => clearTimeout(handle);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [search]);

  function updateParams(updates: Record<string, string | null>) {
    const next = new URLSearchParams(params.toString());
    for (const [k, v] of Object.entries(updates)) {
      if (v === null || v === "") next.delete(k);
      else next.set(k, v);
    }
    startTransition(() => router.replace(`/cadastros/parceiros?${next.toString()}`));
  }

  return (
    <div className="flex flex-wrap items-center gap-3">
      <div className="relative min-w-[240px] flex-1">
        <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
        <Input
          placeholder="Buscar por nome ou OAB..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="pl-9"
        />
      </div>
      <Select value={tipo} onValueChange={(v) => updateParams({ tipo: v })}>
        <SelectTrigger className="w-[180px]">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="todos">Todos os tipos</SelectItem>
          {Object.entries(TIPO_PARCEIRO_LABELS).map(([value, label]) => (
            <SelectItem key={value} value={value as TipoParceiro}>
              {label}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      <Select value={ativo} onValueChange={(v) => updateParams({ ativo: v })}>
        <SelectTrigger className="w-[160px]">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {FILTROS_ATIVO.map((f) => (
            <SelectItem key={f.value} value={f.value}>
              {f.label}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    </div>
  );
}
