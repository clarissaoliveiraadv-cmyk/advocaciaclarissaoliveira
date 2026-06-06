"use client";

import { useEffect, useState, useTransition } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { Search } from "lucide-react";

import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

import { TIPO_FILTRO_LABELS } from "../schema";
import type { CategoriaOpcao, ContaOpcao } from "../queries";

type Props = {
  contas: ContaOpcao[];
  categorias: CategoriaOpcao[];
};

export function LancamentosSearch({ contas, categorias }: Props) {
  const router = useRouter();
  const params = useSearchParams();
  const [, startTransition] = useTransition();

  const [search, setSearch] = useState(params.get("search") ?? "");
  const inicio = params.get("inicio") ?? "";
  const fim = params.get("fim") ?? "";
  const contaId = params.get("contaId") ?? "todas";
  const categoriaId = params.get("categoriaId") ?? "todas";
  const tipo = params.get("tipo") ?? "todos";

  useEffect(() => {
    const handle = setTimeout(() => updateParams({ search, page: "1" }), 300);
    return () => clearTimeout(handle);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [search]);

  function updateParams(updates: Record<string, string | null>) {
    const next = new URLSearchParams(params.toString());
    for (const [k, v] of Object.entries(updates)) {
      if (v === null || v === "" || v === "todas" || v === "todos") next.delete(k);
      else next.set(k, v);
    }
    startTransition(() => router.replace(`/movimento?${next.toString()}`));
  }

  return (
    <div className="space-y-3 rounded-md border bg-card p-4">
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <div>
          <label className="mb-1 block text-xs font-medium text-muted-foreground">
            Data inicial
          </label>
          <Input
            type="date"
            value={inicio}
            onChange={(e) => updateParams({ inicio: e.target.value, page: "1" })}
          />
        </div>
        <div>
          <label className="mb-1 block text-xs font-medium text-muted-foreground">Data final</label>
          <Input
            type="date"
            value={fim}
            onChange={(e) => updateParams({ fim: e.target.value, page: "1" })}
          />
        </div>
        <div>
          <label className="mb-1 block text-xs font-medium text-muted-foreground">Conta</label>
          <Select value={contaId} onValueChange={(v) => updateParams({ contaId: v, page: "1" })}>
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="todas">Todas as contas</SelectItem>
              {contas.map((c) => (
                <SelectItem key={c.id} value={c.id}>
                  {c.codigo} — {c.nome}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div>
          <label className="mb-1 block text-xs font-medium text-muted-foreground">Tipo</label>
          <Select value={tipo} onValueChange={(v) => updateParams({ tipo: v, page: "1" })}>
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {Object.entries(TIPO_FILTRO_LABELS).map(([k, v]) => (
                <SelectItem key={k} value={k}>
                  {v}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </div>

      <div className="grid gap-3 sm:grid-cols-3">
        <div className="sm:col-span-2">
          <label className="mb-1 block text-xs font-medium text-muted-foreground">Buscar</label>
          <div className="relative">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              placeholder="Descrição, observação ou nome do cliente..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-9"
            />
          </div>
        </div>
        <div>
          <label className="mb-1 block text-xs font-medium text-muted-foreground">Categoria</label>
          <Select
            value={categoriaId}
            onValueChange={(v) => updateParams({ categoriaId: v, page: "1" })}
          >
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="todas">Todas as categorias</SelectItem>
              {categorias.map((c) => (
                <SelectItem key={c.id} value={c.id}>
                  {c.nome}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </div>
    </div>
  );
}
