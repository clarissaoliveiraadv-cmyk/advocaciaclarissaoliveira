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

import { STATUS_RECEBIVEL_LABELS } from "../schema";
import type { ClienteOpcao, ParceiroOpcao } from "../queries";

type Props = {
  clientes: ClienteOpcao[];
  parceiros: ParceiroOpcao[];
};

export function RecebiveisSearch({ clientes, parceiros }: Props) {
  const router = useRouter();
  const params = useSearchParams();
  const [, startTransition] = useTransition();

  const [search, setSearch] = useState(params.get("search") ?? "");
  const inicio = params.get("inicio") ?? "";
  const fim = params.get("fim") ?? "";
  const clienteId = params.get("clienteId") ?? "todos";
  const parceiroId = params.get("parceiroId") ?? "todos";
  const status = params.get("status") ?? "todos";

  useEffect(() => {
    const handle = setTimeout(() => updateParams({ search, page: "1" }), 300);
    return () => clearTimeout(handle);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [search]);

  function updateParams(updates: Record<string, string | null>) {
    const next = new URLSearchParams(params.toString());
    for (const [k, v] of Object.entries(updates)) {
      if (v === null || v === "" || v === "todos") next.delete(k);
      else next.set(k, v);
    }
    startTransition(() => router.replace(`/recebiveis?${next.toString()}`));
  }

  return (
    <div className="space-y-3 rounded-md border bg-card p-4">
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <div>
          <label className="mb-1 block text-xs font-medium text-muted-foreground">
            Data prevista (de)
          </label>
          <Input
            type="date"
            value={inicio}
            onChange={(e) => updateParams({ inicio: e.target.value, page: "1" })}
          />
        </div>
        <div>
          <label className="mb-1 block text-xs font-medium text-muted-foreground">
            Data prevista (até)
          </label>
          <Input
            type="date"
            value={fim}
            onChange={(e) => updateParams({ fim: e.target.value, page: "1" })}
          />
        </div>
        <div>
          <label className="mb-1 block text-xs font-medium text-muted-foreground">Cliente</label>
          <Select
            value={clienteId}
            onValueChange={(v) => updateParams({ clienteId: v, page: "1" })}
          >
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="todos">Todos os clientes</SelectItem>
              {clientes.map((c) => (
                <SelectItem key={c.id} value={c.id}>
                  {c.nome}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div>
          <label className="mb-1 block text-xs font-medium text-muted-foreground">Status</label>
          <Select value={status} onValueChange={(v) => updateParams({ status: v, page: "1" })}>
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="todos">Todos</SelectItem>
              {Object.entries(STATUS_RECEBIVEL_LABELS).map(([k, v]) => (
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
              placeholder="CNJ, nome do cliente ou observação..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-9"
            />
          </div>
        </div>
        <div>
          <label className="mb-1 block text-xs font-medium text-muted-foreground">Parceiro</label>
          <Select
            value={parceiroId}
            onValueChange={(v) => updateParams({ parceiroId: v, page: "1" })}
          >
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="todos">Todos os parceiros</SelectItem>
              {parceiros.map((p) => (
                <SelectItem key={p.id} value={p.id}>
                  {p.nome}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </div>
    </div>
  );
}
