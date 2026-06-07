"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { useTransition } from "react";
import { Input } from "@/components/ui/input";

type Props = { processoId: string };

export function PrestacaoFiltros({ processoId }: Props) {
  const router = useRouter();
  const params = useSearchParams();
  const [, startTransition] = useTransition();

  const inicio = params.get("inicio") ?? "";
  const fim = params.get("fim") ?? "";

  function setParam(key: string, value: string) {
    const next = new URLSearchParams(params.toString());
    if (value) next.set(key, value);
    else next.delete(key);
    startTransition(() => router.replace(`/prestacao-contas/${processoId}?${next.toString()}`));
  }

  return (
    <div className="flex flex-wrap items-end gap-3 rounded-md border bg-card p-4 print:hidden">
      <div>
        <label className="mb-1 block text-xs font-medium text-muted-foreground">De</label>
        <Input type="date" value={inicio} onChange={(e) => setParam("inicio", e.target.value)} />
      </div>
      <div>
        <label className="mb-1 block text-xs font-medium text-muted-foreground">Até</label>
        <Input type="date" value={fim} onChange={(e) => setParam("fim", e.target.value)} />
      </div>
      <p className="ml-auto self-center text-xs text-muted-foreground">
        Sem datas = inclui todas as distribuições confirmadas.
      </p>
    </div>
  );
}
