"use client";

import { useTransition } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { ChevronLeft, ChevronRight } from "lucide-react";

import { Button } from "@/components/ui/button";
import { formatCompetencia } from "../schema";

type Props = { competencia: string };

function navega(competencia: string, delta: number): string {
  const [ano, mes] = competencia.split("-").map(Number);
  const d = new Date(Date.UTC(ano, mes - 1 + delta, 1));
  const a = d.getUTCFullYear();
  const m = String(d.getUTCMonth() + 1).padStart(2, "0");
  return `${a}-${m}`;
}

export function CompetenciaPicker({ competencia }: Props) {
  const router = useRouter();
  const params = useSearchParams();
  const [, startTransition] = useTransition();

  function ir(nova: string) {
    const next = new URLSearchParams(params.toString());
    next.set("competencia", nova);
    startTransition(() => router.replace(`/contas-a-pagar?${next.toString()}`));
  }

  return (
    <div className="flex items-center gap-2">
      <Button variant="outline" size="sm" onClick={() => ir(navega(competencia, -1))}>
        <ChevronLeft className="h-4 w-4" />
      </Button>
      <span className="min-w-[140px] text-center text-sm font-medium">
        {formatCompetencia(competencia)}
      </span>
      <Button variant="outline" size="sm" onClick={() => ir(navega(competencia, 1))}>
        <ChevronRight className="h-4 w-4" />
      </Button>
    </div>
  );
}
