"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { ChevronLeft, ChevronRight } from "lucide-react";
import { Button } from "@/components/ui/button";

type Props = { page: number; pageSize: number; total: number };

export function RecebiveisPagination({ page, pageSize, total }: Props) {
  const router = useRouter();
  const params = useSearchParams();
  const totalPages = Math.max(1, Math.ceil(total / pageSize));

  function goTo(p: number) {
    const next = new URLSearchParams(params.toString());
    next.set("page", String(p));
    router.replace(`/recebiveis?${next.toString()}`);
  }

  return (
    <div className="flex items-center justify-between text-sm text-muted-foreground">
      <span>
        {total === 0 ? "Nenhum recebível" : `${total} recebível${total === 1 ? "" : "is"}`}
        {totalPages > 1 && ` · Página ${page} de ${totalPages}`}
      </span>
      <div className="flex items-center gap-1">
        <Button variant="outline" size="sm" onClick={() => goTo(page - 1)} disabled={page <= 1}>
          <ChevronLeft className="h-4 w-4" />
          Anterior
        </Button>
        <Button
          variant="outline"
          size="sm"
          onClick={() => goTo(page + 1)}
          disabled={page >= totalPages}
        >
          Próxima
          <ChevronRight className="h-4 w-4" />
        </Button>
      </div>
    </div>
  );
}
