"use client";

import { useTransition } from "react";
import { RotateCcw, X } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { excluirPrevisao, reverterPagamento } from "../actions";

export function ReverterPagamentoButton({ id }: { id: string }) {
  const [pending, startTransition] = useTransition();
  function onClick() {
    startTransition(async () => {
      const result = await reverterPagamento(id);
      if (!result.ok) {
        toast.error(result.error);
        return;
      }
      toast.success("Pagamento revertido");
    });
  }
  return (
    <Button variant="ghost" size="sm" onClick={onClick} disabled={pending}>
      <RotateCcw className="mr-1 h-4 w-4" />
      Reverter
    </Button>
  );
}

export function PularPrevisaoButton({ id }: { id: string }) {
  const [pending, startTransition] = useTransition();
  function onClick() {
    if (!confirm("Pular esta conta neste mês? A previsão será removida.")) return;
    startTransition(async () => {
      const result = await excluirPrevisao(id);
      if (!result.ok) {
        toast.error(result.error);
        return;
      }
      toast.success("Previsão removida");
    });
  }
  return (
    <Button
      variant="ghost"
      size="sm"
      onClick={onClick}
      disabled={pending}
      className="text-muted-foreground"
    >
      <X className="mr-1 h-4 w-4" />
      Pular
    </Button>
  );
}
