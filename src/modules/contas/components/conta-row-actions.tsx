"use client";

import { useTransition } from "react";
import { Power } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { alternarAtivoConta } from "../actions";

type Props = { contaId: string; ativo: boolean };

export function ContaAtivoToggle({ contaId, ativo }: Props) {
  const [pending, startTransition] = useTransition();

  function onClick() {
    startTransition(async () => {
      const result = await alternarAtivoConta(contaId);
      if (!result.ok) {
        toast.error(result.error);
        return;
      }
      toast.success(ativo ? "Conta inativada" : "Conta ativada");
    });
  }

  return (
    <Button variant="ghost" size="sm" onClick={onClick} disabled={pending}>
      <Power className="mr-1 h-4 w-4" />
      {ativo ? "Inativar" : "Ativar"}
    </Button>
  );
}
