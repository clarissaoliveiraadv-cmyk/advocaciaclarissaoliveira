"use client";

import { useTransition } from "react";
import { Power } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { alternarAtivoParceiro } from "../actions";

type Props = { parceiroId: string; ativo: boolean };

export function ParceiroAtivoToggle({ parceiroId, ativo }: Props) {
  const [pending, startTransition] = useTransition();

  function onClick() {
    startTransition(async () => {
      const result = await alternarAtivoParceiro(parceiroId);
      if (!result.ok) {
        toast.error(result.error);
        return;
      }
      toast.success(ativo ? "Parceiro inativado" : "Parceiro ativado");
    });
  }

  return (
    <Button variant="ghost" size="sm" onClick={onClick} disabled={pending}>
      <Power className="mr-1 h-4 w-4" />
      {ativo ? "Inativar" : "Ativar"}
    </Button>
  );
}
