"use client";

import { useTransition } from "react";
import { Power } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { alternarAtivoCliente } from "../actions";

type Props = { clienteId: string; ativo: boolean };

export function ClienteAtivoToggle({ clienteId, ativo }: Props) {
  const [pending, startTransition] = useTransition();

  function onClick() {
    startTransition(async () => {
      const result = await alternarAtivoCliente(clienteId);
      if (!result.ok) {
        toast.error(result.error);
        return;
      }
      toast.success(ativo ? "Cliente inativado" : "Cliente ativado");
    });
  }

  return (
    <Button variant="ghost" size="sm" onClick={onClick} disabled={pending}>
      <Power className="mr-1 h-4 w-4" />
      {ativo ? "Inativar" : "Ativar"}
    </Button>
  );
}
