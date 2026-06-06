"use client";

import { useTransition } from "react";
import { Ban, RotateCcw } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { cancelarRecebivel, reabrirRecebivel } from "../actions";

type Props = { recebivelId: string; cancelado: boolean; bloqueado?: boolean };

export function RecebivelCancelToggle({ recebivelId, cancelado, bloqueado }: Props) {
  const [pending, startTransition] = useTransition();

  function onClick() {
    startTransition(async () => {
      const result = cancelado
        ? await reabrirRecebivel(recebivelId)
        : await cancelarRecebivel(recebivelId);
      if (!result.ok) {
        toast.error(result.error);
        return;
      }
      toast.success(cancelado ? "Recebível reaberto" : "Recebível cancelado");
    });
  }

  return (
    <Button
      variant="ghost"
      size="sm"
      onClick={onClick}
      disabled={pending || bloqueado}
      title={
        bloqueado
          ? "Apenas recebíveis PREVISTOS ou CANCELADOS podem ser alternados aqui."
          : undefined
      }
    >
      {cancelado ? <RotateCcw className="mr-1 h-4 w-4" /> : <Ban className="mr-1 h-4 w-4" />}
      {cancelado ? "Reabrir" : "Cancelar"}
    </Button>
  );
}
