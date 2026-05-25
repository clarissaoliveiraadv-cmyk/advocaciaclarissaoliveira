"use client";

import { useTransition } from "react";
import { Power } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { alternarAtivoCategoria } from "../actions";

type Props = { categoriaId: string; ativo: boolean };

export function CategoriaAtivoToggle({ categoriaId, ativo }: Props) {
  const [pending, startTransition] = useTransition();

  function onClick() {
    startTransition(async () => {
      const result = await alternarAtivoCategoria(categoriaId);
      if (!result.ok) {
        toast.error(result.error);
        return;
      }
      toast.success(ativo ? "Categoria inativada" : "Categoria ativada");
    });
  }

  return (
    <Button variant="ghost" size="sm" onClick={onClick} disabled={pending}>
      <Power className="mr-1 h-4 w-4" />
      {ativo ? "Inativar" : "Ativar"}
    </Button>
  );
}
