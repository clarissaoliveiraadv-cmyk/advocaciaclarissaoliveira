"use client";

import { useTransition } from "react";
import { Undo2 } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";

import { reverterRepasse } from "../repasse-actions";

type Props = { itemId: string };

export function ReverterRepasseDialog({ itemId }: Props) {
  const [pending, startTransition] = useTransition();

  function onConfirm(event: React.MouseEvent<HTMLButtonElement>) {
    event.preventDefault();
    startTransition(async () => {
      const result = await reverterRepasse(itemId);
      if (!result.ok) {
        toast.error(result.error);
        return;
      }
      toast.success("Repasse revertido");
    });
  }

  return (
    <AlertDialog>
      <AlertDialogTrigger asChild>
        <Button variant="ghost" size="sm">
          <Undo2 className="mr-1 h-4 w-4" />
          Reverter
        </Button>
      </AlertDialogTrigger>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Reverter este repasse?</AlertDialogTitle>
          <AlertDialogDescription>
            Vai <strong>deletar o lançamento de saída</strong> gerado e voltar o item para o status
            PENDENTE_REPASSE. Se o recebível havia sido marcado como REPASSADA, volta para RECEBIDA
            automaticamente.
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel>Cancelar</AlertDialogCancel>
          <AlertDialogAction onClick={onConfirm} disabled={pending}>
            {pending ? "Revertendo..." : "Reverter"}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
