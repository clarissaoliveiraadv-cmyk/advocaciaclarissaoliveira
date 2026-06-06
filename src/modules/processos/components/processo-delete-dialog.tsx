"use client";

import { useTransition } from "react";
import { Trash2 } from "lucide-react";
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

import { excluirProcesso } from "../actions";

type Props = {
  processoId: string;
  rotulo: string;
  podeExcluir: boolean;
};

export function ProcessoDeleteDialog({ processoId, rotulo, podeExcluir }: Props) {
  const [pending, startTransition] = useTransition();

  function onConfirm(event: React.MouseEvent<HTMLButtonElement>) {
    event.preventDefault();
    startTransition(async () => {
      const result = await excluirProcesso(processoId);
      if (!result.ok) {
        toast.error(result.error);
        return;
      }
      toast.success(`Processo "${rotulo}" excluído`);
    });
  }

  if (!podeExcluir) {
    return (
      <Button
        variant="ghost"
        size="sm"
        disabled
        title="Processo possui recebíveis, lançamentos ou outros registros vinculados. Inative em vez de excluir."
      >
        <Trash2 className="mr-1 h-4 w-4" />
        Excluir
      </Button>
    );
  }

  return (
    <AlertDialog>
      <AlertDialogTrigger asChild>
        <Button variant="ghost" size="sm" className="text-destructive hover:text-destructive">
          <Trash2 className="mr-1 h-4 w-4" />
          Excluir
        </Button>
      </AlertDialogTrigger>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Excluir processo?</AlertDialogTitle>
          <AlertDialogDescription>
            Esta ação não pode ser desfeita. O processo <strong>{rotulo}</strong> será removido
            permanentemente.
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel>Cancelar</AlertDialogCancel>
          <AlertDialogAction onClick={onConfirm} disabled={pending}>
            {pending ? "Excluindo..." : "Excluir"}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
