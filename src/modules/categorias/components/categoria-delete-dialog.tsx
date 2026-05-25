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

import { excluirCategoria } from "../actions";

type Props = {
  categoriaId: string;
  rotulo: string;
  podeExcluir: boolean;
  motivoBloqueio?: string;
};

export function CategoriaDeleteDialog({ categoriaId, rotulo, podeExcluir, motivoBloqueio }: Props) {
  const [pending, startTransition] = useTransition();

  function onConfirm(event: React.MouseEvent<HTMLButtonElement>) {
    event.preventDefault();
    startTransition(async () => {
      const result = await excluirCategoria(categoriaId);
      if (!result.ok) {
        toast.error(result.error);
        return;
      }
      toast.success(`Categoria "${rotulo}" excluída`);
    });
  }

  if (!podeExcluir) {
    return (
      <Button variant="ghost" size="sm" disabled title={motivoBloqueio}>
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
          <AlertDialogTitle>Excluir categoria?</AlertDialogTitle>
          <AlertDialogDescription>
            Esta ação não pode ser desfeita. A categoria <strong>{rotulo}</strong> será removida
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
