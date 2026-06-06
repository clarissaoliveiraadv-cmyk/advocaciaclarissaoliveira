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

import { excluirLancamento, excluirTransferencia } from "../actions";

type Props = {
  lancamentoId: string;
  rotulo: string;
  ehTransferencia: boolean;
  podeExcluir: boolean;
  motivoBloqueio?: string;
};

export function LancamentoDeleteDialog({
  lancamentoId,
  rotulo,
  ehTransferencia,
  podeExcluir,
  motivoBloqueio,
}: Props) {
  const [pending, startTransition] = useTransition();

  function onConfirm(event: React.MouseEvent<HTMLButtonElement>) {
    event.preventDefault();
    startTransition(async () => {
      const result = ehTransferencia
        ? await excluirTransferencia(lancamentoId)
        : await excluirLancamento(lancamentoId);
      if (!result.ok) {
        toast.error(result.error);
        return;
      }
      toast.success(ehTransferencia ? "Transferência excluída" : "Lançamento excluído");
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
          <AlertDialogTitle>
            {ehTransferencia ? "Excluir transferência?" : "Excluir lançamento?"}
          </AlertDialogTitle>
          <AlertDialogDescription>
            {ehTransferencia ? (
              <>
                Esta ação excluirá os <strong>dois lançamentos da transferência</strong>{" "}
                <em>{rotulo}</em> de forma atômica. Não pode ser desfeita.
              </>
            ) : (
              <>
                Esta ação não pode ser desfeita. O lançamento <strong>{rotulo}</strong> será
                removido permanentemente.
              </>
            )}
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
