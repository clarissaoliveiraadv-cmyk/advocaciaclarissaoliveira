"use client";

import { useRouter } from "next/navigation";
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

import { reverterDistribuicao } from "../actions";

type Props = { recebivelId: string };

export function ReverterButton({ recebivelId }: Props) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();

  function onConfirm(event: React.MouseEvent<HTMLButtonElement>) {
    event.preventDefault();
    startTransition(async () => {
      const result = await reverterDistribuicao(recebivelId);
      if (!result.ok) {
        toast.error(result.error);
        return;
      }
      toast.success("Distribuição revertida");
      router.push("/recebiveis");
      router.refresh();
    });
  }

  return (
    <AlertDialog>
      <AlertDialogTrigger asChild>
        <Button variant="outline">
          <Undo2 className="mr-2 h-4 w-4" />
          Reverter distribuição
        </Button>
      </AlertDialogTrigger>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Reverter esta distribuição?</AlertDialogTitle>
          <AlertDialogDescription>
            Esta ação vai <strong>deletar o lançamento de entrada</strong> gerado e a distribuição
            (incluindo todos os itens). O recebível voltará para o status PREVISTA. O histórico fica
            registrado em auditoria.
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
