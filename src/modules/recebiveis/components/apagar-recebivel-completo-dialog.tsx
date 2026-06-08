"use client";

import { useState, useTransition } from "react";
import { Skull } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
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

import { apagarRecebivelCompleto } from "../actions";

type Props = {
  recebivelId: string;
  rotulo: string;
};

/**
 * Atalho destrutivo para apagar um recebível e TUDO ligado a ele
 * (distribuição, lançamentos de entrada e repasse). Usado em
 * cenários de teste — exige digitar APAGAR para confirmar e está
 * restrito a perfil ADMIN no backend.
 */
export function ApagarRecebivelCompletoDialog({ recebivelId, rotulo }: Props) {
  const [open, setOpen] = useState(false);
  const [confirmacao, setConfirmacao] = useState("");
  const [pending, startTransition] = useTransition();

  function onConfirm(event: React.MouseEvent<HTMLButtonElement>) {
    event.preventDefault();
    if (confirmacao.trim().toUpperCase() !== "APAGAR") {
      toast.error("Digite APAGAR para confirmar.");
      return;
    }
    startTransition(async () => {
      const result = await apagarRecebivelCompleto(recebivelId);
      if (!result.ok) {
        toast.error(result.error);
        return;
      }
      toast.success("Recebível e tudo vinculado foram apagados.");
      setConfirmacao("");
      setOpen(false);
    });
  }

  return (
    <AlertDialog open={open} onOpenChange={setOpen}>
      <AlertDialogTrigger asChild>
        <Button
          variant="ghost"
          size="sm"
          className="text-destructive hover:bg-destructive/10 hover:text-destructive"
          title="Apagar recebível + distribuição + lançamentos (atalho de teste)"
        >
          <Skull className="mr-1 h-4 w-4" />
          Apagar tudo
        </Button>
      </AlertDialogTrigger>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Apagar tudo deste recebível?</AlertDialogTitle>
          <AlertDialogDescription asChild>
            <div className="space-y-3">
              <p>
                Esta ação remove em cascata, <strong>sem possibilidade de desfazer</strong>:
              </p>
              <ul className="list-disc pl-5 text-sm">
                <li>
                  O recebível <strong>{rotulo}</strong>
                </li>
                <li>A distribuição vinculada e todos os itens</li>
                <li>O lançamento de ENTRADA criado no recebimento</li>
                <li>Quaisquer lançamentos de SAÍDA de repasse já feitos</li>
              </ul>
              <p className="text-xs text-muted-foreground">
                Ressarcimentos que apontam para este recebível ficam preservados (apenas o vínculo
                é zerado). Para usar o fluxo seguro, reverta o recebimento e depois cancele ou
                exclua na lista.
              </p>
              <div className="space-y-1">
                <label className="text-sm font-medium">
                  Digite <code className="rounded bg-muted px-1">APAGAR</code> para confirmar:
                </label>
                <Input
                  value={confirmacao}
                  onChange={(e) => setConfirmacao(e.target.value)}
                  placeholder="APAGAR"
                  autoComplete="off"
                />
              </div>
            </div>
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel
            onClick={() => {
              setConfirmacao("");
            }}
          >
            Cancelar
          </AlertDialogCancel>
          <AlertDialogAction
            onClick={onConfirm}
            disabled={pending || confirmacao.trim().toUpperCase() !== "APAGAR"}
            className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
          >
            {pending ? "Apagando..." : "Apagar tudo"}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
