"use client";

import { useState, useTransition } from "react";
import { CheckCircle2, RotateCcw } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";

import { marcarRepasse, reverterRepasse } from "../actions";

const NOMES = { clarissa: "Clarissa", vivian: "Vivian" } as const;

export function MarcarRepasseDialog({
  id,
  socia,
}: {
  id: string;
  socia: "clarissa" | "vivian";
}) {
  const [open, setOpen] = useState(false);
  const [data, setData] = useState(() => new Date().toISOString().slice(0, 10));
  const [pending, startTransition] = useTransition();
  const nome = NOMES[socia];

  function onConfirm() {
    startTransition(async () => {
      const result = await marcarRepasse({ id, socia, data });
      if (!result.ok) {
        toast.error(result.error);
        return;
      }
      toast.success(`Repasse para ${nome} registrado`);
      setOpen(false);
    });
  }

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="ghost" size="sm" className="h-7 px-2 text-xs">
          <CheckCircle2 className="mr-1 h-3 w-3" />
          {nome}
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>Registrar repasse para {nome}</DialogTitle>
          <DialogDescription>
            Informe a data em que o valor foi efetivamente repassado. Lembre-se de registrar o
            lançamento de saída no Movimento de Caixa.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-2">
          <label className="text-sm font-medium">Data do repasse</label>
          <Input type="date" value={data} onChange={(e) => setData(e.target.value)} />
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => setOpen(false)} disabled={pending}>
            Cancelar
          </Button>
          <Button onClick={onConfirm} disabled={pending || !data}>
            {pending ? "Confirmando..." : "Confirmar"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export function ReverterRepasseButton({
  id,
  socia,
}: {
  id: string;
  socia: "clarissa" | "vivian";
}) {
  const [pending, startTransition] = useTransition();
  const nome = NOMES[socia];
  function onClick() {
    startTransition(async () => {
      const result = await reverterRepasse(id, socia);
      if (!result.ok) {
        toast.error(result.error);
        return;
      }
      toast.success(`Repasse para ${nome} revertido`);
    });
  }
  return (
    <Button variant="ghost" size="sm" onClick={onClick} disabled={pending} className="h-7 px-2 text-xs">
      <RotateCcw className="mr-1 h-3 w-3" />
      {nome}
    </Button>
  );
}
