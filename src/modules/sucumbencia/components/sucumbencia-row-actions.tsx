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

import { marcarRepasseParceiro, reverterRepasseParceiro } from "../actions";

export function MarcarRepasseParceiroDialog({ id }: { id: string }) {
  const [open, setOpen] = useState(false);
  const [data, setData] = useState(() => new Date().toISOString().slice(0, 10));
  const [pending, startTransition] = useTransition();

  function onConfirm() {
    startTransition(async () => {
      const result = await marcarRepasseParceiro({ id, data });
      if (!result.ok) {
        toast.error(result.error);
        return;
      }
      toast.success("Repasse ao parceiro registrado");
      setOpen(false);
    });
  }

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="ghost" size="sm">
          <CheckCircle2 className="mr-1 h-4 w-4" />
          Marcar repasse
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>Registrar repasse ao parceiro externo</DialogTitle>
          <DialogDescription>
            Informe a data em que você pagou o parceiro. Lembre-se de criar também o lançamento
            de SAÍDA correspondente no Movimento de Caixa.
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

export function ReverterRepasseParceiroButton({ id }: { id: string }) {
  const [pending, startTransition] = useTransition();
  function onClick() {
    startTransition(async () => {
      const result = await reverterRepasseParceiro(id);
      if (!result.ok) {
        toast.error(result.error);
        return;
      }
      toast.success("Repasse revertido");
    });
  }
  return (
    <Button variant="ghost" size="sm" onClick={onClick} disabled={pending}>
      <RotateCcw className="mr-1 h-4 w-4" />
      Reverter repasse
    </Button>
  );
}
