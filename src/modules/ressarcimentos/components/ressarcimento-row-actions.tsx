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

import { marcarRessarcimentoReembolsado, reverterReembolso } from "../actions";

export function MarcarReembolsadoDialog({ id }: { id: string }) {
  const [open, setOpen] = useState(false);
  const [data, setData] = useState(() => new Date().toISOString().slice(0, 10));
  const [pending, startTransition] = useTransition();

  function onConfirm() {
    startTransition(async () => {
      const result = await marcarRessarcimentoReembolsado({ id, dataReembolso: data });
      if (!result.ok) {
        toast.error(result.error);
        return;
      }
      toast.success("Ressarcimento marcado como reembolsado");
      setOpen(false);
    });
  }

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="ghost" size="sm">
          <CheckCircle2 className="mr-1 h-4 w-4" />
          Reembolsar
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>Marcar como reembolsado</DialogTitle>
          <DialogDescription>
            Confirme a data em que o cliente reembolsou esta despesa.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-2">
          <label className="text-sm font-medium">Data do reembolso</label>
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

export function ReverterReembolsoButton({ id }: { id: string }) {
  const [pending, startTransition] = useTransition();
  function onClick() {
    startTransition(async () => {
      const result = await reverterReembolso(id);
      if (!result.ok) {
        toast.error(result.error);
        return;
      }
      toast.success("Reembolso revertido");
    });
  }
  return (
    <Button variant="ghost" size="sm" onClick={onClick} disabled={pending}>
      <RotateCcw className="mr-1 h-4 w-4" />
      Reverter
    </Button>
  );
}
