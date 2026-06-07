"use client";

import { useState } from "react";
import { Pencil, Plus } from "lucide-react";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";

import { RessarcimentoForm } from "./ressarcimento-form";
import type { ProcessoOpcao } from "../queries";
import type { RessarcimentoCreateInput } from "../schema";

type Props = {
  processos: ProcessoOpcao[];
} & (
  | { modo: "criar" }
  | {
      modo: "editar";
      ressarcimentoId: string;
      initialValues: RessarcimentoCreateInput;
      trigger?: React.ReactNode;
    }
);

export function RessarcimentoFormDialog(props: Props) {
  const [open, setOpen] = useState(false);

  const trigger =
    props.modo === "criar" ? (
      <Button>
        <Plus className="mr-2 h-4 w-4" />
        Novo ressarcimento
      </Button>
    ) : (
      (props.trigger ?? (
        <Button variant="ghost" size="sm">
          <Pencil className="mr-1 h-4 w-4" />
          Editar
        </Button>
      ))
    );

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>{trigger}</DialogTrigger>
      <DialogContent className="max-h-[90vh] max-w-2xl overflow-y-auto">
        <DialogHeader>
          <DialogTitle>
            {props.modo === "criar" ? "Novo ressarcimento" : "Editar ressarcimento"}
          </DialogTitle>
          <DialogDescription>
            Despesa paga pelo escritório em nome do cliente. Após o reembolso, marque como
            reembolsado na lista.
          </DialogDescription>
        </DialogHeader>
        <RessarcimentoForm
          modo={props.modo}
          ressarcimentoId={props.modo === "editar" ? props.ressarcimentoId : undefined}
          processos={props.processos}
          initialValues={props.modo === "editar" ? props.initialValues : undefined}
          onSucesso={() => setOpen(false)}
        />
      </DialogContent>
    </Dialog>
  );
}
