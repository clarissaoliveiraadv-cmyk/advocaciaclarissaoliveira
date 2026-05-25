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

import { ProcessoForm } from "./processo-form";
import type { ClienteOpcao } from "./cliente-combobox";
import type { ProcessoCreateInput } from "../schema";

type Props = {
  clientes: ClienteOpcao[];
} & (
  | { modo: "criar" }
  | {
      modo: "editar";
      processoId: string;
      initialValues: ProcessoCreateInput;
      trigger?: React.ReactNode;
    }
);

export function ProcessoFormDialog(props: Props) {
  const [open, setOpen] = useState(false);

  const trigger =
    props.modo === "criar" ? (
      <Button>
        <Plus className="mr-2 h-4 w-4" />
        Novo processo
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
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle>{props.modo === "criar" ? "Novo processo" : "Editar processo"}</DialogTitle>
          <DialogDescription>
            Campos marcados com * são obrigatórios. Número CNJ é opcional para procedimentos
            internos.
          </DialogDescription>
        </DialogHeader>
        <ProcessoForm
          modo={props.modo}
          clientes={props.clientes}
          processoId={props.modo === "editar" ? props.processoId : undefined}
          initialValues={props.modo === "editar" ? props.initialValues : undefined}
          onSucesso={() => setOpen(false)}
        />
      </DialogContent>
    </Dialog>
  );
}
