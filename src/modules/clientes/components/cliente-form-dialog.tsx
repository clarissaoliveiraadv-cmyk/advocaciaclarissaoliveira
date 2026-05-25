"use client";

import { useState } from "react";
import { Plus, Pencil } from "lucide-react";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";

import { ClienteForm } from "./cliente-form";
import type { ClienteCreateInput } from "../schema";

type Props =
  | { modo: "criar" }
  | {
      modo: "editar";
      clienteId: string;
      initialValues: ClienteCreateInput;
      trigger?: React.ReactNode;
    };

export function ClienteFormDialog(props: Props) {
  const [open, setOpen] = useState(false);

  const trigger =
    props.modo === "criar" ? (
      <Button>
        <Plus className="mr-2 h-4 w-4" />
        Novo cliente
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
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{props.modo === "criar" ? "Novo cliente" : "Editar cliente"}</DialogTitle>
          <DialogDescription>Campos marcados com * são obrigatórios.</DialogDescription>
        </DialogHeader>
        <ClienteForm
          modo={props.modo}
          clienteId={props.modo === "editar" ? props.clienteId : undefined}
          initialValues={props.modo === "editar" ? props.initialValues : undefined}
          onSucesso={() => setOpen(false)}
        />
      </DialogContent>
    </Dialog>
  );
}
