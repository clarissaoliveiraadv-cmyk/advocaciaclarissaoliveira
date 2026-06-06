"use client";

import { useState } from "react";
import { ArrowLeftRight, Pencil } from "lucide-react";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";

import { TransferenciaForm } from "./transferencia-form";
import type { CategoriaOpcao, ContaOpcao } from "../queries";
import type { TransferenciaCreateInput } from "../schema";

type Props = {
  contas: ContaOpcao[];
  categorias: CategoriaOpcao[];
} & (
  | { modo: "criar" }
  | {
      modo: "editar";
      pernaId: string;
      initialValues: TransferenciaCreateInput;
      trigger?: React.ReactNode;
    }
);

export function TransferenciaFormDialog(props: Props) {
  const [open, setOpen] = useState(false);

  const trigger =
    props.modo === "criar" ? (
      <Button variant="outline">
        <ArrowLeftRight className="mr-2 h-4 w-4" />
        Nova transferência
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
            {props.modo === "criar" ? "Nova transferência interna" : "Editar transferência"}
          </DialogTitle>
          <DialogDescription>
            Move valor entre duas contas. Cria/atualiza um par de lançamentos vinculados.
          </DialogDescription>
        </DialogHeader>
        <TransferenciaForm
          modo={props.modo}
          pernaId={props.modo === "editar" ? props.pernaId : undefined}
          contas={props.contas}
          categorias={props.categorias}
          initialValues={props.modo === "editar" ? props.initialValues : undefined}
          onSucesso={() => setOpen(false)}
        />
      </DialogContent>
    </Dialog>
  );
}
