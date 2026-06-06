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

import { RecebivelForm } from "./recebivel-form";
import type { ParceiroOpcao, ProcessoOpcao } from "../queries";
import type { RecebivelCreateInput } from "../schema";

type Props = {
  processos: ProcessoOpcao[];
  parceiros: ParceiroOpcao[];
} & (
  | { modo: "criar" }
  | {
      modo: "editar";
      recebivelId: string;
      initialValues: RecebivelCreateInput;
      trigger?: React.ReactNode;
    }
);

export function RecebivelFormDialog(props: Props) {
  const [open, setOpen] = useState(false);

  const trigger =
    props.modo === "criar" ? (
      <Button>
        <Plus className="mr-2 h-4 w-4" />
        Novo recebível
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
      <DialogContent className="max-h-[90vh] max-w-3xl overflow-y-auto">
        <DialogHeader>
          <DialogTitle>
            {props.modo === "criar" ? "Novo recebível" : "Editar recebível"}
          </DialogTitle>
          <DialogDescription>
            Campos marcados com * são obrigatórios. Valores são apenas previsão — a divisão real é
            confirmada no recebimento.
          </DialogDescription>
        </DialogHeader>
        <RecebivelForm
          modo={props.modo}
          recebivelId={props.modo === "editar" ? props.recebivelId : undefined}
          processos={props.processos}
          parceiros={props.parceiros}
          initialValues={props.modo === "editar" ? props.initialValues : undefined}
          onSucesso={() => setOpen(false)}
        />
      </DialogContent>
    </Dialog>
  );
}
