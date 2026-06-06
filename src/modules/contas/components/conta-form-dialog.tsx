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

import { ContaForm } from "./conta-form";
import type { ContaCreateInput } from "../schema";

type Props =
  | { modo: "criar" }
  | {
      modo: "editar";
      contaId: string;
      initialValues: ContaCreateInput;
      temLancamentos: boolean;
      trigger?: React.ReactNode;
    };

export function ContaFormDialog(props: Props) {
  const [open, setOpen] = useState(false);

  const trigger =
    props.modo === "criar" ? (
      <Button>
        <Plus className="mr-2 h-4 w-4" />
        Nova conta
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
          <DialogTitle>{props.modo === "criar" ? "Nova conta" : "Editar conta"}</DialogTitle>
          <DialogDescription>
            Campos marcados com * são obrigatórios. O código é o identificador curto (ex.:
            INTER_PJ).
          </DialogDescription>
        </DialogHeader>
        <ContaForm
          modo={props.modo}
          contaId={props.modo === "editar" ? props.contaId : undefined}
          initialValues={props.modo === "editar" ? props.initialValues : undefined}
          temLancamentos={props.modo === "editar" ? props.temLancamentos : false}
          onSucesso={() => setOpen(false)}
        />
      </DialogContent>
    </Dialog>
  );
}
