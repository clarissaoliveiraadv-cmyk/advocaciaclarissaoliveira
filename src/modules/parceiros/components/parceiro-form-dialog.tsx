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

import { ParceiroForm } from "./parceiro-form";
import type { ParceiroCreateInput } from "../schema";

type Props =
  | { modo: "criar" }
  | {
      modo: "editar";
      parceiroId: string;
      initialValues: ParceiroCreateInput;
      trigger?: React.ReactNode;
    };

export function ParceiroFormDialog(props: Props) {
  const [open, setOpen] = useState(false);

  const trigger =
    props.modo === "criar" ? (
      <Button>
        <Plus className="mr-2 h-4 w-4" />
        Novo parceiro
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
          <DialogTitle>{props.modo === "criar" ? "Novo parceiro" : "Editar parceiro"}</DialogTitle>
          <DialogDescription>
            Campos marcados com * são obrigatórios. O percentual cadastrado aqui é apenas o padrão
            de referência.
          </DialogDescription>
        </DialogHeader>
        <ParceiroForm
          modo={props.modo}
          parceiroId={props.modo === "editar" ? props.parceiroId : undefined}
          initialValues={props.modo === "editar" ? props.initialValues : undefined}
          onSucesso={() => setOpen(false)}
        />
      </DialogContent>
    </Dialog>
  );
}
