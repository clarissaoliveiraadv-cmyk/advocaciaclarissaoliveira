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

import { CategoriaForm } from "./categoria-form";
import type { CategoriaOpcao } from "../queries";
import type { CategoriaCreateInput } from "../schema";

type Props = {
  categorias: CategoriaOpcao[];
} & (
  | { modo: "criar" }
  | {
      modo: "editar";
      categoriaId: string;
      initialValues: CategoriaCreateInput;
      temFilhas: boolean;
      trigger?: React.ReactNode;
    }
);

export function CategoriaFormDialog(props: Props) {
  const [open, setOpen] = useState(false);

  const trigger =
    props.modo === "criar" ? (
      <Button>
        <Plus className="mr-2 h-4 w-4" />
        Nova categoria
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
          <DialogTitle>
            {props.modo === "criar" ? "Nova categoria" : "Editar categoria"}
          </DialogTitle>
          <DialogDescription>
            Campos marcados com * são obrigatórios. Subcategorias devem ter o mesmo tipo e escopo do
            pai.
          </DialogDescription>
        </DialogHeader>
        <CategoriaForm
          modo={props.modo}
          categorias={props.categorias}
          categoriaId={props.modo === "editar" ? props.categoriaId : undefined}
          initialValues={props.modo === "editar" ? props.initialValues : undefined}
          temFilhas={props.modo === "editar" ? props.temFilhas : false}
          onSucesso={() => setOpen(false)}
        />
      </DialogContent>
    </Dialog>
  );
}
