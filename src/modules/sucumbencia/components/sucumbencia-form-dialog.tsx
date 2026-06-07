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

import { SucumbenciaForm } from "./sucumbencia-form";
import type {
  CategoriaReceitaOpcao,
  ContaOpcao,
  ParceiroOpcao,
  ProcessoOpcao,
} from "../queries";
import type { SucumbenciaCreateInput } from "../schema";

type Props = {
  processos: ProcessoOpcao[];
  parceiros: ParceiroOpcao[];
  contas: ContaOpcao[];
  categoriasReceita: CategoriaReceitaOpcao[];
} & (
  | { modo: "criar" }
  | {
      modo: "editar";
      sucumbenciaId: string;
      initialValues: SucumbenciaCreateInput;
      trigger?: React.ReactNode;
    }
);

export function SucumbenciaFormDialog(props: Props) {
  const [open, setOpen] = useState(false);

  const trigger =
    props.modo === "criar" ? (
      <Button>
        <Plus className="mr-2 h-4 w-4" />
        Nova sucumbência
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
            {props.modo === "criar" ? "Nova sucumbência" : "Editar sucumbência"}
          </DialogTitle>
          <DialogDescription>
            Honorários de sucumbência arbitrados em sentença. O valor bruto entra no caixa
            automaticamente como lançamento de ENTRADA. Se houver parceiro externo, a fatia dele
            fica como obrigação pendente até ser paga.
          </DialogDescription>
        </DialogHeader>
        <SucumbenciaForm
          modo={props.modo}
          sucumbenciaId={props.modo === "editar" ? props.sucumbenciaId : undefined}
          processos={props.processos}
          parceiros={props.parceiros}
          contas={props.contas}
          categoriasReceita={props.categoriasReceita}
          initialValues={props.modo === "editar" ? props.initialValues : undefined}
          onSucesso={() => setOpen(false)}
        />
      </DialogContent>
    </Dialog>
  );
}
