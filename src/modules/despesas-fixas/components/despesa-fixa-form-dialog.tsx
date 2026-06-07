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

import { DespesaFixaForm } from "./despesa-fixa-form";
import type { CategoriaDespesaOpcao, ContaOpcao } from "../queries";
import type { DespesaFixaCreateInput } from "../schema";

type Props = {
  categorias: CategoriaDespesaOpcao[];
  contas: ContaOpcao[];
} & (
  | { modo: "criar" }
  | {
      modo: "editar";
      despesaId: string;
      initialValues: DespesaFixaCreateInput;
      trigger?: React.ReactNode;
    }
);

export function DespesaFixaFormDialog(props: Props) {
  const [open, setOpen] = useState(false);

  const trigger =
    props.modo === "criar" ? (
      <Button>
        <Plus className="mr-2 h-4 w-4" />
        Nova despesa fixa
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
            {props.modo === "criar" ? "Nova despesa fixa" : "Editar despesa fixa"}
          </DialogTitle>
          <DialogDescription>
            Cadastre uma despesa que se repete todo mês (luz, condomínio, internet, etc.). O sistema
            gera uma &quot;conta a pagar&quot; mensal a partir desse modelo.
          </DialogDescription>
        </DialogHeader>
        <DespesaFixaForm
          modo={props.modo}
          despesaId={props.modo === "editar" ? props.despesaId : undefined}
          categorias={props.categorias}
          contas={props.contas}
          initialValues={props.modo === "editar" ? props.initialValues : undefined}
          onSucesso={() => setOpen(false)}
        />
      </DialogContent>
    </Dialog>
  );
}
