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

import { LancamentoForm } from "./lancamento-form";
import type { CategoriaOpcao, ClienteOpcao, ContaOpcao, ProcessoOpcao } from "../queries";
import type { LancamentoCreateInput } from "../schema";

type Props = {
  contas: ContaOpcao[];
  categorias: CategoriaOpcao[];
  clientes: ClienteOpcao[];
  processos: ProcessoOpcao[];
} & (
  | { modo: "criar" }
  | {
      modo: "editar";
      lancamentoId: string;
      initialValues: LancamentoCreateInput;
      trigger?: React.ReactNode;
    }
);

export function LancamentoFormDialog(props: Props) {
  const [open, setOpen] = useState(false);

  const trigger =
    props.modo === "criar" ? (
      <Button>
        <Plus className="mr-2 h-4 w-4" />
        Novo lançamento
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
            {props.modo === "criar" ? "Novo lançamento" : "Editar lançamento"}
          </DialogTitle>
          <DialogDescription>
            Campos marcados com * são obrigatórios. Categoria filtrada conforme o tipo.
          </DialogDescription>
        </DialogHeader>
        <LancamentoForm
          modo={props.modo}
          lancamentoId={props.modo === "editar" ? props.lancamentoId : undefined}
          contas={props.contas}
          categorias={props.categorias}
          clientes={props.clientes}
          processos={props.processos}
          initialValues={props.modo === "editar" ? props.initialValues : undefined}
          onSucesso={() => setOpen(false)}
        />
      </DialogContent>
    </Dialog>
  );
}
