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

import { ParceriaForm } from "./parceria-form";
import type { ParceiroOpcao, ProcessoOpcao } from "../queries";
import type { ParceriaCreateInput } from "../schema";

type Props = {
  processos: ProcessoOpcao[];
  parceiros: ParceiroOpcao[];
} & (
  | { modo: "criar" }
  | {
      modo: "editar";
      parceriaId: string;
      initialValues: ParceriaCreateInput;
      trigger?: React.ReactNode;
    }
);

export function ParceriaFormDialog(props: Props) {
  const [open, setOpen] = useState(false);

  const trigger =
    props.modo === "criar" ? (
      <Button>
        <Plus className="mr-2 h-4 w-4" />
        Nova parceria
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
          <DialogTitle>{props.modo === "criar" ? "Nova parceria" : "Editar parceria"}</DialogTitle>
          <DialogDescription>
            Honorários compartilhados com advogado parceiro. O sistema sugere quanto está devido —
            o pagamento real fica como lançamento manual de saída quando você quitar.
          </DialogDescription>
        </DialogHeader>
        <ParceriaForm
          modo={props.modo}
          parceriaId={props.modo === "editar" ? props.parceriaId : undefined}
          processos={props.processos}
          parceiros={props.parceiros}
          initialValues={props.modo === "editar" ? props.initialValues : undefined}
          onSucesso={() => setOpen(false)}
        />
      </DialogContent>
    </Dialog>
  );
}
