"use client";

import { useState } from "react";
import { ArrowDownRight } from "lucide-react";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";

import { RepasseForm } from "./repasse-form";
import type { CategoriaDespesaOpcao, ContaOpcao } from "../queries";

type Props = {
  itemId: string;
  valorItem: number;
  descricaoSugerida: string;
  contas: ContaOpcao[];
  categoriasDespesa: CategoriaDespesaOpcao[];
};

export function RepasseFormDialog({
  itemId,
  valorItem,
  descricaoSugerida,
  contas,
  categoriasDespesa,
}: Props) {
  const [open, setOpen] = useState(false);

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button size="sm">
          <ArrowDownRight className="mr-1 h-4 w-4" />
          Repassar
        </Button>
      </DialogTrigger>
      <DialogContent className="max-h-[90vh] max-w-2xl overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Registrar repasse</DialogTitle>
          <DialogDescription>
            Gera um lançamento de saída na conta escolhida e marca este item como repassado, em uma
            única transação.
          </DialogDescription>
        </DialogHeader>
        <RepasseForm
          itemId={itemId}
          valorItem={valorItem}
          descricaoSugerida={descricaoSugerida}
          contas={contas}
          categoriasDespesa={categoriasDespesa}
          onSucesso={() => setOpen(false)}
        />
      </DialogContent>
    </Dialog>
  );
}
