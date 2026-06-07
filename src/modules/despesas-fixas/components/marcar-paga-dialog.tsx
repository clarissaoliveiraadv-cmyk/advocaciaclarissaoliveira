"use client";

import { useState, useTransition } from "react";
import { CheckCircle2 } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

import { marcarPrevisaoPaga } from "../actions";
import type { ContaOpcao } from "../queries";

type Props = {
  previsaoId: string;
  nomeDespesa: string;
  valorPrevisto: number;
  contaPadraoId: string;
  contas: ContaOpcao[];
};

export function MarcarPagaDialog({
  previsaoId,
  nomeDespesa,
  valorPrevisto,
  contaPadraoId,
  contas,
}: Props) {
  const [open, setOpen] = useState(false);
  const [data, setData] = useState(() => new Date().toISOString().slice(0, 10));
  const [valor, setValor] = useState(String(valorPrevisto));
  const [contaId, setContaId] = useState(contaPadraoId);
  const [descricao, setDescricao] = useState(nomeDespesa);
  const [pending, startTransition] = useTransition();

  function onConfirm() {
    startTransition(async () => {
      const result = await marcarPrevisaoPaga({
        id: previsaoId,
        dataPagamento: data,
        valorPago: Number(valor),
        contaId,
        descricao,
      });
      if (!result.ok) {
        toast.error(result.error);
        return;
      }
      toast.success("Pagamento registrado");
      setOpen(false);
    });
  }

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="default" size="sm">
          <CheckCircle2 className="mr-1 h-4 w-4" />
          Marcar paga
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>Registrar pagamento — {nomeDespesa}</DialogTitle>
          <DialogDescription>
            Cria um lançamento de SAÍDA na conta selecionada e vincula à previsão.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-3">
          <div className="grid gap-3 sm:grid-cols-2">
            <div>
              <label className="mb-1 block text-sm font-medium">Data do pagamento</label>
              <Input type="date" value={data} onChange={(e) => setData(e.target.value)} />
            </div>
            <div>
              <label className="mb-1 block text-sm font-medium">Valor pago (R$)</label>
              <Input
                type="number"
                step="0.01"
                min="0.01"
                inputMode="decimal"
                value={valor}
                onChange={(e) => setValor(e.target.value)}
              />
            </div>
          </div>
          <div>
            <label className="mb-1 block text-sm font-medium">Conta</label>
            <Select value={contaId} onValueChange={setContaId}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {contas.map((c) => (
                  <SelectItem key={c.id} value={c.id}>
                    {c.nome} ({c.codigo})
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div>
            <label className="mb-1 block text-sm font-medium">Descrição do lançamento</label>
            <Input value={descricao} onChange={(e) => setDescricao(e.target.value)} />
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => setOpen(false)} disabled={pending}>
            Cancelar
          </Button>
          <Button onClick={onConfirm} disabled={pending || !data || !valor || !contaId}>
            {pending ? "Registrando..." : "Confirmar pagamento"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
