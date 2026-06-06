"use client";

import { TipoBeneficiario } from "@prisma/client";
import { Trash2 } from "lucide-react";
import { type UseFormReturn } from "react-hook-form";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { TIPO_BENEFICIARIO_LABELS, type ConfirmarDistribuicaoInput } from "../schema";
import type { ParceiroOpcao } from "../queries";

type Props = {
  form: UseFormReturn<ConfirmarDistribuicaoInput>;
  index: number;
  parceiros: ParceiroOpcao[];
  clienteDoProcesso: { id: string; nome: string };
  onRemove: () => void;
};

export function ItemDistribuicaoRow({
  form,
  index,
  parceiros,
  clienteDoProcesso,
  onRemove,
}: Props) {
  const beneficiario = form.watch(`itens.${index}.beneficiario`);
  const erros = form.formState.errors.itens?.[index];

  return (
    <div className="space-y-2 rounded-md border bg-card p-3">
      <div className="grid gap-2 sm:grid-cols-[160px_1fr_120px_40px]">
        <Select
          value={beneficiario}
          onValueChange={(v) => {
            form.setValue(`itens.${index}.beneficiario`, v as TipoBeneficiario);
            // Auto-preenche FKs polimórficos conforme o beneficiário
            if (v === TipoBeneficiario.CLIENTE) {
              form.setValue(`itens.${index}.clienteId`, clienteDoProcesso.id);
              form.setValue(`itens.${index}.parceiroId`, undefined);
            } else if (v === TipoBeneficiario.PARCEIRO) {
              form.setValue(`itens.${index}.clienteId`, undefined);
            } else {
              form.setValue(`itens.${index}.clienteId`, undefined);
              form.setValue(`itens.${index}.parceiroId`, undefined);
            }
          }}
        >
          <SelectTrigger>
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {Object.entries(TIPO_BENEFICIARIO_LABELS).map(([v, label]) => (
              <SelectItem key={v} value={v}>
                {label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>

        <Input placeholder="Descrição (opcional)" {...form.register(`itens.${index}.descricao`)} />

        <Input
          type="number"
          step="0.01"
          min="0"
          inputMode="decimal"
          {...form.register(`itens.${index}.valor`)}
          className="text-right font-mono"
        />

        <Button type="button" variant="ghost" size="icon" onClick={onRemove} title="Remover item">
          <Trash2 className="h-4 w-4 text-destructive" />
        </Button>
      </div>

      {beneficiario === TipoBeneficiario.CLIENTE && (
        <p className="text-xs text-muted-foreground">
          Beneficiário: <strong>{clienteDoProcesso.nome}</strong> (cliente do processo)
        </p>
      )}

      {beneficiario === TipoBeneficiario.PARCEIRO && (
        <div>
          <Select
            value={form.watch(`itens.${index}.parceiroId`) ?? ""}
            onValueChange={(v) => form.setValue(`itens.${index}.parceiroId`, v)}
          >
            <SelectTrigger>
              <SelectValue placeholder="Selecione o parceiro" />
            </SelectTrigger>
            <SelectContent>
              {parceiros.map((p) => (
                <SelectItem key={p.id} value={p.id}>
                  {p.nome}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          {erros?.parceiroId && (
            <p className="mt-1 text-xs text-destructive">{erros.parceiroId.message}</p>
          )}
        </div>
      )}

      {erros?.valor && <p className="text-xs text-destructive">{erros.valor.message}</p>}
      {erros?.clienteId && <p className="text-xs text-destructive">{erros.clienteId.message}</p>}
    </div>
  );
}
