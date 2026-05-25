"use client";

import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { useTransition } from "react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

import { CategoriaCombobox } from "./categoria-combobox";
import { transferenciaCreateSchema, type TransferenciaCreateInput } from "../schema";
import { atualizarTransferencia, criarTransferencia } from "../actions";
import type { CategoriaOpcao, ContaOpcao } from "../queries";

type Props = {
  modo: "criar" | "editar";
  pernaId?: string;
  contas: ContaOpcao[];
  categorias: CategoriaOpcao[];
  initialValues?: Partial<TransferenciaCreateInput>;
  onSucesso: () => void;
};

const VALORES_VAZIOS: TransferenciaCreateInput = {
  data: new Date().toISOString().slice(0, 10),
  descricao: "",
  contaOrigemId: "",
  contaDestinoId: "",
  categoriaId: "",
  valor: 0,
  observacoes: undefined,
};

export function TransferenciaForm({
  modo,
  pernaId,
  contas,
  categorias,
  initialValues,
  onSucesso,
}: Props) {
  const [pending, startTransition] = useTransition();

  const form = useForm<TransferenciaCreateInput>({
    resolver: zodResolver(transferenciaCreateSchema),
    defaultValues: { ...VALORES_VAZIOS, ...initialValues },
  });

  const origemSelecionada = form.watch("contaOrigemId");

  function onSubmit(values: TransferenciaCreateInput) {
    startTransition(async () => {
      const result =
        modo === "criar"
          ? await criarTransferencia(values)
          : await atualizarTransferencia({ id: pernaId ?? "", ...values });

      if (!result.ok) {
        toast.error(result.error);
        if (result.fieldErrors) {
          for (const [field, msgs] of Object.entries(result.fieldErrors)) {
            const msg = msgs?.[0];
            if (msg) form.setError(field as keyof TransferenciaCreateInput, { message: msg });
          }
        }
        return;
      }

      toast.success(modo === "criar" ? "Transferência criada" : "Transferência atualizada");
      onSucesso();
    });
  }

  return (
    <Form {...form}>
      <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
        <FormField
          control={form.control}
          name="data"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Data *</FormLabel>
              <FormControl>
                <Input type="date" {...field} />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />

        <FormField
          control={form.control}
          name="descricao"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Descrição *</FormLabel>
              <FormControl>
                <Input placeholder="Ex.: Transferência Inter PJ → Caixa" {...field} />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />

        <div className="grid gap-4 sm:grid-cols-2">
          <FormField
            control={form.control}
            name="contaOrigemId"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Conta de origem *</FormLabel>
                <Select value={field.value} onValueChange={field.onChange}>
                  <FormControl>
                    <SelectTrigger>
                      <SelectValue placeholder="Selecione" />
                    </SelectTrigger>
                  </FormControl>
                  <SelectContent>
                    {contas.map((c) => (
                      <SelectItem key={c.id} value={c.id}>
                        {c.codigo} — {c.nome}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <FormMessage />
              </FormItem>
            )}
          />

          <FormField
            control={form.control}
            name="contaDestinoId"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Conta de destino *</FormLabel>
                <Select value={field.value} onValueChange={field.onChange}>
                  <FormControl>
                    <SelectTrigger>
                      <SelectValue placeholder="Selecione" />
                    </SelectTrigger>
                  </FormControl>
                  <SelectContent>
                    {contas
                      .filter((c) => c.id !== origemSelecionada)
                      .map((c) => (
                        <SelectItem key={c.id} value={c.id}>
                          {c.codigo} — {c.nome}
                        </SelectItem>
                      ))}
                  </SelectContent>
                </Select>
                <FormMessage />
              </FormItem>
            )}
          />
        </div>

        <div className="grid gap-4 sm:grid-cols-2">
          <FormField
            control={form.control}
            name="valor"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Valor (R$) *</FormLabel>
                <FormControl>
                  <Input
                    type="number"
                    step="0.01"
                    min="0.01"
                    inputMode="decimal"
                    {...field}
                    value={field.value ?? 0}
                  />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />

          <FormField
            control={form.control}
            name="categoriaId"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Categoria *</FormLabel>
                <FormControl>
                  <CategoriaCombobox
                    categorias={categorias}
                    value={field.value}
                    onChange={(v) => field.onChange(v ?? "")}
                  />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
        </div>

        <FormField
          control={form.control}
          name="observacoes"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Observações</FormLabel>
              <FormControl>
                <Textarea rows={2} {...field} value={field.value ?? ""} />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />

        <p className="text-xs text-muted-foreground">
          Será criado um par de lançamentos: saída em <strong>origem</strong> e entrada em{" "}
          <strong>destino</strong>, vinculados atomicamente.
        </p>

        <div className="flex justify-end gap-2 pt-2">
          <Button type="submit" disabled={pending}>
            {pending
              ? "Salvando..."
              : modo === "criar"
                ? "Criar transferência"
                : "Salvar alterações"}
          </Button>
        </div>
      </form>
    </Form>
  );
}
