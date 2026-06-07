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

import { ProcessoCombobox } from "./processo-combobox";
import { ressarcimentoCreateSchema, type RessarcimentoCreateInput } from "../schema";
import { atualizarRessarcimento, criarRessarcimento } from "../actions";
import type { ProcessoOpcao } from "../queries";

type Props = {
  modo: "criar" | "editar";
  ressarcimentoId?: string;
  processos: ProcessoOpcao[];
  initialValues?: Partial<RessarcimentoCreateInput>;
  onSucesso: () => void;
};

const VALORES_VAZIOS: RessarcimentoCreateInput = {
  processoId: "",
  data: new Date().toISOString().slice(0, 10),
  descricao: "",
  valor: 0,
  recebivelId: undefined,
};

export function RessarcimentoForm({
  modo,
  ressarcimentoId,
  processos,
  initialValues,
  onSucesso,
}: Props) {
  const [pending, startTransition] = useTransition();

  const form = useForm<RessarcimentoCreateInput>({
    resolver: zodResolver(ressarcimentoCreateSchema),
    defaultValues: { ...VALORES_VAZIOS, ...initialValues },
  });

  function onSubmit(values: RessarcimentoCreateInput) {
    startTransition(async () => {
      const result =
        modo === "criar"
          ? await criarRessarcimento(values)
          : await atualizarRessarcimento({ id: ressarcimentoId ?? "", ...values });

      if (!result.ok) {
        toast.error(result.error);
        if (result.fieldErrors) {
          for (const [field, msgs] of Object.entries(result.fieldErrors)) {
            const msg = msgs?.[0];
            if (msg) form.setError(field as keyof RessarcimentoCreateInput, { message: msg });
          }
        }
        return;
      }

      toast.success(modo === "criar" ? "Ressarcimento cadastrado" : "Ressarcimento atualizado");
      onSucesso();
    });
  }

  return (
    <Form {...form}>
      <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
        <FormField
          control={form.control}
          name="processoId"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Processo *</FormLabel>
              <FormControl>
                <ProcessoCombobox
                  processos={processos}
                  value={field.value}
                  onChange={(v) => field.onChange(v ?? "")}
                />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />

        <div className="grid gap-4 sm:grid-cols-2">
          <FormField
            control={form.control}
            name="data"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Data da despesa *</FormLabel>
                <FormControl>
                  <Input type="date" {...field} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />

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
        </div>

        <FormField
          control={form.control}
          name="descricao"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Descrição *</FormLabel>
              <FormControl>
                <Textarea
                  rows={2}
                  placeholder="Ex.: Custas iniciais, cópias autenticadas, deslocamento..."
                  {...field}
                />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />

        <div className="flex justify-end gap-2 pt-2">
          <Button type="submit" disabled={pending}>
            {pending ? "Salvando..." : modo === "criar" ? "Cadastrar" : "Salvar alterações"}
          </Button>
        </div>
      </form>
    </Form>
  );
}
