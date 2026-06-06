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
import { toBRL } from "@/lib/money";

import { registrarRepasseSchema, type RegistrarRepasseInput } from "../repasse-schema";
import { registrarRepasse } from "../repasse-actions";
import type { CategoriaDespesaOpcao, ContaOpcao } from "../queries";

type Props = {
  itemId: string;
  valorItem: number;
  descricaoSugerida: string;
  contas: ContaOpcao[];
  categoriasDespesa: CategoriaDespesaOpcao[];
  onSucesso: () => void;
};

export function RepasseForm({
  itemId,
  valorItem,
  descricaoSugerida,
  contas,
  categoriasDespesa,
  onSucesso,
}: Props) {
  const [pending, startTransition] = useTransition();

  const form = useForm<RegistrarRepasseInput>({
    resolver: zodResolver(registrarRepasseSchema),
    defaultValues: {
      itemId,
      data: new Date().toISOString().slice(0, 10),
      contaSaidaId: contas[0]?.id ?? "",
      categoriaId: categoriasDespesa[0]?.id ?? "",
      descricao: descricaoSugerida,
      observacoes: undefined,
    },
  });

  function onSubmit(values: RegistrarRepasseInput) {
    startTransition(async () => {
      const result = await registrarRepasse(values);
      if (!result.ok) {
        toast.error(result.error);
        if (result.fieldErrors) {
          for (const [field, msgs] of Object.entries(result.fieldErrors)) {
            const msg = msgs?.[0];
            if (msg) form.setError(field as keyof RegistrarRepasseInput, { message: msg });
          }
        }
        return;
      }
      toast.success("Repasse registrado");
      onSucesso();
    });
  }

  return (
    <Form {...form}>
      <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
        <div className="rounded-md border bg-muted/30 p-3 text-sm">
          <div className="text-xs uppercase tracking-wide text-muted-foreground">
            Valor do repasse
          </div>
          <div className="font-mono text-xl tabular-nums">{toBRL(valorItem)}</div>
          <p className="mt-1 text-xs text-muted-foreground">
            Valor travado pelo item da distribuição. Para repassar quantia diferente, ajuste o item
            antes de confirmar a distribuição.
          </p>
        </div>

        <div className="grid gap-4 sm:grid-cols-2">
          <FormField
            control={form.control}
            name="data"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Data do repasse *</FormLabel>
                <FormControl>
                  <Input type="date" {...field} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
          <FormField
            control={form.control}
            name="contaSaidaId"
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
        </div>

        <FormField
          control={form.control}
          name="categoriaId"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Categoria de despesa *</FormLabel>
              <Select value={field.value} onValueChange={field.onChange}>
                <FormControl>
                  <SelectTrigger>
                    <SelectValue placeholder="Selecione" />
                  </SelectTrigger>
                </FormControl>
                <SelectContent>
                  {categoriasDespesa.map((c) => (
                    <SelectItem key={c.id} value={c.id}>
                      {c.nome}
                      {c.isPessoal ? " (pessoal)" : ""}
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
          name="descricao"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Descrição do lançamento *</FormLabel>
              <FormControl>
                <Input {...field} />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />

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

        <div className="flex justify-end gap-2 pt-2">
          <Button type="submit" disabled={pending}>
            {pending ? "Registrando..." : "Registrar repasse e gerar saída"}
          </Button>
        </div>
      </form>
    </Form>
  );
}
