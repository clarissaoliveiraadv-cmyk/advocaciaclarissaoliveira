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

import { despesaFixaCreateSchema, type DespesaFixaCreateInput } from "../schema";
import { atualizarDespesaFixa, criarDespesaFixa } from "../actions";
import type { CategoriaDespesaOpcao, ContaOpcao } from "../queries";

type Props = {
  modo: "criar" | "editar";
  despesaId?: string;
  categorias: CategoriaDespesaOpcao[];
  contas: ContaOpcao[];
  initialValues?: Partial<DespesaFixaCreateInput>;
  onSucesso: () => void;
};

const VAZIO: DespesaFixaCreateInput = {
  nome: "",
  categoriaId: "",
  contaId: "",
  valorEstimado: 0,
  diaVencimento: 10,
  ativo: true,
  observacoes: undefined,
};

export function DespesaFixaForm({
  modo,
  despesaId,
  categorias,
  contas,
  initialValues,
  onSucesso,
}: Props) {
  const [pending, startTransition] = useTransition();
  const form = useForm<DespesaFixaCreateInput>({
    resolver: zodResolver(despesaFixaCreateSchema),
    defaultValues: { ...VAZIO, ...initialValues },
  });

  function onSubmit(values: DespesaFixaCreateInput) {
    startTransition(async () => {
      const result =
        modo === "criar"
          ? await criarDespesaFixa(values)
          : await atualizarDespesaFixa({ id: despesaId ?? "", ...values });
      if (!result.ok) {
        toast.error(result.error);
        if (result.fieldErrors) {
          for (const [field, msgs] of Object.entries(result.fieldErrors)) {
            const msg = msgs?.[0];
            if (msg) form.setError(field as keyof DespesaFixaCreateInput, { message: msg });
          }
        }
        return;
      }
      toast.success(modo === "criar" ? "Despesa fixa cadastrada" : "Despesa fixa atualizada");
      onSucesso();
    });
  }

  return (
    <Form {...form}>
      <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
        <FormField
          control={form.control}
          name="nome"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Nome *</FormLabel>
              <FormControl>
                <Input placeholder="Ex.: Energia elétrica" {...field} />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />

        <div className="grid gap-4 sm:grid-cols-2">
          <FormField
            control={form.control}
            name="categoriaId"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Categoria (DESPESA) *</FormLabel>
                <Select value={field.value} onValueChange={field.onChange}>
                  <FormControl>
                    <SelectTrigger>
                      <SelectValue placeholder="Selecione..." />
                    </SelectTrigger>
                  </FormControl>
                  <SelectContent>
                    {categorias.map((c) => (
                      <SelectItem key={c.id} value={c.id}>
                        {c.nome}
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
            name="contaId"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Conta de débito *</FormLabel>
                <Select value={field.value} onValueChange={field.onChange}>
                  <FormControl>
                    <SelectTrigger>
                      <SelectValue placeholder="Selecione..." />
                    </SelectTrigger>
                  </FormControl>
                  <SelectContent>
                    {contas.map((c) => (
                      <SelectItem key={c.id} value={c.id}>
                        {c.nome} ({c.codigo})
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
            name="valorEstimado"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Valor estimado (R$) *</FormLabel>
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
            name="diaVencimento"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Dia do vencimento *</FormLabel>
                <FormControl>
                  <Input
                    type="number"
                    min="1"
                    max="31"
                    step="1"
                    placeholder="10"
                    {...field}
                    value={field.value ?? 10}
                  />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
        </div>

        <FormField
          control={form.control}
          name="ativo"
          render={({ field }) => (
            <FormItem className="flex items-center gap-3 space-y-0">
              <FormControl>
                <input
                  type="checkbox"
                  checked={!!field.value}
                  onChange={(e) => field.onChange(e.target.checked)}
                  className="h-4 w-4"
                />
              </FormControl>
              <FormLabel className="font-normal">
                Ativa (será incluída nas próximas previsões mensais)
              </FormLabel>
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
            {pending ? "Salvando..." : modo === "criar" ? "Cadastrar" : "Salvar alterações"}
          </Button>
        </div>
      </form>
    </Form>
  );
}
