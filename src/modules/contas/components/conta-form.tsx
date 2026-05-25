"use client";

import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { useTransition } from "react";
import { toast } from "sonner";
import { TipoConta } from "@prisma/client";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
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

import { TIPO_CONTA_LABELS, contaCreateSchema, type ContaCreateInput } from "../schema";
import { atualizarConta, criarConta } from "../actions";

type Props = {
  modo: "criar" | "editar";
  contaId?: string;
  initialValues?: Partial<ContaCreateInput>;
  temLancamentos?: boolean;
  onSucesso: () => void;
};

const VALORES_VAZIOS: ContaCreateInput = {
  codigo: "",
  nome: "",
  tipo: TipoConta.CONTA_CORRENTE,
  banco: undefined,
  agencia: undefined,
  conta: undefined,
  saldoInicial: 0,
};

export function ContaForm({ modo, contaId, initialValues, temLancamentos, onSucesso }: Props) {
  const [pending, startTransition] = useTransition();

  const form = useForm<ContaCreateInput>({
    resolver: zodResolver(contaCreateSchema),
    defaultValues: { ...VALORES_VAZIOS, ...initialValues },
  });

  function onSubmit(values: ContaCreateInput) {
    startTransition(async () => {
      const result =
        modo === "criar"
          ? await criarConta(values)
          : await atualizarConta({ id: contaId ?? "", ...values });

      if (!result.ok) {
        toast.error(result.error);
        if (result.fieldErrors) {
          for (const [field, msgs] of Object.entries(result.fieldErrors)) {
            const msg = msgs?.[0];
            if (msg) form.setError(field as keyof ContaCreateInput, { message: msg });
          }
        }
        return;
      }

      toast.success(modo === "criar" ? "Conta cadastrada" : "Conta atualizada");
      onSucesso();
    });
  }

  return (
    <Form {...form}>
      <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
        <div className="grid gap-4 sm:grid-cols-2">
          <FormField
            control={form.control}
            name="codigo"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Código *</FormLabel>
                <FormControl>
                  <Input
                    placeholder="INTER_PJ"
                    autoComplete="off"
                    {...field}
                    onChange={(e) => field.onChange(e.target.value.toUpperCase())}
                  />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
          <FormField
            control={form.control}
            name="tipo"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Tipo</FormLabel>
                <Select value={field.value} onValueChange={field.onChange}>
                  <FormControl>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                  </FormControl>
                  <SelectContent>
                    {Object.entries(TIPO_CONTA_LABELS).map(([value, label]) => (
                      <SelectItem key={value} value={value}>
                        {label}
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
          name="nome"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Nome *</FormLabel>
              <FormControl>
                <Input placeholder="Banco Inter PJ" {...field} />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />

        <div className="grid gap-4 sm:grid-cols-3">
          <FormField
            control={form.control}
            name="banco"
            render={({ field }) => (
              <FormItem className="sm:col-span-1">
                <FormLabel>Banco</FormLabel>
                <FormControl>
                  <Input {...field} value={field.value ?? ""} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
          <FormField
            control={form.control}
            name="agencia"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Agência</FormLabel>
                <FormControl>
                  <Input {...field} value={field.value ?? ""} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
          <FormField
            control={form.control}
            name="conta"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Conta</FormLabel>
                <FormControl>
                  <Input {...field} value={field.value ?? ""} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
        </div>

        <FormField
          control={form.control}
          name="saldoInicial"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Saldo inicial (R$)</FormLabel>
              <FormControl>
                <Input
                  type="number"
                  step="0.01"
                  inputMode="decimal"
                  {...field}
                  value={field.value ?? 0}
                />
              </FormControl>
              {modo === "editar" && temLancamentos && (
                <p className="text-xs text-amber-700">
                  Atenção: esta conta já possui lançamentos. Alterar o saldo inicial afeta saldos
                  históricos. A alteração ficará registrada na auditoria.
                </p>
              )}
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
