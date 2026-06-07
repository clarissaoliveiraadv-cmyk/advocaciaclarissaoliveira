"use client";

import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { useTransition } from "react";
import { toast } from "sonner";
import { TipoParceiro } from "@prisma/client";

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

import { TIPO_PARCEIRO_LABELS, parceiroCreateSchema, type ParceiroCreateInput } from "../schema";
import { atualizarParceiro, criarParceiro } from "../actions";

type Props = {
  modo: "criar" | "editar";
  parceiroId?: string;
  initialValues?: Partial<ParceiroCreateInput>;
  onSucesso: () => void;
};

const VALORES_VAZIOS: ParceiroCreateInput = {
  nome: "",
  tipo: TipoParceiro.PARCEIRO_EXTERNO,
  oab: undefined,
  percentualPadraoSucumbencia: undefined,
};

export function ParceiroForm({ modo, parceiroId, initialValues, onSucesso }: Props) {
  const [pending, startTransition] = useTransition();

  const form = useForm<ParceiroCreateInput>({
    resolver: zodResolver(parceiroCreateSchema),
    defaultValues: { ...VALORES_VAZIOS, ...initialValues },
  });

  function onSubmit(values: ParceiroCreateInput) {
    startTransition(async () => {
      const result =
        modo === "criar"
          ? await criarParceiro(values)
          : await atualizarParceiro({ id: parceiroId ?? "", ...values });

      if (!result.ok) {
        toast.error(result.error);
        if (result.fieldErrors) {
          for (const [field, msgs] of Object.entries(result.fieldErrors)) {
            const msg = msgs?.[0];
            if (msg) form.setError(field as keyof ParceiroCreateInput, { message: msg });
          }
        }
        return;
      }

      toast.success(modo === "criar" ? "Parceiro cadastrado" : "Parceiro atualizado");
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
                <Input placeholder="Dr. Pedro Almeida" autoComplete="off" {...field} />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />

        <div className="grid gap-4 sm:grid-cols-2">
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
                    {Object.entries(TIPO_PARCEIRO_LABELS).map(([value, label]) => (
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

          <FormField
            control={form.control}
            name="oab"
            render={({ field }) => (
              <FormItem>
                <FormLabel>OAB</FormLabel>
                <FormControl>
                  <Input placeholder="123456/SP" {...field} value={field.value ?? ""} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
        </div>

        <FormField
          control={form.control}
          name="percentualPadraoSucumbencia"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Percentual padrão de sucumbência (%)</FormLabel>
              <FormControl>
                <Input
                  type="number"
                  inputMode="decimal"
                  step="0.01"
                  min="0"
                  max="100"
                  placeholder="ex.: 33,33"
                  {...field}
                  value={field.value ?? ""}
                />
              </FormControl>
              <p className="text-xs text-muted-foreground">
                Opcional. Apenas o padrão de referência — o valor final é definido nos módulos
                financeiros (sucumbência, parcerias). Use ponto ou vírgula para decimais (ex.:
                33.33).
              </p>
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
