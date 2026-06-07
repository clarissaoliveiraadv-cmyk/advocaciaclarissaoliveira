"use client";

import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { useMemo, useTransition } from "react";
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
import { toBRL } from "@/lib/money";

import { ProcessoCombobox } from "./processo-combobox";
import { ParceiroCombobox } from "./parceiro-combobox";
import {
  calcularDevidoAoParceiro,
  parceriaCreateSchema,
  type ParceriaCreateInput,
} from "../schema";
import { atualizarParceria, criarParceria } from "../actions";
import type { ParceiroOpcao, ProcessoOpcao } from "../queries";

type Props = {
  modo: "criar" | "editar";
  parceriaId?: string;
  processos: ProcessoOpcao[];
  parceiros: ParceiroOpcao[];
  initialValues?: Partial<ParceriaCreateInput>;
  onSucesso: () => void;
};

const VALORES_VAZIOS: ParceriaCreateInput = {
  parceiroId: "",
  processoId: "",
  dataAcordo: new Date().toISOString().slice(0, 10),
  valorTotal: 0,
  valorRecebido: 0,
  percHonorarios: "30",
  ressarcimentos: 0,
  percParceiro: "50",
  dataPgto: undefined,
  observacoes: undefined,
};

export function ParceriaForm({
  modo,
  parceriaId,
  processos,
  parceiros,
  initialValues,
  onSucesso,
}: Props) {
  const [pending, startTransition] = useTransition();

  const form = useForm<ParceriaCreateInput>({
    resolver: zodResolver(parceriaCreateSchema),
    defaultValues: { ...VALORES_VAZIOS, ...initialValues },
  });

  const valorRecebido = form.watch("valorRecebido");
  const percHonor = form.watch("percHonorarios");
  const ressarc = form.watch("ressarcimentos");
  const percParc = form.watch("percParceiro");

  const calc = useMemo(() => {
    const recebido = Number(valorRecebido) || 0;
    const ph = (Number(percHonor) || 0) / 100;
    const r = Number(ressarc) || 0;
    const pp = (Number(percParc) || 0) / 100;
    const baseHonor = recebido * ph;
    const honorLiquido = Math.max(0, baseHonor - r);
    const devido = calcularDevidoAoParceiro({
      valorRecebido: recebido,
      percHonorarios: ph,
      ressarcimentos: r,
      percParceiro: pp,
    });
    const escritorio = Math.max(0, honorLiquido - devido);
    return { baseHonor, honorLiquido, devido, escritorio };
  }, [valorRecebido, percHonor, ressarc, percParc]);

  function onSubmit(values: ParceriaCreateInput) {
    startTransition(async () => {
      const result =
        modo === "criar"
          ? await criarParceria(values)
          : await atualizarParceria({ id: parceriaId ?? "", ...values });

      if (!result.ok) {
        toast.error(result.error);
        if (result.fieldErrors) {
          for (const [field, msgs] of Object.entries(result.fieldErrors)) {
            const msg = msgs?.[0];
            if (msg) form.setError(field as keyof ParceriaCreateInput, { message: msg });
          }
        }
        return;
      }

      toast.success(modo === "criar" ? "Parceria cadastrada" : "Parceria atualizada");
      onSucesso();
    });
  }

  return (
    <Form {...form}>
      <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
        <div className="grid gap-4 sm:grid-cols-2">
          <FormField
            control={form.control}
            name="parceiroId"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Parceiro *</FormLabel>
                <FormControl>
                  <ParceiroCombobox
                    parceiros={parceiros}
                    value={field.value}
                    onChange={(v) => field.onChange(v ?? "")}
                  />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
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
        </div>

        <div className="grid gap-4 sm:grid-cols-3">
          <FormField
            control={form.control}
            name="dataAcordo"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Data do acordo *</FormLabel>
                <FormControl>
                  <Input type="date" {...field} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
          <FormField
            control={form.control}
            name="valorTotal"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Valor total acordado (R$) *</FormLabel>
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
            name="valorRecebido"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Valor já recebido (R$)</FormLabel>
                <FormControl>
                  <Input
                    type="number"
                    step="0.01"
                    min="0"
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

        <div className="grid gap-4 sm:grid-cols-3">
          <FormField
            control={form.control}
            name="percHonorarios"
            render={({ field }) => (
              <FormItem>
                <FormLabel>% Honorários *</FormLabel>
                <FormControl>
                  <Input
                    type="number"
                    step="0.01"
                    min="0"
                    max="100"
                    inputMode="decimal"
                    {...field}
                    value={field.value ?? ""}
                  />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
          <FormField
            control={form.control}
            name="ressarcimentos"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Ressarcimentos abatidos (R$)</FormLabel>
                <FormControl>
                  <Input
                    type="number"
                    step="0.01"
                    min="0"
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
            name="percParceiro"
            render={({ field }) => (
              <FormItem>
                <FormLabel>% Parceiro (sobre honor. líquidos) *</FormLabel>
                <FormControl>
                  <Input
                    type="number"
                    step="0.01"
                    min="0"
                    max="100"
                    inputMode="decimal"
                    {...field}
                    value={field.value ?? ""}
                  />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
        </div>

        <div className="rounded-md border bg-muted/30 p-3 text-sm">
          <div className="grid grid-cols-2 gap-x-4 gap-y-1 sm:grid-cols-4">
            <span className="text-muted-foreground">Base honorários</span>
            <span className="font-mono tabular-nums">{toBRL(calc.baseHonor)}</span>
            <span className="text-muted-foreground">Honor. líquidos</span>
            <span className="font-mono tabular-nums">{toBRL(calc.honorLiquido)}</span>
            <span className="text-muted-foreground">Devido ao parceiro</span>
            <span className="font-mono font-semibold tabular-nums text-amber-700">
              {toBRL(calc.devido)}
            </span>
            <span className="text-muted-foreground">Escritório</span>
            <span className="font-mono tabular-nums text-emerald-700">{toBRL(calc.escritorio)}</span>
          </div>
        </div>

        <div className="grid gap-4 sm:grid-cols-2">
          <FormField
            control={form.control}
            name="dataPgto"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Data do pagamento ao parceiro</FormLabel>
                <FormControl>
                  <Input type="date" {...field} value={field.value ?? ""} />
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

        <div className="flex justify-end gap-2 pt-2">
          <Button type="submit" disabled={pending}>
            {pending ? "Salvando..." : modo === "criar" ? "Cadastrar" : "Salvar alterações"}
          </Button>
        </div>
      </form>
    </Form>
  );
}
