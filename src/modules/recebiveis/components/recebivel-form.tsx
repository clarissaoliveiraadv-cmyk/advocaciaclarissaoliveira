"use client";

import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { useMemo, useTransition } from "react";
import { toast } from "sonner";
import { TipoParcela } from "@prisma/client";

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

import { ProcessoCombobox } from "./processo-combobox";
import { ParceiroCombobox } from "./parceiro-combobox";
import { RecebivelPreviewCalculos } from "./recebivel-preview-calculos";
import { TIPO_PARCELA_LABELS, recebivelCreateSchema, type RecebivelCreateInput } from "../schema";
import { atualizarRecebivel, criarRecebivel } from "../actions";
import type { ParceiroOpcao, ProcessoOpcao } from "../queries";

type Props = {
  modo: "criar" | "editar";
  recebivelId?: string;
  processos: ProcessoOpcao[];
  parceiros: ParceiroOpcao[];
  initialValues?: Partial<RecebivelCreateInput>;
  onSucesso: () => void;
};

const VALORES_VAZIOS: RecebivelCreateInput = {
  processoId: "",
  dataPrevista: new Date().toISOString().slice(0, 10),
  tipoParcela: TipoParcela.NORMAL,
  numeroParcela: undefined,
  totalParcelas: undefined,
  valorIntegral: 0,
  valorParcela: 0,
  ressarcimentoEmbutido: 0,
  percHonorarios: "30",
  parceiroId: undefined,
  percParceiro: undefined,
  observacoes: undefined,
};

export function RecebivelForm({
  modo,
  recebivelId,
  processos,
  parceiros,
  initialValues,
  onSucesso,
}: Props) {
  const [pending, startTransition] = useTransition();

  const form = useForm<RecebivelCreateInput>({
    resolver: zodResolver(recebivelCreateSchema),
    defaultValues: { ...VALORES_VAZIOS, ...initialValues },
  });

  const valorParcela = form.watch("valorParcela");
  const ressarc = form.watch("ressarcimentoEmbutido");
  const percHonor = form.watch("percHonorarios");
  const parceiroId = form.watch("parceiroId");
  const percParc = form.watch("percParceiro");

  const calc = useMemo(() => {
    const v = Number(valorParcela) || 0;
    const r = Number(ressarc) || 0;
    const ph = (Number(percHonor) || 0) / 100;
    const pp = (Number(percParc) || 0) / 100;
    const honor = v * ph;
    const parceiroValor = parceiroId ? honor * pp : 0;
    const honorEscritorio = honor - parceiroValor;
    const valorCliente = Math.max(0, v - r - honor);
    return { honor, parceiroValor, honorEscritorio, valorCliente };
  }, [valorParcela, ressarc, percHonor, parceiroId, percParc]);

  function onSubmit(values: RecebivelCreateInput) {
    startTransition(async () => {
      const result =
        modo === "criar"
          ? await criarRecebivel(values)
          : await atualizarRecebivel({ id: recebivelId ?? "", ...values });

      if (!result.ok) {
        toast.error(result.error);
        if (result.fieldErrors) {
          for (const [field, msgs] of Object.entries(result.fieldErrors)) {
            const msg = msgs?.[0];
            if (msg) form.setError(field as keyof RecebivelCreateInput, { message: msg });
          }
        }
        return;
      }

      toast.success(modo === "criar" ? "Recebível cadastrado" : "Recebível atualizado");
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

        <div className="grid gap-4 sm:grid-cols-3">
          <FormField
            control={form.control}
            name="dataPrevista"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Data prevista *</FormLabel>
                <FormControl>
                  <Input type="date" {...field} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />

          <FormField
            control={form.control}
            name="tipoParcela"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Tipo de parcela</FormLabel>
                <Select value={field.value} onValueChange={field.onChange}>
                  <FormControl>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                  </FormControl>
                  <SelectContent>
                    {Object.entries(TIPO_PARCELA_LABELS).map(([v, label]) => (
                      <SelectItem key={v} value={v}>
                        {label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <FormMessage />
              </FormItem>
            )}
          />

          <div className="grid grid-cols-2 gap-2">
            <FormField
              control={form.control}
              name="numeroParcela"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Nº</FormLabel>
                  <FormControl>
                    <Input
                      type="number"
                      min="1"
                      step="1"
                      placeholder="3"
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
              name="totalParcelas"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>de</FormLabel>
                  <FormControl>
                    <Input
                      type="number"
                      min="1"
                      step="1"
                      placeholder="7"
                      {...field}
                      value={field.value ?? ""}
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
          </div>
        </div>

        <div className="grid gap-4 sm:grid-cols-3">
          <FormField
            control={form.control}
            name="valorIntegral"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Valor integral (R$) *</FormLabel>
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
            name="valorParcela"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Valor parcela (R$) *</FormLabel>
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
            name="ressarcimentoEmbutido"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Ressarcimento (R$)</FormLabel>
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
                <FormLabel>Honorários (%) *</FormLabel>
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
            name="parceiroId"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Parceiro</FormLabel>
                <FormControl>
                  <ParceiroCombobox
                    parceiros={parceiros}
                    value={field.value}
                    onChange={(v) => {
                      field.onChange(v);
                      if (!v) form.setValue("percParceiro", undefined);
                    }}
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
                <FormLabel>% Parceiro (sobre honorários)</FormLabel>
                <FormControl>
                  <Input
                    type="number"
                    step="0.01"
                    min="0"
                    max="100"
                    inputMode="decimal"
                    placeholder="ex.: 40"
                    disabled={!parceiroId}
                    {...field}
                    value={field.value ?? ""}
                  />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
        </div>

        <RecebivelPreviewCalculos
          honor={calc.honor}
          parceiroValor={calc.parceiroValor}
          honorEscritorio={calc.honorEscritorio}
          valorCliente={calc.valorCliente}
          parceiroId={parceiroId}
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
