"use client";

import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { useMemo, useTransition } from "react";
import { toast } from "sonner";
import { X } from "lucide-react";

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

import { ProcessoCombobox } from "./processo-combobox";
import {
  calcularDistribuicaoSucumbencia,
  sucumbenciaCreateSchema,
  type SucumbenciaCreateInput,
} from "../schema";
import { atualizarSucumbencia, criarSucumbencia } from "../actions";
import type { ParceiroOpcao, ProcessoOpcao } from "../queries";

type Props = {
  modo: "criar" | "editar";
  sucumbenciaId?: string;
  processos: ProcessoOpcao[];
  parceiros: ParceiroOpcao[];
  initialValues?: Partial<SucumbenciaCreateInput>;
  onSucesso: () => void;
};

const VALORES_VAZIOS: SucumbenciaCreateInput = {
  processoId: "",
  valorTotal: 0,
  dataRecebimento: new Date().toISOString().slice(0, 10),
  parceiroExternoId: undefined,
  percParceiroExterno: undefined,
  percEscritorio: "34",
  percClarissa: "33",
  percVivian: "33",
  observacoes: undefined,
};

export function SucumbenciaForm({
  modo,
  sucumbenciaId,
  processos,
  parceiros,
  initialValues,
  onSucesso,
}: Props) {
  const [pending, startTransition] = useTransition();

  const form = useForm<SucumbenciaCreateInput>({
    resolver: zodResolver(sucumbenciaCreateSchema),
    defaultValues: { ...VALORES_VAZIOS, ...initialValues },
  });

  const valorTotal = form.watch("valorTotal");
  const parceiroId = form.watch("parceiroExternoId");
  const percParc = form.watch("percParceiroExterno");
  const percEsc = form.watch("percEscritorio");
  const percCla = form.watch("percClarissa");
  const percViv = form.watch("percVivian");

  const calc = useMemo(() => {
    return calcularDistribuicaoSucumbencia({
      valorTotal: Number(valorTotal) || 0,
      percParceiroExterno: parceiroId && percParc ? (Number(percParc) || 0) / 100 : 0,
      percEscritorio: (Number(percEsc) || 0) / 100,
      percClarissa: (Number(percCla) || 0) / 100,
      percVivian: (Number(percViv) || 0) / 100,
    });
  }, [valorTotal, parceiroId, percParc, percEsc, percCla, percViv]);

  const somaSocios =
    (Number(percEsc) || 0) + (Number(percCla) || 0) + (Number(percViv) || 0);

  function onSubmit(values: SucumbenciaCreateInput) {
    startTransition(async () => {
      const result =
        modo === "criar"
          ? await criarSucumbencia(values)
          : await atualizarSucumbencia({ id: sucumbenciaId ?? "", ...values });

      if (!result.ok) {
        toast.error(result.error);
        if (result.fieldErrors) {
          for (const [field, msgs] of Object.entries(result.fieldErrors)) {
            const msg = msgs?.[0];
            if (msg) form.setError(field as keyof SucumbenciaCreateInput, { message: msg });
          }
        }
        return;
      }

      toast.success(modo === "criar" ? "Sucumbência cadastrada" : "Sucumbência atualizada");
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
            name="dataRecebimento"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Data do recebimento *</FormLabel>
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
                <FormLabel>Valor bruto (R$) *</FormLabel>
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

        <div className="rounded-md border bg-card/50 p-3">
          <div className="mb-2 text-xs font-medium text-muted-foreground">
            Parceiro externo (opcional — sai por cima do bruto)
          </div>
          <div className="grid gap-3 sm:grid-cols-2">
            <FormField
              control={form.control}
              name="parceiroExternoId"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Parceiro externo</FormLabel>
                  <div className="flex items-center gap-1">
                    <Select
                      value={field.value ?? ""}
                      onValueChange={(v) => field.onChange(v || undefined)}
                    >
                      <FormControl>
                        <SelectTrigger>
                          <SelectValue placeholder="Nenhum" />
                        </SelectTrigger>
                      </FormControl>
                      <SelectContent>
                        {parceiros.map((p) => (
                          <SelectItem key={p.id} value={p.id}>
                            {p.nome}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                    {field.value && (
                      <Button
                        type="button"
                        variant="ghost"
                        size="icon"
                        onClick={() => {
                          field.onChange(undefined);
                          form.setValue("percParceiroExterno", undefined);
                        }}
                        title="Remover parceiro"
                      >
                        <X className="h-4 w-4" />
                      </Button>
                    )}
                  </div>
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="percParceiroExterno"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>% Parceiro externo</FormLabel>
                  <FormControl>
                    <Input
                      type="number"
                      step="0.01"
                      min="0"
                      max="100"
                      inputMode="decimal"
                      disabled={!parceiroId}
                      placeholder="ex.: 30"
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

        <div>
          <div className="mb-2 text-xs font-medium text-muted-foreground">
            Rateio entre sócias (deve somar 100%)
          </div>
          <div className="grid gap-3 sm:grid-cols-3">
            <FormField
              control={form.control}
              name="percEscritorio"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>% Escritório</FormLabel>
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
              name="percClarissa"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>% Clarissa</FormLabel>
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
              name="percVivian"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>% Vivian</FormLabel>
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
          {Math.abs(somaSocios - 100) > 0.01 && (
            <p className="mt-1 text-xs text-destructive">
              Soma atual: {somaSocios.toFixed(2)}% — deve ser exatamente 100%.
            </p>
          )}
        </div>

        <div className="rounded-md border bg-muted/30 p-3 text-sm">
          <div className="mb-1 text-xs font-medium text-muted-foreground">Preview do rateio</div>
          <div className="grid grid-cols-2 gap-x-4 gap-y-1 sm:grid-cols-4">
            {parceiroId && (
              <>
                <span className="text-muted-foreground">Parceiro externo</span>
                <span className="font-mono tabular-nums">{toBRL(calc.parceiroExterno)}</span>
              </>
            )}
            <span className="text-muted-foreground">Escritório</span>
            <span className="font-mono tabular-nums text-emerald-700">{toBRL(calc.escritorio)}</span>
            <span className="text-muted-foreground">Clarissa</span>
            <span className="font-mono tabular-nums">{toBRL(calc.clarissa)}</span>
            <span className="text-muted-foreground">Vivian</span>
            <span className="font-mono tabular-nums">{toBRL(calc.vivian)}</span>
          </div>
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
