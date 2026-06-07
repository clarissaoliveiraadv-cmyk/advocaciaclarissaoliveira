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
import type {
  CategoriaReceitaOpcao,
  ContaOpcao,
  ParceiroOpcao,
  ProcessoOpcao,
} from "../queries";

type Props = {
  modo: "criar" | "editar";
  sucumbenciaId?: string;
  processos: ProcessoOpcao[];
  parceiros: ParceiroOpcao[];
  contas: ContaOpcao[];
  categoriasReceita: CategoriaReceitaOpcao[];
  initialValues?: Partial<SucumbenciaCreateInput>;
  onSucesso: () => void;
};

const VALORES_VAZIOS: SucumbenciaCreateInput = {
  processoId: "",
  valorTotal: 0,
  dataRecebimento: new Date().toISOString().slice(0, 10),
  contaRecebimentoId: "",
  categoriaLancamentoId: "",
  descricaoLancamento: "",
  parceiroExternoId: undefined,
  percParceiroExterno: undefined,
  observacoes: undefined,
};

export function SucumbenciaForm({
  modo,
  sucumbenciaId,
  processos,
  parceiros,
  contas,
  categoriasReceita,
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

  const calc = useMemo(
    () =>
      calcularDistribuicaoSucumbencia({
        valorTotal: Number(valorTotal) || 0,
        percParceiroExterno: parceiroId && percParc ? (Number(percParc) || 0) / 100 : 0,
      }),
    [valorTotal, parceiroId, percParc],
  );

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

        <div className="grid gap-4 sm:grid-cols-2">
          <FormField
            control={form.control}
            name="contaRecebimentoId"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Conta de recebimento *</FormLabel>
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
          <FormField
            control={form.control}
            name="categoriaLancamentoId"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Categoria do lançamento *</FormLabel>
                <Select value={field.value} onValueChange={field.onChange}>
                  <FormControl>
                    <SelectTrigger>
                      <SelectValue placeholder="Selecione uma RECEITA..." />
                    </SelectTrigger>
                  </FormControl>
                  <SelectContent>
                    {categoriasReceita.map((c) => (
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
        </div>

        <FormField
          control={form.control}
          name="descricaoLancamento"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Descrição do lançamento *</FormLabel>
              <FormControl>
                <Input
                  placeholder="ex.: Honorários sucumbenciais — Pasta 981"
                  {...field}
                />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />

        <div className="rounded-md border bg-card/50 p-3">
          <div className="mb-2 text-xs font-medium text-muted-foreground">
            Parceiro externo (opcional — só se dividir com outro advogado)
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
                  <FormLabel>% do parceiro</FormLabel>
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

        <div className="rounded-md border bg-muted/30 p-3 text-sm">
          <div className="mb-1 text-xs font-medium text-muted-foreground">
            Preview — como entra no caixa
          </div>
          <div className="grid grid-cols-2 gap-x-4 gap-y-1 sm:grid-cols-4">
            <span className="text-muted-foreground">Bruto recebido</span>
            <span className="font-mono tabular-nums">{toBRL(Number(valorTotal) || 0)}</span>
            {parceiroId && (
              <>
                <span className="text-muted-foreground">Devido ao parceiro</span>
                <span className="font-mono tabular-nums text-amber-700">
                  {toBRL(calc.parceiroExterno)}
                </span>
              </>
            )}
            <span className="text-muted-foreground">Fica com o escritório</span>
            <span className="font-mono font-semibold tabular-nums text-emerald-700">
              {toBRL(calc.escritorio)}
            </span>
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
