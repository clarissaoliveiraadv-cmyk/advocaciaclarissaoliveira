"use client";

import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { useTransition } from "react";
import { toast } from "sonner";
import { TipoLancamento } from "@prisma/client";

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

import { ClienteCombobox } from "./cliente-combobox";
import { ProcessoCombobox } from "./processo-combobox";
import { CategoriaCombobox } from "./categoria-combobox";
import { lancamentoCreateSchema, type LancamentoCreateInput } from "../schema";
import { atualizarLancamento, criarLancamento } from "../actions";
import type { CategoriaOpcao, ClienteOpcao, ContaOpcao, ProcessoOpcao } from "../queries";

type Props = {
  modo: "criar" | "editar";
  lancamentoId?: string;
  contas: ContaOpcao[];
  categorias: CategoriaOpcao[];
  clientes: ClienteOpcao[];
  processos: ProcessoOpcao[];
  initialValues?: Partial<LancamentoCreateInput>;
  onSucesso: () => void;
};

const VALORES_VAZIOS: LancamentoCreateInput = {
  data: new Date().toISOString().slice(0, 10),
  descricao: "",
  tipo: TipoLancamento.SAIDA,
  contaId: "",
  categoriaId: "",
  valor: 0,
  clienteId: undefined,
  processoId: undefined,
  comprovanteUrl: undefined,
  observacoes: undefined,
};

export function LancamentoForm({
  modo,
  lancamentoId,
  contas,
  categorias,
  clientes,
  processos,
  initialValues,
  onSucesso,
}: Props) {
  const [pending, startTransition] = useTransition();

  const form = useForm<LancamentoCreateInput>({
    resolver: zodResolver(lancamentoCreateSchema),
    defaultValues: { ...VALORES_VAZIOS, ...initialValues },
  });

  const tipoSelecionado = form.watch("tipo");
  const clienteSelecionado = form.watch("clienteId");
  const tipoCategoriaFiltro = tipoSelecionado === "ENTRADA" ? "RECEITA" : "DESPESA";

  function onSubmit(values: LancamentoCreateInput) {
    startTransition(async () => {
      const result =
        modo === "criar"
          ? await criarLancamento(values)
          : await atualizarLancamento({ id: lancamentoId ?? "", ...values });

      if (!result.ok) {
        toast.error(result.error);
        if (result.fieldErrors) {
          for (const [field, msgs] of Object.entries(result.fieldErrors)) {
            const msg = msgs?.[0];
            if (msg) form.setError(field as keyof LancamentoCreateInput, { message: msg });
          }
        }
        return;
      }

      toast.success(modo === "criar" ? "Lançamento criado" : "Lançamento atualizado");
      onSucesso();
    });
  }

  return (
    <Form {...form}>
      <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
        <div className="grid gap-4 sm:grid-cols-2">
          <FormField
            control={form.control}
            name="tipo"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Tipo</FormLabel>
                <Select
                  value={field.value}
                  onValueChange={(v) => {
                    field.onChange(v);
                    form.setValue("categoriaId", "");
                  }}
                >
                  <FormControl>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                  </FormControl>
                  <SelectContent>
                    <SelectItem value={TipoLancamento.ENTRADA}>Entrada</SelectItem>
                    <SelectItem value={TipoLancamento.SAIDA}>Saída</SelectItem>
                  </SelectContent>
                </Select>
                <FormMessage />
              </FormItem>
            )}
          />

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
        </div>

        <FormField
          control={form.control}
          name="descricao"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Descrição *</FormLabel>
              <FormControl>
                <Input placeholder="Ex.: Honorário recebido — Cliente X" {...field} />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />

        <div className="grid gap-4 sm:grid-cols-2">
          <FormField
            control={form.control}
            name="contaId"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Conta *</FormLabel>
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
          name="categoriaId"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Categoria *</FormLabel>
              <FormControl>
                <CategoriaCombobox
                  categorias={categorias}
                  tipoFiltro={tipoCategoriaFiltro}
                  value={field.value}
                  onChange={(v) => field.onChange(v ?? "")}
                />
              </FormControl>
              <p className="text-xs text-muted-foreground">
                Filtrada por {tipoSelecionado === "ENTRADA" ? "Receita" : "Despesa"} conforme o tipo
                do lançamento.
              </p>
              <FormMessage />
            </FormItem>
          )}
        />

        <div className="grid gap-4 sm:grid-cols-2">
          <FormField
            control={form.control}
            name="clienteId"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Cliente (opcional)</FormLabel>
                <FormControl>
                  <ClienteCombobox
                    clientes={clientes}
                    value={field.value}
                    onChange={(v) => {
                      field.onChange(v);
                      // se cliente mudou, processo pode não pertencer mais
                      form.setValue("processoId", undefined);
                    }}
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
                <FormLabel>Processo (opcional)</FormLabel>
                <FormControl>
                  <ProcessoCombobox
                    processos={processos}
                    clienteId={clienteSelecionado || undefined}
                    value={field.value}
                    onChange={field.onChange}
                  />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
        </div>

        <FormField
          control={form.control}
          name="comprovanteUrl"
          render={({ field }) => (
            <FormItem>
              <FormLabel>URL do comprovante (opcional)</FormLabel>
              <FormControl>
                <Input type="url" placeholder="https://..." {...field} value={field.value ?? ""} />
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
            {pending ? "Salvando..." : modo === "criar" ? "Cadastrar" : "Salvar alterações"}
          </Button>
        </div>
      </form>
    </Form>
  );
}
