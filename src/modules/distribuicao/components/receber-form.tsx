"use client";

import { useForm, useFieldArray } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { useRouter } from "next/navigation";
import { useTransition } from "react";
import { toast } from "sonner";
import { Plus } from "lucide-react";
import { TipoBeneficiario } from "@prisma/client";

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

import {
  confirmarDistribuicaoSchema,
  type ConfirmarDistribuicaoInput,
  type ItemInput,
} from "../schema";
import { confirmarDistribuicao } from "../actions";
import type { CategoriaReceitaOpcao, ContaOpcao, ParceiroOpcao } from "../queries";
import { ItemDistribuicaoRow } from "./item-distribuicao-row";
import { ResumoDistribuicao } from "./resumo-distribuicao";

type Props = {
  recebivelId: string;
  recebivelDescricao: string;
  clienteDoProcesso: { id: string; nome: string };
  contas: ContaOpcao[];
  categoriasReceita: CategoriaReceitaOpcao[];
  parceiros: ParceiroOpcao[];
  defaultCategoriaId: string | null;
  defaultValorBruto: number;
  itensSugeridos: ItemInput[];
};

export function ReceberForm({
  recebivelId,
  recebivelDescricao,
  clienteDoProcesso,
  contas,
  categoriasReceita,
  parceiros,
  defaultCategoriaId,
  defaultValorBruto,
  itensSugeridos,
}: Props) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();

  const form = useForm<ConfirmarDistribuicaoInput>({
    resolver: zodResolver(confirmarDistribuicaoSchema),
    defaultValues: {
      recebivelId,
      dataRecebimento: new Date().toISOString().slice(0, 10),
      contaRecebimentoId: contas[0]?.id ?? "",
      categoriaLancamentoId: defaultCategoriaId ?? categoriasReceita[0]?.id ?? "",
      valorBrutoRecebido: defaultValorBruto,
      descricaoLancamento: recebivelDescricao,
      observacoesDistribuicao: undefined,
      itens: itensSugeridos,
    },
  });

  const { fields, append, remove } = useFieldArray({ control: form.control, name: "itens" });

  const itensWatch = form.watch("itens");
  const valorBruto = form.watch("valorBrutoRecebido");
  const soma = itensWatch.reduce((acc, i) => acc + (Number(i.valor) || 0), 0);

  function onSubmit(values: ConfirmarDistribuicaoInput) {
    startTransition(async () => {
      const result = await confirmarDistribuicao(values);
      if (!result.ok) {
        toast.error(result.error);
        return;
      }
      toast.success("Distribuição confirmada e lançamento gerado");
      router.push("/recebiveis");
      router.refresh();
    });
  }

  function adicionarItem() {
    append({
      beneficiario: TipoBeneficiario.OUTRO,
      descricao: "",
      valor: 0,
      clienteId: undefined,
      parceiroId: undefined,
      observacoes: undefined,
    });
  }

  const erroItensGeral = form.formState.errors.itens?.root?.message;

  return (
    <Form {...form}>
      <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-6">
        <section className="space-y-4 rounded-md border bg-card p-4">
          <h2 className="text-sm font-semibold uppercase tracking-wide text-muted-foreground">
            Recebimento
          </h2>
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
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
              name="valorBrutoRecebido"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Valor bruto recebido (R$) *</FormLabel>
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
              name="contaRecebimentoId"
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
              name="categoriaLancamentoId"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Categoria (receita) *</FormLabel>
                  <Select value={field.value} onValueChange={field.onChange}>
                    <FormControl>
                      <SelectTrigger>
                        <SelectValue placeholder="Selecione" />
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
                <FormLabel>Descrição do lançamento</FormLabel>
                <FormControl>
                  <Input {...field} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
        </section>

        <section className="space-y-3">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold uppercase tracking-wide text-muted-foreground">
              Distribuição entre beneficiários
            </h2>
            <Button type="button" variant="outline" size="sm" onClick={adicionarItem}>
              <Plus className="mr-1 h-4 w-4" />
              Adicionar item
            </Button>
          </div>
          <ResumoDistribuicao valorBruto={Number(valorBruto) || 0} soma={soma} />
          {erroItensGeral && <p className="text-sm text-destructive">{erroItensGeral}</p>}
          <div className="space-y-2">
            {fields.map((field, index) => (
              <ItemDistribuicaoRow
                key={field.id}
                form={form}
                index={index}
                parceiros={parceiros}
                clienteDoProcesso={clienteDoProcesso}
                onRemove={() => remove(index)}
              />
            ))}
            {fields.length === 0 && (
              <div className="rounded-md border border-dashed p-6 text-center text-sm text-muted-foreground">
                Adicione pelo menos um item para confirmar a distribuição.
              </div>
            )}
          </div>
        </section>

        <FormField
          control={form.control}
          name="observacoesDistribuicao"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Observações da distribuição</FormLabel>
              <FormControl>
                <Textarea rows={2} {...field} value={field.value ?? ""} />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />

        <div className="flex items-center justify-end gap-2 pt-2">
          <Button type="button" variant="outline" onClick={() => router.push("/recebiveis")}>
            Cancelar
          </Button>
          <Button type="submit" disabled={pending}>
            {pending ? "Confirmando..." : "Confirmar distribuição e gerar lançamento"}
          </Button>
        </div>
      </form>
    </Form>
  );
}
