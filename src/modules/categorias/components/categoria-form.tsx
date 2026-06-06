"use client";

import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { useTransition } from "react";
import { toast } from "sonner";
import { TipoCategoria } from "@prisma/client";

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

import { TIPO_CATEGORIA_LABELS, categoriaCreateSchema, type CategoriaCreateInput } from "../schema";
import { atualizarCategoria, criarCategoria } from "../actions";
import { CategoriaPaiCombobox } from "./categoria-pai-combobox";
import type { CategoriaOpcao } from "../queries";

type Props = {
  modo: "criar" | "editar";
  categoriaId?: string;
  categorias: CategoriaOpcao[];
  initialValues?: Partial<CategoriaCreateInput>;
  temFilhas?: boolean;
  onSucesso: () => void;
};

const VALORES_VAZIOS: CategoriaCreateInput = {
  nome: "",
  tipo: TipoCategoria.DESPESA,
  isPessoal: false,
  categoriaPaiId: undefined,
};

export function CategoriaForm({
  modo,
  categoriaId,
  categorias,
  initialValues,
  temFilhas,
  onSucesso,
}: Props) {
  const [pending, startTransition] = useTransition();

  const form = useForm<CategoriaCreateInput>({
    resolver: zodResolver(categoriaCreateSchema),
    defaultValues: { ...VALORES_VAZIOS, ...initialValues },
  });

  const tipoSelecionado = form.watch("tipo");
  const isPessoalSelecionado = form.watch("isPessoal");

  function onSubmit(values: CategoriaCreateInput) {
    startTransition(async () => {
      const result =
        modo === "criar"
          ? await criarCategoria(values)
          : await atualizarCategoria({ id: categoriaId ?? "", ...values });

      if (!result.ok) {
        toast.error(result.error);
        if (result.fieldErrors) {
          for (const [field, msgs] of Object.entries(result.fieldErrors)) {
            const msg = msgs?.[0];
            if (msg) form.setError(field as keyof CategoriaCreateInput, { message: msg });
          }
        }
        return;
      }

      toast.success(modo === "criar" ? "Categoria cadastrada" : "Categoria atualizada");
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
                <Input placeholder="Ex.: Honorário Contratual" autoComplete="off" {...field} />
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
                <Select
                  value={field.value}
                  onValueChange={(v) => {
                    field.onChange(v);
                    // ao trocar tipo, limpa pai (que pode não ser mais compatível)
                    form.setValue("categoriaPaiId", undefined);
                  }}
                  disabled={temFilhas}
                >
                  <FormControl>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                  </FormControl>
                  <SelectContent>
                    {Object.entries(TIPO_CATEGORIA_LABELS).map(([value, label]) => (
                      <SelectItem key={value} value={value}>
                        {label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                {temFilhas && (
                  <p className="text-xs text-muted-foreground">
                    Tipo travado: esta categoria tem subcategorias.
                  </p>
                )}
                <FormMessage />
              </FormItem>
            )}
          />

          <FormField
            control={form.control}
            name="isPessoal"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Escopo</FormLabel>
                <Select
                  value={field.value ? "pessoal" : "escritorio"}
                  onValueChange={(v) => {
                    field.onChange(v === "pessoal");
                    form.setValue("categoriaPaiId", undefined);
                  }}
                >
                  <FormControl>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                  </FormControl>
                  <SelectContent>
                    <SelectItem value="escritorio">Escritório</SelectItem>
                    <SelectItem value="pessoal">Pessoal (sócia)</SelectItem>
                  </SelectContent>
                </Select>
                <FormMessage />
              </FormItem>
            )}
          />
        </div>

        <FormField
          control={form.control}
          name="categoriaPaiId"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Categoria pai</FormLabel>
              <FormControl>
                <CategoriaPaiCombobox
                  categorias={categorias}
                  tipoSelecionado={tipoSelecionado}
                  isPessoalSelecionado={isPessoalSelecionado}
                  excludeId={categoriaId}
                  value={field.value}
                  onChange={field.onChange}
                />
              </FormControl>
              <p className="text-xs text-muted-foreground">
                Opcional. O pai precisa ter o mesmo tipo e escopo desta categoria.
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
