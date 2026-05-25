"use client";

import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { useTransition } from "react";
import { toast } from "sonner";
import { NaturezaProcesso, StatusProcesso } from "@prisma/client";

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
  NATUREZA_LABELS,
  STATUS_LABELS,
  processoCreateSchema,
  type ProcessoCreateInput,
} from "../schema";
import { atualizarProcesso, criarProcesso } from "../actions";
import { ClienteCombobox, type ClienteOpcao } from "./cliente-combobox";

type Props = {
  modo: "criar" | "editar";
  processoId?: string;
  clientes: ClienteOpcao[];
  initialValues?: Partial<ProcessoCreateInput>;
  onSucesso: () => void;
};

const VALORES_VAZIOS: ProcessoCreateInput = {
  clienteId: "",
  numeroCnj: undefined,
  natureza: NaturezaProcesso.OUTRO,
  vara: undefined,
  tribunal: undefined,
  parteContraria: undefined,
  status: StatusProcesso.EM_ANDAMENTO,
  observacoes: undefined,
};

export function ProcessoForm({ modo, processoId, clientes, initialValues, onSucesso }: Props) {
  const [pending, startTransition] = useTransition();

  const form = useForm<ProcessoCreateInput>({
    resolver: zodResolver(processoCreateSchema),
    defaultValues: { ...VALORES_VAZIOS, ...initialValues },
  });

  function onSubmit(values: ProcessoCreateInput) {
    startTransition(async () => {
      const result =
        modo === "criar"
          ? await criarProcesso(values)
          : await atualizarProcesso({ id: processoId ?? "", ...values });

      if (!result.ok) {
        toast.error(result.error);
        if (result.fieldErrors) {
          for (const [field, msgs] of Object.entries(result.fieldErrors)) {
            const msg = msgs?.[0];
            if (msg) form.setError(field as keyof ProcessoCreateInput, { message: msg });
          }
        }
        return;
      }

      toast.success(modo === "criar" ? "Processo cadastrado" : "Processo atualizado");
      onSucesso();
    });
  }

  return (
    <Form {...form}>
      <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
        <FormField
          control={form.control}
          name="clienteId"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Cliente *</FormLabel>
              <FormControl>
                <ClienteCombobox
                  clientes={clientes}
                  value={field.value}
                  onChange={field.onChange}
                />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />

        <FormField
          control={form.control}
          name="numeroCnj"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Número CNJ</FormLabel>
              <FormControl>
                <Input
                  placeholder="0000000-00.0000.0.00.0000 (opcional)"
                  {...field}
                  value={field.value ?? ""}
                />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />

        <div className="grid gap-4 sm:grid-cols-2">
          <FormField
            control={form.control}
            name="natureza"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Natureza</FormLabel>
                <Select value={field.value} onValueChange={field.onChange}>
                  <FormControl>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                  </FormControl>
                  <SelectContent>
                    {Object.entries(NATUREZA_LABELS).map(([value, label]) => (
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
            name="status"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Status</FormLabel>
                <Select value={field.value} onValueChange={field.onChange}>
                  <FormControl>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                  </FormControl>
                  <SelectContent>
                    {Object.entries(STATUS_LABELS).map(([value, label]) => (
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

        <div className="grid gap-4 sm:grid-cols-2">
          <FormField
            control={form.control}
            name="vara"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Vara / Órgão</FormLabel>
                <FormControl>
                  <Input {...field} value={field.value ?? ""} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
          <FormField
            control={form.control}
            name="tribunal"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Tribunal</FormLabel>
                <FormControl>
                  <Input placeholder="ex.: TJSP, TRT-2" {...field} value={field.value ?? ""} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
        </div>

        <FormField
          control={form.control}
          name="parteContraria"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Parte contrária</FormLabel>
              <FormControl>
                <Input {...field} value={field.value ?? ""} />
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
                <Textarea rows={3} {...field} value={field.value ?? ""} />
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
