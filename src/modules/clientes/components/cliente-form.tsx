"use client";

import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { useTransition } from "react";
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

import { clienteCreateSchema, type ClienteCreateInput } from "../schema";
import { atualizarCliente, criarCliente } from "../actions";

type Props = {
  modo: "criar" | "editar";
  clienteId?: string;
  initialValues?: Partial<ClienteCreateInput>;
  onSucesso: () => void;
};

const VALORES_VAZIOS: ClienteCreateInput = {
  nome: "",
  cpfCnpj: undefined,
  email: undefined,
  telefone: undefined,
  observacoes: undefined,
};

export function ClienteForm({ modo, clienteId, initialValues, onSucesso }: Props) {
  const [pending, startTransition] = useTransition();

  const form = useForm<ClienteCreateInput>({
    resolver: zodResolver(clienteCreateSchema),
    defaultValues: { ...VALORES_VAZIOS, ...initialValues },
  });

  function onSubmit(values: ClienteCreateInput) {
    startTransition(async () => {
      const result =
        modo === "criar"
          ? await criarCliente(values)
          : await atualizarCliente({ id: clienteId ?? "", ...values });

      if (!result.ok) {
        toast.error(result.error);
        if (result.fieldErrors) {
          for (const [field, msgs] of Object.entries(result.fieldErrors)) {
            const msg = msgs?.[0];
            if (msg) form.setError(field as keyof ClienteCreateInput, { message: msg });
          }
        }
        return;
      }

      toast.success(modo === "criar" ? "Cliente cadastrado" : "Cliente atualizado");
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
                <Input autoComplete="off" {...field} />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />

        <div className="grid gap-4 sm:grid-cols-2">
          <FormField
            control={form.control}
            name="cpfCnpj"
            render={({ field }) => (
              <FormItem>
                <FormLabel>CPF / CNPJ</FormLabel>
                <FormControl>
                  <Input placeholder="000.000.000-00" {...field} value={field.value ?? ""} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
          <FormField
            control={form.control}
            name="telefone"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Telefone</FormLabel>
                <FormControl>
                  <Input placeholder="(11) 98765-4321" {...field} value={field.value ?? ""} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
        </div>

        <FormField
          control={form.control}
          name="email"
          render={({ field }) => (
            <FormItem>
              <FormLabel>E-mail</FormLabel>
              <FormControl>
                <Input type="email" {...field} value={field.value ?? ""} />
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
