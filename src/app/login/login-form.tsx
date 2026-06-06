"use client";

import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { useTransition } from "react";

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

import { loginSchema, type LoginInput } from "./schema";
import { loginAction } from "./actions";

export function LoginForm({ erro }: { erro: boolean }) {
  const [pending, startTransition] = useTransition();
  const form = useForm<LoginInput>({
    resolver: zodResolver(loginSchema),
    defaultValues: { email: "", senha: "" },
  });

  function onSubmit(values: LoginInput) {
    const fd = new FormData();
    fd.set("email", values.email);
    fd.set("senha", values.senha);
    startTransition(async () => {
      await loginAction(fd);
    });
  }

  return (
    <Form {...form}>
      <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
        <FormField
          control={form.control}
          name="email"
          render={({ field }) => (
            <FormItem>
              <FormLabel>E-mail</FormLabel>
              <FormControl>
                <Input type="email" autoComplete="email" {...field} />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />
        <FormField
          control={form.control}
          name="senha"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Senha</FormLabel>
              <FormControl>
                <Input type="password" autoComplete="current-password" {...field} />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />
        {erro && (
          <p className="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">
            E-mail ou senha inválidos.
          </p>
        )}
        <Button type="submit" className="w-full" disabled={pending}>
          {pending ? "Entrando..." : "Entrar"}
        </Button>
      </form>
    </Form>
  );
}
