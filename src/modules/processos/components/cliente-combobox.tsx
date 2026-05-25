"use client";

import { useState } from "react";
import { Check, ChevronsUpDown } from "lucide-react";

import { Button } from "@/components/ui/button";
import {
  Command,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from "@/components/ui/command";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { cn } from "@/lib/utils";
import { formatCpfCnpj } from "@/lib/format";

export type ClienteOpcao = { id: string; nome: string; cpfCnpj: string | null };

type Props = {
  clientes: ClienteOpcao[];
  value: string;
  onChange: (id: string) => void;
};

export function ClienteCombobox({ clientes, value, onChange }: Props) {
  const [open, setOpen] = useState(false);
  const selecionado = clientes.find((c) => c.id === value);

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button
          type="button"
          variant="outline"
          role="combobox"
          aria-expanded={open}
          className={cn(
            "w-full justify-between font-normal",
            !selecionado && "text-muted-foreground",
          )}
        >
          {selecionado ? selecionado.nome : "Selecione um cliente..."}
          <ChevronsUpDown className="ml-2 h-4 w-4 shrink-0 opacity-50" />
        </Button>
      </PopoverTrigger>
      <PopoverContent className="w-[var(--radix-popover-trigger-width)] p-0" align="start">
        <Command
          filter={(value, search) => {
            const cliente = clientes.find((c) => c.id === value);
            if (!cliente) return 0;
            const haystack = `${cliente.nome} ${cliente.cpfCnpj ?? ""}`.toLowerCase();
            return haystack.includes(search.toLowerCase()) ? 1 : 0;
          }}
        >
          <CommandInput placeholder="Buscar por nome ou CPF/CNPJ..." />
          <CommandList>
            <CommandEmpty>Nenhum cliente encontrado.</CommandEmpty>
            <CommandGroup>
              {clientes.map((c) => (
                <CommandItem
                  key={c.id}
                  value={c.id}
                  onSelect={() => {
                    onChange(c.id);
                    setOpen(false);
                  }}
                >
                  <Check
                    className={cn("mr-2 h-4 w-4", c.id === value ? "opacity-100" : "opacity-0")}
                  />
                  <div className="flex flex-1 items-center justify-between gap-2">
                    <span>{c.nome}</span>
                    {c.cpfCnpj && (
                      <span className="font-mono text-xs text-muted-foreground">
                        {formatCpfCnpj(c.cpfCnpj)}
                      </span>
                    )}
                  </div>
                </CommandItem>
              ))}
            </CommandGroup>
          </CommandList>
        </Command>
      </PopoverContent>
    </Popover>
  );
}
