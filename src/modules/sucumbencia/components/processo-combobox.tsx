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
import { formatCnj } from "@/lib/format";
import type { ProcessoOpcao } from "../queries";

type Props = {
  processos: ProcessoOpcao[];
  value: string | undefined;
  onChange: (id: string | undefined) => void;
};

export function ProcessoCombobox({ processos, value, onChange }: Props) {
  const [open, setOpen] = useState(false);
  const selecionado = processos.find((p) => p.id === value);

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
          {selecionado
            ? `${selecionado.cliente.nome}${selecionado.numeroCnj ? " · " + formatCnj(selecionado.numeroCnj) : ""}`
            : "Selecione um processo..."}
          <ChevronsUpDown className="ml-2 h-4 w-4 shrink-0 opacity-50" />
        </Button>
      </PopoverTrigger>
      <PopoverContent className="w-[var(--radix-popover-trigger-width)] p-0" align="start">
        <Command
          filter={(value, search) => {
            const p = processos.find((p) => p.id === value);
            if (!p) return 0;
            const haystack = `${p.cliente.nome} ${p.numeroCnj ?? ""}`.toLowerCase();
            return haystack.includes(search.toLowerCase()) ? 1 : 0;
          }}
        >
          <CommandInput placeholder="Buscar por cliente ou CNJ..." />
          <CommandList>
            <CommandEmpty>Nenhum processo encontrado.</CommandEmpty>
            <CommandGroup>
              {processos.map((p) => (
                <CommandItem
                  key={p.id}
                  value={p.id}
                  onSelect={() => {
                    onChange(p.id);
                    setOpen(false);
                  }}
                >
                  <Check
                    className={cn("mr-2 h-4 w-4", p.id === value ? "opacity-100" : "opacity-0")}
                  />
                  <div className="flex flex-1 flex-col">
                    <span className="text-sm">{p.cliente.nome}</span>
                    <span className="font-mono text-xs text-muted-foreground">
                      {p.numeroCnj ? formatCnj(p.numeroCnj) : "— sem CNJ —"}
                    </span>
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
