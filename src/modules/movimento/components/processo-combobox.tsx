"use client";

import { useMemo, useState } from "react";
import { Check, ChevronsUpDown, X } from "lucide-react";

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
  clienteId?: string;
  value: string | undefined;
  onChange: (id: string | undefined) => void;
};

export function ProcessoCombobox({ processos, clienteId, value, onChange }: Props) {
  const [open, setOpen] = useState(false);

  const elegiveis = useMemo(() => {
    if (!clienteId) return processos;
    return processos.filter((p) => p.clienteId === clienteId);
  }, [processos, clienteId]);

  const selecionado = elegiveis.find((p) => p.id === value);

  return (
    <div className="flex items-center gap-1">
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
              ? selecionado.numeroCnj
                ? formatCnj(selecionado.numeroCnj)
                : `${selecionado.cliente.nome} (sem CNJ)`
              : "Sem processo"}
            <ChevronsUpDown className="ml-2 h-4 w-4 shrink-0 opacity-50" />
          </Button>
        </PopoverTrigger>
        <PopoverContent className="w-[var(--radix-popover-trigger-width)] p-0" align="start">
          <Command
            filter={(value, search) => {
              const proc = elegiveis.find((p) => p.id === value);
              if (!proc) return 0;
              const haystack = `${proc.cliente.nome} ${proc.numeroCnj ?? ""}`.toLowerCase();
              return haystack.includes(search.toLowerCase()) ? 1 : 0;
            }}
          >
            <CommandInput placeholder="Buscar processo..." />
            <CommandList>
              <CommandEmpty>
                {clienteId ? "Cliente sem processos cadastrados." : "Nenhum processo encontrado."}
              </CommandEmpty>
              <CommandGroup>
                {elegiveis.map((p) => (
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
                      <span className="font-mono text-xs text-muted-foreground">
                        {p.numeroCnj ? formatCnj(p.numeroCnj) : "— sem CNJ —"}
                      </span>
                      <span className="text-sm">{p.cliente.nome}</span>
                    </div>
                  </CommandItem>
                ))}
              </CommandGroup>
            </CommandList>
          </Command>
        </PopoverContent>
      </Popover>
      {value && (
        <Button
          type="button"
          variant="ghost"
          size="icon"
          onClick={() => onChange(undefined)}
          title="Remover processo"
        >
          <X className="h-4 w-4" />
        </Button>
      )}
    </div>
  );
}
