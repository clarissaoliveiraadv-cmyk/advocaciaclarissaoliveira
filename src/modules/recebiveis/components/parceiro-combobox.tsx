"use client";

import { useState } from "react";
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
import type { ParceiroOpcao } from "../queries";

type Props = {
  parceiros: ParceiroOpcao[];
  value: string | undefined;
  onChange: (id: string | undefined) => void;
};

const LABEL_TIPO: Record<ParceiroOpcao["tipo"], string> = {
  PARCEIRO_EXTERNO: "Externo",
  FUNCIONARIO: "Funcionário",
};

export function ParceiroCombobox({ parceiros, value, onChange }: Props) {
  const [open, setOpen] = useState(false);
  const selecionado = parceiros.find((p) => p.id === value);

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
            {selecionado ? selecionado.nome : "Sem parceiro"}
            <ChevronsUpDown className="ml-2 h-4 w-4 shrink-0 opacity-50" />
          </Button>
        </PopoverTrigger>
        <PopoverContent className="w-[var(--radix-popover-trigger-width)] p-0" align="start">
          <Command>
            <CommandInput placeholder="Buscar parceiro..." />
            <CommandList>
              <CommandEmpty>Nenhum parceiro.</CommandEmpty>
              <CommandGroup>
                {parceiros.map((p) => (
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
                    <div className="flex flex-1 items-center justify-between">
                      <span>{p.nome}</span>
                      <span className="text-xs text-muted-foreground">{LABEL_TIPO[p.tipo]}</span>
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
          title="Remover parceiro"
        >
          <X className="h-4 w-4" />
        </Button>
      )}
    </div>
  );
}
