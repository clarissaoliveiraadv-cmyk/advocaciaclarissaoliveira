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
import type { CategoriaOpcao } from "../queries";

type Props = {
  categorias: CategoriaOpcao[];
  tipoSelecionado: CategoriaOpcao["tipo"];
  isPessoalSelecionado: boolean;
  excludeId?: string;
  value: string | undefined;
  onChange: (id: string | undefined) => void;
};

export function CategoriaPaiCombobox({
  categorias,
  tipoSelecionado,
  isPessoalSelecionado,
  excludeId,
  value,
  onChange,
}: Props) {
  const [open, setOpen] = useState(false);

  const elegiveis = useMemo(() => {
    const descendentes = excludeId ? coletarDescendentes(excludeId, categorias) : new Set<string>();
    return categorias.filter(
      (c) =>
        c.tipo === tipoSelecionado &&
        c.isPessoal === isPessoalSelecionado &&
        c.id !== excludeId &&
        !descendentes.has(c.id),
    );
  }, [categorias, tipoSelecionado, isPessoalSelecionado, excludeId]);

  const selecionada = elegiveis.find((c) => c.id === value);

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
              !selecionada && "text-muted-foreground",
            )}
          >
            {selecionada ? selecionada.nome : "Sem pai (categoria raiz)"}
            <ChevronsUpDown className="ml-2 h-4 w-4 shrink-0 opacity-50" />
          </Button>
        </PopoverTrigger>
        <PopoverContent className="w-[var(--radix-popover-trigger-width)] p-0" align="start">
          <Command>
            <CommandInput placeholder="Buscar categoria..." />
            <CommandList>
              <CommandEmpty>Nenhuma categoria compatível.</CommandEmpty>
              <CommandGroup>
                {elegiveis.map((c) => (
                  <CommandItem
                    key={c.id}
                    value={`${c.nome}__${c.id}`}
                    onSelect={() => {
                      onChange(c.id);
                      setOpen(false);
                    }}
                  >
                    <Check
                      className={cn("mr-2 h-4 w-4", c.id === value ? "opacity-100" : "opacity-0")}
                    />
                    {c.nome}
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
          title="Remover pai"
        >
          <X className="h-4 w-4" />
        </Button>
      )}
    </div>
  );
}

function coletarDescendentes(rootId: string, all: CategoriaOpcao[]): Set<string> {
  const out = new Set<string>();
  const fila = [rootId];
  while (fila.length > 0) {
    const cur = fila.shift();
    if (!cur) continue;
    for (const c of all) {
      if (c.categoriaPaiId === cur && !out.has(c.id)) {
        out.add(c.id);
        fila.push(c.id);
      }
    }
  }
  return out;
}
