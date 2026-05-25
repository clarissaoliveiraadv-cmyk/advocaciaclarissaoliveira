"use client";

import { useMemo, useState } from "react";
import { Check, ChevronsUpDown, X } from "lucide-react";
import type { TipoCategoria } from "@prisma/client";

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
  /** Se fornecido, filtra só categorias deste tipo. */
  tipoFiltro?: TipoCategoria;
  allowClear?: boolean;
  value: string | undefined;
  onChange: (id: string | undefined) => void;
};

export function CategoriaCombobox({ categorias, tipoFiltro, allowClear, value, onChange }: Props) {
  const [open, setOpen] = useState(false);

  const elegiveis = useMemo(() => {
    return tipoFiltro ? categorias.filter((c) => c.tipo === tipoFiltro) : categorias;
  }, [categorias, tipoFiltro]);

  const selecionada = elegiveis.find((c) => c.id === value);
  const paiPorId = useMemo(() => new Map(categorias.map((c) => [c.id, c.nome])), [categorias]);

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
            {selecionada ? selecionada.nome : "Selecione uma categoria..."}
            <ChevronsUpDown className="ml-2 h-4 w-4 shrink-0 opacity-50" />
          </Button>
        </PopoverTrigger>
        <PopoverContent className="w-[var(--radix-popover-trigger-width)] p-0" align="start">
          <Command
            filter={(value, search) => {
              const c = elegiveis.find((c) => c.id === value);
              if (!c) return 0;
              const paiNome = c.categoriaPaiId ? (paiPorId.get(c.categoriaPaiId) ?? "") : "";
              const haystack = `${c.nome} ${paiNome}`.toLowerCase();
              return haystack.includes(search.toLowerCase()) ? 1 : 0;
            }}
          >
            <CommandInput placeholder="Buscar categoria..." />
            <CommandList>
              <CommandEmpty>Nenhuma categoria compatível.</CommandEmpty>
              <CommandGroup>
                {elegiveis.map((c) => (
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
                    <div className="flex flex-1 flex-col">
                      <span>{c.nome}</span>
                      <span className="text-xs text-muted-foreground">
                        {c.tipo === "RECEITA" ? "Receita" : "Despesa"}
                        {c.isPessoal ? " · Pessoal" : " · Escritório"}
                        {c.categoriaPaiId && ` · sob ${paiPorId.get(c.categoriaPaiId) ?? "—"}`}
                      </span>
                    </div>
                  </CommandItem>
                ))}
              </CommandGroup>
            </CommandList>
          </Command>
        </PopoverContent>
      </Popover>
      {allowClear && value && (
        <Button
          type="button"
          variant="ghost"
          size="icon"
          onClick={() => onChange(undefined)}
          title="Limpar"
        >
          <X className="h-4 w-4" />
        </Button>
      )}
    </div>
  );
}
