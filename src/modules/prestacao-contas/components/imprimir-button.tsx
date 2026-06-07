"use client";

import { Printer } from "lucide-react";
import { Button } from "@/components/ui/button";

export function ImprimirButton() {
  return (
    <Button onClick={() => window.print()} className="print:hidden">
      <Printer className="mr-2 h-4 w-4" />
      Imprimir / Salvar PDF
    </Button>
  );
}
