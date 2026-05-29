import { ImportedAliasSource } from "./source";

class ImportedSourceToken {}

export class ImportedAliasToken {}

function forwardRef(_factory: () => unknown): unknown {
  return _factory;
}

export const importedForwardAliasProviders = [
  {
    provide: ImportedAliasToken,
    useExisting: forwardRef(() => ImportedSourceToken),
  },
  { provide: ImportedSourceToken, useValue: new ImportedAliasSource() },
];
