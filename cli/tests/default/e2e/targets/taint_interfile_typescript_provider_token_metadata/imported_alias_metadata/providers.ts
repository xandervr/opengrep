import { ImportedAliasToken, ImportedAliasTokenImpl } from "./source";

export const importedTokenProviders = [
  { provide: ImportedAliasToken, useClass: ImportedAliasTokenImpl },
];
