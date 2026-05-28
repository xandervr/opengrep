import { ImportedSpreadSource } from "./source";

export const importedSpreadProviders = [
  { provide: "source", useValue: new ImportedSpreadSource() },
];
