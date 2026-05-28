import { ImportedConstantSource } from "./source";

export const importedProviders = [
  { provide: "source", useFactory: () => new ImportedConstantSource() },
];
