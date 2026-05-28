import { ImportedMultiSource } from "./source";

export const importedMultiProviders = [
  { provide: "sources", useClass: ImportedMultiSource, multi: true },
];
