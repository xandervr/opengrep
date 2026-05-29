import { ImportedNestedSource } from "./source";

export const importedNestedProviders = [
  [{ provide: "source", useValue: new ImportedNestedSource() }],
];
