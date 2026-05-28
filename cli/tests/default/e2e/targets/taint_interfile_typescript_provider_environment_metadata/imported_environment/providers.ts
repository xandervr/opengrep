import { ImportedEnvironmentSource } from "./source";

function makeEnvironmentProviders(_providers: unknown[]): unknown {
  return _providers;
}

export const importedEnvironmentProviders = makeEnvironmentProviders([
  { provide: "source", useValue: new ImportedEnvironmentSource() },
]);
