import { ImportedAliasToken, importedForwardAliasProviders } from "./providers";

function bootstrapApplication(_target: unknown, _metadata: unknown): void {}

function Inject(_key: unknown): ParameterDecorator {
  return () => {};
}

class ImportedAliasApp {
  constructor(@Inject(ImportedAliasToken) source) {
    sink(source.getInput());
  }
}

bootstrapApplication(ImportedAliasApp, {
  providers: importedForwardAliasProviders,
});

new ImportedAliasApp();
