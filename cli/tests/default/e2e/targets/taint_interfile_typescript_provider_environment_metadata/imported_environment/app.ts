import { importedEnvironmentProviders } from "./providers";

function bootstrapApplication(_target: unknown, _metadata: unknown): void {}

function Inject(_key: string): ParameterDecorator {
  return () => {};
}

class ImportedEnvironmentApp {
  constructor(@Inject("source") source) {
    sink(source.getInput());
  }
}

bootstrapApplication(ImportedEnvironmentApp, {
  providers: [importedEnvironmentProviders],
});

new ImportedEnvironmentApp();
