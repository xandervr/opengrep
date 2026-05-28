import { importedNestedProviders } from "./providers";

function Module(_metadata: unknown): ClassDecorator {
  return () => {};
}

function Inject(_key: string): ParameterDecorator {
  return () => {};
}

@Module({ providers: importedNestedProviders })
class ImportedNestedModule {}

class ImportedNestedApp {
  constructor(@Inject("source") source) {
    sink(source.getInput());
  }
}

new ImportedNestedApp();
