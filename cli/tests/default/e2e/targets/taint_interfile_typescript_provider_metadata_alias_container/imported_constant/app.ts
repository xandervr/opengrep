import { importedProviders } from "./providers";

function Module(_metadata: unknown): ClassDecorator {
  return () => {};
}

function Inject(_key: string): ParameterDecorator {
  return () => {};
}

@Module({ providers: importedProviders })
class ImportedConstantModule {}

class ImportedConstantApp {
  constructor(@Inject("source") source) {
    sink(source.getInput());
  }
}

new ImportedConstantApp();
