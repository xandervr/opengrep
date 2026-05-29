import { importedSpreadProviders } from "./providers";

function Module(_metadata: unknown): ClassDecorator {
  return () => {};
}

function Inject(_key: string): ParameterDecorator {
  return () => {};
}

@Module({ providers: [...importedSpreadProviders] })
class ImportedSpreadModule {}

class ImportedSpreadApp {
  constructor(@Inject("source") source) {
    sink(source.getInput());
  }
}

new ImportedSpreadApp();
