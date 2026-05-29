import { importedMultiProviders } from "./providers";

function Module(_metadata: unknown): ClassDecorator {
  return () => {};
}

function Inject(_key: string): ParameterDecorator {
  return () => {};
}

@Module({ providers: importedMultiProviders })
class ImportedMultiModule {}

class ImportedMultiApp {
  constructor(@Inject("sources") sources) {
    sink(sources[0].getInput());
  }
}

new ImportedMultiApp();
