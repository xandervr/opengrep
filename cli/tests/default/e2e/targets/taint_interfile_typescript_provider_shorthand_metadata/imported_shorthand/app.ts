import { importedShorthandProviders } from "./providers";
import { ImportedShorthandSource } from "./source";

function Module(_metadata: unknown): ClassDecorator {
  return () => {};
}

function Inject(_key: unknown): ParameterDecorator {
  return () => {};
}

@Module({ providers: importedShorthandProviders })
class ImportedShorthandModule {}

class ImportedShorthandApp {
  constructor(@Inject(ImportedShorthandSource) source) {
    sink(source.getInput());
  }
}

new ImportedShorthandApp();
