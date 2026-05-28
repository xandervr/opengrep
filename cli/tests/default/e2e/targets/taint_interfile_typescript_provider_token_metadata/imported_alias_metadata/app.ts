import { importedTokenProviders } from "./providers";
import { ImportedAliasToken } from "./source";

function Injectable(): ClassDecorator {
  return () => {};
}

function Module(_metadata: unknown): ClassDecorator {
  return () => {};
}

@Module({ providers: importedTokenProviders })
class ImportedAliasTokenModule {}

@Injectable()
class ImportedAliasTokenApp {
  constructor(source: ImportedAliasToken) {
    sink(source.getInput());
  }
}

new ImportedAliasTokenApp();
