import { AliasToken, AliasTokenImpl } from "./source";

function Injectable(): ClassDecorator {
  return () => {};
}

function Module(_metadata: unknown): ClassDecorator {
  return () => {};
}

const aliasProviders = [{ provide: AliasToken, useClass: AliasTokenImpl }];

@Module({ providers: aliasProviders })
class AliasTokenModule {}

@Injectable()
class AliasTokenApp {
  constructor(source: AliasToken) {
    sink(source.getInput());
  }
}

new AliasTokenApp();
