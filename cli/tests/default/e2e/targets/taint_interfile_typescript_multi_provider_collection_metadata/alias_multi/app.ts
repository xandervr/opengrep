import { AliasMultiSource } from "./source";

function Module(_metadata: unknown): ClassDecorator {
  return () => {};
}

function Inject(_key: string): ParameterDecorator {
  return () => {};
}

const aliasMultiProviders = [
  { provide: "sources", useClass: AliasMultiSource, multi: true },
];

@Module({ providers: aliasMultiProviders })
class AliasMultiModule {}

class AliasMultiApp {
  constructor(@Inject("sources") sources) {
    sink(sources[0].getInput());
  }
}

new AliasMultiApp();
