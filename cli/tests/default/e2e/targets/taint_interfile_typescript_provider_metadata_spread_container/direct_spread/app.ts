import { DirectSpreadSource } from "./source";

function Module(_metadata: unknown): ClassDecorator {
  return () => {};
}

function Inject(_key: string): ParameterDecorator {
  return () => {};
}

const directProviders = [
  { provide: "source", useClass: DirectSpreadSource },
];

@Module({ providers: [...directProviders] })
class DirectSpreadModule {}

class DirectSpreadApp {
  constructor(@Inject("source") source) {
    sink(source.getInput());
  }
}

new DirectSpreadApp();
