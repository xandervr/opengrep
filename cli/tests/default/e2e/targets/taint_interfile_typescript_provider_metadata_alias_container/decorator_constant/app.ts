import { DecoratorConstantSource } from "./source";

function Module(_metadata: unknown): ClassDecorator {
  return () => {};
}

function Inject(_key: string): ParameterDecorator {
  return () => {};
}

const decoratorProviders = [
  { provide: "source", useClass: DecoratorConstantSource },
];

@Module({ providers: decoratorProviders })
class DecoratorConstantModule {}

class DecoratorConstantApp {
  constructor(@Inject("source") source) {
    sink(source.getInput());
  }
}

new DecoratorConstantApp();
