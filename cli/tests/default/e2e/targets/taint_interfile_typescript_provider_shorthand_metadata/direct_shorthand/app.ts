import { DirectShorthandSource } from "./source";

function Module(_metadata: unknown): ClassDecorator {
  return () => {};
}

function Inject(_key: unknown): ParameterDecorator {
  return () => {};
}

@Module({ providers: [DirectShorthandSource] })
class DirectShorthandModule {}

class DirectShorthandApp {
  constructor(@Inject(DirectShorthandSource) source) {
    sink(source.getInput());
  }
}

new DirectShorthandApp();
