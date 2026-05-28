import { InjectForwardRefSource } from "./source";

function Module(_metadata: unknown): ClassDecorator {
  return () => {};
}

function Inject(_key: unknown): ParameterDecorator {
  return () => {};
}

function forwardRef(_factory: unknown): unknown {
  return {};
}

@Module({ providers: [InjectForwardRefSource] })
class InjectForwardRefModule {}

class InjectForwardRefApp {
  constructor(@Inject(forwardRef(() => InjectForwardRefSource)) source) {
    sink(source.getInput());
  }
}

new InjectForwardRefApp();
