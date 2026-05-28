import { ProviderForwardRefSource } from "./source";

function Module(_metadata: unknown): ClassDecorator {
  return () => {};
}

function Inject(_key: unknown): ParameterDecorator {
  return () => {};
}

function forwardRef(_factory: unknown): unknown {
  return {};
}

@Module({ providers: [forwardRef(() => ProviderForwardRefSource)] })
class ProviderForwardRefModule {}

class ProviderForwardRefApp {
  constructor(@Inject(ProviderForwardRefSource) source) {
    sink(source.getInput());
  }
}

new ProviderForwardRefApp();
