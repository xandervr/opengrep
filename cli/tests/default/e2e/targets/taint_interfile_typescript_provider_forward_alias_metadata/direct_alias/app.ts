import { DirectAliasSource } from "./source";

class DirectSourceToken {}

class DirectAliasToken {}

function Module(_metadata: unknown): ClassDecorator {
  return () => {};
}

function Inject(_key: unknown): ParameterDecorator {
  return () => {};
}

function forwardRef(_factory: () => unknown): unknown {
  return _factory;
}

@Module({
  providers: [
    { provide: DirectSourceToken, useClass: DirectAliasSource },
    { provide: DirectAliasToken, useExisting: forwardRef(() => DirectSourceToken) },
  ],
})
class DirectAliasModule {}

class DirectAliasApp {
  constructor(@Inject(DirectAliasToken) source) {
    sink(source.getInput());
  }
}

new DirectAliasApp();
