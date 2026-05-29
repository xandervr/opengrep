import { ClassTokenAliasSource } from "./source";

class SourceToken {}

class AliasToken {}

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
    { provide: AliasToken, useExisting: forwardRef(() => SourceToken) },
    { provide: SourceToken, useClass: ClassTokenAliasSource },
  ],
})
class ClassTokenAliasModule {}

class ClassTokenAliasApp {
  constructor(@Inject(AliasToken) source) {
    sink(source.getInput());
  }
}

new ClassTokenAliasApp();
