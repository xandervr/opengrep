import { FunctionFactorySource } from "./source";

function Inject(_key: unknown): ParameterDecorator {
  return () => {};
}

function Module(_metadata: unknown): ClassDecorator {
  return () => {};
}

function selectSource(source) {
  return source;
}

@Module({
  providers: [
    { provide: "source", useClass: FunctionFactorySource },
    {
      provide: "factorySource",
      useFactory: selectSource,
      deps: ["source"],
    },
  ],
})
class FunctionFactoryModule {}

class FunctionFactoryApp {
  constructor(@Inject("factorySource") source) {
    sink(source.getInput());
  }
}

new FunctionFactoryApp();
