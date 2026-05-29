import { ConstFactorySource } from "./source";

function Inject(_key: unknown): ParameterDecorator {
  return () => {};
}

function Module(_metadata: unknown): ClassDecorator {
  return () => {};
}

const selectSource = (source) => source;

@Module({
  providers: [
    { provide: "source", useClass: ConstFactorySource },
    {
      provide: "factorySource",
      useFactory: selectSource,
      deps: ["source"],
    },
  ],
})
class ConstFactoryModule {}

class ConstFactoryApp {
  constructor(@Inject("factorySource") source) {
    sink(source.getInput());
  }
}

new ConstFactoryApp();
