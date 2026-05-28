import { InjectDepSource } from "./source";

function Inject(_key: unknown): ParameterDecorator {
  return () => {};
}

function Module(_metadata: unknown): ClassDecorator {
  return () => {};
}

@Module({
  providers: [
    { provide: "source", useClass: InjectDepSource },
    {
      provide: "factorySource",
      useFactory: (source) => source,
      inject: ["source"],
    },
  ],
})
class InjectDepsModule {}

class InjectDepsApp {
  constructor(@Inject("factorySource") source) {
    sink(source.getInput());
  }
}

new InjectDepsApp();
