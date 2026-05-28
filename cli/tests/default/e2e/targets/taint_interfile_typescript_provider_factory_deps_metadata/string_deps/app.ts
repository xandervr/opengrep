import { StringDepSource } from "./source";

function Inject(_key: unknown): ParameterDecorator {
  return () => {};
}

function Module(_metadata: unknown): ClassDecorator {
  return () => {};
}

@Module({
  providers: [
    { provide: "source", useClass: StringDepSource },
    {
      provide: "factorySource",
      useFactory: (source) => source,
      deps: ["source"],
    },
  ],
})
class StringDepsModule {}

class StringDepsApp {
  constructor(@Inject("factorySource") source) {
    sink(source.getInput());
  }
}

new StringDepsApp();
