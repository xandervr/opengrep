import { DecoratorMultiSource } from "./source";

function Module(_metadata: unknown): ClassDecorator {
  return () => {};
}

function Inject(_key: string): ParameterDecorator {
  return () => {};
}

@Module({
  providers: [
    { provide: "sources", useClass: DecoratorMultiSource, multi: true },
  ],
})
class DecoratorMultiModule {}

class DecoratorMultiApp {
  constructor(@Inject("sources") sources) {
    sink(sources[0].getInput());
  }
}

new DecoratorMultiApp();
