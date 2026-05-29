import { DecoratorModuleSource } from "./source";

function Module(_metadata: unknown): ClassDecorator {
  return () => {};
}

function Inject(_key: string): ParameterDecorator {
  return () => {};
}

@Module({
  providers: [{ provide: "source", useClass: DecoratorModuleSource }],
})
class AppModule {}

class DecoratorModuleApp {
  constructor(@Inject("source") source) {
    sink(source.getInput());
  }
}

new DecoratorModuleApp();
