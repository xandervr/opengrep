import { DirectNestedSource } from "./source";

function Module(_metadata: unknown): ClassDecorator {
  return () => {};
}

function Inject(_key: string): ParameterDecorator {
  return () => {};
}

@Module({
  providers: [[{ provide: "source", useClass: DirectNestedSource }]],
})
class DirectNestedModule {}

class DirectNestedApp {
  constructor(@Inject("source") source) {
    sink(source.getInput());
  }
}

new DirectNestedApp();
