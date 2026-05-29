import { CreateModuleSource } from "./source";

function createModule(_metadata: unknown): void {}

function Inject(_key: string): ParameterDecorator {
  return () => {};
}

createModule({
  providers: [{ provide: "source", useFactory: () => new CreateModuleSource() }],
});

class CreateModuleApp {
  constructor(@Inject("source") source) {
    sink(source.getInput());
  }
}

new CreateModuleApp();
