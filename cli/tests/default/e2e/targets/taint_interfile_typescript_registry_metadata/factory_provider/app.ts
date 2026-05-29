import { RegistryFactorySource } from "./source";

function registry(_providers: unknown[]): ClassDecorator {
  return () => {};
}

function inject(_key: string): ParameterDecorator {
  return () => {};
}

@registry([
  { token: "source", useFactory: () => new RegistryFactorySource() },
])
class RegistryFactoryBindings {}

class RegistryFactoryApp {
  constructor(@inject("source") source) {
    sink(source.getInput());
  }
}

new RegistryFactoryBindings();
new RegistryFactoryApp();
