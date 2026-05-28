import { RegistryClassSource } from "./source";

function registry(_providers: unknown[]): ClassDecorator {
  return () => {};
}

function inject(_key: string): ParameterDecorator {
  return () => {};
}

@registry([
  { token: "source", useClass: RegistryClassSource },
])
class RegistryClassBindings {}

class RegistryClassApp {
  constructor(@inject("source") source) {
    sink(source.getInput());
  }
}

new RegistryClassBindings();
new RegistryClassApp();
