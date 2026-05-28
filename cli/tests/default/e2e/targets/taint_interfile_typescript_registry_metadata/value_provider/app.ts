import { RegistryValueSource } from "./source";

function registry(_providers: unknown[]): ClassDecorator {
  return () => {};
}

function inject(_key: string): ParameterDecorator {
  return () => {};
}

@registry([
  { token: "source", useValue: new RegistryValueSource() },
])
class RegistryValueBindings {}

class RegistryValueApp {
  constructor(@inject("source") source) {
    sink(source.getInput());
  }
}

new RegistryValueBindings();
new RegistryValueApp();
