import { DelayInjectSource } from "./source";

function registry(_providers: unknown[]): ClassDecorator {
  return () => {};
}

function inject(_key: unknown): ParameterDecorator {
  return () => {};
}

function delay(_callback: () => unknown): unknown {
  return _callback;
}

class DelayInjectToken {}

@registry([
  { token: DelayInjectToken, useClass: DelayInjectSource },
])
class DelayInjectBindings {}

class DelayInjectApp {
  constructor(@inject(delay(() => DelayInjectToken)) source) {
    sink(source.getInput());
  }
}

new DelayInjectBindings();
new DelayInjectApp();
