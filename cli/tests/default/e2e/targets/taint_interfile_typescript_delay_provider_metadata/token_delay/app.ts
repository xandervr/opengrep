import { DelayTokenSource } from "./source";

function registry(_providers: unknown[]): ClassDecorator {
  return () => {};
}

function inject(_key: unknown): ParameterDecorator {
  return () => {};
}

function delay(_callback: () => unknown): unknown {
  return _callback;
}

class DelayTokenToken {}

@registry([
  { token: delay(() => DelayTokenToken), useFactory: () => new DelayTokenSource() },
])
class DelayTokenBindings {}

class DelayTokenApp {
  constructor(@inject(DelayTokenToken) source) {
    sink(source.getInput());
  }
}

new DelayTokenBindings();
new DelayTokenApp();
