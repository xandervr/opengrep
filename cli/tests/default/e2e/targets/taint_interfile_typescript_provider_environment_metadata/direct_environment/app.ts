import { DirectEnvironmentSource } from "./source";

function bootstrapApplication(_target: unknown, _metadata: unknown): void {}

function makeEnvironmentProviders(_providers: unknown[]): unknown {
  return _providers;
}

function Inject(_key: string): ParameterDecorator {
  return () => {};
}

class DirectEnvironmentApp {
  constructor(@Inject("source") source) {
    sink(source.getInput());
  }
}

bootstrapApplication(DirectEnvironmentApp, {
  providers: [
    makeEnvironmentProviders([
      { provide: "source", useClass: DirectEnvironmentSource },
    ]),
  ],
});

new DirectEnvironmentApp();
