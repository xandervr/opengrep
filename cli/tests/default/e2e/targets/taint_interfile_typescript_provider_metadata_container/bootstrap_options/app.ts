import { BootstrapOptionsSource } from "./source";

function bootstrapApplication(_target: unknown, _metadata: unknown): void {}

function Inject(_key: string): ParameterDecorator {
  return () => {};
}

class BootstrapOptionsApp {
  constructor(@Inject("source") source) {
    sink(source.getInput());
  }
}

bootstrapApplication(BootstrapOptionsApp, {
  providers: [{ provide: "source", useValue: new BootstrapOptionsSource() }],
});

new BootstrapOptionsApp();
