import { AliasNestedSource } from "./source";

function bootstrapApplication(_target: unknown, _metadata: unknown): void {}

function Inject(_key: string): ParameterDecorator {
  return () => {};
}

const aliasNestedProviders = [
  [{ provide: "source", useFactory: () => new AliasNestedSource() }],
];

class AliasNestedApp {
  constructor(@Inject("source") source) {
    sink(source.getInput());
  }
}

bootstrapApplication(AliasNestedApp, { providers: aliasNestedProviders });

new AliasNestedApp();
