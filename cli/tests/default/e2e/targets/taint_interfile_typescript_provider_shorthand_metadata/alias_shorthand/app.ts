import { AliasShorthandSource } from "./source";

function bootstrapApplication(_target: unknown, _metadata: unknown): void {}

function Inject(_key: unknown): ParameterDecorator {
  return () => {};
}

const aliasShorthandProviders = [AliasShorthandSource];

class AliasShorthandApp {
  constructor(@Inject(AliasShorthandSource) source) {
    sink(source.getInput());
  }
}

bootstrapApplication(AliasShorthandApp, { providers: aliasShorthandProviders });

new AliasShorthandApp();
