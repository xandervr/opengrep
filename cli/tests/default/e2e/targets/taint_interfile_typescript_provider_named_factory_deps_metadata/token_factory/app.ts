import { TokenFactoryAlias, TokenFactorySource, TokenFactoryToken } from "./source";

function Injectable(): ClassDecorator {
  return () => {};
}

function Module(_metadata: unknown): ClassDecorator {
  return () => {};
}

function selectSource(source) {
  return source;
}

@Module({
  providers: [
    { provide: TokenFactoryToken, useClass: TokenFactorySource },
    {
      provide: TokenFactoryAlias,
      useFactory: selectSource,
      inject: [TokenFactoryToken],
    },
  ],
})
class TokenFactoryModule {}

@Injectable()
class TokenFactoryApp {
  constructor(source: TokenFactoryAlias) {
    sink(source.getInput());
  }
}

new TokenFactoryApp();
