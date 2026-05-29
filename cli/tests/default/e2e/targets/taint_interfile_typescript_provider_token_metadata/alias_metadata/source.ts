export class AliasToken {}

export class AliasTokenImpl {
  getInput(): string {
    return source();
  }
}
