export class DirectToken {}

export class DirectTokenImpl {
  getInput(): string {
    return source();
  }
}
