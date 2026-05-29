export class StaticSource {
  static value = source();

  static getInput() {
    return StaticSource.value;
  }
}
