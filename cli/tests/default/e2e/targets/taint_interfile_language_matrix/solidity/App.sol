contract App {
  function run() public { sink(Helpers.passThrough(Source.getInput())); }
  function sink(string memory value) public {}
}
