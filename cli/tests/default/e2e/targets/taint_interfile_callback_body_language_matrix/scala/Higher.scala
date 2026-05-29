object Higher { def applyCallback(callback: String => Unit): Unit = callback(Source.getInput()) }
