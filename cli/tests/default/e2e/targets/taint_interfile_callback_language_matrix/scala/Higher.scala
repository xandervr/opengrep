object Higher { def applyCallback(callback: String => String): String = callback(Source.getInput()) }
