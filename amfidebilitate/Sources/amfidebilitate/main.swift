//
//  main.swift
//  jailbreakd
//
//  Created by Linus Henze.
//  Copyright © 2021 Linus Henze. All rights reserved.
//

import amfiC
import externalCStuff
import Foundation
import KernelExploit

var pe: PostExploitation!

do {
    pe = try PostExploitation()
    neuter()
} catch MemoryAccessError.failedToInitialize {
    execv(Bundle.main.executablePath, CommandLine.unsafeArgv)
    fatalError("Failed to re-exec myself!")

} catch let e {
    Logger.print("Failed to initialize a PostExploitation object")
    Logger.print("Error: \(e)")
}

destroy_exit(0)
pe.unsafelyUnwrapped.killMe()
pe.unsafelyUnwrapped.deinitKernelCall()
