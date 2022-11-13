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
    if memorystatus_control(UInt32(MEMORYSTATUS_CMD_SET_JETSAM_TASK_LIMIT), getpid(), 100, nil, 0) == -1 { // set memory limit to 100mb
        print("[WARNING] Failed to set mem limit - will crash if run as daemon")
    }

    pe = try PostExploitation()
    neuter()

    destroy_exit(0)
    pe.unsafelyUnwrapped.killMe()
    pe.unsafelyUnwrapped.deinitKernelCall()

} catch MemoryAccessError.failedToInitialize {
    execv(Bundle.main.executablePath, CommandLine.unsafeArgv)
    fatalError("Failed to re-exec myself!")

} catch let e {
    Logger.print("Failed to initialize a PostExploitation object")
    Logger.print("Error: \(e)")
}
