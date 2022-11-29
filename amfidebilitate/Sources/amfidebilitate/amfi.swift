import amfiC
import Darwin
import externalCStuff
import Foundation
import KernelExploit

var cubbyhole: UInt64 = 0

// func addHash(cdhashes: [[UInt8]]) -> UInt64? {
//     var tc = Data()
//     tc += [0x01, 0x00, 0x00, 0x00] // version
//     tc += [UInt8](0 ..< 16).map { _ in .random(in: UInt8.min ... UInt8.max) } // random UUID

//     withUnsafeBytes(of: UInt32(cdhashes.count).littleEndian) { tc.append(contentsOf: $0) } // cdhash count
//     for hash in cdhashes {
//         guard hash.count == 22 else {
//             print("Length of hash was \(hash.count), panic.")
//             return 0
//         }

//         tc += hash // cdhashes
//         // tc += [0x02, 0x00] // flag, hash type --- this should be done by hand now to be safe
//     }

//     // Logger.print("Injecting \(cdhashes.count) trust caches: \(Array(tc))")
//     return pe.injectTC(data: tc)
// }

@_cdecl("kread_s")
func kread(_ kptr: UInt64, _ buffer: UnsafeMutableRawPointer, _ count: UInt64) -> Int {
    do {
        let data = try pe.mem.readBytes(virt: kptr, count: count)
        data.copyBytes(to: buffer.assumingMemoryBound(to: UInt8.self), count: Int(count))
        return 0
    } catch {
        return 1
    }
}

@_cdecl("kwrite_s")
func kwrite(_ kptr: UInt64, _ buffer: UnsafeMutableRawPointer, _ count: UInt64) -> Int {
    do {
        let data = Data(bytesNoCopy: buffer, count: Int(count), deallocator: .none)
        try pe.mem.writeBytes(virt: kptr, data: data)
        return 0
    } catch {
        return 1
    }
}

@_cdecl("fetch_deets")
func fetch_deets(kdetails: UnsafeMutablePointer<KDetails>) -> Int {
    do {
        // maybe store this statically?
        kdetails.pointee.allproc = try pe.mem.r64(virt: pe.slide(pe.offsets.allProcAddr))
        kdetails.pointee.kbase = pe.mem.kernelVirtBase
        kdetails.pointee.kslide = pe.mem.kernelSlide
        kdetails.pointee.tcroot = pe.slide(pe.mem.offsets.loadedTCRoot)
        kdetails.pointee.cubby = cubbyhole

        return 0
    } catch {
        print("Failed to init kdetails")
        return 1
    }
}

@_cdecl("init_tc")
func createEmpty(count: UInt32) -> UInt64 {
    // return addHash(cdhashes: [[UInt8]](repeating: Array([[0x02, 0x00], [UInt8](repeating: 0, count: 20)].joined()), count: count)) ?? 0 // enforce specific hash type + flag, user can change it later if the need arises
    do {
        return try pe.injectEmptyTrustCache(space: count)
    } catch let e {
        print("Error adding: \(e)")
        return 0
    }
}

@_cdecl("signPointer")
func signPointer(value: UInt64, context: UInt64) -> UInt64 {
    do {
        return try pe.pacda(value: value, context: context, blendFactor: 0x84E8) // and with this, I HAVE INFINITE POWER!
    } catch let e {
        print("Failed to sign pointer: \(e)")
        return 0
    }
}

func queue() {
    DispatchQueue(label: "amfi", qos: .userInteractive, attributes: [], autoreleaseFrequency: .workItem).async {
        autoreleasepool { // you know where there's a dripping sound somewhere but you can't FUCKING find where?! Leaking mem - three hours to find it
            var receive_msg = OOLReceiveMessage()
            receive_ool(&receive_msg, UInt32(MACH_MSG_TIMEOUT_NONE))

            queue() // start another queue
            amfi_handle(&receive_msg)
        }
    }
}

func neuter() {
    // Create empty trust cache that will have its contents replaced it whenever an app needs to be run
    Logger.print("Aight, let's make our cubby hole")
    guard setup_mach() == 1 else {
        print("Failed to init mach!")
        return
    }

    do {
        cubbyhole = try pe.injectEmptyTrustCache(space: 1)
    } catch let e {
        print("Failed to add placeholder trustcache: \(e)")
        return
    }

    print("Cubbyhole: \(cubbyhole)")

    // start loop - honestly this is probably a horrible way to do this
    print("Waiting for instructions")
    queue()

    RunLoop.main.run() // prevent app termination
}
