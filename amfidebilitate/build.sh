set -e

CODESIGN_IDENTITY="Apple Development: barfie@gabba.ga (Z3HQ2A5H59)"

swiftcArgs=(-sdk "`xcrun --sdk iphoneos --show-sdk-path`" -target arm64-apple-ios14.0 -O -framework IOKit)

swiftBuild=(swift build -c release -Xcc "-DIOS_BUILD" -Xcc -target -Xcc arm64-apple-ios14.0 -Xcc -isysroot -Xcc "`xcrun --sdk iphoneos --show-sdk-path`" )
for arg in ${swiftcArgs[*]}
do
    swiftBuild+=(-Xswiftc "$arg")
done

echo Building amfidebilitate
echo ${swiftBuild[*]}
${swiftBuild[*]}

echo Stripping amfidebilitate
# strip -s keep .build/release/amfidebilitate

echo Signing amfidebilitate
codesign -s "$CODESIGN_IDENTITY" --entitlements amfidebilitate.entitlements .build/release/amfidebilitate

rm jad.tc amfidebilitate || true
cp .build/release/amfidebilitate .
./tc_macos_x86_64 create jad.tc amfidebilitate

ssh root@le-carote -p 44 "/binpack/bin/rm /binpack/amfidebilitate" | true
scp -P 44 amfidebilitate jad.tc root@le-carote:/binpack
ssh root@le-carote -p 44 "/.Fugu14Untether/jailbreakd loadTC /binpack/jad.tc"
# ssh root@le-carote -p 44 "/binpack/amfidebilitate neuter"

CDHash=$(codesign -dvvv amfidebilitate 2>&1 | grep 'CDHash=' | sed 's/CDHash=//g')
echo CDHash of amfidebilitate: $CDHash
